//! Versioned business DTOs. This crate has no GUI, HTTP or SQLite dependency.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERSION: u32 = 1;
pub const MAX_RPC_BYTES: usize = 60 * 1024;
pub const MAX_DESCRIPTION_BYTES: usize = 4 * 1024;
pub const MAX_PLAINTEXT_BYTES: usize = 32 * 1024;
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_PLAINTEXT_BYTES + 12 + 16;
pub const MAX_ENTRIES: i64 = 100_000;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const SESSION_TTL: i64 = 48 * 60 * 60;
pub const OPERATION_TTL: i64 = 7 * 24 * 60 * 60;
pub const ROTATION_IDLE_TTL: i64 = 60 * 60;
pub const ROTATION_MAX_TTL: i64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnsupportedProtocol,
    InvalidRequest,
    LimitExceeded,
    Unauthenticated,
    InvalidCredentials,
    SessionExpired,
    Forbidden,
    VaultUninitialized,
    VaultUnavailable,
    AlreadyInitialized,
    NotFound,
    GenerationChanged,
    KeyEpochChanged,
    RevisionChanged,
    RotationConflict,
    RotationIncomplete,
    RotationExpired,
    OperationMismatch,
    OperationExpired,
    RateLimited,
    Busy,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:?})", self.message, self.code)
    }
}
impl std::error::Error for ApiError {}
pub type ApiResult<T> = Result<T, ApiError>;

pub fn invalid(message: &str) -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest, message)
}

pub fn random_id() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    pub algorithm: String,
    pub version: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_bytes: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".into(),
            version: 19,
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
            output_bytes: 32,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionMeta {
    pub content_format: u32,
    pub kdf: KdfParams,
    pub salt: String,
    pub verifier: String,
}

fn decode_canonical(value: &str) -> ApiResult<Vec<u8>> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| invalid("invalid base64"))?;
    if STANDARD.encode(&bytes) != value {
        return Err(invalid("noncanonical base64"));
    }
    Ok(bytes)
}

impl EncryptionMeta {
    pub fn validate(&self) -> ApiResult<()> {
        if self.content_format != 1 || self.kdf != KdfParams::default() {
            return Err(invalid("unsupported content format or KDF parameters"));
        }
        if self.salt.len() != 24 || decode_canonical(&self.salt)?.len() != 16 {
            return Err(invalid("salt must be 16 bytes"));
        }
        if self.verifier.len() != 52 || decode_canonical(&self.verifier)?.len() != 39 {
            return Err(invalid("invalid verifier format"));
        }
        Ok(())
    }
}

pub fn validate_description(value: &str) -> ApiResult<()> {
    if value.len() > MAX_DESCRIPTION_BYTES {
        return Err(ApiError::new(
            ErrorCode::LimitExceeded,
            "description exceeds 4 KiB",
        ));
    }
    Ok(())
}

pub fn validate_content(value: &str) -> ApiResult<()> {
    if value.len() > MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4 {
        return Err(ApiError::new(
            ErrorCode::LimitExceeded,
            "content exceeds 32 KiB envelope",
        ));
    }
    let bytes = decode_canonical(value)?;
    if !(28..=MAX_CIPHERTEXT_BYTES).contains(&bytes.len()) {
        return Err(invalid("invalid AES-GCM ciphertext size"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteContext {
    pub operation_id: String,
    pub generation: String,
    pub key_epoch: i64,
    pub valid_until: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotatedEntry {
    pub id: i64,
    pub content: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", content = "args", deny_unknown_fields)]
pub enum Command {
    #[serde(rename = "server.info")]
    ServerInfo,
    #[serde(rename = "auth.login")]
    AuthLogin { username: String, password: String },
    #[serde(rename = "auth.validate")]
    AuthValidate,
    #[serde(rename = "auth.logout")]
    AuthLogout,
    #[serde(rename = "vault.initialize")]
    VaultInitialize {
        write: WriteContext,
        encryption: EncryptionMeta,
    },
    #[serde(rename = "vault.meta")]
    VaultMeta,
    #[serde(rename = "entries.list")]
    EntriesList {
        generation: String,
        expected_revision: Option<i64>,
        after_id: Option<i64>,
        limit: u16,
    },
    #[serde(rename = "entries.read_content")]
    EntriesReadContent {
        generation: String,
        id: i64,
        expected_revision: i64,
    },
    #[serde(rename = "entries.create")]
    EntriesCreate {
        write: WriteContext,
        description: String,
        content: String,
    },
    #[serde(rename = "entries.update")]
    EntriesUpdate {
        write: WriteContext,
        id: i64,
        description: Option<String>,
        content: Option<String>,
    },
    #[serde(rename = "entries.delete")]
    EntriesDelete { write: WriteContext, id: i64 },
    #[serde(rename = "operations.get")]
    OperationsGet {
        generation: String,
        operation_id: String,
    },
    #[serde(rename = "rotation.begin")]
    RotationBegin {
        write: WriteContext,
        expected_vault_revision: i64,
        new_encryption: EncryptionMeta,
    },
    #[serde(rename = "rotation.read_batch")]
    RotationReadBatch {
        generation: String,
        job_id: String,
        after_id: Option<i64>,
        limit: u16,
    },
    #[serde(rename = "rotation.stage")]
    RotationStage {
        write: WriteContext,
        job_id: String,
        entries: Vec<RotatedEntry>,
    },
    #[serde(rename = "rotation.commit")]
    RotationCommit { write: WriteContext, job_id: String },
    #[serde(rename = "rotation.abort")]
    RotationAbort { write: WriteContext, job_id: String },
    #[serde(rename = "rotation.status")]
    RotationStatus { generation: String, job_id: String },
}

impl Command {
    pub fn write(&self) -> Option<&WriteContext> {
        match self {
            Self::VaultInitialize { write, .. }
            | Self::EntriesCreate { write, .. }
            | Self::EntriesUpdate { write, .. }
            | Self::EntriesDelete { write, .. }
            | Self::RotationBegin { write, .. }
            | Self::RotationStage { write, .. }
            | Self::RotationCommit { write, .. }
            | Self::RotationAbort { write, .. } => Some(write),
            _ => None,
        }
    }

    /// Canonicalization is independent of serde_json's feature-unified map type.
    /// Only typed, integer-only DTOs enter this digest; transport/session fields do not.
    pub fn digest(&self) -> ApiResult<[u8; 32]> {
        let value = serde_json::to_value(self).map_err(|_| invalid("cannot encode command"))?;
        let mut bytes = Vec::new();
        canonical_json(&serde_json::json!([VERSION, value]), &mut bytes)?;
        Ok(Sha256::digest(bytes).into())
    }
}

fn canonical_json(value: &serde_json::Value, output: &mut Vec<u8>) -> ApiResult<()> {
    match value {
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|_| invalid("cannot canonicalize command"))?;
                output.push(b':');
                canonical_json(value, output)?;
            }
            output.push(b'}');
        }
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                canonical_json(value, output)?;
            }
            output.push(b']');
        }
        value => serde_json::to_writer(output, value)
            .map_err(|_| invalid("cannot canonicalize command"))?,
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcRequest {
    pub protocol_version: u32,
    pub request_id: String,
    pub session_token: Option<String>,
    pub command: Command,
}

impl Drop for RpcRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(token) = &mut self.session_token {
            token.zeroize();
        }
        if let Command::AuthLogin { password, .. } = &mut self.command {
            password.zeroize();
        }
    }
}

impl RpcRequest {
    pub fn new(command: Command, session_token: Option<String>) -> Self {
        Self {
            protocol_version: VERSION,
            request_id: random_id(),
            session_token,
            command,
        }
    }

    pub fn decode(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() > MAX_RPC_BYTES {
            return Err(ApiError::new(
                ErrorCode::LimitExceeded,
                "RPC exceeds 60 KiB",
            ));
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| invalid("invalid RPC JSON"))?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> ApiResult<()> {
        if self.protocol_version != VERSION {
            return Err(ApiError::new(
                ErrorCode::UnsupportedProtocol,
                "unsupported protocol version",
            ));
        }
        if !valid_id(&self.request_id) {
            return Err(invalid("invalid request_id"));
        }
        if let Some(write) = self.command.write()
            && (!valid_id(&write.operation_id)
                || !valid_id(&write.generation)
                || write.key_epoch < 0
                || write.valid_until < 0)
        {
            return Err(invalid("invalid write context"));
        }
        if self
            .session_token
            .as_ref()
            .is_some_and(|token| token.len() > 128)
        {
            return Err(invalid("invalid session token"));
        }
        if self.encode()?.len() > MAX_RPC_BYTES {
            return Err(ApiError::new(
                ErrorCode::LimitExceeded,
                "RPC exceeds 60 KiB",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> ApiResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| invalid("cannot encode RPC"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerInfo {
    pub server_id: String,
    pub generation: String,
    pub initialized: bool,
    pub server_time: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSession {
    pub username: String,
    pub token: Option<String>,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultMeta {
    pub vault_id: String,
    pub generation: String,
    pub vault_revision: i64,
    pub key_epoch: i64,
    pub encryption: EncryptionMeta,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryMeta {
    pub id: i64,
    pub description: String,
    pub revision: i64,
    pub key_epoch: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryPage {
    pub generation: String,
    pub vault_revision: i64,
    pub key_epoch: i64,
    pub entries: Vec<EntryMeta>,
    pub next_after_id: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryContent {
    pub id: i64,
    pub revision: i64,
    pub key_epoch: i64,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryMutation {
    pub entry: EntryMeta,
    pub vault_revision: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    NotFound,
    Committed,
    Rejected,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub state: OperationState,
    pub outcome: Option<Box<RpcOutcome>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationState {
    Staging,
    Committed,
    Aborted,
    Expired,
    Conflicted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationInfo {
    pub job_id: String,
    pub state: RotationState,
    pub baseline_revision: i64,
    pub key_epoch: i64,
    pub total_entries: i64,
    pub staged_entries: i64,
    pub expires_at: i64,
    pub committed_meta: Option<VaultMeta>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationBatch {
    pub job: RotationInfo,
    pub entries: Vec<RotatedEntry>,
    pub next_after_id: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ResponseBody {
    ServerInfo(ServerInfo),
    Session(AuthSession),
    LoggedOut,
    VaultMeta(VaultMeta),
    Entries(EntryPage),
    Content(EntryContent),
    Entry(EntryMutation),
    Deleted { id: i64, vault_revision: i64 },
    Operation(OperationRecord),
    Rotation(RotationInfo),
    RotationBatch(RotationBatch),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RpcOutcome {
    Ok { result: Box<ResponseBody> },
    Error { error: ApiError },
}

impl From<ApiResult<ResponseBody>> for RpcOutcome {
    fn from(value: ApiResult<ResponseBody>) -> Self {
        match value {
            Ok(result) => Self::Ok {
                result: Box::new(result),
            },
            Err(error) => Self::Error { error },
        }
    }
}

impl RpcOutcome {
    pub fn into_result(self) -> ApiResult<ResponseBody> {
        match self {
            Self::Ok { result } => Ok(*result),
            Self::Error { error } => Err(error),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcResponse {
    pub protocol_version: u32,
    pub request_id: String,
    pub outcome: RpcOutcome,
}

impl RpcResponse {
    pub fn new(request_id: String, result: ApiResult<ResponseBody>) -> Self {
        Self {
            protocol_version: VERSION,
            request_id,
            outcome: result.into(),
        }
    }

    pub fn encode(&self) -> ApiResult<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| invalid("cannot encode response"))?;
        if bytes.len() > MAX_RPC_BYTES {
            return Err(ApiError::new(
                ErrorCode::LimitExceeded,
                "response exceeds 60 KiB",
            ));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_boundaries_and_metadata_are_strict() {
        assert!(validate_content(&STANDARD.encode([0; 27])).is_err());
        assert!(validate_content(&STANDARD.encode([0; 28])).is_ok());
        assert!(validate_content(&STANDARD.encode(vec![0; MAX_CIPHERTEXT_BYTES])).is_ok());
        assert!(validate_content(&STANDARD.encode(vec![0; MAX_CIPHERTEXT_BYTES + 1])).is_err());
        let mut meta = EncryptionMeta {
            content_format: 1,
            kdf: KdfParams::default(),
            salt: STANDARD.encode([0; 16]),
            verifier: STANDARD.encode([0; 39]),
        };
        assert!(meta.validate().is_ok());
        meta.kdf.memory_kib = u32::MAX;
        assert!(meta.validate().is_err());
        assert!(validate_description(&"中".repeat(1366)).is_err());
    }

    #[test]
    fn wire_rejects_unknown_duplicate_version_and_oversized_fields() {
        let request = RpcRequest::new(Command::ServerInfo, None);
        let bytes = request.encode().unwrap();
        assert!(RpcRequest::decode(&bytes).is_ok());
        let json = String::from_utf8(bytes).unwrap();
        assert!(
            RpcRequest::decode(json.replacen('{', "{\"unknown\":true,", 1).as_bytes()).is_err()
        );
        assert!(
            RpcRequest::decode(json.replacen('{', "{\"protocol_version\":1,", 1).as_bytes())
                .is_err()
        );
        let mut request = request;
        request.protocol_version = 2;
        assert!(matches!(
            request.validate(),
            Err(ApiError {
                code: ErrorCode::UnsupportedProtocol,
                ..
            })
        ));
        assert!(RpcRequest::decode(&vec![b' '; MAX_RPC_BYTES + 1]).is_err());
    }

    #[test]
    fn idempotency_digest_ignores_transport_but_binds_business_fields() {
        let mut request = RpcRequest::new(
            Command::EntriesDelete {
                write: WriteContext {
                    operation_id: random_id(),
                    generation: random_id(),
                    key_epoch: 1,
                    valid_until: 123,
                },
                id: 1,
            },
            None,
        );
        let digest = request.command.digest().unwrap();
        request.request_id = random_id();
        request.session_token = Some("new-session".into());
        assert_eq!(digest, request.command.digest().unwrap());
        if let Command::EntriesDelete { id, .. } = &mut request.command {
            *id = 2;
        }
        assert_ne!(digest, request.command.digest().unwrap());
    }

    #[test]
    fn canonicalization_sorts_nested_keys_independently_of_feature_unification() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"z":{"b":1,"a":2},"a":"中"}"#).unwrap();
        let mut bytes = Vec::new();
        canonical_json(&value, &mut bytes).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"a":"中","z":{"a":2,"b":1}}"#
        );
    }
}
