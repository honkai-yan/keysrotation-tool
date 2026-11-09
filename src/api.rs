use crate::{config::Config, crypto};
use keyrotation_protocol::*;
use keyrotation_transport::{Client, Endpoint, TransportError};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, TransportError>;

#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    pub url: String,
    pub public_key: Option<String>,
    pub ca_file: Option<String>,
}
impl Scope {
    pub fn from_config(config: &Config) -> Self {
        Self {
            url: config.server_url.clone(),
            public_key: config.trusted_servers.get(&config.server_url).cloned(),
            ca_file: config.trusted_ca_files.get(&config.server_url).cloned(),
        }
    }
    pub fn client(&self) -> Result<Client> {
        let ca = self
            .ca_file
            .as_ref()
            .map(std::fs::read_to_string)
            .transpose()
            .map_err(|_| TransportError::InvalidPublicKey)?;
        Client::new(
            Endpoint::parse(&self.url)?,
            self.public_key.as_deref(),
            ca.as_deref(),
        )
    }
}

#[derive(Clone)]
pub struct Snapshot {
    pub meta: VaultMeta,
    pub rows: Vec<EntryMeta>,
}
pub struct PreparedBatch {
    pub entries: Vec<RotatedEntry>,
    pub next_after_id: Option<i64>,
}

pub fn snapshot(client: &mut Client, token: Option<String>) -> Result<Snapshot> {
    for _ in 0..3 {
        let ResponseBody::VaultMeta(meta) =
            client.call(&RpcRequest::new(Command::VaultMeta, token.clone()))?
        else {
            return Err(TransportError::InvalidResponse);
        };
        let mut rows = Vec::new();
        let mut after_id = None;
        let mut changed = false;
        loop {
            let result = client.call(&RpcRequest::new(
                Command::EntriesList {
                    generation: meta.generation.clone(),
                    expected_revision: Some(meta.vault_revision),
                    after_id,
                    limit: MAX_PAGE_SIZE,
                },
                token.clone(),
            ));
            let page = match result {
                Ok(ResponseBody::Entries(page)) => page,
                Err(TransportError::Remote(error)) if error.code == ErrorCode::RevisionChanged => {
                    changed = true;
                    break;
                }
                Err(error) => return Err(error),
                _ => return Err(TransportError::InvalidResponse),
            };
            if page.generation != meta.generation
                || page.vault_revision != meta.vault_revision
                || page.key_epoch != meta.key_epoch
                || rows.len() + page.entries.len() > MAX_ENTRIES as usize
            {
                return Err(TransportError::InvalidResponse);
            }
            let mut last = after_id.unwrap_or(0);
            for entry in &page.entries {
                if entry.id <= last
                    || entry.key_epoch != meta.key_epoch
                    || validate_description(&entry.description).is_err()
                {
                    return Err(TransportError::InvalidResponse);
                }
                last = entry.id;
            }
            if page
                .next_after_id
                .is_some_and(|cursor| cursor != last || Some(cursor) == after_id)
                || page.next_after_id.is_some() && page.entries.is_empty()
            {
                return Err(TransportError::InvalidResponse);
            }
            rows.extend(page.entries);
            after_id = page.next_after_id;
            if after_id.is_none() {
                break;
            }
        }
        if !changed {
            return Ok(Snapshot { meta, rows });
        }
    }
    Err(TransportError::Remote(ApiError::new(
        ErrorCode::RevisionChanged,
        "数据库正在变化，请重试",
    )))
}

pub fn prepare_rotation_batch(
    client: &mut Client,
    request: &RpcRequest,
    old: &crypto::Key,
    new: &crypto::Key,
) -> Result<PreparedBatch> {
    let ResponseBody::RotationBatch(batch) = client.call(request)? else {
        return Err(TransportError::InvalidResponse);
    };
    let mut entries = Vec::new();
    for entry in batch.entries {
        validate_content(&entry.content).map_err(TransportError::Remote)?;
        let plain = Zeroizing::new(crypto::decrypt(old, &entry.content).map_err(|_| {
            TransportError::Remote(ApiError::new(
                ErrorCode::InvalidRequest,
                "旧数据解密失败，未修改密钥",
            ))
        })?);
        let content = crypto::encrypt(new, &plain).map_err(|_| TransportError::InvalidResponse)?;
        entries.push(RotatedEntry {
            id: entry.id,
            content,
        });
    }
    Ok(PreparedBatch {
        entries,
        next_after_id: batch.next_after_id,
    })
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
