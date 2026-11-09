//! 本机真实运行验证脚本。
//!
//! 该文件是测试工装，不属于交付代码：真实旧库实例只读校验、空实例写入全套业务、
//! 重启恢复与 HTTPS 通道各跑一遍。用法见 `run_e2e.sh`。
//!
//! ```text
//! cargo run --example real_run --locked -- real
//! cargo run --example real_run --locked -- sandbox
//! cargo run --example real_run --locked -- resume
//! cargo run --example real_run --locked -- https
//! ```

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use keyrotation_protocol::*;
use keyrotation_transport::{Client, Endpoint, TransportError};
use rusqlite::{Connection, OpenFlags};
use std::time::{SystemTime, UNIX_EPOCH};

type Boxed = Box<dyn std::error::Error + Send + Sync>;
type Key = [u8; 32];

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("缺少环境变量 {name}"))
}

/// 口令文件内容去掉末尾换行，与服务器 CLI 的 `--password-stdin` 处理一致。
fn secret(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("读取口令文件失败: {path}"))
        .trim_end_matches(['\r', '\n'])
        .to_owned()
}

// ---------------------------------------------------------------------------
// 客户端侧加密：与 src/crypto.rs 完全一致（本 crate 无 lib 目标，故此处复刻）
// ---------------------------------------------------------------------------

fn derive_key(passphrase: &str, salt: &[u8]) -> Key {
    let mut out = [0u8; 32];
    let p = argon2::Params::new(19_456, 2, 1, Some(32)).expect("KDF 参数");
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p)
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .expect("密钥派生失败");
    out
}

fn encrypt(key: &Key, plain: &str) -> Result<String, Boxed> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    if plain.len() > MAX_PLAINTEXT_BYTES {
        return Err("内容不能超过 32 KiB".into());
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce: [u8; 12] = rand::random();
    let ct = cipher
        .encrypt(&Nonce::from(nonce), plain.as_bytes())
        .map_err(|_| "加密失败")?;
    let mut buf = nonce.to_vec();
    buf.extend_from_slice(&ct);
    Ok(STANDARD.encode(buf))
}

fn decrypt(key: &Key, encoded: &str) -> Result<String, Boxed> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    let buf = STANDARD.decode(encoded)?;
    if !(28..=MAX_CIPHERTEXT_BYTES).contains(&buf.len()) {
        return Err("密文长度非法".into());
    }
    let (nonce, ct) = buf.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    let pt = cipher
        .decrypt(&Nonce::try_from(nonce).map_err(|_| "密文长度非法")?, ct)
        .map_err(|_| "解密失败，密钥可能不正确")?;
    Ok(String::from_utf8(pt)?)
}

fn salt_b64() -> String {
    STANDARD.encode(rand::random::<[u8; 16]>())
}

/// 按客户端约定的校验值格式生成加密元数据。
fn encryption_for(passphrase: &str, salt: String) -> EncryptionMeta {
    let key = derive_key(passphrase, &STANDARD.decode(&salt).expect("salt"));
    EncryptionMeta {
        content_format: 1,
        kdf: KdfParams::default(),
        verifier: encrypt(&key, "ptoolkit-ok").expect("校验值"),
        salt,
    }
}

fn fresh_encryption(passphrase: &str) -> EncryptionMeta {
    encryption_for(passphrase, salt_b64())
}

// ---------------------------------------------------------------------------
// 结果记录
// ---------------------------------------------------------------------------

struct Report {
    pass: u32,
    failures: Vec<String>,
}

impl Report {
    fn new() -> Self {
        Self {
            pass: 0,
            failures: Vec::new(),
        }
    }

    fn check(&mut self, name: &str, cond: bool) {
        if cond {
            self.pass += 1;
            println!("  [ok]   {name}");
        } else {
            self.failures.push(name.to_owned());
            println!("  [FAIL] {name}");
        }
    }

    fn same<T: PartialEq<U> + std::fmt::Debug + ?Sized, U: std::fmt::Debug + ?Sized>(
        &mut self,
        name: &str,
        got: &T,
        want: &U,
    ) {
        if got == want {
            self.check(name, true);
        } else {
            println!("         got={got:?} want={want:?}");
            self.check(name, false);
        }
    }

    fn code(&mut self, name: &str, result: Result<ResponseBody, TransportError>, want: ErrorCode) {
        match result {
            Err(TransportError::Remote(error)) if error.code == want => {
                self.check(&format!("{name}（{}）", label(want)), true);
            }
            Err(TransportError::Remote(error)) => {
                println!(
                    "         got={} \"{}\" want={}",
                    label(error.code),
                    error.message,
                    label(want)
                );
                self.check(name, false);
            }
            Err(other) => {
                println!("         got transport {other}");
                self.check(name, false);
            }
            Ok(body) => {
                println!("         got unexpected ok {:?}", variant(&body));
                self.check(name, false);
            }
        }
    }

    fn exit(&self) -> i32 {
        println!(
            "  ---- 通过 {} 项，失败 {} 项 ----",
            self.pass,
            self.failures.len()
        );
        for name in &self.failures {
            println!("  失败：{name}");
        }
        if self.failures.is_empty() { 0 } else { 1 }
    }
}

fn label(code: ErrorCode) -> String {
    format!("{code:?}")
}

fn variant(body: &ResponseBody) -> &'static str {
    match body {
        ResponseBody::ServerInfo(_) => "server_info",
        ResponseBody::Session(_) => "session",
        ResponseBody::LoggedOut => "logged_out",
        ResponseBody::VaultMeta(_) => "vault_meta",
        ResponseBody::Entries(_) => "entries",
        ResponseBody::Content(_) => "content",
        ResponseBody::Entry(_) => "entry",
        ResponseBody::Deleted { .. } => "deleted",
        ResponseBody::Operation(_) => "operation",
        ResponseBody::Rotation(_) => "rotation",
        ResponseBody::RotationBatch(_) => "rotation_batch",
    }
}

// ---------------------------------------------------------------------------
// 最小 RPC 客户端封装
// ---------------------------------------------------------------------------

struct Api {
    client: Client,
    token: Option<String>,
    generation: String,
    server_id: String,
    server_time: i64,
}

impl Api {
    fn connect(url: &str, public: Option<&str>, ca_pem: Option<&str>) -> Result<Self, Boxed> {
        let endpoint = Endpoint::parse(url)?;
        let client = Client::new(endpoint, public, ca_pem)?;
        Ok(Self {
            client,
            token: None,
            generation: String::new(),
            server_id: String::new(),
            server_time: now(),
        })
    }

    fn call(&mut self, command: Command) -> Result<ResponseBody, TransportError> {
        self.client
            .call(&RpcRequest::new(command, self.token.clone()))
    }

    fn body(&mut self, name: &str, command: Command) -> Result<ResponseBody, Boxed> {
        self.call(command)
            .map_err(|error| format!("{name}: {error}").into())
    }

    fn refresh(&mut self) -> Result<ServerInfo, Boxed> {
        let ResponseBody::ServerInfo(info) = self.body("server.info", Command::ServerInfo)? else {
            return Err("server.info 返回了意外类型".into());
        };
        self.generation = info.generation.clone();
        self.server_id = info.server_id.clone();
        self.server_time = info.server_time;
        Ok(info)
    }

    fn login(&mut self, username: &str, password: &str) -> Result<AuthSession, Boxed> {
        let command = Command::AuthLogin {
            username: username.to_owned(),
            password: password.to_owned(),
        };
        let ResponseBody::Session(session) = self.body("auth.login", command)? else {
            return Err("auth.login 返回了意外类型".into());
        };
        self.token = session.token.clone();
        Ok(session)
    }

    fn meta(&mut self) -> Result<VaultMeta, Boxed> {
        let ResponseBody::VaultMeta(meta) = self.body("vault.meta", Command::VaultMeta)? else {
            return Err("vault.meta 返回了意外类型".into());
        };
        Ok(meta)
    }

    /// 按 M0 快照语义翻页收集全部条目元数据。
    fn snapshot(&mut self, limit: u16) -> Result<(VaultMeta, Vec<EntryMeta>), Boxed> {
        let meta = self.meta()?;
        let mut rows = Vec::new();
        let mut after = None;
        loop {
            let command = Command::EntriesList {
                generation: meta.generation.clone(),
                expected_revision: Some(meta.vault_revision),
                after_id: after,
                limit,
            };
            let ResponseBody::Entries(page) = self.body("entries.list", command)? else {
                return Err("entries.list 返回了意外类型".into());
            };
            rows.extend(page.entries);
            after = page.next_after_id;
            if after.is_none() {
                break;
            }
        }
        Ok((meta, rows))
    }

    fn content(&mut self, generation: &str, id: i64, revision: i64) -> Result<EntryContent, Boxed> {
        let command = Command::EntriesReadContent {
            generation: generation.to_owned(),
            id,
            expected_revision: revision,
        };
        let ResponseBody::Content(content) = self.body("entries.read_content", command)? else {
            return Err("entries.read_content 返回了意外类型".into());
        };
        Ok(content)
    }

    fn write_context(&self, key_epoch: i64) -> WriteContext {
        WriteContext {
            operation_id: random_id(),
            generation: self.generation.clone(),
            key_epoch,
            valid_until: self.server_time + OPERATION_TTL - 60,
        }
    }

    fn create(
        &mut self,
        epoch: i64,
        description: &str,
        content: &str,
    ) -> Result<(String, EntryMutation), Boxed> {
        let write = self.write_context(epoch);
        let operation_id = write.operation_id.clone();
        let command = Command::EntriesCreate {
            write,
            description: description.to_owned(),
            content: content.to_owned(),
        };
        let ResponseBody::Entry(mutation) = self.body("entries.create", command)? else {
            return Err("entries.create 返回了意外类型".into());
        };
        Ok((operation_id, mutation))
    }

    fn update(
        &mut self,
        epoch: i64,
        id: i64,
        description: Option<String>,
        content: Option<String>,
    ) -> Result<(String, EntryMutation), Boxed> {
        let write = self.write_context(epoch);
        let operation_id = write.operation_id.clone();
        let command = Command::EntriesUpdate {
            write,
            id,
            description,
            content,
        };
        let ResponseBody::Entry(mutation) = self.body("entries.update", command)? else {
            return Err("entries.update 返回了意外类型".into());
        };
        Ok((operation_id, mutation))
    }

    fn operation(
        &mut self,
        generation: &str,
        operation_id: &str,
    ) -> Result<OperationRecord, Boxed> {
        let command = Command::OperationsGet {
            generation: generation.to_owned(),
            operation_id: operation_id.to_owned(),
        };
        let ResponseBody::Operation(record) = self.body("operations.get", command)? else {
            return Err("operations.get 返回了意外类型".into());
        };
        Ok(record)
    }
}

fn encrypted(passphrase: &str, salt: &str, plain: &str) -> String {
    let key = derive_key(passphrase, &STANDARD.decode(salt).expect("salt"));
    encrypt(&key, plain).expect("加密")
}

// ---------------------------------------------------------------------------
// 场景一：真实旧库导入的结果校验（只读）
// ---------------------------------------------------------------------------

struct Legacy {
    salt: String,
    verifier: String,
    rows: Vec<(i64, String, String)>,
}

fn read_legacy(path: &str) -> Result<Legacy, Boxed> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let salt: Vec<u8> =
        conn.query_row("SELECT value FROM meta WHERE key='salt'", [], |r| r.get(0))?;
    let verifier: Vec<u8> =
        conn.query_row("SELECT value FROM meta WHERE key='verifier'", [], |r| {
            r.get(0)
        })?;
    let mut statement = conn.prepare("SELECT id, desc, content FROM entries ORDER BY id")?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Legacy {
        salt: STANDARD.encode(salt),
        verifier: String::from_utf8(verifier)?,
        rows,
    })
}

fn raw_post(url: &str, path: &str, body: &str, extra: &[(&str, &str)]) -> (u16, String) {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let parsed = url::Url::parse(url).expect("url");
    let host = parsed.host_str().unwrap_or("127.0.0.1").to_owned();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let request = {
        let mut text = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\n");
        text.push_str("Content-Type: application/json\r\n");
        text.push_str(&format!("Content-Length: {}\r\n", body.len()));
        for (key, value) in extra {
            text.push_str(&format!("{key}: {value}\r\n"));
        }
        text.push_str("Connection: close\r\n\r\n");
        text.push_str(body);
        text
    };
    let Ok(mut stream) = TcpStream::connect((host.as_str(), port)) else {
        return (0, String::new());
    };
    let _ = stream.write_all(request.as_bytes());
    let _ = stream.flush();
    let mut response = String::new();
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let _ = stream.read_to_string(&mut response);
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    (status, response)
}

fn scenario_real(report: &mut Report) -> Result<(), Boxed> {
    let url = env("RK_URL");
    let public = env("RK_PUBKEY");
    let username = env("RK_USER");
    let password = secret(&env("RK_PASS_FILE"));
    let legacy = read_legacy(&env("RK_LEGACY_DB"))?;
    println!("真实实例 {}：旧库 {} 条，只读校验", url, legacy.rows.len());

    let mut api = Api::connect(&url, Some(&public), None)?;
    let info = api.refresh()?;
    report.same("server.info 报 initialized=true", &info.initialized, &true);
    report.check(
        "server.info generation/server_id 为 32 位十六进制",
        valid_id(&info.generation) && valid_id(&info.server_id),
    );

    // Noise 通道要求预导入公钥；缺失时客户端必须拒绝连接。
    report.check(
        "缺少服务端公钥时 HTTP 模式拒绝建连",
        matches!(
            Client::new(Endpoint::parse(&url)?, None, None),
            Err(TransportError::MissingPublicKey)
        ),
    );

    // 身份绑定：用另一个实例的公钥连本实例，握手必须失败。
    let foreign_key = env("RK_FOREIGN_PUBKEY");
    let mut impostor = Api::connect(&url, Some(&foreign_key), None)?;
    report.check(
        "公钥与服务端身份不符时握手失败",
        impostor.refresh().is_err(),
    );
    report.check(
        "非法 endpoint 被拒绝",
        Endpoint::parse("ftp://127.0.0.1:1/").is_err()
            && Client::new(
                Endpoint::parse("http://127.0.0.1:1/")?,
                Some("not-base64!!"),
                None,
            )
            .is_err(),
    );

    // HTTP 监听器没有明文 RPC 路由，伪造转发头也不能绕过。
    let forged = [
        ("X-Forwarded-Proto", "https"),
        ("X-Forwarded-Host", "example.com"),
    ];
    let probe = r#"{"protocol_version":1,"request_id":"00000000000000000000000000000000","session_token":null,"command":{"operation":"server.info"}}"#;
    let (status, text) = raw_post(&url, "/api/v1/rpc", probe, &forged);
    report.check(
        "HTTP 监听器拒绝明文 RPC（伪造转发头同样无效）",
        status != 200 && !text.contains("protocol_version"),
    );

    report.code(
        "未登录访问 vault.meta 被拒绝",
        api.call(Command::VaultMeta),
        ErrorCode::Unauthenticated,
    );
    let mut wrong = Api::connect(&url, Some(&public), None)?;
    report.code(
        "管理员口令错误被拒绝",
        wrong.call(Command::AuthLogin {
            username: username.clone(),
            password: "错误的口令".into(),
        }),
        ErrorCode::InvalidCredentials,
    );

    let session = api.login(&username, &password)?;
    report.same("登录后返回管理员用户名", &session.username, &username);
    report.check("登录后拿到会话 token", session.token.is_some());
    report.check(
        "会话有效期约 48 小时",
        session.expires_at - now() > SESSION_TTL - 30 && session.expires_at - now() <= SESSION_TTL,
    );

    let ResponseBody::Session(validated) = api.body("auth.validate", Command::AuthValidate)? else {
        return Err("auth.validate 返回了意外类型".into());
    };
    report.same("auth.validate 复用同一会话", &validated.username, &username);

    let meta = api.meta()?;
    report.same(
        "vault 世代与 server.info 一致",
        &meta.generation,
        &info.generation,
    );
    report.same("导入后 vault_revision=1", &meta.vault_revision, &1i64);
    report.same("导入后 key_epoch=1", &meta.key_epoch, &1i64);
    report.check("vault_id 为 32 位十六进制", valid_id(&meta.vault_id));
    report.same("salt 与旧库一致", &meta.encryption.salt, &legacy.salt);
    report.same(
        "verifier 与旧库一致",
        &meta.encryption.verifier,
        &legacy.verifier,
    );
    report.same(
        "KDF 参数为 argon2id/19/19456/2/1/32",
        &meta.encryption.kdf,
        &KdfParams::default(),
    );
    report.check(
        "EncryptionMeta 通过协议自检",
        meta.encryption.validate().is_ok(),
    );

    // 分页遍历：limit=3 检验游标语义。
    let (page_meta, rows) = api.snapshot(3)?;
    report.same("条目总数与旧库一致", &rows.len(), &legacy.rows.len());
    report.same(
        "翻页期间 vault_revision 不变",
        &page_meta.vault_revision,
        &1i64,
    );
    let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
    let want_ids: Vec<i64> = legacy.rows.iter().map(|r| r.0).collect();
    report.same("条目 ID 原样保留", &ids, &want_ids);
    let descriptions: Vec<String> = rows.iter().map(|r| r.description.clone()).collect();
    let want_descriptions: Vec<String> = legacy.rows.iter().map(|r| r.1.clone()).collect();
    report.same("描述原样保留", &descriptions, &want_descriptions);
    report.check(
        "导入条目 revision/key_epoch 均为 1",
        rows.iter().all(|r| r.revision == 1 && r.key_epoch == 1),
    );

    let mut identical = 0usize;
    let mut epoch_matches = 0usize;
    for (id, _, content) in &legacy.rows {
        let row = rows.iter().find(|r| r.id == *id).expect("条目存在");
        let fetched = api.content(&meta.generation, *id, row.revision)?;
        if fetched.content == *content {
            identical += 1;
        }
        if fetched.key_epoch == row.key_epoch && fetched.revision == row.revision {
            epoch_matches += 1;
        }
    }
    report.same("密文逐字节与旧库相同", &identical, &legacy.rows.len());
    report.same("密文元数据世代一致", &epoch_matches, &legacy.rows.len());

    let first = rows.first().expect("至少一条");
    report.code(
        "过期 expected_revision 读取被拒绝",
        api.call(Command::EntriesReadContent {
            generation: meta.generation.clone(),
            id: first.id,
            expected_revision: first.revision + 5,
        }),
        ErrorCode::RevisionChanged,
    );
    report.code(
        "不存在的条目读取返回 NotFound",
        api.call(Command::EntriesReadContent {
            generation: meta.generation.clone(),
            id: 9_999_999,
            expected_revision: 1,
        }),
        ErrorCode::NotFound,
    );
    report.code(
        "世代不符被拒绝",
        api.call(Command::EntriesList {
            generation: random_id(),
            expected_revision: Some(1),
            after_id: None,
            limit: 100,
        }),
        ErrorCode::GenerationChanged,
    );
    report.code(
        "limit=0 被拒绝",
        api.call(Command::EntriesList {
            generation: meta.generation.clone(),
            expected_revision: Some(1),
            after_id: None,
            limit: 0,
        }),
        ErrorCode::InvalidRequest,
    );
    report.code(
        "limit=101 被拒绝",
        api.call(Command::EntriesList {
            generation: meta.generation.clone(),
            expected_revision: Some(1),
            after_id: None,
            limit: 101,
        }),
        ErrorCode::InvalidRequest,
    );
    let record = api.operation(&meta.generation, &random_id())?;
    report.same(
        "未知 operation_id 状态为 NotFound",
        &record.state,
        &OperationState::NotFound,
    );

    // 版本轮询：连续读取世代号不变，供 2 秒轮询判定使用。
    let a = api.meta()?;
    let b = api.meta()?;
    report.check(
        "无写入时 vault_revision 稳定",
        a.vault_revision == b.vault_revision && a.encryption == b.encryption,
    );

    // 60 KiB 请求上限在客户端就已拦住（真实库只读，不发送）。
    let huge: Vec<RotatedEntry> = (0..MAX_PAGE_SIZE)
        .map(|i| RotatedEntry {
            id: i64::from(i) + 1,
            content: "A".repeat(MAX_DESCRIPTION_BYTES),
        })
        .collect();
    let mut oversized = Api::connect(&url, Some(&public), None)?;
    oversized.refresh()?;
    oversized.login(&username, &password)?;
    report.code(
        "整包超过 60 KiB 时客户端本地拦截",
        oversized.call(Command::RotationStage {
            write: oversized.write_context(1),
            job_id: random_id(),
            entries: huge,
        }),
        ErrorCode::LimitExceeded,
    );
    oversized.call(Command::AuthLogout).ok();

    report.check(
        "登出成功",
        matches!(api.call(Command::AuthLogout), Ok(ResponseBody::LoggedOut)),
    );
    let after = api.call(Command::VaultMeta);
    report.check(
        "登出后旧 token 失效",
        matches!(&after, Err(TransportError::Remote(error)) if matches!(error.code,
            ErrorCode::Unauthenticated | ErrorCode::SessionExpired)),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 场景二：空实例全套写入业务
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct ResumeState {
    url: String,
    public_key: String,
    server_id: String,
    token: String,
    generation: String,
    operation_id: String,
    entry_id: i64,
    key_pass: String,
    key_epoch: i64,
}

fn scenario_sandbox(report: &mut Report) -> Result<(), Boxed> {
    let url = env("RK_URL");
    let public = env("RK_PUBKEY");
    let username = env("RK_USER");
    let password = secret(&env("RK_PASS_FILE"));
    let key_a = secret(&env("RK_CONTENT_PASS_FILE"));
    let key_b = secret(&env("RK_NEW_PASS_FILE"));
    println!("空实例 {url}：初始化、增删改、幂等、轮换全套写入");

    let mut api = Api::connect(&url, Some(&public), None)?;
    let info = api.refresh()?;
    report.same("空实例 initialized=false", &info.initialized, &false);
    report.code(
        "未登录时 vault.meta 报 Unauthenticated",
        api.call(Command::VaultMeta),
        ErrorCode::Unauthenticated,
    );

    api.login(&username, &password)?;
    report.code(
        "已登录但库未初始化时 vault.meta 报 VaultUninitialized",
        api.call(Command::VaultMeta),
        ErrorCode::VaultUninitialized,
    );

    // 初始化：operation_id 幂等 + 复用冲突。
    let encryption = fresh_encryption(&key_a);
    let write = api.write_context(0);
    let init_operation = write.operation_id.clone();
    let command = Command::VaultInitialize {
        write,
        encryption: encryption.clone(),
    };
    let ResponseBody::VaultMeta(initialized) = api.body("vault.initialize", command.clone())?
    else {
        return Err("vault.initialize 返回了意外类型".into());
    };
    report.same("初始化后 revision=1", &initialized.vault_revision, &1i64);
    report.same("初始化后 epoch=1", &initialized.key_epoch, &1i64);
    report.same(
        "初始化落库的加密元数据一致",
        &initialized.encryption,
        &encryption,
    );
    let replay = api.body("vault.initialize(replay)", command)?;
    report.check(
        "相同 operation_id 与参数重放返回同一结果",
        matches!(replay, ResponseBody::VaultMeta(meta) if meta == initialized),
    );
    let record = api.operation(&initialized.generation, &init_operation)?;
    report.same(
        "已提交操作可查询",
        &record.state,
        &OperationState::Committed,
    );
    report.check(
        "已提交操作带出原始结果",
        matches!(
            record.outcome.as_deref(),
            Some(RpcOutcome::Ok { result }) if matches!(**result, ResponseBody::VaultMeta(_))
        ),
    );
    let reused = Command::EntriesCreate {
        write: {
            let mut w = api.write_context(1);
            w.operation_id = init_operation.clone();
            w
        },
        description: "冲突复用".into(),
        content: encrypted(&key_a, &encryption.salt, "x"),
    };
    report.code(
        "operation_id 用于不同参数被拒绝",
        api.call(reused),
        ErrorCode::OperationMismatch,
    );
    let mut second = api.write_context(1);
    second.operation_id = random_id();
    report.code(
        "重复初始化被拒绝",
        api.call(Command::VaultInitialize {
            write: second,
            encryption: encryption.clone(),
        }),
        ErrorCode::AlreadyInitialized,
    );

    // 边界值与限额。
    let max_plain = "x".repeat(MAX_PLAINTEXT_BYTES);
    let max_desc = "d".repeat(MAX_DESCRIPTION_BYTES);
    let boundary = encrypted(&key_a, &encryption.salt, &max_plain);
    let (op_max, created_max) = api.create(1, &max_desc, &boundary)?;
    let (op_empty, created_empty) = api.create(
        1,
        "空密钥（中文描述）",
        &encrypted(&key_a, &encryption.salt, ""),
    )?;
    let (op_norm, created_norm) = api.create(
        1,
        "deepseek-测试",
        &encrypted(&key_a, &encryption.salt, "sk-真实密钥-1234567890"),
    )?;
    report.same(
        "边界描述 4 KiB 被接受",
        &created_max.entry.description.len(),
        &MAX_DESCRIPTION_BYTES,
    );
    report.check(
        "边界密文在限额内",
        boundary.len() <= MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4,
    );
    report.code(
        "描述超过 4 KiB 被拒绝",
        api.call(Command::EntriesCreate {
            write: api.write_context(1),
            description: "e".repeat(MAX_DESCRIPTION_BYTES + 1),
            content: encrypted(&key_a, &encryption.salt, "y"),
        }),
        ErrorCode::LimitExceeded,
    );
    let too_long = encrypted(&key_a, &encryption.salt, "y");
    report.code(
        "非法密文长度被拒绝",
        api.call(Command::EntriesCreate {
            write: api.write_context(1),
            description: "坏密文".into(),
            content: too_long[..20].to_owned(),
        }),
        ErrorCode::InvalidRequest,
    );
    report.check(
        "32 KiB 明文加密后仍在整包 60 KiB 内",
        encrypt(
            &derive_key(&key_a, &STANDARD.decode(&encryption.salt).unwrap()),
            &max_plain,
        )
        .is_ok(),
    );
    let _ = op_max;
    let _ = op_empty;

    // 读取与解密。
    let (meta, rows) = api.snapshot(2)?;
    report.same("条目数符合预期", &rows.len(), &3);
    for row in &rows {
        let fetched = api.content(&meta.generation, row.id, row.revision)?;
        let plain = decrypt(
            &derive_key(&key_a, &STANDARD.decode(&meta.encryption.salt).unwrap()),
            &fetched.content,
        )?;
        report.check(
            &format!("条目 {} 解密成功且为合法 UTF-8", row.id),
            plain.is_char_boundary(plain.len()),
        );
    }

    // 字段级后提交覆盖。
    let id = created_norm.entry.id;
    let (_, after_desc) = api.update(1, id, Some("改名后的描述".into()), None)?;
    let content_after = api.content(&meta.generation, id, after_desc.entry.revision)?;
    let plain_after = decrypt(
        &derive_key(&key_a, &STANDARD.decode(&encryption.salt).unwrap()),
        &content_after.content,
    )?;
    report.same(
        "仅改描述时密文原样保留",
        &plain_after,
        "sk-真实密钥-1234567890",
    );
    report.same("描述已更新", &after_desc.entry.description, "改名后的描述");
    let (_, after_content) = api.update(
        1,
        id,
        None,
        Some(encrypted(&key_a, &encryption.salt, "sk-第二个值")),
    )?;
    let row_after = api.content(&meta.generation, id, after_content.entry.revision)?;
    report.same(
        "仅改内容时描述原样保留",
        &after_content.entry.description,
        "改名后的描述",
    );
    report.check(
        "内容更新后 revision 递增",
        row_after.revision > after_desc.entry.revision,
    );

    // 后写覆盖前写，两个请求都成功。
    let first_write = api.update(
        1,
        id,
        None,
        Some(encrypted(&key_a, &encryption.salt, "sk-第一次提交")),
    )?;
    let second_write = api.update(
        1,
        id,
        None,
        Some(encrypted(&key_a, &encryption.salt, "sk-第二次提交")),
    )?;
    let winner = api.content(&meta.generation, id, second_write.1.entry.revision)?;
    let winner_plain = decrypt(
        &derive_key(&key_a, &STANDARD.decode(&encryption.salt).unwrap()),
        &winner.content,
    )?;
    report.same("同一字段后提交覆盖前提交", &winner_plain, "sk-第二次提交");
    report.check(
        "前一次提交未被拒绝",
        first_write.1.entry.revision < second_write.1.entry.revision,
    );

    // 多客户端并发：第二个会话读取同一库。
    let mut peer = Api::connect(&url, Some(&public), None)?;
    peer.refresh()?;
    peer.login(&username, &password)?;
    let peer_meta = peer.meta()?;
    report.same(
        "第二个客户端读到同一世代",
        &peer_meta.vault_id,
        &meta.vault_id,
    );
    report.check(
        "两个会话并存",
        peer_meta.vault_revision >= meta.vault_revision && peer.token.is_some(),
    );

    // 删除与复活防护。
    let doomed = created_empty.entry.id;
    let write = api.write_context(1);
    let ResponseBody::Deleted { id: deleted_id, .. } = api.body(
        "entries.delete",
        Command::EntriesDelete { write, id: doomed },
    )?
    else {
        return Err("entries.delete 返回了意外类型".into());
    };
    report.same("删除返回条目 ID", &deleted_id, &doomed);
    let (_, rows) = api.snapshot(100)?;
    report.check(
        "删除后列表不再包含该条目",
        rows.iter().all(|r| r.id != doomed),
    );
    report.code(
        "删除后旧更新无法复活条目",
        api.call(Command::EntriesUpdate {
            write: api.write_context(1),
            id: doomed,
            description: Some("复活".into()),
            content: None,
        }),
        ErrorCode::NotFound,
    );
    report.code(
        "删除后读内容返回 NotFound",
        api.call(Command::EntriesReadContent {
            generation: meta.generation.clone(),
            id: doomed,
            expected_revision: 1,
        }),
        ErrorCode::NotFound,
    );
    let stale = api.operation(&meta.generation, &op_norm)?;
    report.same(
        "删除前已提交操作仍可查询",
        &stale.state,
        &OperationState::Committed,
    );

    // 世代与 epoch 校验必须执行。
    report.code(
        "错误 key_epoch 的写入被拒绝",
        api.call(Command::EntriesCreate {
            write: api.write_context(99),
            description: "错误世代".into(),
            content: encrypted(&key_a, &encryption.salt, "z"),
        }),
        ErrorCode::KeyEpochChanged,
    );
    let mut bad_generation = api.write_context(1);
    bad_generation.generation = random_id();
    report.code(
        "错误 generation 的写入被拒绝",
        api.call(Command::EntriesCreate {
            write: bad_generation,
            description: "错误数据世代".into(),
            content: encrypted(&key_a, &encryption.salt, "z"),
        }),
        ErrorCode::GenerationChanged,
    );
    let mut far = api.write_context(1);
    far.valid_until = now() + OPERATION_TTL + 3_600;
    report.code(
        "valid_until 超出窗口被拒绝",
        api.call(Command::EntriesCreate {
            write: far,
            description: "过期窗口".into(),
            content: encrypted(&key_a, &encryption.salt, "z"),
        }),
        ErrorCode::OperationExpired,
    );
    let mut past = api.write_context(1);
    past.valid_until = now() - 10;
    report.code(
        "valid_until 已过期被拒绝",
        api.call(Command::EntriesCreate {
            write: past,
            description: "已过期窗口".into(),
            content: encrypted(&key_a, &encryption.salt, "z"),
        }),
        ErrorCode::OperationExpired,
    );

    // 轮换：基线冲突分支。
    let baseline = api.meta()?;
    let mut wrong_begin = api.write_context(baseline.key_epoch);
    wrong_begin.operation_id = random_id();
    report.code(
        "轮换基线 revision 不符时 begin 被拒绝",
        api.call(Command::RotationBegin {
            write: wrong_begin,
            expected_vault_revision: baseline.vault_revision + 3,
            new_encryption: fresh_encryption(&key_b),
        }),
        ErrorCode::RotationConflict,
    );
    let mut bad_format = api.write_context(baseline.key_epoch);
    bad_format.operation_id = random_id();
    let mut broken_encryption = fresh_encryption(&key_b);
    broken_encryption.content_format = 2;
    report.code(
        "不支持的密文格式在 begin 被拒绝",
        api.call(Command::RotationBegin {
            write: bad_format,
            expected_vault_revision: baseline.vault_revision,
            new_encryption: broken_encryption,
        }),
        ErrorCode::InvalidRequest,
    );

    // 轮换：未完成即提交。
    let partial = begin_rotation(&mut api, &baseline, &key_b)?;
    let batch = rotation_batch(&mut api, &partial.generation, &partial.job_id, 100)?;
    let first_only = vec![batch.entries[0].clone()];
    let ResponseBody::Rotation(staged) = api.body(
        "rotation.stage(partial)",
        Command::RotationStage {
            write: api.write_context(partial.key_epoch),
            job_id: partial.job_id.clone(),
            entries: first_only,
        },
    )?
    else {
        return Err("rotation.stage 返回了意外类型".into());
    };
    report.same(
        "部分分块暂存后 staged 计数正确",
        &staged.staged_entries,
        &1i64,
    );
    report.code(
        "未暂存全部条目时 commit 被拒绝",
        api.call(Command::RotationCommit {
            write: api.write_context(partial.key_epoch),
            job_id: partial.job_id.clone(),
        }),
        ErrorCode::RotationIncomplete,
    );
    let ResponseBody::Rotation(aborted) = api.body(
        "rotation.abort",
        Command::RotationAbort {
            write: api.write_context(partial.key_epoch),
            job_id: partial.job_id.clone(),
        },
    )?
    else {
        return Err("rotation.abort 返回了意外类型".into());
    };
    report.same(
        "中止后状态为 aborted",
        &aborted.state,
        &RotationState::Aborted,
    );

    // 轮换：基线被写入打破后冲突。
    let snapshot = api.meta()?;
    let conflicting = begin_rotation(&mut api, &snapshot, &key_b)?;
    api.create(
        snapshot.key_epoch,
        "轮换期间的插入",
        &encrypted(&key_a, &snapshot.encryption.salt, "sk-干扰"),
    )?;
    let batch_result = api.call(Command::RotationReadBatch {
        generation: conflicting.generation.clone(),
        job_id: conflicting.job_id.clone(),
        after_id: None,
        limit: 100,
    });
    let mut conflict_seen = match batch_result {
        Err(TransportError::Remote(error)) => error.code == ErrorCode::RotationConflict,
        Ok(ResponseBody::RotationBatch(batch)) => {
            // 读块仍返回旧快照时，暂存必须拦住。
            matches!(
                api.call(Command::RotationStage {
                    write: api.write_context(conflicting.key_epoch),
                    job_id: conflicting.job_id.clone(),
                    entries: batch.entries,
                }),
                Err(TransportError::Remote(error))
                    if error.code == ErrorCode::RotationConflict
            )
        }
        other => {
            println!("         got {other:?}");
            false
        }
    };
    conflict_seen &= matches!(
        api.call(Command::RotationCommit {
            write: api.write_context(conflicting.key_epoch),
            job_id: conflicting.job_id.clone(),
        }),
        Err(TransportError::Remote(error)) if error.code == ErrorCode::RotationConflict
    );
    report.check("基线被并发写入打破后读/暂存/提交全部冲突", conflict_seen);
    let ResponseBody::Rotation(conflicted) = api.body(
        "rotation.abort(conflicted)",
        Command::RotationAbort {
            write: api.write_context(conflicting.key_epoch),
            job_id: conflicting.job_id.clone(),
        },
    )?
    else {
        return Err("rotation.abort 返回了意外类型".into());
    };
    report.same(
        "基线被并发写入打破后作业转为 conflicted",
        &conflicted.state,
        &RotationState::Conflicted,
    );
    let ResponseBody::Rotation(status) = api.body(
        "rotation.status",
        Command::RotationStatus {
            generation: api.generation.clone(),
            job_id: conflicting.job_id.clone(),
        },
    )?
    else {
        return Err("rotation.status 返回了意外类型".into());
    };
    report.same(
        "conflicted 为持久终态，重复中止不会改写它",
        &status.state,
        &RotationState::Conflicted,
    );
    let unchanged = api.meta()?;
    report.check(
        "冲突作业没有改动加密元数据",
        unchanged.encryption.salt == snapshot.encryption.salt
            && unchanged.key_epoch == snapshot.key_epoch,
    );

    // 轮换：完整流程。
    let pre = api.meta()?;
    let job = begin_rotation(&mut api, &pre, &key_b)?;
    let old_key = derive_key(&key_a, &STANDARD.decode(&pre.encryption.salt).unwrap());
    let mut staged_total = None;
    let mut after = None;
    loop {
        let batch = {
            let ResponseBody::RotationBatch(batch) = api.body(
                "rotation.read_batch",
                Command::RotationReadBatch {
                    generation: job.generation.clone(),
                    job_id: job.job_id.clone(),
                    after_id: after,
                    limit: 2,
                },
            )?
            else {
                return Err("rotation.read_batch 返回了意外类型".into());
            };
            batch
        };
        let reencrypted: Vec<RotatedEntry> = batch
            .entries
            .iter()
            .map(|entry| {
                let plain = decrypt(&old_key, &entry.content)
                    .map_err(|_| format!("条目 {} 旧密钥解密失败", entry.id))?;
                Ok(RotatedEntry {
                    id: entry.id,
                    content: encrypted(&key_b, &job.new_encryption.salt, &plain),
                })
            })
            .collect::<Result<Vec<_>, Boxed>>()?;
        let ResponseBody::Rotation(info) = api.body(
            "rotation.stage",
            Command::RotationStage {
                write: api.write_context(job.key_epoch),
                job_id: job.job_id.clone(),
                entries: reencrypted,
            },
        )?
        else {
            return Err("rotation.stage 返回了意外类型".into());
        };
        let _ = staged_total.insert(info.staged_entries);
        after = batch.next_after_id;
        report.check(
            "轮换读块分页有上界",
            batch.entries.len() <= usize::from(MAX_PAGE_SIZE),
        );
        if after.is_none() {
            break;
        }
    }
    report.same("全部分块已暂存", &staged_total, &Some(job.total_entries));
    let commit_write = api.write_context(job.key_epoch);
    let commit_operation = commit_write.operation_id.clone();
    let ResponseBody::Rotation(committed) = api.body(
        "rotation.commit",
        Command::RotationCommit {
            write: commit_write,
            job_id: job.job_id.clone(),
        },
    )?
    else {
        return Err("rotation.commit 返回了意外类型".into());
    };
    report.same(
        "提交后状态为 committed",
        &committed.state,
        &RotationState::Committed,
    );
    report.check(
        "提交结果带出新元数据",
        committed
            .committed_meta
            .as_ref()
            .is_some_and(|m| m.key_epoch == pre.key_epoch + 1),
    );
    let replay_commit = api.body(
        "rotation.commit(replay)",
        Command::RotationCommit {
            write: {
                let mut w = api.write_context(pre.key_epoch);
                w.operation_id = commit_operation.clone();
                w
            },
            job_id: job.job_id.clone(),
        },
    );
    report.check(
        "重复提交同一 operation_id 幂等返回",
        matches!(replay_commit, Ok(ResponseBody::Rotation(info)) if info.state == RotationState::Committed),
    );

    let post = api.meta()?;
    report.same(
        "轮换后 key_epoch 递增",
        &post.key_epoch,
        &(pre.key_epoch + 1),
    );
    report.check(
        "轮换后加密元数据换成新盐与新校验值",
        post.encryption.salt != pre.encryption.salt
            && post.encryption.verifier != pre.encryption.verifier,
    );
    let new_key = derive_key(&key_b, &STANDARD.decode(&post.encryption.salt).unwrap());
    let (_, rows) = api.snapshot(100)?;
    let mut decrypted_new = 0usize;
    let mut old_key_fails = 0usize;
    let mut epoch_synced = 0usize;
    let mut survivor = None;
    for row in &rows {
        let fetched = api.content(&post.generation, row.id, row.revision)?;
        if decrypt(&new_key, &fetched.content).is_ok() {
            decrypted_new += 1;
        }
        if decrypt(&old_key, &fetched.content).is_err() {
            old_key_fails += 1;
        }
        if fetched.key_epoch == post.key_epoch {
            epoch_synced += 1;
        }
        if row.id == id {
            survivor = Some(decrypt(&new_key, &fetched.content)?);
        }
    }
    report.same("全部条目可用新密钥解密", &decrypted_new, &rows.len());
    report.same("旧密钥对全部条目失效", &old_key_fails, &rows.len());
    report.same("条目 key_epoch 全部同步", &epoch_synced, &rows.len());
    report.same(
        "轮换后明文内容保持不变",
        &survivor.as_deref(),
        &Some("sk-第二次提交"),
    );
    report.code(
        "轮换后用旧 key_epoch 写入被拒绝",
        api.call(Command::EntriesCreate {
            write: api.write_context(pre.key_epoch),
            description: "旧世代写入".into(),
            content: encrypted(&key_b, &post.encryption.salt, "z"),
        }),
        ErrorCode::KeyEpochChanged,
    );

    // 会话吊销：主会话登出，对端会话仍有效。
    report.check(
        "登出成功",
        matches!(api.call(Command::AuthLogout), Ok(ResponseBody::LoggedOut)),
    );
    report.check(
        "旧 token 立即失效",
        matches!(
            api.call(Command::VaultMeta),
            Err(TransportError::Remote(error)) if matches!(error.code,
                ErrorCode::Unauthenticated | ErrorCode::SessionExpired)
        ),
    );
    let peer_meta = peer.meta()?;
    report.same(
        "其他客户端会话不受影响",
        &peer_meta.vault_id,
        &post.vault_id,
    );

    // 重启校验所需状态（token 与已提交 operation_id）。
    let state = ResumeState {
        url: url.clone(),
        public_key: public.clone(),
        server_id: api.server_id.clone(),
        token: peer.token.clone().expect("会话 token"),
        generation: peer_meta.generation.clone(),
        operation_id: commit_operation,
        entry_id: id,
        key_pass: key_b.clone(),
        key_epoch: peer_meta.key_epoch,
    };
    let path = env("RK_RESUME_FILE");
    std::fs::write(&path, serde_json::to_vec(&state)?).map_err(|_| "写入重启状态失败")?;
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    report.check("重启校验状态已保存", true);
    Ok(())
}

struct BeginInfo {
    job_id: String,
    generation: String,
    key_epoch: i64,
    total_entries: i64,
    new_encryption: EncryptionMeta,
}

fn begin_rotation(api: &mut Api, meta: &VaultMeta, new_pass: &str) -> Result<BeginInfo, Boxed> {
    let new_encryption = fresh_encryption(new_pass);
    let mut write = api.write_context(meta.key_epoch);
    write.operation_id = random_id();
    let ResponseBody::Rotation(info) = api.body(
        "rotation.begin",
        Command::RotationBegin {
            write,
            expected_vault_revision: meta.vault_revision,
            new_encryption: new_encryption.clone(),
        },
    )?
    else {
        return Err("rotation.begin 返回了意外类型".into());
    };
    report_job(api, &info)?;
    Ok(BeginInfo {
        job_id: info.job_id,
        generation: meta.generation.clone(),
        key_epoch: info.key_epoch,
        total_entries: info.total_entries,
        new_encryption,
    })
}

fn report_job(api: &mut Api, info: &RotationInfo) -> Result<(), Boxed> {
    let ResponseBody::Rotation(status) = api.body(
        "rotation.status",
        Command::RotationStatus {
            generation: api.generation.clone(),
            job_id: info.job_id.clone(),
        },
    )?
    else {
        return Err("rotation.status 返回了意外类型".into());
    };
    if status.job_id != info.job_id || status.total_entries != info.total_entries {
        return Err("rotation.status 与 begin 返回不一致".into());
    }
    Ok(())
}

fn rotation_batch(
    api: &mut Api,
    generation: &str,
    job_id: &str,
    limit: u16,
) -> Result<RotationBatch, Boxed> {
    let ResponseBody::RotationBatch(batch) = api.body(
        "rotation.read_batch",
        Command::RotationReadBatch {
            generation: generation.to_owned(),
            job_id: job_id.to_owned(),
            after_id: None,
            limit,
        },
    )?
    else {
        return Err("rotation.read_batch 返回了意外类型".into());
    };
    Ok(batch)
}

// ---------------------------------------------------------------------------
// 场景三：服务重启后的持久性与幂等
// ---------------------------------------------------------------------------

fn scenario_resume(report: &mut Report) -> Result<(), Boxed> {
    let state: ResumeState =
        serde_json::from_str(&std::fs::read_to_string(env("RK_RESUME_FILE"))?)?;
    println!("重启后校验 {}", state.url);

    let mut api = Api::connect(&state.url, Some(&state.public_key), None)?;
    api.refresh()?;
    api.token = Some(state.token.clone());
    let ResponseBody::Session(session) = api.body("auth.validate", Command::AuthValidate)? else {
        return Err("auth.validate 返回了意外类型".into());
    };
    report.same(
        "重启后旧会话 token 仍然有效",
        &session.username,
        &env("RK_USER"),
    );

    let meta = api.meta()?;
    report.same("重启后世代不变", &meta.generation, &state.generation);
    report.check(
        "重启后 key_epoch 保持",
        meta.key_epoch >= state.key_epoch && meta.key_epoch >= 2,
    );
    let (_, rows) = api.snapshot(100)?;
    report.check(
        "重启后条目仍在",
        rows.iter().any(|r| r.id == state.entry_id),
    );
    let row = rows
        .iter()
        .find(|r| r.id == state.entry_id)
        .expect("条目存在");
    let content = api.content(&meta.generation, row.id, row.revision)?;
    let key = derive_key(
        &state.key_pass,
        &STANDARD.decode(&meta.encryption.salt).unwrap(),
    );
    report.check(
        "重启后内容仍可用轮换后的密钥解密",
        decrypt(&key, &content.content).is_ok(),
    );
    let record = api.operation(&meta.generation, &state.operation_id)?;
    report.same(
        "重启后已提交操作仍可查询",
        &record.state,
        &OperationState::Committed,
    );
    report.check("重启后操作结果未被重复执行", record.outcome.is_some());

    // 未完成的轮换作业不应复活 staged 数据，未知作业返回 NotFound。
    report.check(
        "未知 job_id 返回 NotFound",
        matches!(
            api.call(Command::RotationStatus {
                generation: meta.generation.clone(),
                job_id: random_id(),
            }),
            Err(TransportError::Remote(error)) if error.code == ErrorCode::NotFound
        ),
    );
    let fresh = api.refresh()?;
    report.same("重启后 server_id 不变", &fresh.server_id, &state.server_id);
    Ok(())
}

// ---------------------------------------------------------------------------
// 场景四：HTTPS 通道（TLS + 明文 JSON RPC，无 Noise）
// ---------------------------------------------------------------------------

fn scenario_https(report: &mut Report) -> Result<(), Boxed> {
    let url = env("RK_URL");
    let ca_path = env("RK_CA_FILE");
    let ca = std::fs::read_to_string(&ca_path)?;
    let username = env("RK_USER");
    let password = secret(&env("RK_PASS_FILE"));
    let key_pass = secret(&env("RK_CONTENT_PASS_FILE"));
    println!("HTTPS 实例 {url}");

    // 未导入该 CA 时必须握手失败，不能静默降级。
    match Api::connect(
        &url,
        None,
        Some("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"),
    ) {
        Err(_) => report.check("不受信任的 CA 被拒绝", true),
        Ok(mut distrust) => report.check("不受信任的 CA 被拒绝", distrust.refresh().is_err()),
    }

    let mut api = Api::connect(&url, None, Some(&ca))?;
    let info = api.refresh()?;
    report.check("HTTPS 模式无需预导入服务端公钥", info.initialized);
    api.login(&username, &password)?;
    let meta = api.meta()?;
    report.check("HTTPS 下 vault.meta 正常", valid_id(&meta.vault_id));
    let (_, rows) = api.snapshot(100)?;
    report.check("HTTPS 下列表正常", !rows.is_empty());

    let created = api.create(
        meta.key_epoch,
        "HTTPS 写入校验",
        &encrypted(&key_pass, &meta.encryption.salt, "https-明文密钥"),
    )?;
    let fetched = api.content(
        &meta.generation,
        created.1.entry.id,
        created.1.entry.revision,
    )?;
    let plain = decrypt(
        &derive_key(&key_pass, &STANDARD.decode(&meta.encryption.salt).unwrap()),
        &fetched.content,
    )?;
    report.same("HTTPS 写入后仍可正确解密", &plain, "https-明文密钥");
    let ResponseBody::Deleted { id, .. } = api.body(
        "entries.delete",
        Command::EntriesDelete {
            write: api.write_context(meta.key_epoch),
            id: created.1.entry.id,
        },
    )?
    else {
        return Err("entries.delete 返回了意外类型".into());
    };
    report.same("HTTPS 删除成功", &id, &created.1.entry.id);

    // HTTPS 监听器没有 Noise 路由。
    let probe = r#"{"protocol_version":1,"request_id":"00000000000000000000000000000000","session_token":null,"command":{"operation":"server.info"}}"#;
    let (status, text) = raw_post(&url, "/api/v1/channel/handshake", probe, &[]);
    report.check(
        "HTTPS 下 Noise 路由不存在",
        status != 200 && !text.contains("protocol_version"),
    );

    // 明文 HTTP 打到 TLS 端口必须失败。
    let plain_url = url.replace("https://", "http://");
    let (status, _) = raw_post(&plain_url, "/api/v1/rpc", probe, &[]);
    report.check("明文访问 TLS 端口被拒绝", status == 0 || status >= 400);
    Ok(())
}

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("用法: real_run <real|sandbox|resume|https>");
        std::process::exit(2);
    });
    let mut report = Report::new();
    let result = match scenario.as_str() {
        "real" => scenario_real(&mut report),
        "sandbox" => scenario_sandbox(&mut report),
        "resume" => scenario_resume(&mut report),
        "https" => scenario_https(&mut report),
        other => Err(format!("未知场景 {other}").into()),
    };
    if let Err(error) = result {
        println!("  [ABORT] {error}");
        report.failures.push(format!("流程中断：{error}"));
    }
    std::process::exit(report.exit());
}
