use argon2::{Argon2, password_hash::PasswordHasher};
use base64::{Engine, engine::general_purpose::STANDARD};
use keyrotation_protocol::*;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub const DB_NAME: &str = "ptoolkit_keys.db";
const SCHEMA: &str = include_str!("schema.sql");
const APPLICATION_ID: i64 = 1_381_190_449;

pub(crate) fn storage_error(_: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ErrorCode::VaultUnavailable,
        "database unavailable; no automatic replacement",
    )
}

pub struct Repository {
    pub(crate) conn: Connection,
    path: PathBuf,
    #[cfg(unix)]
    identity: (u64, u64),
    pub(crate) login_window: i64,
    pub(crate) login_attempts: u32,
}

fn private_dir(path: &Path) -> ApiResult<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && (!meta.is_dir() || meta.file_type().is_symlink())
    {
        return Err(invalid("data directory must be a real directory"));
    }
    fs::create_dir_all(path).map_err(storage_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(storage_error)?;
    }
    Ok(())
}

fn create_private(path: &Path) -> ApiResult<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(storage_error)
}

impl Repository {
    /// Creates a database only on explicit administrative request. Existing targets
    /// are never opened for initialization, truncated or overwritten.
    pub fn create(data_dir: &Path, username: &str, password: &str) -> ApiResult<Self> {
        Self::create_with_import(data_dir, username, password, None)
    }

    pub fn import_legacy(
        data_dir: &Path,
        source: &Path,
        username: &str,
        password: &str,
    ) -> ApiResult<Self> {
        if data_dir.join(DB_NAME).exists() {
            return Err(ApiError::new(
                ErrorCode::AlreadyInitialized,
                "target already exists",
            ));
        }
        let source_conn = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(storage_error)?;
        source_conn
            .execute_batch("BEGIN; PRAGMA query_only=ON;")
            .map_err(storage_error)?;
        let import = LegacyImport::validate(&source_conn, source)?;
        Self::create_with_import(data_dir, username, password, Some((&source_conn, import)))
    }

    fn create_with_import(
        data_dir: &Path,
        username: &str,
        password: &str,
        import: Option<(&Connection, LegacyImport)>,
    ) -> ApiResult<Self> {
        validate_admin(username, password)?;
        if data_dir.join(DB_NAME).exists() {
            return Err(ApiError::new(
                ErrorCode::AlreadyInitialized,
                "target already exists",
            ));
        }
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes())
            .map_err(storage_error)?
            .to_string();
        private_dir(data_dir)?;
        let temp = data_dir.join(format!(".init-{}", random_id()));
        let file = create_private(&temp)?;
        let result = (|| {
            let conn = Connection::open_with_flags(&temp, OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(storage_error)?;
            conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;").map_err(storage_error)?;
            conn.execute_batch(SCHEMA).map_err(storage_error)?;
            conn.execute(
                "INSERT INTO service_state VALUES (1, ?1, ?2, ?3)",
                params![
                    random_id(),
                    random_id(),
                    import.as_ref().map(|(_, i)| i.digest.as_str())
                ],
            )
            .map_err(storage_error)?;
            conn.execute(
                "INSERT INTO users VALUES (1, ?1, ?2)",
                params![username, password_hash],
            )
            .map_err(storage_error)?;
            if let Some((source, imported)) = &import {
                conn.execute(
                    "INSERT INTO vault_meta VALUES (1, ?1, 1, 1, ?2)",
                    params![
                        random_id(),
                        serde_json::to_string(&imported.encryption).map_err(storage_error)?
                    ],
                )
                .map_err(storage_error)?;
                let mut rows = source
                    .prepare("SELECT id, desc, content FROM entries ORDER BY id")
                    .map_err(storage_error)?;
                let mut rows = rows.query([]).map_err(storage_error)?;
                while let Some(row) = rows.next().map_err(storage_error)? {
                    conn.execute(
                        "INSERT INTO entries VALUES (?1, ?2, ?3, 1, 1)",
                        params![
                            row.get::<_, i64>(0).map_err(storage_error)?,
                            row.get::<_, String>(1).map_err(storage_error)?,
                            row.get::<_, String>(2).map_err(storage_error)?
                        ],
                    )
                    .map_err(storage_error)?;
                }
            }
            conn.execute_batch("COMMIT;").map_err(storage_error)?;
            drop(conn);
            file.sync_all().map_err(storage_error)?;
            // hard_link is atomic and fails if a competing init already installed
            // the target. rename() alone could overwrite that other database.
            fs::hard_link(&temp, data_dir.join(DB_NAME)).map_err(storage_error)?;
            fs::File::open(data_dir)
                .and_then(|directory| directory.sync_all())
                .map_err(storage_error)?;
            Ok(())
        })();
        drop(file);
        let _ = fs::remove_file(&temp);
        let _ = fs::remove_file(temp.with_file_name(format!(
            "{}-journal",
            temp.file_name().unwrap().to_string_lossy()
        )));
        result?;
        Self::open(data_dir)
    }

    pub fn open(data_dir: &Path) -> ApiResult<Self> {
        let path = data_dir.join(DB_NAME);
        let metadata = fs::symlink_metadata(&path).map_err(storage_error)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(storage_error("not a regular database"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(invalid("database permissions must be 600"));
            }
            if fs::metadata(data_dir)
                .map_err(storage_error)?
                .permissions()
                .mode()
                & 0o077
                != 0
            {
                return Err(invalid("data directory permissions must be 700"));
            }
        }
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(storage_error)?;
        conn.busy_timeout(std::time::Duration::from_secs(2))
            .map_err(storage_error)?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(storage_error)?;
        let application: i64 = conn
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(storage_error)?;
        if version != 1 || application != APPLICATION_ID {
            return Err(storage_error("unsupported schema"));
        }
        check_integrity(&conn)?;
        conn.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )
        .map_err(storage_error)?;
        // Prepare all expected tables before accepting service requests.
        for table in [
            "service_state",
            "users",
            "sessions",
            "vault_meta",
            "entries",
            "operation_results",
            "rotation_jobs",
            "rotation_members",
            "rotation_entries",
        ] {
            conn.prepare(&format!("SELECT * FROM {table} LIMIT 0"))
                .map_err(storage_error)?;
        }
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        };
        let repository = Self {
            conn,
            path,
            #[cfg(unix)]
            identity,
            login_window: 0,
            login_attempts: 0,
        };
        if !valid_id(&repository.generation()?) {
            return Err(storage_error("invalid generation"));
        }
        let users: i64 = repository
            .conn
            .query_row("SELECT count(*) FROM users WHERE id=1", [], |r| r.get(0))
            .map_err(storage_error)?;
        if users != 1 {
            return Err(storage_error("administrator missing"));
        }
        if let Err(error) = repository.meta()
            && error.code != ErrorCode::VaultUninitialized
        {
            return Err(error);
        }
        Ok(repository)
    }

    pub fn check_health(&self) -> ApiResult<()> {
        let metadata = fs::symlink_metadata(&self.path).map_err(storage_error)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(storage_error("database removed"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (metadata.dev(), metadata.ino()) != self.identity {
                return Err(storage_error("database replaced"));
            }
        }
        let mut header = [0; 16];
        fs::File::open(&self.path)
            .and_then(|mut file| file.read_exact(&mut header))
            .map_err(storage_error)?;
        if &header != b"SQLite format 3\0" {
            return Err(storage_error("database header corrupted"));
        }
        Ok(())
    }

    pub fn generation(&self) -> ApiResult<String> {
        self.conn
            .query_row(
                "SELECT generation FROM service_state WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(storage_error)
    }

    pub fn meta(&self) -> ApiResult<VaultMeta> {
        self.check_health()?;
        let row = self.conn.query_row("SELECT vault_id, vault_revision, key_epoch, encryption_json FROM vault_meta WHERE singleton=1", [], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?))).optional().map_err(storage_error)?;
        let (vault_id, vault_revision, key_epoch, json) = match row {
            Some(row) => row,
            None => {
                self.ensure_no_entries()?;
                return Err(ApiError::new(
                    ErrorCode::VaultUninitialized,
                    "vault is not initialized",
                ));
            }
        };
        if !valid_id(&vault_id) || vault_revision <= 0 || key_epoch <= 0 {
            return Err(storage_error("invalid vault metadata"));
        }
        let encryption: EncryptionMeta = serde_json::from_str(&json).map_err(storage_error)?;
        encryption.validate().map_err(storage_error)?;
        Ok(VaultMeta {
            vault_id,
            generation: self.generation()?,
            vault_revision,
            key_epoch,
            encryption,
        })
    }

    fn ensure_no_entries(&self) -> ApiResult<()> {
        let count: i64 = self
            .conn
            .query_row("SELECT count(*) FROM entries", [], |r| r.get(0))
            .map_err(storage_error)?;
        if count != 0 {
            return Err(storage_error("entries exist without encryption metadata"));
        }
        Ok(())
    }

    pub fn initialize(&self, encryption: &EncryptionMeta) -> ApiResult<VaultMeta> {
        encryption.validate()?;
        if self
            .conn
            .query_row("SELECT count(*) FROM vault_meta", [], |r| {
                r.get::<_, i64>(0)
            })
            .map_err(storage_error)?
            != 0
        {
            return Err(ApiError::new(
                ErrorCode::AlreadyInitialized,
                "vault already initialized",
            ));
        }
        self.ensure_no_entries()?;
        self.conn
            .execute(
                "INSERT INTO vault_meta VALUES (1, ?1, 1, 1, ?2)",
                params![
                    random_id(),
                    serde_json::to_string(encryption).map_err(storage_error)?
                ],
            )
            .map_err(storage_error)?;
        self.meta()
    }

    pub fn entry(&self, id: i64) -> ApiResult<EntryMeta> {
        self.conn
            .query_row(
                "SELECT id, description, revision, key_epoch FROM entries WHERE id=?1",
                [id],
                |r| {
                    Ok(EntryMeta {
                        id: r.get(0)?,
                        description: r.get(1)?,
                        revision: r.get(2)?,
                        key_epoch: r.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(storage_error)?
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "entry not found"))
    }

    /// Low-level transaction helper; callers commit data and revision together.
    pub fn advance_revision(&self) -> ApiResult<i64> {
        let current = self.meta()?.vault_revision;
        let next = current
            .checked_add(1)
            .ok_or_else(|| ApiError::new(ErrorCode::LimitExceeded, "revision limit reached"))?;
        self.conn
            .execute(
                "UPDATE vault_meta SET vault_revision=?1 WHERE singleton=1",
                [next],
            )
            .map_err(storage_error)?;
        self.conn.execute("UPDATE rotation_jobs SET state='conflicted' WHERE state='staging' AND baseline_revision!=?1",[next]).map_err(storage_error)?;
        Ok(next)
    }

    pub fn reset_password(&self, username: &str, password: &str) -> ApiResult<()> {
        self.check_health()?;
        validate_admin(username, password)?;
        let hash = Argon2::default()
            .hash_password(password.as_bytes())
            .map_err(storage_error)?
            .to_string();
        let transaction = self.conn.unchecked_transaction().map_err(storage_error)?;
        self.conn
            .execute(
                "UPDATE users SET username=?1,password_hash=?2 WHERE id=1",
                params![username, hash],
            )
            .map_err(storage_error)?;
        self.conn
            .execute("DELETE FROM sessions", [])
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)
    }
}

fn validate_admin(username: &str, password: &str) -> ApiResult<()> {
    if username.trim().is_empty()
        || username.len() > 128
        || password.is_empty()
        || password.len() > 1024
    {
        return Err(invalid(
            "administrator username/password is empty or exceeds limits",
        ));
    }
    Ok(())
}

fn check_integrity(conn: &Connection) -> ApiResult<()> {
    let mut statement = conn
        .prepare("PRAGMA integrity_check")
        .map_err(storage_error)?;
    let results = statement
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    if results != ["ok"] {
        return Err(storage_error("integrity check failed"));
    }
    Ok(())
}

struct LegacyImport {
    encryption: EncryptionMeta,
    digest: String,
}

impl LegacyImport {
    fn validate(conn: &Connection, path: &Path) -> ApiResult<Self> {
        check_integrity(conn)?;
        let mut objects = conn
            .prepare(
                "SELECT name, type FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .map_err(storage_error)?;
        let objects = objects
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        if objects
            .iter()
            .any(|(name, kind)| kind != "table" || !matches!(name.as_str(), "entries" | "meta"))
            || objects.len() != 2
        {
            return Err(invalid("source is not a legacy meta/entries database"));
        }
        for (table, expected) in [
            (
                "meta",
                vec![
                    ("key".to_string(), "TEXT".to_string(), 0, 1),
                    ("value".to_string(), "BLOB".to_string(), 1, 0),
                ],
            ),
            (
                "entries",
                vec![
                    ("id".to_string(), "INTEGER".to_string(), 0, 1),
                    ("desc".to_string(), "TEXT".to_string(), 1, 0),
                    ("content".to_string(), "TEXT".to_string(), 1, 0),
                ],
            ),
        ] {
            let mut statement = conn
                .prepare(&format!("PRAGMA table_info({table})"))
                .map_err(storage_error)?;
            let columns = statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?.to_uppercase(),
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(5)?,
                    ))
                })
                .map_err(storage_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage_error)?;
            if columns != expected {
                return Err(invalid("source columns do not match legacy schema"));
            }
        }
        let salt: Vec<u8> = conn
            .query_row("SELECT value FROM meta WHERE key='salt'", [], |r| r.get(0))
            .map_err(storage_error)?;
        let verifier: Vec<u8> = conn
            .query_row("SELECT value FROM meta WHERE key='verifier'", [], |r| {
                r.get(0)
            })
            .map_err(storage_error)?;
        let encryption = EncryptionMeta {
            content_format: 1,
            kdf: KdfParams::default(),
            salt: STANDARD.encode(salt),
            verifier: String::from_utf8(verifier).map_err(storage_error)?,
        };
        encryption.validate()?;
        let mut problems = Vec::new();
        let mut statement = conn
            .prepare("SELECT id, desc, content FROM entries ORDER BY id")
            .map_err(storage_error)?;
        let mut rows = statement.query([]).map_err(storage_error)?;
        let mut count = 0;
        while let Some(row) = rows.next().map_err(storage_error)? {
            count += 1;
            let id: i64 = row.get(0).map_err(storage_error)?;
            if id <= 0 {
                problems.push(format!("entry {id}: nonpositive ID"));
            }
            let description: String = row.get(1).map_err(storage_error)?;
            let content: String = row.get(2).map_err(storage_error)?;
            if let Err(error) = validate_description(&description) {
                problems.push(format!("entry {id}: {}", error.message));
            }
            if let Err(error) = validate_content(&content) {
                problems.push(format!("entry {id}: {}", error.message));
            }
        }
        if count > MAX_ENTRIES {
            problems.push(format!("entry count {count} exceeds {MAX_ENTRIES}"));
        }
        if !problems.is_empty() {
            return Err(ApiError::new(ErrorCode::LimitExceeded, problems.join("\n")));
        }
        let mut file = fs::File::open(path).map_err(storage_error)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 65536];
        loop {
            let length = file.read(&mut buffer).map_err(storage_error)?;
            if length == 0 {
                break;
            }
            hasher.update(&buffer[..length]);
        }
        let digest = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(Self { encryption, digest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encryption() -> EncryptionMeta {
        EncryptionMeta {
            content_format: 1,
            kdf: KdfParams::default(),
            salt: STANDARD.encode([7; 16]),
            verifier: STANDARD.encode([8; 39]),
        }
    }

    fn legacy(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL); CREATE TABLE entries (id INTEGER PRIMARY KEY AUTOINCREMENT, desc TEXT NOT NULL, content TEXT NOT NULL);").unwrap();
        conn.execute(
            "INSERT INTO meta VALUES ('salt', ?1), ('verifier', ?2)",
            params![vec![7u8; 16], STANDARD.encode([8; 39]).into_bytes()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO entries VALUES (42, '迁移条目', ?1)",
            [STANDARD.encode([9; 28])],
        )
        .unwrap();
    }

    #[test]
    fn missing_corrupt_and_newer_databases_are_never_created_or_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        assert!(Repository::open(directory.path()).is_err());
        assert!(!directory.path().join(DB_NAME).exists());
        let repo = Repository::create(directory.path(), "admin", "synthetic-login").unwrap();
        assert_eq!(repo.meta().unwrap_err().code, ErrorCode::VaultUninitialized);
        repo.conn.pragma_update(None, "user_version", 99).unwrap();
        drop(repo);
        let before = fs::read(directory.path().join(DB_NAME)).unwrap();
        assert!(Repository::open(directory.path()).is_err());
        assert!(Repository::create(directory.path(), "admin", "new-password").is_err());
        assert_eq!(before, fs::read(directory.path().join(DB_NAME)).unwrap());
        fs::write(directory.path().join(DB_NAME), b"corrupted fixture").unwrap();
        assert!(Repository::open(directory.path()).is_err());
        assert_eq!(
            fs::read(directory.path().join(DB_NAME)).unwrap(),
            b"corrupted fixture"
        );
    }

    #[test]
    fn initialized_metadata_survives_restart_and_has_restricted_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let repo = Repository::create(directory.path(), "admin", "synthetic-login").unwrap();
        let transaction = repo.conn.unchecked_transaction().unwrap();
        let meta = repo.initialize(&encryption()).unwrap();
        transaction.commit().unwrap();
        drop(repo);
        let repo = Repository::open(directory.path()).unwrap();
        assert_eq!(repo.meta().unwrap(), meta);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(directory.path().join(DB_NAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn entries_and_revision_rollback_together_on_transaction_failure() {
        let directory = tempfile::tempdir().unwrap();
        let repo = Repository::create(directory.path(), "admin", "synthetic-login").unwrap();
        repo.initialize(&encryption()).unwrap();
        {
            let _transaction = repo.conn.unchecked_transaction().unwrap();
            repo.conn
                .execute(
                    "INSERT INTO entries VALUES (1, 'description', ?1, 1, 1)",
                    [STANDARD.encode([0; 28])],
                )
                .unwrap();
            repo.advance_revision().unwrap();
            assert!(
                repo.conn
                    .execute(
                        "INSERT INTO entries VALUES (1, 'duplicate', ?1, 1, 1)",
                        [STANDARD.encode([0; 28])]
                    )
                    .is_err()
            );
        }
        assert_eq!(repo.meta().unwrap().vault_revision, 1);
        assert_eq!(repo.entry(1).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn legacy_import_preserves_ids_ciphertext_metadata_and_source_bytes() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("legacy.db");
        legacy(&source);
        let before = fs::read(&source).unwrap();
        let destination = tempfile::tempdir().unwrap();
        let repo =
            Repository::import_legacy(destination.path(), &source, "admin", "synthetic-login")
                .unwrap();
        assert_eq!(repo.entry(42).unwrap().description, "迁移条目");
        assert_eq!(repo.meta().unwrap().encryption, encryption());
        let content: String = repo
            .conn
            .query_row("SELECT content FROM entries WHERE id=42", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(content, STANDARD.encode([9; 28]));
        assert_eq!(before, fs::read(&source).unwrap());
        let target_before = fs::read(destination.path().join(DB_NAME)).unwrap();
        assert!(
            Repository::import_legacy(destination.path(), &source, "admin", "synthetic-login")
                .is_err()
        );
        assert_eq!(
            target_before,
            fs::read(destination.path().join(DB_NAME)).unwrap()
        );
    }

    #[test]
    fn invalid_legacy_structure_or_oversized_rows_do_not_install_a_database() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("legacy.db");
        legacy(&source);
        let conn = Connection::open(&source).unwrap();
        conn.execute("UPDATE entries SET desc=?1", ["中".repeat(1400)])
            .unwrap();
        let before = fs::read(&source).unwrap();
        let destination = tempfile::tempdir().unwrap();
        let error = match Repository::import_legacy(
            destination.path(),
            &source,
            "admin",
            "synthetic-login",
        ) {
            Err(error) => error,
            Ok(_) => panic!("must reject oversized source"),
        };
        assert!(error.message.contains("entry 42"));
        assert!(!destination.path().join(DB_NAME).exists());
        assert_eq!(before, fs::read(&source).unwrap());
        conn.execute_batch("DROP TABLE entries;").unwrap();
        assert!(
            Repository::import_legacy(destination.path(), &source, "admin", "synthetic-login")
                .is_err()
        );
        assert!(!destination.path().join(DB_NAME).exists());
    }

    #[test]
    fn deleted_or_replaced_open_database_stops_requests() {
        let directory = tempfile::tempdir().unwrap();
        let repo = Repository::create(directory.path(), "admin", "synthetic-login").unwrap();
        let path = directory.path().join(DB_NAME);
        fs::rename(&path, directory.path().join("saved.db")).unwrap();
        assert_eq!(
            repo.check_health().unwrap_err().code,
            ErrorCode::VaultUnavailable
        );
        fs::write(&path, b"replacement").unwrap();
        assert_eq!(
            repo.check_health().unwrap_err().code,
            ErrorCode::VaultUnavailable
        );
        assert_eq!(fs::read(path).unwrap(), b"replacement");
    }

    #[test]
    fn corruption_of_an_open_database_header_stops_requests_without_repair() {
        let directory = tempfile::tempdir().unwrap();
        let repo = Repository::create(directory.path(), "admin", "synthetic-login").unwrap();
        fs::write(directory.path().join(DB_NAME), b"runtime corruption").unwrap();
        assert_eq!(
            repo.check_health().unwrap_err().code,
            ErrorCode::VaultUnavailable
        );
        assert_eq!(
            fs::read(directory.path().join(DB_NAME)).unwrap(),
            b"runtime corruption"
        );
    }

    #[test]
    fn missing_encryption_metadata_with_existing_entries_cannot_be_reinitialized() {
        let directory = tempfile::tempdir().unwrap();
        let repo = Repository::create(directory.path(), "admin", "synthetic-login").unwrap();
        repo.initialize(&encryption()).unwrap();
        repo.conn
            .execute(
                "INSERT INTO entries VALUES (1,'existing',?1,1,1)",
                [STANDARD.encode([0; 28])],
            )
            .unwrap();
        repo.conn.execute("DELETE FROM vault_meta", []).unwrap();
        assert_eq!(repo.meta().unwrap_err().code, ErrorCode::VaultUnavailable);
        assert_eq!(
            repo.initialize(&encryption()).unwrap_err().code,
            ErrorCode::VaultUnavailable
        );
        drop(repo);
        let bytes = fs::read(directory.path().join(DB_NAME)).unwrap();
        assert!(Repository::open(directory.path()).is_err());
        assert_eq!(bytes, fs::read(directory.path().join(DB_NAME)).unwrap());
    }
}
