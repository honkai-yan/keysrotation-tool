use crate::store::{Repository, storage_error};
use argon2::{
    Argon2,
    password_hash::{PasswordVerifier, phc::PasswordHash},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use keyrotation_protocol::*;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

fn error(code: ErrorCode, message: &str) -> ApiError {
    ApiError::new(code, message)
}
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs() as i64)
        .unwrap_or(0)
}

impl Repository {
    pub fn dispatch(&mut self, request: &RpcRequest, now: i64) -> RpcResponse {
        let result = (|| {
            request.validate()?;
            self.check_health()?;
            self.housekeeping(now)?;
            if matches!(request.command, Command::ServerInfo) {
                return self.info(now).map(ResponseBody::ServerInfo);
            }
            if let Command::AuthLogin { username, password } = &request.command {
                return self
                    .login(username, password, now)
                    .map(ResponseBody::Session);
            }
            if let Some(write) = request.command.write() {
                return self.write_request(request, write, now);
            }
            let snapshot = self.conn.unchecked_transaction().map_err(storage_error)?;
            let session = self.authenticate(request.session_token.as_deref(), now)?;
            let result = self.read_request(
                &request.command,
                session,
                request.session_token.as_deref(),
                now,
            );
            snapshot.commit().map_err(storage_error)?;
            result
        })();
        RpcResponse::new(request.request_id.clone(), result)
    }

    fn housekeeping(&self, now: i64) -> ApiResult<()> {
        self.conn.execute("UPDATE operation_results SET outcome_json=NULL WHERE expires_at<=?1 AND outcome_json IS NOT NULL",[now]).map_err(storage_error)?;
        self.conn
            .execute(
                "UPDATE rotation_jobs SET state='expired' WHERE state='staging' AND expires_at<=?1",
                [now],
            )
            .map_err(storage_error)?;
        self.conn.execute("DELETE FROM rotation_entries WHERE job_id IN (SELECT id FROM rotation_jobs WHERE state!='staging')",[]).map_err(storage_error)?;
        Ok(())
    }

    fn info(&self, now: i64) -> ApiResult<ServerInfo> {
        let server_id = self
            .conn
            .query_row(
                "SELECT server_id FROM service_state WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(storage_error)?;
        let initialized = self
            .conn
            .query_row("SELECT count(*) FROM vault_meta", [], |r| {
                r.get::<_, i64>(0)
            })
            .map_err(storage_error)?
            != 0;
        Ok(ServerInfo {
            server_id,
            generation: self.generation()?,
            initialized,
            server_time: now,
        })
    }

    fn login(&mut self, username: &str, password: &str, now: i64) -> ApiResult<AuthSession> {
        if username.len() > 128 || password.len() > 1024 {
            return Err(invalid("login exceeds limits"));
        }
        if now - self.login_window >= 60 {
            self.login_window = now;
            self.login_attempts = 0;
        }
        if self.login_attempts >= 10 {
            return Err(error(ErrorCode::RateLimited, "login rate exceeded"));
        }
        self.login_attempts += 1;
        let (saved, hash) = self
            .conn
            .query_row(
                "SELECT username,password_hash FROM users WHERE id=1",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .map_err(storage_error)?;
        let parsed = PasswordHash::new(&hash).map_err(storage_error)?;
        let valid = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        if !valid || username != saved {
            return Err(error(
                ErrorCode::InvalidCredentials,
                "invalid login credentials",
            ));
        }
        let transaction = self.conn.unchecked_transaction().map_err(storage_error)?;
        self.conn
            .execute("DELETE FROM sessions WHERE expires_at<=?1", [now])
            .map_err(storage_error)?;
        let active = self
            .conn
            .query_row("SELECT count(*) FROM sessions", [], |r| r.get::<_, i64>(0))
            .map_err(storage_error)?;
        if active >= 32 {
            return Err(error(ErrorCode::RateLimited, "too many active sessions"));
        }
        let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let digest = Sha256::digest(token.as_bytes());
        let expires_at = now + SESSION_TTL;
        self.conn
            .execute(
                "INSERT INTO sessions VALUES (?1,1,?2,?3)",
                params![digest.as_slice(), now, expires_at],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        Ok(AuthSession {
            username: saved,
            token: Some(token),
            expires_at,
        })
    }

    fn authenticate(&self, token: Option<&str>, now: i64) -> ApiResult<AuthSession> {
        let token = token.ok_or_else(|| error(ErrorCode::Unauthenticated, "login required"))?;
        if token.len() != 43
            || URL_SAFE_NO_PAD
                .decode(token)
                .map_or(true, |bytes| bytes.len() != 32)
        {
            return Err(error(ErrorCode::Unauthenticated, "invalid session"));
        }
        let digest = Sha256::digest(token.as_bytes());
        let row=self.conn.query_row("SELECT u.username,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_digest=?1",[digest.as_slice()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?))).optional().map_err(storage_error)?.ok_or_else(||error(ErrorCode::Unauthenticated,"invalid session"))?;
        if row.1 <= now {
            return Err(error(ErrorCode::SessionExpired, "session expired"));
        }
        Ok(AuthSession {
            username: row.0,
            token: None,
            expires_at: row.1,
        })
    }

    fn generation_matches(&self, generation: &str) -> ApiResult<()> {
        if !valid_id(generation) || generation != self.generation()? {
            return Err(error(
                ErrorCode::GenerationChanged,
                "server data generation changed",
            ));
        }
        Ok(())
    }

    fn write_request(
        &self,
        request: &RpcRequest,
        write: &WriteContext,
        now: i64,
    ) -> ApiResult<ResponseBody> {
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        self.authenticate(request.session_token.as_deref(), now)?;
        self.generation_matches(&write.generation)?;
        let digest = request.command.digest()?;
        let existing=self.conn.query_row("SELECT request_digest,outcome_json FROM operation_results WHERE generation=?1 AND user_id=1 AND operation_id=?2",params![write.generation,write.operation_id],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Option<String>>(1)?))).optional().map_err(storage_error)?;
        if let Some((saved, outcome)) = existing {
            if saved != digest {
                return Err(error(
                    ErrorCode::OperationMismatch,
                    "operation_id was used with different parameters",
                ));
            }
            let outcome = outcome.ok_or_else(|| {
                error(ErrorCode::OperationExpired, "operation result has expired")
            })?;
            let outcome: RpcOutcome = serde_json::from_str(&outcome).map_err(storage_error)?;
            return outcome.into_result();
        }
        if write.valid_until < now || write.valid_until > now + OPERATION_TTL {
            return Err(error(
                ErrorCode::OperationExpired,
                "operation deadline is invalid or expired",
            ));
        }
        let key_epoch = match self.meta() {
            Ok(meta) => meta.key_epoch,
            Err(e) if e.code == ErrorCode::VaultUninitialized => 0,
            Err(e) => return Err(e),
        };
        if write.key_epoch != key_epoch {
            return Err(error(
                ErrorCode::KeyEpochChanged,
                "content key epoch changed",
            ));
        }
        self.conn
            .execute_batch("SAVEPOINT business;")
            .map_err(storage_error)?;
        let result = self.execute_write(&request.command, now);
        if result.as_ref().is_err_and(|error| {
            matches!(
                error.code,
                ErrorCode::VaultUnavailable | ErrorCode::Internal
            )
        }) {
            return result;
        }
        if result.is_err() {
            self.conn
                .execute_batch("ROLLBACK TO business;")
                .map_err(storage_error)?;
        }
        self.conn
            .execute_batch("RELEASE business;")
            .map_err(storage_error)?;
        let outcome: RpcOutcome = result.clone().into();
        let json = serde_json::to_string(&outcome).map_err(storage_error)?;
        self.conn
            .execute(
                "INSERT INTO operation_results VALUES (?1,1,?2,?3,?4,?5,?6,?7)",
                params![
                    write.generation,
                    write.operation_id,
                    digest.as_slice(),
                    i64::from(result.is_ok()),
                    json,
                    now,
                    now + OPERATION_TTL
                ],
            )
            .map_err(storage_error)?;
        self.check_health()?;
        transaction.commit().map_err(storage_error)?;
        result
    }

    fn execute_write(&self, command: &Command, now: i64) -> ApiResult<ResponseBody> {
        match command {
            Command::VaultInitialize { encryption, .. } => {
                self.initialize(encryption).map(ResponseBody::VaultMeta)
            }
            Command::EntriesCreate {
                description,
                content,
                ..
            } => {
                validate_description(description)?;
                validate_content(content)?;
                let meta = self.meta()?;
                if self
                    .conn
                    .query_row("SELECT count(*) FROM entries", [], |r| r.get::<_, i64>(0))
                    .map_err(storage_error)?
                    >= MAX_ENTRIES
                {
                    return Err(error(ErrorCode::LimitExceeded, "entry limit reached"));
                }
                self.conn.execute("INSERT INTO entries (description,content,revision,key_epoch) VALUES (?1,?2,1,?3)",params![description,content,meta.key_epoch]).map_err(storage_error)?;
                let id = self.conn.last_insert_rowid();
                let revision = self.advance_revision()?;
                Ok(ResponseBody::Entry(EntryMutation {
                    entry: self.entry(id)?,
                    vault_revision: revision,
                }))
            }
            Command::EntriesUpdate {
                id,
                description,
                content,
                ..
            } => {
                self.meta()?;
                self.entry(*id)?;
                if description.is_none() && content.is_none() {
                    return Err(invalid("empty update"));
                }
                if let Some(description) = description {
                    validate_description(description)?;
                }
                if let Some(content) = content {
                    validate_content(content)?;
                }
                self.conn.execute("UPDATE entries SET description=COALESCE(?2,description),content=COALESCE(?3,content),revision=revision+1 WHERE id=?1",params![id,description,content]).map_err(storage_error)?;
                let revision = self.advance_revision()?;
                Ok(ResponseBody::Entry(EntryMutation {
                    entry: self.entry(*id)?,
                    vault_revision: revision,
                }))
            }
            Command::EntriesDelete { id, .. } => {
                self.meta()?;
                if self
                    .conn
                    .execute("DELETE FROM entries WHERE id=?1", [id])
                    .map_err(storage_error)?
                    == 0
                {
                    return Err(error(ErrorCode::NotFound, "entry not found"));
                }
                Ok(ResponseBody::Deleted {
                    id: *id,
                    vault_revision: self.advance_revision()?,
                })
            }
            Command::RotationBegin {
                expected_vault_revision,
                new_encryption,
                ..
            } => {
                new_encryption.validate()?;
                let meta = self.meta()?;
                if meta.vault_revision != *expected_vault_revision {
                    return Err(error(
                        ErrorCode::RotationConflict,
                        "rotation baseline changed",
                    ));
                }
                if self
                    .conn
                    .query_row(
                        "SELECT count(*) FROM rotation_jobs WHERE state='staging'",
                        [],
                        |r| r.get::<_, i64>(0),
                    )
                    .map_err(storage_error)?
                    > 0
                {
                    return Err(error(ErrorCode::Busy, "another rotation is staging"));
                }
                let id = random_id();
                let count = self
                    .conn
                    .query_row("SELECT count(*) FROM entries", [], |r| r.get::<_, i64>(0))
                    .map_err(storage_error)?;
                self.conn.execute("INSERT INTO rotation_jobs VALUES (?1,1,?2,?3,?4,?5,'staging',?6,?7,?8,NULL)",params![id,meta.generation,meta.vault_revision,meta.key_epoch,serde_json::to_string(new_encryption).map_err(storage_error)?,count,now,now+ROTATION_IDLE_TTL]).map_err(storage_error)?;
                self.conn
                    .execute(
                        "INSERT INTO rotation_members SELECT ?1,id,revision FROM entries",
                        [&id],
                    )
                    .map_err(storage_error)?;
                self.rotation_info(&id).map(ResponseBody::Rotation)
            }
            Command::RotationStage {
                job_id, entries, ..
            } => {
                self.active_rotation(job_id)?;
                if entries.is_empty() || entries.len() > usize::from(MAX_PAGE_SIZE) {
                    return Err(invalid("invalid rotation batch size"));
                }
                let mut seen = std::collections::HashSet::new();
                for entry in entries {
                    validate_content(&entry.content)?;
                    if !seen.insert(entry.id) {
                        return Err(invalid("duplicate entry in rotation batch"));
                    }
                    let member = self
                        .conn
                        .query_row(
                            "SELECT count(*) FROM rotation_members WHERE job_id=?1 AND entry_id=?2",
                            params![job_id, entry.id],
                            |r| r.get::<_, i64>(0),
                        )
                        .map_err(storage_error)?;
                    if member != 1 {
                        return Err(invalid("entry does not belong to rotation"));
                    }
                    self.conn.execute("INSERT INTO rotation_entries VALUES (?1,?2,?3) ON CONFLICT(job_id,entry_id) DO UPDATE SET content=excluded.content",params![job_id,entry.id,entry.content]).map_err(storage_error)?;
                }
                self.conn
                    .execute(
                        "UPDATE rotation_jobs SET expires_at=min(created_at+?2,?3) WHERE id=?1",
                        params![job_id, ROTATION_MAX_TTL, now + ROTATION_IDLE_TTL],
                    )
                    .map_err(storage_error)?;
                self.rotation_info(job_id).map(ResponseBody::Rotation)
            }
            Command::RotationCommit { job_id, .. } => {
                let job = self.active_rotation(job_id)?;
                if job.staged_entries != job.total_entries {
                    return Err(error(
                        ErrorCode::RotationIncomplete,
                        "rotation is incomplete",
                    ));
                }
                let meta = self.meta()?;
                let epoch = meta
                    .key_epoch
                    .checked_add(1)
                    .ok_or_else(|| storage_error("key epoch overflow"))?;
                let encryption: String = self
                    .conn
                    .query_row(
                        "SELECT encryption_json FROM rotation_jobs WHERE id=?1",
                        [job_id],
                        |r| r.get(0),
                    )
                    .map_err(storage_error)?;
                self.conn.execute("UPDATE entries SET content=(SELECT content FROM rotation_entries WHERE job_id=?1 AND entry_id=entries.id),key_epoch=?2,revision=revision+1",params![job_id,epoch]).map_err(storage_error)?;
                self.conn
                    .execute(
                        "UPDATE vault_meta SET key_epoch=?1,encryption_json=?2 WHERE singleton=1",
                        params![epoch, encryption],
                    )
                    .map_err(storage_error)?;
                self.advance_revision()?;
                let committed = self.meta()?;
                self.conn.execute("UPDATE rotation_jobs SET state='committed',committed_meta_json=?2 WHERE id=?1",params![job_id,serde_json::to_string(&committed).map_err(storage_error)?]).map_err(storage_error)?;
                self.rotation_info(job_id).map(ResponseBody::Rotation)
            }
            Command::RotationAbort { job_id, .. } => {
                let job = self.rotation_info(job_id)?;
                if job.state == RotationState::Staging {
                    self.conn
                        .execute(
                            "UPDATE rotation_jobs SET state='aborted' WHERE id=?1",
                            [job_id],
                        )
                        .map_err(storage_error)?;
                }
                self.rotation_info(job_id).map(ResponseBody::Rotation)
            }
            _ => Err(invalid("not a data mutation")),
        }
    }

    fn read_request(
        &self,
        command: &Command,
        session: AuthSession,
        token: Option<&str>,
        _now: i64,
    ) -> ApiResult<ResponseBody> {
        match command {
            Command::AuthValidate => Ok(ResponseBody::Session(session)),
            Command::AuthLogout => {
                let digest = Sha256::digest(token.unwrap_or_default().as_bytes());
                self.conn
                    .execute(
                        "DELETE FROM sessions WHERE token_digest=?1",
                        [digest.as_slice()],
                    )
                    .map_err(storage_error)?;
                Ok(ResponseBody::LoggedOut)
            }
            Command::VaultMeta => self.meta().map(ResponseBody::VaultMeta),
            Command::EntriesList {
                generation,
                expected_revision,
                after_id,
                limit,
            } => {
                self.generation_matches(generation)?;
                let meta = self.meta()?;
                if expected_revision.is_some_and(|revision| revision != meta.vault_revision) {
                    return Err(error(ErrorCode::RevisionChanged, "list revision changed"));
                }
                validate_page(*after_id, *limit)?;
                let mut statement=self.conn.prepare("SELECT id,description,revision,key_epoch FROM entries WHERE id>?1 ORDER BY id LIMIT ?2").map_err(storage_error)?;
                let entries = statement
                    .query_map(params![after_id.unwrap_or(0), i64::from(*limit) + 1], |r| {
                        Ok(EntryMeta {
                            id: r.get(0)?,
                            description: r.get(1)?,
                            revision: r.get(2)?,
                            key_epoch: r.get(3)?,
                        })
                    })
                    .map_err(storage_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(storage_error)?;
                let mut page = EntryPage {
                    generation: meta.generation,
                    vault_revision: meta.vault_revision,
                    key_epoch: meta.key_epoch,
                    entries: Vec::new(),
                    next_after_id: None,
                };
                for entry in &entries {
                    if page.entries.len() == usize::from(*limit) {
                        break;
                    }
                    page.entries.push(entry.clone());
                    page.next_after_id = Some(entry.id);
                    if !fits(&ResponseBody::Entries(page.clone())) {
                        page.entries.pop();
                        break;
                    }
                }
                page.next_after_id = if page.entries.len() < entries.len() {
                    page.entries.last().map(|entry| entry.id)
                } else {
                    None
                };
                if page.entries.is_empty() && !entries.is_empty() {
                    return Err(error(ErrorCode::LimitExceeded, "entry cannot fit response"));
                }
                Ok(ResponseBody::Entries(page))
            }
            Command::EntriesReadContent {
                generation,
                id,
                expected_revision,
            } => {
                self.generation_matches(generation)?;
                let entry = self.entry(*id)?;
                if entry.revision != *expected_revision {
                    return Err(error(ErrorCode::RevisionChanged, "entry revision changed"));
                }
                let content = self
                    .conn
                    .query_row("SELECT content FROM entries WHERE id=?1", [id], |r| {
                        r.get(0)
                    })
                    .map_err(storage_error)?;
                Ok(ResponseBody::Content(EntryContent {
                    id: *id,
                    revision: entry.revision,
                    key_epoch: entry.key_epoch,
                    content,
                }))
            }
            Command::OperationsGet {
                generation,
                operation_id,
            } => {
                self.generation_matches(generation)?;
                if !valid_id(operation_id) {
                    return Err(invalid("invalid operation_id"));
                }
                let row=self.conn.query_row("SELECT committed,outcome_json FROM operation_results WHERE generation=?1 AND user_id=1 AND operation_id=?2",params![generation,operation_id],|r|Ok((r.get::<_,bool>(0)?,r.get::<_,Option<String>>(1)?))).optional().map_err(storage_error)?;
                let record = match row {
                    None => OperationRecord {
                        state: OperationState::NotFound,
                        outcome: None,
                    },
                    Some((_, None)) => OperationRecord {
                        state: OperationState::Expired,
                        outcome: None,
                    },
                    Some((committed, Some(json))) => OperationRecord {
                        state: if committed {
                            OperationState::Committed
                        } else {
                            OperationState::Rejected
                        },
                        outcome: Some(Box::new(
                            serde_json::from_str(&json).map_err(storage_error)?,
                        )),
                    },
                };
                Ok(ResponseBody::Operation(record))
            }
            Command::RotationStatus { generation, job_id } => {
                self.generation_matches(generation)?;
                self.rotation_info(job_id).map(ResponseBody::Rotation)
            }
            Command::RotationReadBatch {
                generation,
                job_id,
                after_id,
                limit,
            } => {
                self.generation_matches(generation)?;
                validate_page(*after_id, *limit)?;
                let job = self.active_rotation(job_id)?;
                let mut statement=self.conn.prepare("SELECT e.id,e.content FROM entries e JOIN rotation_members m ON m.entry_id=e.id WHERE m.job_id=?1 AND e.id>?2 ORDER BY e.id LIMIT ?3").map_err(storage_error)?;
                let entries = statement
                    .query_map(
                        params![job_id, after_id.unwrap_or(0), i64::from(*limit) + 1],
                        |r| {
                            Ok(RotatedEntry {
                                id: r.get(0)?,
                                content: r.get(1)?,
                            })
                        },
                    )
                    .map_err(storage_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(storage_error)?;
                let mut batch = RotationBatch {
                    job,
                    entries: Vec::new(),
                    next_after_id: None,
                };
                for entry in &entries {
                    if batch.entries.len() == usize::from(*limit) {
                        break;
                    }
                    batch.entries.push(entry.clone());
                    batch.next_after_id = Some(entry.id);
                    if !fits(&ResponseBody::RotationBatch(batch.clone())) {
                        batch.entries.pop();
                        break;
                    }
                }
                batch.next_after_id = if batch.entries.len() < entries.len() {
                    batch.entries.last().map(|entry| entry.id)
                } else {
                    None
                };
                if batch.entries.is_empty() && !entries.is_empty() {
                    return Err(error(
                        ErrorCode::LimitExceeded,
                        "rotation entry cannot fit response",
                    ));
                }
                Ok(ResponseBody::RotationBatch(batch))
            }
            _ => Err(invalid("unsupported read")),
        }
    }

    fn rotation_info(&self, id: &str) -> ApiResult<RotationInfo> {
        if !valid_id(id) {
            return Err(invalid("invalid rotation ID"));
        }
        let row=self.conn.query_row("SELECT state,baseline_revision,key_epoch,total_entries,expires_at,committed_meta_json FROM rotation_jobs WHERE id=?1 AND owner=1",[id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?,r.get::<_,Option<String>>(5)?))).optional().map_err(storage_error)?.ok_or_else(||error(ErrorCode::NotFound,"rotation not found"))?;
        let state = match row.0.as_str() {
            "staging" => RotationState::Staging,
            "committed" => RotationState::Committed,
            "aborted" => RotationState::Aborted,
            "expired" => RotationState::Expired,
            "conflicted" => RotationState::Conflicted,
            _ => return Err(storage_error("invalid rotation state")),
        };
        let staged_entries = if state == RotationState::Committed {
            row.3
        } else {
            self.conn
                .query_row(
                    "SELECT count(*) FROM rotation_entries WHERE job_id=?1",
                    [id],
                    |r| r.get(0),
                )
                .map_err(storage_error)?
        };
        Ok(RotationInfo {
            job_id: id.into(),
            state,
            baseline_revision: row.1,
            key_epoch: row.2,
            total_entries: row.3,
            staged_entries,
            expires_at: row.4,
            committed_meta: row
                .5
                .map(|json| serde_json::from_str(&json))
                .transpose()
                .map_err(storage_error)?,
        })
    }

    fn active_rotation(&self, id: &str) -> ApiResult<RotationInfo> {
        let job = self.rotation_info(id)?;
        if job.state == RotationState::Expired {
            return Err(error(ErrorCode::RotationExpired, "rotation expired"));
        }
        if job.state != RotationState::Staging {
            return Err(error(
                ErrorCode::RotationConflict,
                "rotation is no longer staging",
            ));
        }
        let meta = self.meta()?;
        if meta.vault_revision != job.baseline_revision || meta.key_epoch != job.key_epoch {
            return Err(error(
                ErrorCode::RotationConflict,
                "rotation baseline changed",
            ));
        }
        Ok(job)
    }
}

fn validate_page(after: Option<i64>, limit: u16) -> ApiResult<()> {
    if after.is_some_and(|id| id < 0) || !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(invalid("invalid page parameters"));
    }
    Ok(())
}
fn fits(body: &ResponseBody) -> bool {
    RpcResponse::new("0".repeat(32), Ok(body.clone()))
        .encode()
        .is_ok()
}
