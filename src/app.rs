use crate::{
    api::{self, Scope, Snapshot},
    config::{self, Config},
    crypto::{self, Key},
    sync::{self, Event, Output, Purpose, SyncWorker, Task},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use keyrotation_protocol::*;
use keyrotation_transport::{Endpoint, TransportError};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const REVEAL_TTL: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const ADOPT_OVERLAY: Duration = Duration::from_millis(500);
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Page {
    Wizard,
    Login,
    Initialize,
    Main,
    Retry,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field {
    Desc,
    Content,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Overlay {
    None,
    Busy,
    Resolving,
}
pub(crate) struct Revealed {
    pub plain: String,
    pub expires: Instant,
    pub paused_left: Option<Duration>,
}
impl Drop for Revealed {
    fn drop(&mut self) {
        self.plain.zeroize();
    }
}
pub(crate) struct Edit {
    pub id: i64,
    pub field: Field,
    pub buf: String,
}
impl Drop for Edit {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

enum Action {
    Initialize,
    Added,
    Description(i64),
    Content(i64, Option<Zeroizing<String>>),
    Delete,
    RotationBegin,
    RotationStage,
    RotationCommit,
    RotationAbort(String),
}
struct PendingWrite {
    request: RpcRequest,
    action: Action,
    expired: bool,
}
struct PendingRotation {
    pass: Zeroizing<String>,
    key: Zeroizing<Key>,
    job: Option<String>,
    cursor: Option<i64>,
    next_cursor: Option<i64>,
    cancel: bool,
}
struct AfterWrite {
    action: Action,
    receipt: Option<EntryMeta>,
}

pub struct App {
    pub(crate) page: Page,
    pub(crate) cfg: Config,
    pub(crate) focused: bool,
    pub(crate) worker: SyncWorker,
    pub(crate) overlay: Overlay,
    pub(crate) status: String,
    pub(crate) config_error: Option<String>,
    pub(crate) status_flash: Option<Instant>,
    pub(crate) auto_sync_notice: String,
    pub(crate) auto_flash: Option<Instant>,
    pub(crate) url_buf: String,
    pub(crate) port_buf: String,
    pub(crate) key_buf: String,
    pub(crate) w_url: String,
    pub(crate) w_key: String,
    pub(crate) w_public_key: String,
    pub(crate) w_ca_file: String,
    pub(crate) l_user: String,
    pub(crate) l_pass: String,
    pub(crate) rows: Vec<EntryMeta>,
    pub(crate) revealed: HashMap<i64, Revealed>,
    pub(crate) edit: Option<Edit>,
    pub(crate) pending_delete: Option<i64>,
    pub(crate) reading: HashSet<i64>,
    cfg_path: Option<PathBuf>,
    cipher: Option<Zeroizing<Key>>,
    meta: Option<VaultMeta>,
    info: Option<ServerInfo>,
    info_at: Instant,
    active: usize,
    pending_write: Option<PendingWrite>,
    rotation: Option<PendingRotation>,
    retry_due: Option<Instant>,
    last_poll: Instant,
    pending_snapshot: Option<Snapshot>,
    overlay_until: Option<Instant>,
    remote_refresh: bool,
    after_write: Option<AfterWrite>,
    #[cfg(test)]
    fixture: Option<HashMap<i64, String>>,
}
impl Drop for App {
    fn drop(&mut self) {
        self.worker.cancel_all();
        self.w_key.zeroize();
        self.key_buf.zeroize();
        self.l_pass.zeroize();
    }
}
impl App {
    pub fn new() -> Self {
        let path = config::path();
        let loaded = path
            .as_ref()
            .map(|path| config::load_at(path))
            .unwrap_or_else(|| Err("无法确定配置目录".into()));
        let (cfg, error) = match loaded {
            Ok(cfg) => (cfg, None),
            Err(error) => (Config::default(), Some(format!("读取配置失败: {error}"))),
        };
        let mut app = Self::blank(cfg);
        app.cfg_path = path;
        if let Some(error) = error {
            app.set_status(error);
        } else if app.cfg.legacy_endpoint.is_some() {
            app.set_status("请改为新服务 API 地址，旧 WebDAV 凭据不会用于新服务");
        } else if !app.cfg.server_url.is_empty() && !app.cfg.sym_key.is_empty() {
            app.start_connect(true);
        }
        app
    }
    fn blank(cfg: Config) -> Self {
        Self {
            page: Page::Wizard,
            w_url: cfg.server_url.clone(),
            w_key: String::new(),
            w_public_key: cfg
                .trusted_servers
                .get(&cfg.server_url)
                .cloned()
                .unwrap_or_default(),
            w_ca_file: cfg
                .trusted_ca_files
                .get(&cfg.server_url)
                .cloned()
                .unwrap_or_default(),
            l_user: cfg.username.clone().unwrap_or_default(),
            l_pass: String::new(),
            url_buf: cfg.server_url.clone(),
            port_buf: port_of(&cfg.server_url),
            key_buf: String::new(),
            cfg,
            focused: false,
            worker: SyncWorker::new(),
            overlay: Overlay::None,
            status: String::new(),
            config_error: None,
            status_flash: None,
            auto_sync_notice: String::new(),
            auto_flash: None,
            rows: Vec::new(),
            revealed: HashMap::new(),
            edit: None,
            pending_delete: None,
            reading: HashSet::new(),
            cfg_path: None,
            cipher: None,
            meta: None,
            info: None,
            info_at: Instant::now(),
            active: 0,
            pending_write: None,
            rotation: None,
            retry_due: None,
            last_poll: Instant::now(),
            pending_snapshot: None,
            overlay_until: None,
            remote_refresh: false,
            after_write: None,
            #[cfg(test)]
            fixture: None,
        }
    }
    pub(crate) fn set_status(&mut self, text: impl Into<String>) {
        self.status = text.into();
        self.status_flash = Some(Instant::now());
    }
    fn save_cfg(&mut self) {
        if let Some(path) = &self.cfg_path {
            match config::save_at(path, &self.cfg) {
                Ok(()) => self.config_error = None,
                Err(error) => {
                    let message = format!("保存配置失败: {error}");
                    self.config_error = Some(message.clone());
                    self.set_status(message);
                }
            }
        }
    }
    pub(crate) fn retry_save_config(&mut self) {
        self.save_cfg();
        if self.config_error.is_none() {
            self.set_status("配置已保存");
        }
    }
    fn clear_sensitive(&mut self) {
        if let Some(after) = &mut self.after_write
            && let Action::Content(_, plain) = &mut after.action
        {
            *plain = None;
        }
        if let Some(pending) = &mut self.pending_write
            && let Action::Content(_, plain) = &mut pending.action
        {
            *plain = None;
        }
        self.revealed.clear();
        self.edit = None;
        self.pending_delete = None;
        self.reading.clear();
        self.l_pass.zeroize();
        self.w_key.zeroize();
        self.key_buf.zeroize();
    }
    fn clear_view(&mut self) {
        self.clear_sensitive();
        self.rows.clear();
        self.meta = None;
        self.cipher = None;
        self.pending_snapshot = None;
        self.overlay_until = None;
        self.auto_sync_notice.clear();
        self.auto_flash = None;
        self.after_write = None;
    }
    fn reset_tasks(&mut self) {
        self.worker.cancel_all();
        self.active = 0;
        self.reading.clear();
        self.retry_due = None;
    }
    fn send(&mut self, purpose: Purpose, task: Task) {
        self.active += 1;
        self.worker.send(sync::Command {
            epoch: self.worker.epoch(),
            scope: Scope::from_config(&self.cfg),
            purpose,
            task,
        });
    }
    fn rpc(&mut self, purpose: Purpose, command: Command) {
        self.send(
            purpose,
            Task::Rpc(RpcRequest::new(command, self.cfg.token.clone())),
        );
    }
    fn write_context(&self) -> Option<WriteContext> {
        let generation = self
            .meta
            .as_ref()
            .map(|meta| meta.generation.clone())
            .or_else(|| self.info.as_ref().map(|info| info.generation.clone()))?;
        let key_epoch = self.meta.as_ref().map_or(0, |meta| meta.key_epoch);
        let server_now = self.info.as_ref().map_or(api::now(), |info| {
            info.server_time + self.info_at.elapsed().as_secs() as i64
        });
        Some(WriteContext {
            operation_id: random_id(),
            generation,
            key_epoch,
            valid_until: server_now + OPERATION_TTL,
        })
    }
    fn submit(&mut self, command: Command, action: Action) {
        if self.pending_write.is_some() {
            return;
        }
        let request = RpcRequest::new(command, self.cfg.token.clone());
        if let Err(error) = request.validate() {
            self.set_status(error.message);
            return;
        }
        self.pending_write = Some(PendingWrite {
            request: request.clone(),
            action,
            expired: false,
        });
        self.overlay = Overlay::Busy;
        self.send(Purpose::Mutation, Task::Rpc(request));
    }
    pub(crate) fn start_connect(&mut self, use_token: bool) {
        if self.cfg.legacy_endpoint.is_some() {
            self.page = Page::Wizard;
            self.overlay = Overlay::None;
            return;
        }
        let Ok(endpoint) = Endpoint::parse(&self.cfg.server_url) else {
            self.page = Page::Wizard;
            self.overlay = Overlay::None;
            self.set_status("服务器地址不合法");
            return;
        };
        if endpoint.is_http()
            && self
                .cfg
                .trusted_servers
                .get(&self.cfg.server_url)
                .is_none_or(|key| keyrotation_transport::public_key(key).is_err())
        {
            self.page = Page::Wizard;
            self.overlay = Overlay::None;
            self.w_url = self.cfg.server_url.clone();
            self.set_status("请通过可信途径输入服务端公钥");
            return;
        }
        self.reset_tasks();
        self.clear_view();
        if !use_token {
            self.cfg.token = None;
        }
        self.overlay = Overlay::Busy;
        self.rpc(Purpose::Info, Command::ServerInfo);
    }
    pub(crate) fn wizard_confirm(&mut self) {
        let endpoint = match Endpoint::parse(self.w_url.trim()) {
            Ok(endpoint) => endpoint,
            Err(_) => {
                self.set_status("请输入完整的 HTTP 或 HTTPS API 地址");
                return;
            }
        };
        if self
            .cfg
            .legacy_endpoint
            .as_ref()
            .is_some_and(|old| Endpoint::parse(old).is_ok_and(|old| old == endpoint))
        {
            self.set_status("请填写新服务的 API 地址，不能继续使用旧 WebDAV 地址");
            return;
        }
        if self.w_key.is_empty() && self.cfg.sym_key.is_empty() {
            self.set_status("请输入对称加密密钥");
            return;
        }
        if endpoint.is_http() && keyrotation_transport::public_key(&self.w_public_key).is_err() {
            self.set_status("请输入可信的服务端公钥（base64）");
            return;
        }
        if self.cfg.server_url != endpoint.as_str() {
            self.reset_tasks();
            self.pending_write = None;
            self.rotation = None;
            self.cfg.token = None;
            self.cfg.username = None;
        }
        self.cfg.server_url = endpoint.as_str().into();
        self.cfg.legacy_endpoint = None;
        if !self.w_key.is_empty() {
            self.cfg.sym_key.zeroize();
            self.cfg.sym_key = std::mem::take(&mut self.w_key);
        }
        if endpoint.is_http() {
            self.cfg
                .trusted_servers
                .insert(self.cfg.server_url.clone(), self.w_public_key.trim().into());
        }
        if !self.w_ca_file.trim().is_empty() {
            self.cfg
                .trusted_ca_files
                .insert(self.cfg.server_url.clone(), self.w_ca_file.trim().into());
        } else {
            self.cfg.trusted_ca_files.remove(&self.cfg.server_url);
        }
        self.url_buf = self.cfg.server_url.clone();
        self.port_buf = port_of(&self.url_buf);
        self.save_cfg();
        self.start_connect(true);
    }
    pub(crate) fn login(&mut self) {
        if self.l_user.is_empty() || self.l_pass.is_empty() {
            self.set_status("请输入账号和密码");
            return;
        }
        self.overlay = Overlay::Busy;
        let password = std::mem::take(&mut self.l_pass);
        self.rpc(
            Purpose::Login,
            Command::AuthLogin {
                username: self.l_user.clone(),
                password,
            },
        );
    }
    fn authenticated(&mut self) {
        if self.pending_write.is_some() {
            self.retry_pending();
        } else if self.rotation.is_some() {
            self.read_rotation_batch();
        } else {
            self.load_snapshot(false);
        }
    }
    pub(crate) fn initialize_vault(&mut self) {
        let Some(write) = self.write_context() else {
            return;
        };
        match encryption_for(&self.cfg.sym_key) {
            Ok((encryption, key)) => {
                self.cipher = Some(Zeroizing::new(key));
                self.submit(
                    Command::VaultInitialize { write, encryption },
                    Action::Initialize,
                );
            }
            Err(error) => self.set_status(error),
        }
    }
    fn load_snapshot(&mut self, remote: bool) {
        self.remote_refresh = remote;
        self.overlay = Overlay::Busy;
        if remote {
            self.clear_sensitive();
            self.overlay_until = Some(Instant::now() + ADOPT_OVERLAY);
        }
        self.send(Purpose::Snapshot, Task::Snapshot(self.cfg.token.clone()));
    }
    pub(crate) fn handle_event(&mut self, event: Event) {
        if event.epoch != self.worker.epoch() {
            return;
        }
        self.active = self.active.saturating_sub(1);
        match event.result {
            Err(error) => self.failure(event.purpose, error),
            Ok(Output::Snapshot(snapshot)) => {
                if self.pending_write.is_none() {
                    if self
                        .overlay_until
                        .is_some_and(|until| until > Instant::now())
                    {
                        self.pending_snapshot = Some(snapshot);
                    } else {
                        self.install_snapshot(snapshot);
                    }
                }
            }
            Ok(Output::Prepared(batch)) => {
                if self
                    .rotation
                    .as_ref()
                    .is_some_and(|rotation| rotation.cancel)
                {
                    self.fail_rotation("已取消轮换");
                    return;
                }
                if let Some(rotation) = &mut self.rotation {
                    rotation.next_cursor = batch.next_after_id;
                }
                if batch.entries.is_empty() {
                    self.commit_rotation();
                } else if let (Some(write), Some(job)) = (
                    self.write_context(),
                    self.rotation
                        .as_ref()
                        .and_then(|rotation| rotation.job.clone()),
                ) {
                    self.submit(
                        Command::RotationStage {
                            write,
                            job_id: job,
                            entries: batch.entries,
                        },
                        Action::RotationStage,
                    );
                }
            }
            Ok(Output::Body(body)) => self.handle_body(event.purpose, *body),
        }
    }
    fn handle_body(&mut self, purpose: Purpose, body: ResponseBody) {
        match (purpose, body) {
            (Purpose::Info, ResponseBody::ServerInfo(info)) => {
                self.info = Some(info);
                self.info_at = Instant::now();
                if self.cfg.token.is_some() {
                    self.rpc(Purpose::Validate, Command::AuthValidate);
                } else {
                    self.page = Page::Login;
                    self.overlay = Overlay::None;
                }
            }
            (Purpose::Validate, ResponseBody::Session(_)) => self.authenticated(),
            (Purpose::Login, ResponseBody::Session(session)) => {
                self.cfg.token = session.token;
                self.cfg.username = Some(session.username.clone());
                self.l_user = session.username;
                self.save_cfg();
                self.authenticated();
            }
            (Purpose::Poll, ResponseBody::VaultMeta(meta)) => {
                if self.pending_write.is_none()
                    && self.rotation.is_none()
                    && self.meta.as_ref().is_none_or(|old| {
                        old.generation != meta.generation
                            || old.vault_revision != meta.vault_revision
                            || old.key_epoch != meta.key_epoch
                    })
                {
                    self.load_snapshot(true);
                }
            }
            (Purpose::Content(id), ResponseBody::Content(content)) => {
                self.reading.remove(&id);
                if self.pending_write.is_none() {
                    self.install_content(id, content);
                }
            }
            (Purpose::Mutation, body) => self.confirm_write(Ok(body)),
            (Purpose::Resolve, ResponseBody::Operation(record)) => {
                match (record.state, record.outcome) {
                    (OperationState::Committed | OperationState::Rejected, Some(outcome)) => {
                        self.confirm_write(outcome.into_result())
                    }
                    (OperationState::NotFound, _) => {
                        if let Some(pending) = &mut self.pending_write {
                            pending.request.request_id = random_id();
                            pending.request.session_token = self.cfg.token.clone();
                            let request = pending.request.clone();
                            self.send(Purpose::Mutation, Task::Rpc(request));
                        }
                    }
                    _ => {
                        if let Some(pending) = &mut self.pending_write {
                            pending.expired = true;
                        }
                        self.overlay = Overlay::Resolving;
                        self.set_status("操作结果已过期，不会重复执行；请重新加载确认服务器数据");
                    }
                }
            }
            (Purpose::Logout, _) => {}
            _ => self.failure(purpose, TransportError::InvalidResponse),
        }
    }
    fn install_content(&mut self, id: i64, content: EntryContent) {
        if self.rows.iter().any(|row| {
            row.id == id && row.revision == content.revision && row.key_epoch == content.key_epoch
        }) && let Some(key) = &self.cipher
        {
            match crypto::decrypt(key, &content.content) {
                Ok(plain) => {
                    self.revealed.insert(
                        id,
                        Revealed {
                            plain,
                            expires: Instant::now() + REVEAL_TTL,
                            paused_left: None,
                        },
                    );
                }
                Err(_) => self.set_status("内容解密失败，请核对加密密钥"),
            }
        }
    }
    fn install_snapshot(&mut self, snapshot: Snapshot) {
        let key = match key_for(&self.cfg.sym_key, &snapshot.meta.encryption) {
            Ok(key) => key,
            Err(error) => {
                self.reset_tasks();
                self.clear_view();
                self.page = Page::Wizard;
                self.overlay = Overlay::None;
                self.set_status(error);
                return;
            }
        };
        let after = self.after_write.take();
        let includes_remote_changes = after.is_some()
            && self.meta.as_ref().is_some_and(|old| {
                old.generation != snapshot.meta.generation
                    || old.key_epoch != snapshot.meta.key_epoch
                    || old.vault_revision.checked_add(1) != Some(snapshot.meta.vault_revision)
            });
        if after.is_none() || self.remote_refresh || includes_remote_changes {
            self.clear_sensitive();
        } else {
            let old = &self.rows;
            let local_description = after.as_ref().and_then(|after| match &after.action {
                Action::Description(id) => {
                    after.receipt.as_ref().map(|entry| (*id, entry.revision))
                }
                _ => None,
            });
            self.revealed.retain(|id, _| {
                snapshot.rows.iter().any(|new| {
                    new.id == *id
                        && old.iter().any(|old| {
                            old.id == *id
                                && old.key_epoch == new.key_epoch
                                && (old.revision == new.revision
                                    || local_description.is_some_and(|(local_id, revision)| {
                                        local_id == *id
                                            && old.revision.checked_add(1) == Some(revision)
                                            && new.revision == revision
                                    }))
                        })
                })
            });
        }
        self.cipher = Some(Zeroizing::new(key));
        self.meta = Some(snapshot.meta);
        self.rows = snapshot.rows;
        self.page = Page::Main;
        self.overlay = Overlay::None;
        self.overlay_until = None;
        self.last_poll = Instant::now();
        if let Some(after) = after {
            match after.action {
                Action::Added => {
                    if let Some(entry) = after.receipt
                        && self.rows.iter().any(|row| row.id == entry.id)
                    {
                        self.start_edit(entry.id, Field::Desc);
                    }
                }
                Action::Content(id, Some(mut plain)) => {
                    if let Some(receipt) = after.receipt
                        && self.rows.iter().any(|row| {
                            row.id == id
                                && row.revision == receipt.revision
                                && row.key_epoch == receipt.key_epoch
                        })
                    {
                        self.revealed.insert(
                            id,
                            Revealed {
                                plain: std::mem::take(&mut *plain),
                                expires: Instant::now() + REVEAL_TTL,
                                paused_left: None,
                            },
                        );
                    }
                }
                _ => {}
            }
            self.set_status("保存成功");
        }
        if self.remote_refresh {
            self.auto_sync_notice = "数据库自动同步成功".into();
            self.auto_flash = Some(Instant::now());
            self.remote_refresh = false;
        }
    }
    fn confirm_write(&mut self, result: ApiResult<ResponseBody>) {
        let Some(pending) = self.pending_write.take() else {
            return;
        };
        self.retry_due = None;
        let body = match result {
            Ok(body) => body,
            Err(error) => {
                self.reject_write(pending.action, error);
                return;
            }
        };
        match pending.action {
            Action::RotationBegin => {
                if let ResponseBody::Rotation(job) = body
                    && let Some(rotation) = &mut self.rotation
                {
                    rotation.job = Some(job.job_id);
                    self.read_rotation_batch();
                } else {
                    self.fail_rotation("轮换响应无效");
                }
            }
            Action::RotationStage => {
                if self
                    .rotation
                    .as_ref()
                    .is_some_and(|rotation| rotation.cancel)
                {
                    self.fail_rotation("已取消轮换");
                    return;
                }
                let more = self
                    .rotation
                    .as_ref()
                    .is_some_and(|rotation| rotation.next_cursor.is_some());
                if let Some(rotation) = &mut self.rotation {
                    rotation.cursor = rotation.next_cursor;
                }
                if more {
                    self.read_rotation_batch();
                } else {
                    self.commit_rotation();
                }
            }
            Action::RotationCommit => {
                if let ResponseBody::Rotation(job) = body
                    && let Some(meta) = job.committed_meta
                    && let Some(rotation) = self.rotation.take()
                {
                    if key_for(&rotation.pass, &meta.encryption).is_err() {
                        self.overlay = Overlay::None;
                        self.set_status("轮换已提交，但新密钥校验失败，请重新配置");
                        self.page = Page::Wizard;
                        return;
                    }
                    self.cfg.sym_key.zeroize();
                    self.cfg.sym_key = rotation.pass.to_string();
                    self.cipher = Some(Zeroizing::new(*rotation.key));
                    self.save_cfg();
                    self.load_snapshot(false);
                    self.set_status("密钥轮换已确认");
                } else {
                    self.fail_rotation("轮换提交结果无效");
                }
            }
            Action::RotationAbort(message) => {
                self.rotation = None;
                self.overlay = Overlay::None;
                self.set_status(message);
            }
            action => {
                let receipt = if let ResponseBody::Entry(mutation) = body {
                    Some(mutation.entry)
                } else {
                    None
                };
                self.after_write = Some(AfterWrite { action, receipt });
                self.load_snapshot(false);
            }
        }
    }
    fn reject_write(&mut self, action: Action, error: ApiError) {
        if matches!(
            error.code,
            ErrorCode::KeyEpochChanged | ErrorCode::GenerationChanged
        ) {
            self.rotation = None;
            self.clear_sensitive();
            self.start_connect(true);
            self.set_status(error.message);
            return;
        }
        if matches!(action, Action::RotationAbort(_)) {
            self.rotation = None;
            self.overlay = Overlay::None;
            self.set_status(error.message);
            return;
        }
        if self.rotation.is_some() {
            self.fail_rotation(&error.message);
        } else {
            self.overlay = Overlay::None;
            self.set_status(error.message);
        }
    }
    fn failure(&mut self, purpose: Purpose, error: TransportError) {
        if purpose == Purpose::Logout {
            return;
        }
        if let Purpose::Content(id) = purpose {
            self.reading.remove(&id);
        }
        if let TransportError::Remote(remote) = &error {
            if matches!(
                remote.code,
                ErrorCode::Unauthenticated | ErrorCode::SessionExpired
            ) {
                self.reset_tasks();
                self.clear_sensitive();
                self.cfg.token = None;
                self.save_cfg();
                self.page = Page::Login;
                self.overlay = Overlay::None;
                self.auto_sync_notice.clear();
                self.set_status("登录已失效，请重新登录");
                return;
            }
            if remote.code == ErrorCode::VaultUninitialized && purpose == Purpose::Snapshot {
                self.page = Page::Initialize;
                self.overlay = Overlay::None;
                return;
            }
            if purpose == Purpose::Login {
                self.page = Page::Login;
                self.overlay = Overlay::None;
                self.set_status(remote.message.clone());
                return;
            }
            if purpose == Purpose::Mutation
                && !matches!(
                    remote.code,
                    ErrorCode::VaultUnavailable | ErrorCode::Internal
                )
            {
                self.confirm_write(Err(remote.clone()));
                return;
            }
            if purpose == Purpose::RotationRead {
                self.fail_rotation(&remote.message);
                return;
            }
            if purpose == Purpose::Resolve
                && matches!(
                    remote.code,
                    ErrorCode::GenerationChanged | ErrorCode::OperationExpired
                )
            {
                if let Some(pending) = &mut self.pending_write {
                    pending.expired = true;
                }
                self.overlay = Overlay::Resolving;
                self.set_status(remote.message.clone());
                return;
            }
        }
        self.reset_tasks();
        self.clear_sensitive();
        if let Some(pending) = &mut self.pending_write {
            if let Action::Content(_, plain) = &mut pending.action {
                *plain = None;
            }
            self.overlay = Overlay::Resolving;
            self.retry_due = Some(Instant::now() + Duration::from_secs(2));
            self.set_status("提交结果未知，正在重连查询原操作结果");
        } else if self.rotation.is_some() {
            self.overlay = Overlay::Resolving;
            self.retry_due = Some(Instant::now() + Duration::from_secs(2));
            self.set_status("轮换连接中断，等待重连");
        } else {
            self.overlay = Overlay::None;
            self.page = Page::Retry;
            self.auto_sync_notice.clear();
            self.set_status(match error {
                TransportError::Remote(error) => error.message,
                TransportError::Channel => "安全通道校验失败，请核对地址与服务端公钥".into(),
                TransportError::InvalidPublicKey | TransportError::MissingPublicKey => {
                    "服务端公钥或可信 CA 配置无效".into()
                }
                _ => "网络暂时不可达，配置已保留".into(),
            });
        }
    }
    pub(crate) fn retry_pending(&mut self) {
        if self.active > 0 {
            return;
        }
        self.retry_due = None;
        if self
            .pending_write
            .as_ref()
            .is_some_and(|pending| pending.expired)
        {
            self.pending_write = None;
            self.rotation = None;
            self.start_connect(true);
            return;
        }
        if let Some(pending) = &self.pending_write
            && let Some(write) = pending.request.command.write()
        {
            let command = Command::OperationsGet {
                generation: write.generation.clone(),
                operation_id: write.operation_id.clone(),
            };
            self.overlay = Overlay::Resolving;
            self.rpc(Purpose::Resolve, command);
        } else if self.rotation.is_some() {
            self.read_rotation_batch();
        }
    }
    pub(crate) fn pending_expired(&self) -> bool {
        self.pending_write
            .as_ref()
            .is_some_and(|pending| pending.expired)
    }
    pub(crate) fn tick_sync(&mut self) {
        #[cfg(test)]
        if self.fixture.is_some() {
            return;
        }
        if self.pending_snapshot.is_some()
            && self
                .overlay_until
                .is_none_or(|until| until <= Instant::now())
        {
            if let Some(snapshot) = self.pending_snapshot.take() {
                self.install_snapshot(snapshot);
            }
            return;
        }
        if self.retry_due.is_some_and(|due| due <= Instant::now())
            && self.active == 0
            && self.page != Page::Login
        {
            self.retry_pending();
            return;
        }
        if self.page == Page::Main
            && self.focused
            && self.overlay == Overlay::None
            && self.active == 0
            && self.pending_write.is_none()
            && self.rotation.is_none()
            && self.last_poll.elapsed() >= POLL_INTERVAL
        {
            self.last_poll = Instant::now();
            self.rpc(Purpose::Poll, Command::VaultMeta);
        }
    }
    pub(crate) fn expire_reveals(&mut self) {
        let now = Instant::now();
        self.revealed
            .retain(|_, revealed| revealed.paused_left.is_some() || revealed.expires > now);
    }
    pub(crate) fn reveal(&mut self, id: i64) {
        if self.overlay != Overlay::None || self.reading.contains(&id) {
            return;
        }
        let Some(row) = self.rows.iter().find(|row| row.id == id).cloned() else {
            return;
        };
        #[cfg(test)]
        if let Some(fixture) = &self.fixture
            && let Some(content) = fixture.get(&id)
        {
            self.install_content(
                id,
                EntryContent {
                    id,
                    revision: row.revision,
                    key_epoch: row.key_epoch,
                    content: content.clone(),
                },
            );
            return;
        }
        let Some(meta) = &self.meta else {
            return;
        };
        self.reading.insert(id);
        self.rpc(
            Purpose::Content(id),
            Command::EntriesReadContent {
                generation: meta.generation.clone(),
                id,
                expected_revision: row.revision,
            },
        );
    }
    pub(crate) fn start_edit(&mut self, id: i64, field: Field) {
        if self.overlay != Overlay::None {
            return;
        }
        self.cancel_edit();
        let buf = match field {
            Field::Desc => match self.rows.iter().find(|row| row.id == id) {
                Some(row) => row.description.clone(),
                None => return,
            },
            Field::Content => match self.revealed.get_mut(&id) {
                Some(revealed) => {
                    revealed.paused_left =
                        Some(revealed.expires.saturating_duration_since(Instant::now()));
                    revealed.plain.clone()
                }
                None => return,
            },
        };
        self.edit = Some(Edit { id, field, buf });
    }
    pub(crate) fn cancel_edit(&mut self) {
        if let Some(edit) = self.edit.take()
            && edit.field == Field::Content
            && let Some(revealed) = self.revealed.get_mut(&edit.id)
            && let Some(left) = revealed.paused_left.take()
        {
            revealed.expires = Instant::now() + left;
        }
    }
    pub(crate) fn commit_edit(&mut self) {
        let Some(mut edit) = self.edit.take() else {
            return;
        };
        let Some(write) = self.write_context() else {
            return;
        };
        let valid = match edit.field {
            Field::Desc => validate_description(&edit.buf),
            Field::Content => {
                if edit.buf.len() > MAX_PLAINTEXT_BYTES {
                    Err(ApiError::new(
                        ErrorCode::LimitExceeded,
                        "内容不能超过 32 KiB",
                    ))
                } else {
                    Ok(())
                }
            }
        };
        if let Err(error) = valid {
            self.set_status(error.message);
            self.edit = Some(edit);
            return;
        }
        let (description, content, action) = match edit.field {
            Field::Desc => (
                Some(std::mem::take(&mut edit.buf)),
                None,
                Action::Description(edit.id),
            ),
            Field::Content => {
                let Some(key) = &self.cipher else {
                    return;
                };
                let encrypted = match crypto::encrypt(key, &edit.buf) {
                    Ok(value) => value,
                    Err(_) => {
                        self.set_status("内容加密失败");
                        return;
                    }
                };
                (
                    None,
                    Some(encrypted),
                    Action::Content(edit.id, Some(Zeroizing::new(std::mem::take(&mut edit.buf)))),
                )
            }
        };
        #[cfg(test)]
        if let Some(fixture) = &mut self.fixture {
            if let Some(row) = self.rows.iter_mut().find(|row| row.id == edit.id) {
                row.revision += 1;
                if let Some(description) = description {
                    row.description = description;
                }
                if let Some(content) = content {
                    fixture.insert(edit.id, content);
                }
            }
            if let Action::Content(id, Some(mut plain)) = action {
                self.revealed.insert(
                    id,
                    Revealed {
                        plain: std::mem::take(&mut *plain),
                        expires: Instant::now() + REVEAL_TTL,
                        paused_left: None,
                    },
                );
            }
            return;
        }
        if edit.field == Field::Content {
            self.revealed.remove(&edit.id);
        }
        self.submit(
            Command::EntriesUpdate {
                write,
                id: edit.id,
                description,
                content,
            },
            action,
        );
    }
    pub(crate) fn add_row(&mut self) {
        if self.overlay != Overlay::None {
            return;
        }
        let (Some(write), Some(key)) = (self.write_context(), self.cipher.as_ref()) else {
            return;
        };
        if let Ok(content) = crypto::encrypt(key, "") {
            self.submit(
                Command::EntriesCreate {
                    write,
                    description: String::new(),
                    content,
                },
                Action::Added,
            );
        }
    }
    pub(crate) fn delete_row(&mut self, id: i64) {
        if self.edit.as_ref().is_some_and(|edit| edit.id == id) {
            return;
        }
        if let Some(write) = self.write_context() {
            self.submit(Command::EntriesDelete { write, id }, Action::Delete);
        }
    }
    pub(crate) fn apply_url(&mut self) {
        let Ok(endpoint) = Endpoint::parse(self.url_buf.trim()) else {
            self.set_status("服务器地址不合法");
            return;
        };
        if endpoint.as_str() == self.cfg.server_url {
            return;
        }
        self.reset_tasks();
        self.clear_view();
        self.pending_write = None;
        self.rotation = None;
        self.cfg.server_url = endpoint.as_str().into();
        self.cfg.token = None;
        self.cfg.username = None;
        self.l_user.clear();
        self.w_url = self.cfg.server_url.clone();
        self.w_public_key = self
            .cfg
            .trusted_servers
            .get(&self.cfg.server_url)
            .cloned()
            .unwrap_or_default();
        self.w_ca_file = self
            .cfg
            .trusted_ca_files
            .get(&self.cfg.server_url)
            .cloned()
            .unwrap_or_default();
        self.url_buf = self.cfg.server_url.clone();
        self.port_buf = port_of(&self.url_buf);
        self.save_cfg();
        self.start_connect(false);
    }
    pub(crate) fn logout(&mut self) {
        self.reset_tasks();
        if self.cfg.token.is_some() {
            self.rpc(Purpose::Logout, Command::AuthLogout);
        }
        self.clear_view();
        self.pending_write = None;
        self.rotation = None;
        self.cfg.sym_key.zeroize();
        self.cfg.token = None;
        self.cfg.username = None;
        self.l_user.clear();
        self.page = Page::Wizard;
        self.overlay = Overlay::None;
        self.save_cfg();
        self.set_status("已退出登录");
    }
    pub(crate) fn change_key(&mut self, pass: String) {
        let pass = Zeroizing::new(pass);
        if pass.as_str() == self.cfg.sym_key || pass.is_empty() {
            return;
        }
        if self.active > 0 || self.pending_write.is_some() || self.rotation.is_some() {
            self.set_status("请求处理中，请稍后修改密钥");
            return;
        }
        let (Some(write), Some(meta)) = (self.write_context(), self.meta.clone()) else {
            return;
        };
        match encryption_for(&pass) {
            Ok((encryption, key)) => {
                self.clear_sensitive();
                self.rotation = Some(PendingRotation {
                    pass,
                    key: Zeroizing::new(key),
                    job: None,
                    cursor: None,
                    next_cursor: None,
                    cancel: false,
                });
                self.submit(
                    Command::RotationBegin {
                        write,
                        expected_vault_revision: meta.vault_revision,
                        new_encryption: encryption,
                    },
                    Action::RotationBegin,
                );
            }
            Err(error) => self.set_status(error),
        }
    }
    fn read_rotation_batch(&mut self) {
        if self
            .rotation
            .as_ref()
            .is_some_and(|rotation| rotation.cancel)
        {
            self.fail_rotation("已取消轮换");
            return;
        }
        let (Some(rotation), Some(meta), Some(old)) = (
            self.rotation.as_ref(),
            self.meta.as_ref(),
            self.cipher.as_ref(),
        ) else {
            return;
        };
        let Some(job) = &rotation.job else {
            return;
        };
        let request = RpcRequest::new(
            Command::RotationReadBatch {
                generation: meta.generation.clone(),
                job_id: job.clone(),
                after_id: rotation.cursor,
                limit: 1,
            },
            self.cfg.token.clone(),
        );
        let task = Task::RotationRead {
            request,
            old: Zeroizing::new(**old),
            new: Zeroizing::new(*rotation.key),
        };
        self.overlay = Overlay::Busy;
        self.send(Purpose::RotationRead, task);
    }
    fn commit_rotation(&mut self) {
        if self
            .rotation
            .as_ref()
            .is_some_and(|rotation| rotation.cancel)
        {
            self.fail_rotation("已取消轮换");
            return;
        }
        if let (Some(write), Some(job)) = (
            self.write_context(),
            self.rotation
                .as_ref()
                .and_then(|rotation| rotation.job.clone()),
        ) {
            self.submit(
                Command::RotationCommit { write, job_id: job },
                Action::RotationCommit,
            );
        }
    }
    pub(crate) fn can_cancel_rotation(&self) -> bool {
        self.rotation
            .as_ref()
            .is_some_and(|rotation| !rotation.cancel)
            && !self.pending_write.as_ref().is_some_and(|pending| {
                matches!(
                    pending.action,
                    Action::RotationCommit | Action::RotationAbort(_)
                )
            })
    }
    pub(crate) fn cancel_rotation(&mut self) {
        if !self.can_cancel_rotation() {
            return;
        }
        if let Some(rotation) = &mut self.rotation {
            rotation.cancel = true;
        }
        self.set_status("正在取消轮换");
        if self.active == 0 && self.pending_write.is_none() {
            self.fail_rotation("已取消轮换");
        }
    }
    fn fail_rotation(&mut self, message: &str) {
        if let (Some(write), Some(job)) = (
            self.write_context(),
            self.rotation
                .as_ref()
                .and_then(|rotation| rotation.job.clone()),
        ) {
            self.submit(
                Command::RotationAbort { write, job_id: job },
                Action::RotationAbort(message.into()),
            );
        } else {
            self.rotation = None;
            self.overlay = Overlay::None;
            self.set_status(message);
        }
    }
}
fn port_of(value: &str) -> String {
    url::Url::parse(value)
        .ok()
        .and_then(|url| url.port_or_known_default())
        .map(|port| port.to_string())
        .unwrap_or_default()
}
fn encryption_for(pass: &str) -> Result<(EncryptionMeta, Key), String> {
    let salt = crypto::new_salt();
    let key = crypto::derive_key(pass, &salt).map_err(|_| "密钥派生失败")?;
    let verifier = crypto::encrypt(&key, "ptoolkit-ok").map_err(|_| "校验值加密失败")?;
    Ok((
        EncryptionMeta {
            content_format: 1,
            kdf: KdfParams::default(),
            salt: STANDARD.encode(salt),
            verifier,
        },
        key,
    ))
}
fn key_for(pass: &str, encryption: &EncryptionMeta) -> Result<Key, String> {
    encryption.validate().map_err(|_| "服务器加密元数据无效")?;
    let salt = STANDARD
        .decode(&encryption.salt)
        .map_err(|_| "盐值格式错误")?;
    let key = crypto::derive_key(pass, &salt).map_err(|_| "密钥派生失败")?;
    let plain = Zeroizing::new(
        crypto::decrypt(&key, &encryption.verifier).map_err(|_| "加密密钥与服务器数据库不匹配")?,
    );
    if plain.as_str() != "ptoolkit-ok" {
        return Err("加密密钥与服务器数据库不匹配".into());
    }
    Ok(key)
}
#[cfg(test)]
impl App {
    pub(crate) fn test_vault() -> Self {
        let mut app = Self::blank(Config::default());
        app.cfg.sym_key = "synthetic-test-key".into();
        let (encryption, key) = encryption_for(&app.cfg.sym_key).unwrap();
        app.meta = Some(VaultMeta {
            vault_id: random_id(),
            generation: random_id(),
            vault_revision: 1,
            key_epoch: 1,
            encryption,
        });
        app.cipher = Some(Zeroizing::new(key));
        app.rows = vec![EntryMeta {
            id: 1,
            description: "测试条目".into(),
            revision: 1,
            key_epoch: 1,
        }];
        app.fixture = Some(HashMap::from([(
            1,
            crypto::encrypt(&key, "synthetic secret").unwrap(),
        )]));
        app.page = Page::Main;
        app
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_write_refresh_that_also_observes_remote_changes_clears_all_old_views() {
        let mut app = App::test_vault();
        app.reveal(1);
        app.start_edit(1, Field::Content);
        let mut meta = app.meta.clone().unwrap();
        meta.vault_revision += 2;
        let rows = app.rows.clone();
        app.after_write = Some(AfterWrite {
            action: Action::Delete,
            receipt: None,
        });
        app.install_snapshot(Snapshot { meta, rows });
        assert!(app.revealed.is_empty());
        assert!(app.edit.is_none());
    }

    #[test]
    fn confirmed_key_is_retained_when_config_save_fails_and_persistence_can_retry() {
        let mut app = App::test_vault();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        std::fs::create_dir(&path).unwrap();
        app.cfg_path = Some(path.clone());
        app.cfg.sym_key = "confirmed-new-synthetic-key".into();
        app.save_cfg();
        assert!(app.config_error.is_some());
        app.set_status("数据库提交已确认");
        assert!(app.config_error.is_some());
        assert_eq!(app.cfg.sym_key, "confirmed-new-synthetic-key");
        std::fs::remove_dir(&path).unwrap();
        app.retry_save_config();
        assert!(app.config_error.is_none());
        assert_eq!(
            config::load_at(&path).unwrap().sym_key,
            "confirmed-new-synthetic-key"
        );
    }

    #[test]
    fn unknown_write_preserves_configuration_and_id_but_clears_plaintext_and_old_events() {
        let mut app = App::test_vault();
        app.cfg.token = Some("synthetic-token".into());
        app.reveal(1);
        app.start_edit(1, Field::Content);
        let write = app.write_context().unwrap();
        let operation_id = write.operation_id.clone();
        app.pending_write = Some(PendingWrite {
            request: RpcRequest::new(
                Command::EntriesUpdate {
                    write,
                    id: 1,
                    description: None,
                    content: Some(STANDARD.encode([0; 28])),
                },
                app.cfg.token.clone(),
            ),
            action: Action::Content(1, Some(Zeroizing::new("pending plaintext".into()))),
            expired: false,
        });
        let old_epoch = app.worker.epoch();
        app.failure(Purpose::Mutation, TransportError::Network);
        assert!(app.revealed.is_empty());
        assert!(app.edit.is_none());
        assert!(app.cfg.token.is_some());
        assert_eq!(app.cfg.sym_key, "synthetic-test-key");
        assert!(app.overlay == Overlay::Resolving);
        let pending = app.pending_write.as_ref().unwrap();
        assert_eq!(
            pending.request.command.write().unwrap().operation_id,
            operation_id
        );
        assert!(matches!(pending.action, Action::Content(_, None)));
        app.handle_event(Event {
            epoch: old_epoch,
            purpose: Purpose::Content(1),
            result: Ok(Output::Body(Box::new(ResponseBody::Content(
                EntryContent {
                    id: 1,
                    revision: 1,
                    key_epoch: 1,
                    content: app.fixture.as_ref().unwrap()[&1].clone(),
                },
            )))),
        });
        assert!(app.revealed.is_empty());
    }

    #[test]
    fn pending_mutation_defers_old_poll_and_reading_stale_content_never_reveals() {
        let mut app = App::test_vault();
        let mut changed = app.meta.clone().unwrap();
        changed.vault_revision += 1;
        let write = app.write_context().unwrap();
        app.pending_write = Some(PendingWrite {
            request: RpcRequest::new(Command::EntriesDelete { write, id: 1 }, None),
            action: Action::Delete,
            expired: false,
        });
        app.handle_body(Purpose::Poll, ResponseBody::VaultMeta(changed));
        assert!(!app.remote_refresh);
        assert_eq!(app.meta.as_ref().unwrap().vault_revision, 1);
        app.pending_write = None;
        app.rows[0].revision = 2;
        app.install_content(
            1,
            EntryContent {
                id: 1,
                revision: 1,
                key_epoch: 1,
                content: app.fixture.as_ref().unwrap()[&1].clone(),
            },
        );
        assert!(app.revealed.is_empty());
        app.start_edit(1, Field::Content);
        assert!(app.edit.is_none());
    }

    #[test]
    fn independent_reveal_deadlines_and_cancel_preserve_remaining_time() {
        let mut app = App::test_vault();
        app.reveal(1);
        app.revealed.insert(
            2,
            Revealed {
                plain: "other".into(),
                expires: Instant::now() - Duration::from_secs(1),
                paused_left: None,
            },
        );
        app.start_edit(1, Field::Content);
        app.expire_reveals();
        assert!(app.revealed.contains_key(&1));
        assert!(!app.revealed.contains_key(&2));
        let paused = app.revealed[&1].paused_left.unwrap();
        app.cancel_edit();
        assert!(
            app.revealed[&1]
                .expires
                .saturating_duration_since(Instant::now())
                <= paused
        );
    }

    struct LocalServer {
        handle: axum_server::Handle<std::net::SocketAddr>,
        thread: Option<std::thread::JoinHandle<()>>,
        _data: tempfile::TempDir,
        endpoint: Endpoint,
        public: String,
    }
    impl LocalServer {
        fn start() -> Self {
            Self::start_with_source(None)
        }
        fn start_with_source(source: Option<&std::path::Path>) -> Self {
            let data = tempfile::tempdir().unwrap();
            if let Some(source) = source {
                keyrotation_server::store::Repository::import_legacy(
                    data.path(),
                    source,
                    "admin",
                    "synthetic-login-password",
                )
                .unwrap();
            } else {
                keyrotation_server::store::Repository::create(
                    data.path(),
                    "admin",
                    "synthetic-login-password",
                )
                .unwrap();
            }
            let worker = keyrotation_server::worker::DbWorker::open(data.path()).unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let endpoint =
                Endpoint::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
            let identity =
                std::sync::Arc::new(keyrotation_transport::Identity::generate().unwrap());
            let public = identity.public_base64();
            let app = keyrotation_server::http::router(
                endpoint.clone(),
                Some(identity),
                keyrotation_server::dispatcher(worker),
            )
            .unwrap();
            let handle = axum_server::Handle::new();
            let serving = handle.clone();
            let thread = std::thread::spawn(move || {
                tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(async move {
                        axum_server::from_tcp(listener)
                            .unwrap()
                            .handle(serving)
                            .serve(app.into_make_service())
                            .await
                            .unwrap();
                    });
            });
            Self {
                handle,
                thread: Some(thread),
                _data: data,
                endpoint,
                public,
            }
        }
    }
    impl Drop for LocalServer {
        fn drop(&mut self) {
            self.handle.shutdown();
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }
    fn pump(app: &mut App, done: impl Fn(&App) -> bool) {
        let until = Instant::now() + Duration::from_secs(10);
        while !done(app) && Instant::now() < until {
            while let Some(event) = app.worker.try_recv() {
                app.handle_event(event);
            }
            app.tick_sync();
            app.expire_reveals();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(done(app), "state did not complete: {}", app.status);
    }

    #[test]
    fn desktop_worker_login_crud_rotation_and_logout_use_real_api_without_a_local_database() {
        let server = LocalServer::start();
        let config_dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.server_url = server.endpoint.as_str().into();
        cfg.sym_key = "old-synthetic-content-key".into();
        cfg.trusted_servers
            .insert(cfg.server_url.clone(), server.public.clone());
        let mut app = App::blank(cfg);
        app.cfg_path = Some(config_dir.path().join("config.json"));
        app.start_connect(true);
        pump(&mut app, |app| app.page == Page::Login);
        app.l_user = "admin".into();
        app.l_pass = "synthetic-login-password".into();
        app.login();
        pump(&mut app, |app| app.page == Page::Initialize);
        app.initialize_vault();
        pump(&mut app, |app| {
            app.page == Page::Main && app.overlay == Overlay::None
        });
        app.add_row();
        pump(&mut app, |app| app.edit.is_some());
        let id = app.rows[0].id;
        app.edit.as_mut().unwrap().buf = "接口条目".into();
        app.commit_edit();
        pump(&mut app, |app| {
            app.overlay == Overlay::None && app.edit.is_none()
        });
        assert_eq!(app.rows[0].description, "接口条目");
        assert!(app.revealed.is_empty());
        app.reveal(id);
        pump(&mut app, |app| app.revealed.contains_key(&id));
        app.start_edit(id, Field::Content);
        app.edit.as_mut().unwrap().buf = "synthetic API content 🔑".into();
        app.commit_edit();
        pump(&mut app, |app| {
            app.overlay == Overlay::None
                && app
                    .revealed
                    .get(&id)
                    .is_some_and(|revealed| revealed.plain == "synthetic API content 🔑")
        });
        app.change_key("new-synthetic-content-key".into());
        pump(&mut app, |app| {
            app.rotation.is_none()
                && app.overlay == Overlay::None
                && app.cfg.sym_key == "new-synthetic-content-key"
        });
        assert!(app.revealed.is_empty());
        assert_eq!(app.meta.as_ref().unwrap().key_epoch, 2);
        assert_eq!(
            config::load_at(app.cfg_path.as_ref().unwrap())
                .unwrap()
                .sym_key,
            "new-synthetic-content-key"
        );
        app.reveal(id);
        pump(&mut app, |app| app.revealed.contains_key(&id));
        assert_eq!(app.revealed[&id].plain, "synthetic API content 🔑");
        app.delete_row(id);
        pump(&mut app, |app| {
            app.rows.is_empty() && app.overlay == Overlay::None
        });
        let token = app.cfg.token.clone();
        app.logout();
        pump(&mut app, |app| app.active == 0);
        assert!(app.cfg.token.is_none());
        assert!(app.cfg.sym_key.is_empty());
        let files: Vec<_> = std::fs::read_dir(config_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(files, vec![std::ffi::OsString::from("config.json")]);
        let mut client =
            keyrotation_transport::Client::new(server.endpoint.clone(), Some(&server.public), None)
                .unwrap();
        assert!(matches!(
            client.call(&RpcRequest::new(Command::AuthValidate, token)),
            Err(TransportError::Remote(ApiError {
                code: ErrorCode::Unauthenticated,
                ..
            }))
        ));
    }

    #[test]
    fn synthetic_legacy_import_keeps_ids_and_content_decryptable_after_api_rotation() {
        use rusqlite::{Connection, params};
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("legacy.db");
        let pass = "synthetic-legacy-pass";
        let salt = [6u8; 16];
        let key = crypto::derive_key(pass, &salt).unwrap();
        let conn = Connection::open(&source).unwrap();
        conn.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY,value BLOB NOT NULL);CREATE TABLE entries (id INTEGER PRIMARY KEY AUTOINCREMENT,desc TEXT NOT NULL,content TEXT NOT NULL);").unwrap();
        conn.execute(
            "INSERT INTO meta VALUES ('salt',?1),('verifier',?2)",
            params![
                salt.as_slice(),
                crypto::encrypt(&key, "ptoolkit-ok").unwrap().into_bytes()
            ],
        )
        .unwrap();
        for (id, text) in [(42, "迁移内容 🔑"), (99, "")] {
            conn.execute(
                "INSERT INTO entries VALUES (?1,?2,?3)",
                params![
                    id,
                    format!("条目{id}"),
                    crypto::encrypt(&key, text).unwrap()
                ],
            )
            .unwrap();
        }
        drop(conn);
        let before = std::fs::read(&source).unwrap();
        let server = LocalServer::start_with_source(Some(&source));
        assert_eq!(before, std::fs::read(&source).unwrap());
        let mut cfg = Config::default();
        cfg.server_url = server.endpoint.as_str().into();
        cfg.sym_key = pass.into();
        cfg.trusted_servers
            .insert(cfg.server_url.clone(), server.public.clone());
        let mut app = App::blank(cfg);
        app.start_connect(true);
        pump(&mut app, |app| app.page == Page::Login);
        app.l_user = "admin".into();
        app.l_pass = "synthetic-login-password".into();
        app.login();
        pump(&mut app, |app| {
            app.page == Page::Main && app.overlay == Overlay::None
        });
        assert_eq!(
            app.rows.iter().map(|row| row.id).collect::<Vec<_>>(),
            [42, 99]
        );
        app.reveal(42);
        pump(&mut app, |app| app.revealed.contains_key(&42));
        assert_eq!(app.revealed[&42].plain, "迁移内容 🔑");
        app.change_key("discarded-synthetic-pass".into());
        app.cancel_rotation();
        pump(&mut app, |app| {
            app.rotation.is_none() && app.overlay == Overlay::None
        });
        assert_eq!(app.cfg.sym_key, pass);
        assert_eq!(app.meta.as_ref().unwrap().key_epoch, 1);
        app.change_key("new-synthetic-migrated-pass".into());
        pump(&mut app, |app| {
            app.rotation.is_none()
                && app.overlay == Overlay::None
                && app.cfg.sym_key == "new-synthetic-migrated-pass"
        });
        for (id, text) in [(42, "迁移内容 🔑"), (99, "")] {
            app.reveal(id);
            pump(&mut app, |app| app.revealed.contains_key(&id));
            assert_eq!(app.revealed[&id].plain, text);
        }
        assert_eq!(before, std::fs::read(&source).unwrap());
        assert_eq!(app.rows.len(), 2);
    }
}
