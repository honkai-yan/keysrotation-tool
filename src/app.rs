use crate::config::{self, Config};
use crate::crypto::{self, Key};
use crate::db::{Db, Entry};
use crate::sync::{
    Command, ConnectFailure, ConnectOutcome, DownloadPurpose, Event, LoginFailure, SyncWorker,
    UploadPurpose,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use url::Url;

/// 明文密钥的自动恢复时间
const REVEAL_TTL: Duration = Duration::from_secs(60);
/// 用于校验对称密钥是否与数据库匹配的固定明文
const VERIFY_TEXT: &str = "ptoolkit-ok";
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const ADOPT_OVERLAY: Duration = Duration::from_millis(500);
const RECOVERY_DELAY: Duration = Duration::from_millis(200);

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum Page {
    Wizard,
    Login,
    Main,
    Retry,
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum Field {
    Desc,
    Content,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SyncState {
    Idle,
    Connecting,
    Polling,
    Uploading,
    Recovering,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Overlay {
    None,
    Busy,
    UploadFailed,
}

pub(crate) struct Revealed {
    pub(crate) plain: String,
    pub(crate) expires: Instant,
    /// 编辑期间冻结倒计时时保存的剩余时间
    pub(crate) paused_left: Option<Duration>,
}

pub(crate) struct Edit {
    pub(crate) id: i64,
    pub(crate) field: Field,
    pub(crate) buf: String,
}

struct PendingKeyChange {
    new_pass: String,
    new_key: Key,
    staged_db: Db,
}

struct QueuedUpload {
    bytes: Vec<u8>,
    purpose: UploadPurpose,
}

struct InFlightUpload {
    digest: [u8; 32],
}

/// 自动同步轮询的纯决策结果，便于模型测试。
enum PollAction {
    Same,
    LocalWins,
    /// 服务器库不存在或损坏：用内存中的库覆盖修复（运行期不新建空库）。
    RepairLocal(&'static str),
    Adopt(Db, Key, [u8; 32]),
    WrongKey,
}

const REPAIR_MISSING: &str = "服务器数据库不存在，已用本地数据库修复";
const REPAIR_CORRUPT: &str = "服务器数据库损坏，已用本地数据库修复";

fn evaluate_poll(
    local_changed: bool,
    bytes: Option<Vec<u8>>,
    last_server_digest: Option<[u8; 32]>,
    pass: &str,
) -> PollAction {
    if local_changed {
        return PollAction::LocalWins;
    }
    let Some(bytes) = bytes else {
        return PollAction::RepairLocal(REPAIR_MISSING);
    };
    let digest = digest_bytes(&bytes);
    if last_server_digest == Some(digest) {
        return PollAction::Same;
    }
    match open_db(Some(bytes), pass) {
        Ok((db, key, _)) => PollAction::Adopt(db, key, digest),
        Err(DbOpenError::Corrupt(_)) => PollAction::RepairLocal(REPAIR_CORRUPT),
        Err(DbOpenError::WrongKey) => PollAction::WrongKey,
    }
}

/// 上传失败后“恢复同步”的纯决策结果。
enum RecoveryAction {
    AdoptOld(Db, Key),
    AdoptNew(Db, Key),
    /// 服务器库不存在或损坏：内存里已有库，直接上传覆盖修复。
    RepairLocal(&'static str),
    Fail,
}

fn evaluate_recovery(
    bytes: Option<&[u8]>,
    old_pass: &str,
    new_pass: Option<&str>,
) -> RecoveryAction {
    let Some(bytes) = bytes else {
        return RecoveryAction::RepairLocal(REPAIR_MISSING);
    };
    match open_db(Some(bytes.to_vec()), old_pass) {
        Ok((db, key, _)) => return RecoveryAction::AdoptOld(db, key),
        Err(DbOpenError::Corrupt(_)) => return RecoveryAction::RepairLocal(REPAIR_CORRUPT),
        Err(DbOpenError::WrongKey) => {}
    }
    if let Some(pass) = new_pass {
        match open_db(Some(bytes.to_vec()), pass) {
            Ok((db, key, _)) => return RecoveryAction::AdoptNew(db, key),
            Err(DbOpenError::Corrupt(_)) => return RecoveryAction::RepairLocal(REPAIR_CORRUPT),
            Err(DbOpenError::WrongKey) => {}
        }
    }
    RecoveryAction::Fail
}

#[derive(Debug)]
enum DbOpenError {
    Corrupt(String),
    WrongKey,
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn port_of(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| u.port_or_known_default())
        .map(|p| p.to_string())
        .unwrap_or_default()
}

fn valid_url(url: &str) -> bool {
    matches!(Url::parse(url), Ok(u) if matches!(u.scheme(), "http" | "https"))
}

/// 打开（或新建）数据库并校验对称密钥。
/// Corrupt 表示 SQLite/结构损坏；WrongKey 表示结构可读但密钥不匹配。
fn open_db(bytes: Option<Vec<u8>>, pass: &str) -> Result<(Db, Key, bool), DbOpenError> {
    match bytes {
        None => {
            let db = Db::new_empty().map_err(|e| DbOpenError::Corrupt(e.to_string()))?;
            let salt = crypto::new_salt();
            let key =
                crypto::derive_key(pass, &salt).map_err(|e| DbOpenError::Corrupt(e.to_string()))?;
            db.set_meta("salt", &salt)
                .map_err(|e| DbOpenError::Corrupt(e.to_string()))?;
            let verifier = crypto::encrypt(&key, VERIFY_TEXT)
                .map_err(|e| DbOpenError::Corrupt(e.to_string()))?;
            db.set_meta("verifier", verifier.as_bytes())
                .map_err(|e| DbOpenError::Corrupt(e.to_string()))?;
            Ok((db, key, true))
        }
        Some(b) => {
            let db = Db::from_bytes(&b).map_err(|e| DbOpenError::Corrupt(e.to_string()))?;
            let salt = db
                .meta("salt")
                .map_err(|e| DbOpenError::Corrupt(e.to_string()))?
                .ok_or_else(|| DbOpenError::Corrupt("数据库缺少盐值".into()))?;
            let key =
                crypto::derive_key(pass, &salt).map_err(|e| DbOpenError::Corrupt(e.to_string()))?;
            let verifier = db
                .meta("verifier")
                .map_err(|e| DbOpenError::Corrupt(e.to_string()))?
                .ok_or_else(|| DbOpenError::Corrupt("数据库缺少校验信息".into()))?;
            let verifier =
                std::str::from_utf8(&verifier).map_err(|e| DbOpenError::Corrupt(e.to_string()))?;
            match crypto::decrypt(&key, verifier) {
                Ok(text) if text == VERIFY_TEXT => Ok((db, key, false)),
                Ok(_) => Err(DbOpenError::WrongKey),
                Err(_) => Err(DbOpenError::WrongKey),
            }
        }
    }
}

pub struct App {
    pub(crate) page: Page,
    pub(crate) cfg: Config,
    pub(crate) focused: bool,
    pub(crate) worker: SyncWorker,
    pub(crate) overlay: Overlay,
    overlay_until: Option<Instant>,
    pub(crate) status: String,
    pub(crate) status_flash: Option<Instant>,
    pub(crate) auto_sync_notice: String,
    pub(crate) auto_flash: Option<Instant>,
    auto_notice_pending: bool,
    pending_status_after_overlay: Option<String>,
    sync_state: SyncState,
    last_server_digest: Option<[u8; 32]>,
    local_revision: u64,
    poll_revision: u64,
    last_poll: Instant,
    recovery_due: Option<Instant>,
    pub(crate) pending_delete: Option<i64>,
    pending_key_change: Option<PendingKeyChange>,
    queued_upload: Option<QueuedUpload>,
    in_flight_upload: Option<InFlightUpload>,
    /// 上一次修复性上传完成后要在状态栏显示的说明
    repair_note: Option<String>,
    pub(crate) w_url: String,
    pub(crate) w_key: String,
    pub(crate) l_user: String,
    pub(crate) l_pass: String,
    pub(crate) url_buf: String,
    pub(crate) port_buf: String,
    pub(crate) key_buf: String,
    db: Option<Db>,
    cipher: Option<Key>,
    pub(crate) rows: Vec<Entry>,
    pub(crate) revealed: HashMap<i64, Revealed>,
    pub(crate) edit: Option<Edit>,
}

impl App {
    pub fn new() -> Self {
        Self::from_config(config::load().unwrap_or_default())
    }

    pub(crate) fn from_config(cfg: Config) -> Self {
        let mut app = App {
            page: Page::Wizard,
            w_url: cfg.server_url.clone(),
            w_key: String::new(),
            l_user: cfg.username.clone().unwrap_or_default(),
            l_pass: String::new(),
            url_buf: cfg.server_url.clone(),
            port_buf: port_of(&cfg.server_url),
            key_buf: String::new(),
            focused: false,
            worker: SyncWorker::new(),
            overlay: Overlay::None,
            overlay_until: None,
            status: String::new(),
            status_flash: None,
            auto_sync_notice: String::new(),
            auto_flash: None,
            auto_notice_pending: false,
            pending_status_after_overlay: None,
            sync_state: SyncState::Idle,
            last_server_digest: None,
            local_revision: 0,
            poll_revision: 0,
            last_poll: Instant::now(),
            recovery_due: None,
            pending_delete: None,
            pending_key_change: None,
            queued_upload: None,
            in_flight_upload: None,
            repair_note: None,
            db: None,
            cipher: None,
            rows: Vec::new(),
            revealed: HashMap::new(),
            edit: None,
            cfg,
        };
        if !app.cfg.server_url.is_empty() && !app.cfg.sym_key.is_empty() {
            app.start_connect(true);
        }
        app
    }

    fn dav_url(&self) -> Option<Url> {
        Url::parse(&self.cfg.server_url).ok()
    }

    fn creds(&self) -> Option<(String, String)> {
        match (&self.cfg.username, &self.cfg.password) {
            (Some(u), Some(p)) => Some((u.clone(), p.clone())),
            _ => None,
        }
    }

    pub(crate) fn set_status(&mut self, text: impl Into<String>) {
        self.status = text.into();
        self.status_flash = Some(Instant::now());
    }

    fn clear_status(&mut self) {
        self.status.clear();
        self.status_flash = None;
    }

    fn set_auto_notice_after_overlay(&mut self, text: impl Into<String>) {
        self.auto_sync_notice = text.into();
        self.auto_flash = None;
        self.auto_notice_pending = true;
    }

    fn clear_auto_notice(&mut self) {
        self.auto_sync_notice.clear();
        self.auto_flash = None;
        self.auto_notice_pending = false;
    }

    fn save_cfg(&mut self) {
        if let Err(e) = config::save(&self.cfg) {
            self.set_status(format!("保存配置失败: {e}"));
        }
    }

    pub(crate) fn start_connect(&mut self, use_saved_credentials: bool) {
        let Some(dav) = self.dav_url() else {
            self.set_status("服务器地址不合法");
            self.page = Page::Wizard;
            return;
        };
        self.worker.cancel_all();
        let token = if use_saved_credentials {
            self.cfg.token.clone()
        } else {
            None
        };
        let creds = if use_saved_credentials {
            self.creds()
        } else {
            None
        };
        self.sync_state = SyncState::Connecting;
        self.overlay = Overlay::Busy;
        self.overlay_until = None;
        self.worker.send(Command::Connect {
            epoch: self.worker.epoch(),
            dav,
            token,
            creds,
        });
    }

    pub(crate) fn login(&mut self) {
        let Some(dav) = self.dav_url() else {
            self.set_status("服务器地址不合法");
            return;
        };
        let user = self.l_user.trim().to_string();
        let pass = self.l_pass.clone();
        self.worker.cancel_all();
        self.sync_state = SyncState::Connecting;
        self.overlay = Overlay::Busy;
        self.overlay_until = None;
        self.worker.send(Command::Login {
            epoch: self.worker.epoch(),
            dav,
            user,
            pass,
        });
    }

    pub(crate) fn handle_event(&mut self, event: Event) {
        let current_epoch = self.worker.epoch();
        match event {
            Event::Connect { epoch, result } => {
                if epoch != current_epoch {
                    return;
                }
                self.overlay = Overlay::None;
                match result {
                    Ok(ConnectOutcome::NeedLogin) => {
                        self.sync_state = SyncState::Idle;
                        self.page = Page::Login;
                        self.l_user = self.cfg.username.clone().unwrap_or_default();
                        self.l_pass.clear();
                        self.clear_status();
                    }
                    Ok(ConnectOutcome::Loaded(bytes)) => {
                        self.on_db_loaded(bytes);
                    }
                    Err(ConnectFailure::Download) => {
                        self.sync_state = SyncState::Idle;
                        self.reset_to_wizard("数据库下载失败");
                    }
                    Err(ConnectFailure::AuthProbe) => {
                        self.sync_state = SyncState::Idle;
                        self.page = Page::Retry;
                        self.set_status("连接失败");
                    }
                }
            }
            Event::Login { epoch, result } => {
                if epoch != current_epoch {
                    return;
                }
                match result {
                    Ok(outcome) => {
                        self.cfg.username = Some(outcome.user);
                        self.cfg.password = Some(outcome.pass);
                        self.cfg.token = Some(outcome.token);
                        self.save_cfg();
                        self.l_pass.clear();
                        self.on_db_loaded(outcome.bytes);
                    }
                    Err(LoginFailure::Login(message)) => {
                        self.overlay = Overlay::None;
                        self.sync_state = SyncState::Idle;
                        self.l_pass.clear();
                        self.set_status(message);
                    }
                    Err(LoginFailure::Download) => {
                        self.overlay = Overlay::None;
                        self.sync_state = SyncState::Idle;
                        self.reset_to_wizard("数据库下载失败");
                    }
                }
            }
            Event::Download {
                epoch,
                result,
                purpose,
            } => {
                if epoch != current_epoch {
                    return;
                }
                match purpose {
                    DownloadPurpose::Poll => match result {
                        Ok(bytes) => self.handle_poll(bytes),
                        Err(_) => self.reset_to_wizard("自动同步失败"),
                    },
                    DownloadPurpose::Recovery => match result {
                        Ok(bytes) => self.handle_recovery(bytes),
                        Err(_) => self.reset_to_wizard("数据库上传失败且恢复失败"),
                    },
                }
            }
            Event::Upload {
                epoch,
                result,
                purpose,
            } => {
                if epoch != current_epoch {
                    return;
                }
                match result {
                    Ok(()) => self.handle_upload_success(purpose),
                    Err(_) => self.handle_upload_failure(),
                }
            }
        }
    }

    fn on_db_loaded(&mut self, bytes: Option<Vec<u8>>) {
        match open_db(bytes.clone(), &self.cfg.sym_key) {
            Ok((db, key, created)) => {
                let digest = bytes.as_ref().map(|b| digest_bytes(b));
                self.install_db(db, key, digest);
                self.overlay = Overlay::None;
                self.overlay_until = None;
                self.sync_state = SyncState::Idle;
                self.last_poll = Instant::now();
                self.clear_status();
                if created {
                    self.upload_current_db(UploadPurpose::Edit);
                }
            }
            Err(DbOpenError::Corrupt(message)) => {
                self.overlay = Overlay::None;
                self.overlay_until = None;
                self.sync_state = SyncState::Idle;
                self.set_status(format!("数据库文件损坏，已重建: {message}"));
                match open_db(None, &self.cfg.sym_key) {
                    Ok((db, key, _)) => {
                        self.install_db(db, key, None);
                        self.upload_current_db(UploadPurpose::Edit);
                    }
                    Err(_) => self.reset_to_wizard("数据库下载失败"),
                }
            }
            Err(DbOpenError::WrongKey) => {
                self.overlay = Overlay::None;
                self.overlay_until = None;
                self.sync_state = SyncState::Idle;
                self.reset_to_wizard("加密密钥与服务器数据库不匹配");
            }
        }
    }

    fn install_db(&mut self, db: Db, key: Key, digest: Option<[u8; 32]>) {
        self.db = Some(db);
        self.cipher = Some(key);
        self.revealed.clear();
        self.edit = None;
        self.pending_delete = None;
        self.pending_key_change = None;
        self.queued_upload = None;
        self.in_flight_upload = None;
        self.key_buf.clear();
        self.last_server_digest = digest;
        self.local_revision = self.local_revision.wrapping_add(1);
        self.page = Page::Main;
        self.reload_rows();
    }

    fn reload_rows(&mut self) {
        if let Some(db) = &self.db {
            match db.entries() {
                Ok(rows) => self.rows = rows,
                Err(e) => self.set_status(format!("读取条目失败: {e}")),
            }
        }
    }

    fn upload_current_db(&mut self, purpose: UploadPurpose) {
        let Some(db) = self.db.as_mut() else {
            return;
        };
        let bytes = match db.export_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                self.set_status(format!("导出数据库失败: {e}"));
                return;
            }
        };
        self.start_upload(bytes, purpose);
    }

    fn start_upload(&mut self, bytes: Vec<u8>, purpose: UploadPurpose) {
        if self.sync_state != SyncState::Idle {
            self.queued_upload = Some(QueuedUpload { bytes, purpose });
            return;
        }
        self.begin_upload(bytes, purpose);
    }

    fn begin_upload(&mut self, bytes: Vec<u8>, purpose: UploadPurpose) {
        let Some(dav) = self.dav_url() else {
            self.set_status("服务器地址不合法");
            return;
        };
        let creds = self.creds();
        let digest = digest_bytes(&bytes);
        self.sync_state = SyncState::Uploading;
        self.overlay = Overlay::Busy;
        self.overlay_until = None;
        self.in_flight_upload = Some(InFlightUpload { digest });
        self.last_poll = Instant::now();
        self.worker.send(Command::Upload {
            epoch: self.worker.epoch(),
            dav,
            creds,
            bytes,
            purpose,
        });
    }

    fn handle_upload_success(&mut self, purpose: UploadPurpose) {
        let Some(in_flight) = self.in_flight_upload.take() else {
            self.sync_state = SyncState::Idle;
            self.overlay = Overlay::None;
            return;
        };
        if purpose == UploadPurpose::KeyChange
            && let Some(pending) = self.pending_key_change.take()
        {
            self.db = Some(pending.staged_db);
            self.cipher = Some(pending.new_key);
            self.cfg.sym_key = pending.new_pass;
            self.save_cfg();
            self.reload_rows();
        }
        self.last_server_digest = Some(in_flight.digest);
        self.sync_state = SyncState::Idle;
        self.overlay = Overlay::None;
        self.overlay_until = None;
        match self.repair_note.take() {
            Some(note) => self.set_status(note),
            None => self.set_status("同步完成"),
        }
        if purpose == UploadPurpose::Repair {
            self.revealed.clear();
            self.edit = None;
            self.pending_delete = None;
            self.key_buf.clear();
        }
        self.last_poll = Instant::now();
        if let Some(queued) = self.queued_upload.take() {
            self.begin_upload(queued.bytes, queued.purpose);
        }
    }

    fn handle_upload_failure(&mut self) {
        self.in_flight_upload = None;
        self.queued_upload = None;
        self.pending_delete = None;
        self.sync_state = SyncState::Recovering;
        self.overlay = Overlay::UploadFailed;
        self.overlay_until = None;
        self.recovery_due = Some(Instant::now() + RECOVERY_DELAY);
        self.set_status("上传数据库失败");
    }

    fn handle_poll(&mut self, bytes: Option<Vec<u8>>) {
        self.sync_state = SyncState::Idle;
        let local_changed = self.local_revision != self.poll_revision;
        match evaluate_poll(
            local_changed,
            bytes,
            self.last_server_digest,
            &self.cfg.sym_key,
        ) {
            PollAction::Same => {}
            PollAction::LocalWins => {
                if let Some(queued) = self.queued_upload.take() {
                    self.begin_upload(queued.bytes, queued.purpose);
                }
            }
            PollAction::RepairLocal(note) => self.repair_from_local(note),
            PollAction::Adopt(db, key, digest) => self.adopt_server(db, key, digest, None),
            PollAction::WrongKey => self.reset_to_wizard("加密密钥与服务器数据库不匹配"),
        }
    }

    /// 运行期间服务端库不存在或损坏时，用内存中的库覆盖修复（不新建空库）。
    fn repair_from_local(&mut self, note: &str) {
        if self.db.is_none() {
            // 没有内存库可用来修复，只能重置。
            self.reset_to_wizard("自动同步失败");
            return;
        }
        self.repair_note = Some(note.to_string());
        self.set_status(note);
        self.upload_current_db(UploadPurpose::Repair);
    }

    fn adopt_server(&mut self, db: Db, key: Key, digest: [u8; 32], left_status: Option<&str>) {
        self.install_db(db, key, Some(digest));
        self.sync_state = SyncState::Idle;
        self.overlay = Overlay::Busy;
        self.overlay_until = Some(Instant::now() + ADOPT_OVERLAY);
        self.pending_status_after_overlay = left_status.map(str::to_owned);
        self.set_auto_notice_after_overlay("数据库自动同步成功");
        self.last_poll = Instant::now();
    }

    fn handle_recovery(&mut self, bytes: Option<Vec<u8>>) {
        let old_pass = self.cfg.sym_key.clone();
        let new_pass = self.pending_key_change.as_ref().map(|p| p.new_pass.clone());
        match evaluate_recovery(bytes.as_deref(), &old_pass, new_pass.as_deref()) {
            RecoveryAction::AdoptOld(db, key) => {
                let digest = digest_bytes(bytes.as_deref().unwrap_or_default());
                self.pending_key_change = None;
                self.adopt_server(db, key, digest, Some("同步完成"));
            }
            RecoveryAction::AdoptNew(db, key) => {
                let digest = digest_bytes(bytes.as_deref().unwrap_or_default());
                if let Some(pending) = self.pending_key_change.take() {
                    self.cfg.sym_key = pending.new_pass;
                    self.save_cfg();
                }
                self.adopt_server(db, key, digest, Some("同步完成"));
            }
            RecoveryAction::RepairLocal(note) => self.recover_by_repair(note),
            RecoveryAction::Fail => self.reset_to_wizard("数据库上传失败且恢复失败"),
        }
    }

    /// 恢复同步发现服务器库缺失或损坏：内存里已有库，用它覆盖修复。
    fn recover_by_repair(&mut self, note: &str) {
        if self.db.is_none() {
            self.reset_to_wizard("数据库上传失败且恢复失败");
            return;
        }
        self.pending_key_change = None;
        self.sync_state = SyncState::Idle;
        self.recovery_due = None;
        self.overlay_until = None;
        self.repair_note = Some(note.to_string());
        self.set_status(note);
        self.upload_current_db(UploadPurpose::Repair);
    }

    pub(crate) fn tick_sync(&mut self) {
        let now = Instant::now();
        if let Some(until) = self.overlay_until
            && now >= until
        {
            self.overlay_until = None;
            self.overlay = Overlay::None;
            if let Some(status) = self.pending_status_after_overlay.take() {
                self.set_status(status);
            }
            if self.auto_notice_pending {
                self.auto_flash = Some(now);
                self.auto_notice_pending = false;
            }
        }

        if self.sync_state == SyncState::Recovering {
            if let Some(due) = self.recovery_due
                && now >= due
            {
                self.recovery_due = None;
                if let Some(dav) = self.dav_url() {
                    self.worker.send(Command::Download {
                        epoch: self.worker.epoch(),
                        dav,
                        creds: self.creds(),
                        purpose: DownloadPurpose::Recovery,
                    });
                } else {
                    self.reset_to_wizard("数据库上传失败且恢复失败");
                }
            }
            return;
        }

        if self.page != Page::Main
            || self.overlay != Overlay::None
            || self.sync_state != SyncState::Idle
        {
            return;
        }
        if !self.focused {
            return;
        }
        if let Some(queued) = self.queued_upload.take() {
            self.begin_upload(queued.bytes, queued.purpose);
        } else if self.last_poll.elapsed() >= POLL_INTERVAL {
            self.start_poll();
        }
    }

    fn start_poll(&mut self) {
        let Some(dav) = self.dav_url() else {
            self.reset_to_wizard("自动同步失败");
            return;
        };
        self.sync_state = SyncState::Polling;
        self.poll_revision = self.local_revision;
        self.last_poll = Instant::now();
        self.worker.send(Command::Download {
            epoch: self.worker.epoch(),
            dav,
            creds: self.creds(),
            purpose: DownloadPurpose::Poll,
        });
    }

    fn reset_to_wizard(&mut self, reason: &str) {
        self.worker.cancel_all();
        self.reset_db_view();
        self.cfg.sym_key.clear();
        self.cfg.username = None;
        self.cfg.password = None;
        self.cfg.token = None;
        self.save_cfg();
        self.page = Page::Wizard;
        self.overlay = Overlay::None;
        self.overlay_until = None;
        self.pending_status_after_overlay = None;
        self.sync_state = SyncState::Idle;
        self.recovery_due = None;
        self.w_url = self.cfg.server_url.clone();
        self.w_key.clear();
        self.l_user.clear();
        self.l_pass.clear();
        self.url_buf = self.cfg.server_url.clone();
        self.port_buf = port_of(&self.cfg.server_url);
        self.key_buf.clear();
        self.last_poll = Instant::now();
        self.set_status(reason);
    }

    pub(crate) fn logout(&mut self) {
        self.reset_to_wizard("已退出登录");
    }

    fn reset_db_view(&mut self) {
        self.db = None;
        self.cipher = None;
        self.rows.clear();
        self.revealed.clear();
        self.edit = None;
        self.pending_delete = None;
        self.pending_key_change = None;
        self.queued_upload = None;
        self.in_flight_upload = None;
        self.key_buf.clear();
        self.last_server_digest = None;
        self.clear_auto_notice();
        self.local_revision = self.local_revision.wrapping_add(1);
    }

    pub(crate) fn apply_url(&mut self) {
        let url = self.url_buf.trim().to_string();
        if url == self.cfg.server_url {
            return;
        }
        if !valid_url(&url) {
            self.set_status("服务器地址不合法");
            return;
        }

        self.worker.cancel_all();
        self.cfg.server_url = url.clone();
        self.cfg.username = None;
        self.cfg.password = None;
        self.cfg.token = None;
        self.save_cfg();
        self.reset_db_view();
        self.overlay = Overlay::None;
        self.overlay_until = None;
        self.sync_state = SyncState::Idle;
        self.recovery_due = None;
        self.pending_status_after_overlay = None;
        self.page = Page::Login;
        self.l_user.clear();
        self.l_pass.clear();
        self.w_url = url.clone();
        self.w_key.clear();
        self.url_buf = url.clone();
        self.port_buf = port_of(&url);
        self.key_buf.clear();
        self.last_poll = Instant::now();
        self.clear_status();
        self.start_connect(false);
    }

    pub(crate) fn change_key(&mut self, new_pass: String) {
        if new_pass == self.cfg.sym_key {
            self.key_buf.clear();
            return;
        }
        if self.pending_key_change.is_some() {
            self.set_status("密钥修改正在同步");
            return;
        }
        if self.sync_state != SyncState::Idle {
            self.set_status("同步中，请稍后修改密钥");
            return;
        }
        let Some(old_key) = self.cipher else {
            return;
        };
        let old_bytes = match self.db.as_mut() {
            Some(db) => match db.export_bytes() {
                Ok(bytes) => bytes,
                Err(e) => {
                    self.set_status(format!("读取数据库失败: {e}"));
                    return;
                }
            },
            None => return,
        };
        let mut staged = match Db::from_bytes(&old_bytes) {
            Ok(db) => db,
            Err(e) => {
                self.set_status(format!("复制数据库失败: {e}"));
                return;
            }
        };
        let entries = match staged.entries() {
            Ok(entries) => entries,
            Err(e) => {
                self.set_status(format!("读取条目失败: {e}"));
                return;
            }
        };
        let salt = crypto::new_salt();
        let new_key = match crypto::derive_key(&new_pass, &salt) {
            Ok(key) => key,
            Err(e) => {
                self.set_status(e.to_string());
                return;
            }
        };
        for entry in &entries {
            let plain = match crypto::decrypt(&old_key, &entry.content) {
                Ok(plain) => plain,
                Err(e) => {
                    self.set_status(format!("旧数据解密失败，未修改密钥: {e}"));
                    return;
                }
            };
            let encrypted = match crypto::encrypt(&new_key, &plain) {
                Ok(encrypted) => encrypted,
                Err(e) => {
                    self.set_status(e.to_string());
                    return;
                }
            };
            if let Err(e) = staged.update_content(entry.id, &encrypted) {
                self.set_status(format!("写入数据库失败: {e}"));
                return;
            }
        }
        if let Err(e) = staged.set_meta("salt", &salt) {
            self.set_status(format!("写入数据库失败: {e}"));
            return;
        }
        let verifier = match crypto::encrypt(&new_key, VERIFY_TEXT) {
            Ok(verifier) => verifier,
            Err(e) => {
                self.set_status(e.to_string());
                return;
            }
        };
        if let Err(e) = staged.set_meta("verifier", verifier.as_bytes()) {
            self.set_status(format!("写入数据库失败: {e}"));
            return;
        }
        let bytes = match staged.export_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                self.set_status(format!("导出数据库失败: {e}"));
                return;
            }
        };

        self.local_revision = self.local_revision.wrapping_add(1);
        self.revealed.clear();
        self.edit = None;
        self.pending_delete = None;
        self.queued_upload = None;
        self.key_buf.clear();
        self.pending_key_change = Some(PendingKeyChange {
            new_pass,
            new_key,
            staged_db: staged,
        });
        self.start_upload(bytes, UploadPurpose::KeyChange);
    }

    pub(crate) fn expire_reveals(&mut self) {
        let now = Instant::now();
        self.revealed
            .retain(|_, r| r.paused_left.is_some() || r.expires > now);
    }

    pub(crate) fn reveal(&mut self, id: i64) {
        let (Some(key), Some(row)) = (self.cipher, self.rows.iter().find(|r| r.id == id)) else {
            return;
        };
        match crypto::decrypt(&key, &row.content) {
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
            Err(e) => self.set_status(e.to_string()),
        }
    }

    pub(crate) fn start_edit(&mut self, id: i64, field: Field) {
        self.cancel_edit();
        let buf = match field {
            Field::Desc => match self.rows.iter().find(|r| r.id == id) {
                Some(r) => r.desc.clone(),
                None => return,
            },
            Field::Content => match self.revealed.get_mut(&id) {
                Some(r) => {
                    r.paused_left = Some(r.expires.saturating_duration_since(Instant::now()));
                    r.plain.clone()
                }
                None => return,
            },
        };
        self.edit = Some(Edit { id, field, buf });
    }

    pub(crate) fn cancel_edit(&mut self) {
        if let Some(ed) = self.edit.take()
            && ed.field == Field::Content
            && let Some(r) = self.revealed.get_mut(&ed.id)
            && let Some(left) = r.paused_left.take()
        {
            r.expires = Instant::now() + left;
        }
    }

    pub(crate) fn commit_edit(&mut self) {
        let Some(ed) = self.edit.take() else {
            return;
        };
        let Some(db) = &self.db else { return };
        match ed.field {
            Field::Desc => {
                if let Err(e) = db.update_desc(ed.id, &ed.buf) {
                    self.set_status(format!("保存失败: {e}"));
                    return;
                }
            }
            Field::Content => {
                let Some(key) = self.cipher else { return };
                let enc = match crypto::encrypt(&key, &ed.buf) {
                    Ok(e) => e,
                    Err(e) => {
                        self.set_status(e.to_string());
                        return;
                    }
                };
                if let Err(e) = db.update_content(ed.id, &enc) {
                    self.set_status(format!("保存失败: {e}"));
                    return;
                }
                self.revealed.insert(
                    ed.id,
                    Revealed {
                        plain: ed.buf,
                        expires: Instant::now() + REVEAL_TTL,
                        paused_left: None,
                    },
                );
            }
        }
        self.local_revision = self.local_revision.wrapping_add(1);
        self.reload_rows();
        self.upload_current_db(UploadPurpose::Edit);
    }

    pub(crate) fn add_row(&mut self) {
        let Some(key) = self.cipher else { return };
        let Some(db) = &self.db else { return };
        let id = match crypto::encrypt(&key, "").and_then(|enc| db.insert("", &enc)) {
            Ok(id) => id,
            Err(e) => {
                self.set_status(format!("新增失败: {e}"));
                return;
            }
        };
        self.local_revision = self.local_revision.wrapping_add(1);
        self.reload_rows();
        self.start_edit(id, Field::Desc);
        self.upload_current_db(UploadPurpose::Edit);
    }

    pub(crate) fn delete_row(&mut self, id: i64) {
        let Some(db) = &self.db else { return };
        if let Err(e) = db.delete(id) {
            self.set_status(format!("删除失败: {e}"));
            return;
        }
        self.revealed.remove(&id);
        if self.edit.as_ref().is_some_and(|ed| ed.id == id) {
            self.edit = None;
        }
        self.local_revision = self.local_revision.wrapping_add(1);
        self.reload_rows();
        self.upload_current_db(UploadPurpose::Edit);
    }

    pub(crate) fn wizard_confirm(&mut self) {
        let url = self.w_url.trim().to_string();
        if !valid_url(&url) {
            self.set_status("服务器地址不合法");
            return;
        }
        if self.w_key.is_empty() {
            self.set_status("加密密钥不能为空");
            return;
        }
        let changed = url != self.cfg.server_url;
        self.cfg.server_url = url.clone();
        self.cfg.sym_key = std::mem::take(&mut self.w_key);
        if changed {
            self.cfg.username = None;
            self.cfg.password = None;
            self.cfg.token = None;
        }
        self.worker.cancel_all();
        self.reset_db_view();
        self.save_cfg();
        self.url_buf = url.clone();
        self.port_buf = port_of(&url);
        self.start_connect(true);
    }
}

#[cfg(test)]
impl App {
    pub(crate) fn test_vault() -> Self {
        let mut app = Self::from_config(Config::default());
        app.cfg.sym_key = "synthetic-test-key".into();
        let (db, key, _) = open_db(None, &app.cfg.sym_key).unwrap();
        db.insert(
            "测试条目",
            &crypto::encrypt(&key, "synthetic secret").unwrap(),
        )
        .unwrap();
        app.install_db(db, key, None);
        app
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_and_content_sensitive() {
        let a = digest_bytes(b"hello");
        assert_eq!(a, digest_bytes(b"hello"));
        assert_ne!(a, digest_bytes(b"hello!"));
    }

    #[test]
    fn new_db_roundtrip_and_wrong_key() {
        let (mut db, key, created) = open_db(None, "correct horse").expect("new db");
        assert!(created);
        assert_eq!(key.len(), 32);
        db.set_meta("note", b"value").unwrap();
        let bytes = db.export_bytes().unwrap();

        let (db2, key2, created2) = open_db(Some(bytes.clone()), "correct horse").expect("open");
        assert!(!created2);
        assert_eq!(key, key2);
        assert_eq!(db2.meta("note").unwrap().unwrap(), b"value");

        match open_db(Some(bytes), "wrong key") {
            Err(DbOpenError::WrongKey) => {}
            _ => panic!("expected WrongKey"),
        }
    }

    #[test]
    fn corrupt_db_is_corrupt_not_wrong_key() {
        match open_db(Some(b"this is not sqlite".to_vec()), "any") {
            Err(DbOpenError::Corrupt(_)) => {}
            _ => panic!("expected Corrupt"),
        }
    }

    #[test]
    fn poll_model_matches_digest_and_recovery_rules() {
        let (mut db, _key, _) = open_db(None, "pass").unwrap();
        let bytes = db.export_bytes().unwrap();
        let digest = digest_bytes(&bytes);

        assert!(matches!(
            evaluate_poll(false, Some(bytes.clone()), Some(digest), "pass"),
            PollAction::Same
        ));
        assert!(matches!(
            evaluate_poll(false, Some(bytes.clone()), None, "pass"),
            PollAction::Adopt(..)
        ));
        assert!(matches!(
            evaluate_poll(true, Some(bytes.clone()), Some(digest), "pass"),
            PollAction::LocalWins
        ));
        assert!(matches!(
            evaluate_poll(false, None, Some(digest), "pass"),
            PollAction::RepairLocal(REPAIR_MISSING)
        ));
        assert!(matches!(
            evaluate_poll(false, Some(b"broken".to_vec()), None, "pass"),
            PollAction::RepairLocal(REPAIR_CORRUPT)
        ));
        assert!(matches!(
            evaluate_poll(false, Some(bytes), None, "wrong"),
            PollAction::WrongKey
        ));
    }

    #[test]
    fn recovery_model_repairs_local_instead_of_creating_empty_db() {
        // 服务器库缺失：用内存库修复，而不是新建空库
        assert!(matches!(
            evaluate_recovery(None, "old", None),
            RecoveryAction::RepairLocal(REPAIR_MISSING)
        ));

        // 服务器库损坏：同样用内存库修复
        assert!(matches!(
            evaluate_recovery(Some(b"garbage bytes"), "old", None),
            RecoveryAction::RepairLocal(REPAIR_CORRUPT)
        ));

        // 服务器仍是旧密钥的库：采用服务器版本
        let (mut db, _, _) = open_db(None, "old").unwrap();
        let old_bytes = db.export_bytes().unwrap();
        assert!(matches!(
            evaluate_recovery(Some(&old_bytes), "old", Some("new")),
            RecoveryAction::AdoptOld(..)
        ));

        // MOVE 已成功但响应丢失：服务器库已用新密钥，用新密钥打开并提交
        let (mut db2, _, _) = open_db(None, "new").unwrap();
        let new_bytes = db2.export_bytes().unwrap();
        assert!(matches!(
            evaluate_recovery(Some(&new_bytes), "old", Some("new")),
            RecoveryAction::AdoptNew(..)
        ));

        // 两把密钥都打不开且不是损坏：真失败
        assert!(matches!(
            evaluate_recovery(Some(&old_bytes), "another", None),
            RecoveryAction::Fail
        ));
    }
}
