use crate::webdav;
use eframe::egui;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use url::Url;

#[derive(Debug)]
pub enum ConnectOutcome {
    NeedLogin,
    Loaded(Option<Vec<u8>>),
}

#[derive(Debug)]
pub enum ConnectFailure {
    AuthProbe,
    Download,
}

#[derive(Debug)]
pub struct LoginOutcome {
    pub user: String,
    pub pass: String,
    pub token: String,
    pub bytes: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum LoginFailure {
    Login(String),
    Download,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadPurpose {
    Poll,
    Recovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadPurpose {
    Edit,
    Repair,
    KeyChange,
}

pub enum Command {
    Connect {
        epoch: u64,
        dav: Url,
        token: Option<String>,
        creds: Option<(String, String)>,
    },
    Login {
        epoch: u64,
        dav: Url,
        user: String,
        pass: String,
    },
    Download {
        epoch: u64,
        dav: Url,
        creds: Option<(String, String)>,
        purpose: DownloadPurpose,
    },
    Upload {
        epoch: u64,
        dav: Url,
        creds: Option<(String, String)>,
        bytes: Vec<u8>,
        purpose: UploadPurpose,
    },
}

impl Command {
    fn epoch(&self) -> u64 {
        match self {
            Command::Connect { epoch, .. }
            | Command::Login { epoch, .. }
            | Command::Download { epoch, .. }
            | Command::Upload { epoch, .. } => *epoch,
        }
    }
}

pub enum Event {
    Connect {
        epoch: u64,
        result: Result<ConnectOutcome, ConnectFailure>,
    },
    Login {
        epoch: u64,
        result: Result<LoginOutcome, LoginFailure>,
    },
    Download {
        epoch: u64,
        result: Result<Option<Vec<u8>>, String>,
        purpose: DownloadPurpose,
    },
    Upload {
        epoch: u64,
        result: Result<(), String>,
        purpose: UploadPurpose,
    },
}

pub struct SyncWorker {
    tx: Sender<Command>,
    rx: Receiver<Event>,
    epoch: Arc<AtomicU64>,
}

impl SyncWorker {
    pub fn new(ctx: egui::Context) -> Self {
        let (tx, cmd_rx) = mpsc::channel::<Command>();
        let (event_tx, rx) = mpsc::channel::<Event>();
        let epoch = Arc::new(AtomicU64::new(0));
        let worker_epoch = epoch.clone();

        thread::spawn(move || {
            while let Ok(cmd) = cmd_rx.recv() {
                if cmd.epoch() != worker_epoch.load(Ordering::SeqCst) {
                    continue;
                }
                let event = execute(cmd);
                if event_tx.send(event).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });

        Self { tx, rx, epoch }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// 丢弃尚未开始的任务；已发出的 blocking 请求会自然结束，但结果 epoch 已过期。
    pub fn cancel_all(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

    pub fn send(&self, cmd: Command) {
        let _ = self.tx.send(cmd);
    }

    pub fn try_recv(&self) -> Option<Event> {
        self.rx.try_recv().ok()
    }
}

fn execute(cmd: Command) -> Event {
    match cmd {
        Command::Connect {
            epoch,
            dav,
            token,
            creds,
        } => Event::Connect {
            epoch,
            result: connect_flow(&dav, token.as_deref(), creds.as_ref()),
        },
        Command::Login {
            epoch,
            dav,
            user,
            pass,
        } => Event::Login {
            epoch,
            result: login_flow(&dav, user, pass),
        },
        Command::Download {
            epoch,
            dav,
            creds,
            purpose,
        } => Event::Download {
            epoch,
            result: webdav::download(&dav, creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())))
                .map_err(|e| e.to_string()),
            purpose,
        },
        Command::Upload {
            epoch,
            dav,
            creds,
            bytes,
            purpose,
        } => Event::Upload {
            epoch,
            result: webdav::upload_atomic(
                &dav,
                creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
                bytes,
            )
            .map_err(|e| e.to_string()),
            purpose,
        },
    }
}

fn connect_flow(
    dav: &Url,
    token: Option<&str>,
    creds: Option<&(String, String)>,
) -> Result<ConnectOutcome, ConnectFailure> {
    let needs_login = webdav::auth_required(dav).map_err(|_| ConnectFailure::AuthProbe)?;
    if needs_login {
        let token_ok = match token {
            Some(t) => webdav::token_valid(dav, t).map_err(|_| ConnectFailure::AuthProbe)?,
            None => false,
        };
        if !token_ok || creds.is_none() {
            return Ok(ConnectOutcome::NeedLogin);
        }
    }
    let creds = creds.map(|(u, p)| (u.as_str(), p.as_str()));
    let bytes = webdav::download(dav, creds).map_err(|_| ConnectFailure::Download)?;
    Ok(ConnectOutcome::Loaded(bytes))
}

fn login_flow(dav: &Url, user: String, pass: String) -> Result<LoginOutcome, LoginFailure> {
    let token = webdav::login(dav, &user, &pass).map_err(|e| LoginFailure::Login(e.to_string()))?;
    let bytes = webdav::download(dav, Some((&user, &pass))).map_err(|_| LoginFailure::Download)?;
    Ok(LoginOutcome {
        user,
        pass,
        token,
        bytes,
    })
}
