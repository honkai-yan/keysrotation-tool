//! One blocking API worker. Epoch changes discard queued work and stale results.
use crate::{
    api::{self, PreparedBatch, Scope, Snapshot},
    crypto::Key,
};
use keyrotation_protocol::*;
use keyrotation_transport::{Client, TransportError};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use zeroize::Zeroizing;

pub enum Task {
    Rpc(RpcRequest),
    Snapshot(Option<String>),
    RotationRead {
        request: RpcRequest,
        old: Zeroizing<Key>,
        new: Zeroizing<Key>,
    },
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Info,
    Validate,
    Login,
    Snapshot,
    Poll,
    Content(i64),
    Mutation,
    Resolve,
    RotationRead,
    Logout,
}
pub enum Output {
    Body(Box<ResponseBody>),
    Snapshot(Snapshot),
    Prepared(PreparedBatch),
}
pub struct Command {
    pub epoch: u64,
    pub scope: Scope,
    pub purpose: Purpose,
    pub task: Task,
}
pub struct Event {
    pub epoch: u64,
    pub purpose: Purpose,
    pub result: api::Result<Output>,
}
pub struct SyncWorker {
    tx: mpsc::Sender<Command>,
    rx: mpsc::Receiver<Event>,
    epoch: Arc<AtomicU64>,
}

impl SyncWorker {
    pub fn new() -> Self {
        let (tx, commands) = mpsc::channel::<Command>();
        let (events, rx) = mpsc::channel();
        let epoch = Arc::new(AtomicU64::new(0));
        let current = epoch.clone();
        std::thread::spawn(move || {
            let mut connection: Option<(Scope, Client)> = None;
            while let Ok(command) = commands.recv() {
                if command.epoch != current.load(Ordering::SeqCst) {
                    continue;
                }
                let result = (|| {
                    if connection
                        .as_ref()
                        .is_none_or(|(scope, _)| *scope != command.scope)
                    {
                        connection = Some((command.scope.clone(), command.scope.client()?));
                    }
                    let client = &mut connection.as_mut().ok_or(TransportError::Network)?.1;
                    match command.task {
                        Task::Rpc(request) => client
                            .call(&request)
                            .map(|body| Output::Body(Box::new(body))),
                        Task::Snapshot(token) => api::snapshot(client, token).map(Output::Snapshot),
                        Task::RotationRead { request, old, new } => {
                            api::prepare_rotation_batch(client, &request, &old, &new)
                                .map(Output::Prepared)
                        }
                    }
                })();
                if events
                    .send(Event {
                        epoch: command.epoch,
                        purpose: command.purpose,
                        result,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self { tx, rx, epoch }
    }
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }
    pub fn cancel_all(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }
    pub fn send(&self, command: Command) {
        let _ = self.tx.send(command);
    }
    pub fn try_recv(&self) -> Option<Event> {
        self.rx.try_recv().ok()
    }
}
