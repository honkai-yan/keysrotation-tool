//! Every database request runs on one dedicated thread, with bounded backpressure.
use crate::store::Repository;
use keyrotation_protocol::{ApiError, ApiResult, ErrorCode};
use std::{
    path::Path,
    sync::{Arc, mpsc},
    thread,
};

type Job = Box<dyn FnOnce(&mut Repository) + Send>;
struct Inner {
    sender: Option<mpsc::SyncSender<Job>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Clone)]
pub struct DbWorker(Arc<Inner>);

impl DbWorker {
    pub fn open(directory: &Path) -> ApiResult<Self> {
        let mut repository = Repository::open(directory)?;
        let (sender, receiver) = mpsc::sync_channel::<Job>(64);
        let thread = thread::Builder::new()
            .name("keyrotation-db".into())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    job(&mut repository);
                }
            })
            .map_err(|_| unavailable())?;
        Ok(Self(Arc::new(Inner {
            sender: Some(sender),
            thread: Some(thread),
        })))
    }

    pub fn call<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut Repository) -> ApiResult<T> + Send + 'static,
    ) -> ApiResult<T> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.0
            .sender
            .as_ref()
            .ok_or_else(unavailable)?
            .try_send(Box::new(move |repository| {
                let result = repository.check_health().and_then(|()| work(repository));
                let _ = sender.send(result);
            }))
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    ApiError::new(ErrorCode::Busy, "database queue is full")
                }
                mpsc::TrySendError::Disconnected(_) => unavailable(),
            })?;
        receiver.recv().map_err(|_| unavailable())?
    }
}

fn unavailable() -> ApiError {
    ApiError::new(ErrorCode::VaultUnavailable, "database worker unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_callers_all_execute_on_one_database_thread() {
        let directory = tempfile::tempdir().unwrap();
        Repository::create(directory.path(), "admin", "synthetic-login").unwrap();
        let worker = DbWorker::open(directory.path()).unwrap();
        let callers: Vec<_> = (0..8)
            .map(|_| {
                let worker = worker.clone();
                std::thread::spawn(move || {
                    worker.call(|_| Ok(std::thread::current().id())).unwrap()
                })
            })
            .collect();
        let ids: Vec<_> = callers
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(ids.iter().all(|id| *id == ids[0]));
        assert_ne!(ids[0], std::thread::current().id());
        drop(worker);
        assert!(Repository::open(directory.path()).is_ok());
    }
}
