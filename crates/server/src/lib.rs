mod dispatch;
pub mod http;
pub mod store;
pub mod worker;
pub use dispatch::now;
pub mod identity;

pub fn dispatcher(worker: worker::DbWorker) -> http::Dispatch {
    std::sync::Arc::new(move |request| {
        let id = request.request_id.clone();
        match worker.call(move |repository| Ok(repository.dispatch(&request, now()))) {
            Ok(response) => response,
            Err(error) => keyrotation_protocol::RpcResponse::new(id, Err(error)),
        }
    })
}
