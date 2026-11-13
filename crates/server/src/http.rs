//! Listener mode is selected at construction, never from forwarded headers.
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use keyrotation_protocol::{MAX_RPC_BYTES, RpcRequest, RpcResponse, random_id, valid_id};
use keyrotation_transport::{
    CHANNEL_HEADER, CHANNEL_IDLE, CHANNEL_MAX, Endpoint, Identity, MAX_NOISE_BYTES, accept,
    decrypt, encrypt,
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

pub type Dispatch = Arc<dyn Fn(RpcRequest) -> RpcResponse + Send + Sync>;

struct Channel {
    noise: snow_state::State,
    created: Instant,
    touched: Instant,
    _slot: OwnedSemaphorePermit,
}
// TransportState stays an implementation detail of the transport crate's API.
mod snow_state {
    pub type State = keyrotation_transport::NoiseState;
}
impl Channel {
    fn alive(&self) -> bool {
        self.alive_at(Instant::now())
    }
    fn alive_at(&self, now: Instant) -> bool {
        now.duration_since(self.created) < CHANNEL_MAX
            && now.duration_since(self.touched) < CHANNEL_IDLE
    }
}

struct Service {
    endpoint: Endpoint,
    identity: Option<Arc<Identity>>,
    dispatch: Dispatch,
    channels: Mutex<HashMap<String, Channel>>,
    slots: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
    requests: Semaphore,
}

/// For HTTPS, this router must be served by a TLS listener. The CLI never binds
/// its JSON mode to an unencrypted socket. HTTP mode has no plaintext RPC route.
pub fn router(
    endpoint: Endpoint,
    identity: Option<Arc<Identity>>,
    dispatch: Dispatch,
) -> Result<Router, &'static str> {
    if endpoint.is_http() != identity.is_some() {
        return Err("listener mode and identity disagree");
    }
    let is_http = endpoint.is_http();
    let base_path = endpoint.base_path().trim_end_matches('/').to_string();
    let state = Arc::new(Service {
        endpoint,
        identity,
        dispatch,
        channels: Mutex::new(HashMap::new()),
        slots: Arc::new(Semaphore::new(128)),
        handshakes: Arc::new(Semaphore::new(16)),
        requests: Semaphore::new(64),
    });
    let routes = if is_http {
        Router::new()
            .route("/api/v1/channel/handshake", post(handshake))
            .route("/api/v1/channel/message", post(message))
    } else {
        Router::new().route("/api/v1/rpc", post(rpc))
    }
    .with_state(state.clone())
    .layer(axum::middleware::from_fn_with_state(state, limit_request))
    .layer(DefaultBodyLimit::max(MAX_NOISE_BYTES));
    Ok(if base_path.is_empty() {
        routes
    } else {
        Router::new().nest(&base_path, routes)
    })
}

async fn limit_request(
    State(service): State<Arc<Service>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let Ok(_permit) = service.requests.try_acquire() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            b"busy".to_vec(),
        );
    };
    tokio::time::timeout(Duration::from_secs(30), next.run(request))
        .await
        .unwrap_or_else(|_| failed())
}

fn response(status: StatusCode, kind: &str, body: Vec<u8>) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, kind),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}
fn failed() -> Response {
    response(
        StatusCode::BAD_REQUEST,
        "text/plain",
        b"channel failed".to_vec(),
    )
}
fn media(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next().unwrap_or("").trim() == expected)
}

async fn handshake(
    State(service): State<Arc<Service>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !media(&headers, "application/octet-stream") || body.len() > 1024 {
        return failed();
    }
    let Ok(_handshake) = service.handshakes.clone().try_acquire_owned() else {
        return failed();
    };
    service
        .channels
        .lock()
        .await
        .retain(|_, channel| channel.alive());
    let Ok(slot) = service.slots.clone().try_acquire_owned() else {
        return failed();
    };
    let Some(identity) = service.identity.clone() else {
        return failed();
    };
    let endpoint = service.endpoint.clone();
    let Ok(Ok((state, reply))) =
        tokio::task::spawn_blocking(move || accept(&endpoint, &identity, &body)).await
    else {
        return failed();
    };
    let id = random_id();
    service.channels.lock().await.insert(
        id.clone(),
        Channel {
            noise: state,
            created: Instant::now(),
            touched: Instant::now(),
            _slot: slot,
        },
    );
    let mut result = response(StatusCode::OK, "application/octet-stream", reply);
    if let Ok(id) = id.parse() {
        result.headers_mut().insert(CHANNEL_HEADER, id);
    }
    result
}

async fn message(State(service): State<Arc<Service>>, headers: HeaderMap, body: Bytes) -> Response {
    if !media(&headers, "application/octet-stream") || body.len() > MAX_RPC_BYTES + 16 {
        return failed();
    }
    let Some(id) = headers
        .get(CHANNEL_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_id(v))
        .map(str::to_owned)
    else {
        return failed();
    };
    // Removing the channel grants exclusive ownership. A second simultaneous
    // request cannot queue on or reuse the same directional counter state.
    let Some(mut channel) = service.channels.lock().await.remove(&id) else {
        return failed();
    };
    if !channel.alive() {
        return failed();
    }
    let dispatch = service.dispatch.clone();
    let result = tokio::task::spawn_blocking(move || {
        let payload = decrypt(&mut channel.noise, &body).ok()?;
        let request = RpcRequest::decode(&payload).ok()?;
        let result = dispatch(request);
        let bytes = result.encode().ok()?;
        let reply = encrypt(&mut channel.noise, &bytes).ok()?;
        channel.touched = Instant::now();
        Some((channel, reply))
    })
    .await;
    let Ok(Some((channel, reply))) = result else {
        return failed();
    };
    if channel.alive() {
        service.channels.lock().await.insert(id, channel);
    }
    response(StatusCode::OK, "application/octet-stream", reply)
}

async fn rpc(State(service): State<Arc<Service>>, headers: HeaderMap, body: Bytes) -> Response {
    if !media(&headers, "application/json") || body.len() > MAX_RPC_BYTES {
        return failed();
    }
    let Ok(request) = RpcRequest::decode(&body) else {
        return failed();
    };
    let dispatch = service.dispatch.clone();
    let Ok(result) = tokio::task::spawn_blocking(move || dispatch(request)).await else {
        return failed();
    };
    match result.encode() {
        Ok(bytes) => response(StatusCode::OK, "application/json", bytes),
        Err(_) => failed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use keyrotation_protocol::{Command, ResponseBody, ServerInfo};
    use tower::ServiceExt;
    fn dispatch() -> Dispatch {
        Arc::new(|request| {
            RpcResponse::new(
                request.request_id.clone(),
                Ok(ResponseBody::ServerInfo(ServerInfo {
                    server_id: random_id(),
                    generation: random_id(),
                    initialized: false,
                    server_time: 1,
                })),
            )
        })
    }
    #[test]
    fn channel_idle_and_absolute_lifetime_boundaries_expire_without_nonce_reuse() {
        let endpoint = Endpoint::parse("http://localhost/").unwrap();
        let identity = Identity::generate().unwrap();
        let (_, message) =
            keyrotation_transport::initiate(&endpoint, identity.public_bytes()).unwrap();
        let (noise, _) = accept(&endpoint, &identity, &message).unwrap();
        let now = Instant::now();
        let mut channel = Channel {
            noise,
            created: now,
            touched: now,
            _slot: Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
        };
        assert!(channel.alive_at(now + CHANNEL_IDLE - Duration::from_nanos(1)));
        assert!(!channel.alive_at(now + CHANNEL_IDLE));
        channel.touched = now + CHANNEL_MAX - Duration::from_secs(1);
        assert!(!channel.alive_at(now + CHANNEL_MAX));
    }
    #[tokio::test]
    async fn http_listener_rejects_plaintext_even_with_forged_proxy_headers() {
        let endpoint = Endpoint::parse("http://localhost/keys/").unwrap();
        let app = router(
            endpoint,
            Some(Arc::new(Identity::generate().unwrap())),
            dispatch(),
        )
        .unwrap();
        let request = RpcRequest::new(Command::ServerInfo, None).encode().unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/keys/api/v1/rpc")
                    .header("x-forwarded-proto", "https")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    #[tokio::test]
    async fn new_server_has_no_old_channels_and_https_has_no_noise_routes() {
        let endpoint = Endpoint::parse("http://localhost/").unwrap();
        let app = router(
            endpoint,
            Some(Arc::new(Identity::generate().unwrap())),
            dispatch(),
        )
        .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/channel/message")
                    .header("content-type", "application/octet-stream")
                    .header(CHANNEL_HEADER, random_id())
                    .body(axum::body::Body::from(vec![0; 32]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let app = router(
            Endpoint::parse("https://localhost/").unwrap(),
            None,
            dispatch(),
        )
        .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/channel/handshake")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
