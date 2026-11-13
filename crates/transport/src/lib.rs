//! Fixed Noise NK profile, and a sequential blocking HTTP/HTTPS client.
use base64::{Engine, engine::general_purpose::STANDARD};
#[cfg(feature = "client")]
use keyrotation_protocol::valid_id;
use keyrotation_protocol::{
    ApiError, MAX_RPC_BYTES, ResponseBody, RpcRequest, RpcResponse, VERSION,
};
use snow::{HandshakeState, TransportState};
use url::Url;
use zeroize::Zeroizing;

pub const PROFILE: &str = "Noise_NK_25519_ChaChaPoly_SHA256";
pub const MAX_NOISE_BYTES: usize = 65_535;
// Shared channel limits; clients renew before these server-enforced deadlines.
pub const CHANNEL_IDLE: std::time::Duration = std::time::Duration::from_secs(300);
pub const CHANNEL_MAX: std::time::Duration = std::time::Duration::from_secs(3600);
pub const CHANNEL_HEADER: &str = "x-keyrotation-channel";
pub type NoiseState = TransportState;

#[derive(Debug)]
pub enum TransportError {
    InvalidEndpoint,
    MissingPublicKey,
    InvalidPublicKey,
    Channel,
    Network,
    Http(u16),
    InvalidResponse,
    Remote(ApiError),
}
impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Remote(error) => write!(f, "{error}"),
            Self::Http(status) => write!(f, "HTTP {status}"),
            other => write!(f, "{other:?}"),
        }
    }
}
impl std::error::Error for TransportError {}
impl From<snow::Error> for TransportError {
    fn from(_: snow::Error) -> Self {
        Self::Channel
    }
}
pub type Result<T> = std::result::Result<T, TransportError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint(Url);
impl Endpoint {
    pub fn parse(value: &str) -> Result<Self> {
        let mut url = Url::parse(value).map_err(|_| TransportError::InvalidEndpoint)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.has_host()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(TransportError::InvalidEndpoint);
        }
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }
        Ok(Self(url))
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    pub fn is_http(&self) -> bool {
        self.0.scheme() == "http"
    }
    pub fn base_path(&self) -> &str {
        self.0.path()
    }
    pub fn join(&self, path: &str) -> Result<Url> {
        self.0
            .join(path)
            .map_err(|_| TransportError::InvalidEndpoint)
    }
    pub fn prologue(&self) -> Vec<u8> {
        format!("rust-keyrotation\nv1\nhttp-noise\n{}", self.as_str()).into_bytes()
    }
}

pub struct Identity {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}
impl Identity {
    pub fn generate() -> Result<Self> {
        let pair = snow::Builder::new(PROFILE.parse()?).generate_keypair()?;
        let private: [u8; 32] = pair
            .private
            .as_slice()
            .try_into()
            .map_err(|_| TransportError::Channel)?;
        Ok(Self::from_private(private))
    }
    pub fn from_private(private: [u8; 32]) -> Self {
        let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
        Self {
            private: Zeroizing::new(private),
            public,
        }
    }
    pub fn private_bytes(&self) -> &[u8; 32] {
        &self.private
    }
    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }
    pub fn public_base64(&self) -> String {
        STANDARD.encode(self.public)
    }
}

pub fn public_key(value: &str) -> Result<[u8; 32]> {
    let value = value.trim();
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| TransportError::InvalidPublicKey)?;
    if STANDARD.encode(&bytes) != value {
        return Err(TransportError::InvalidPublicKey);
    }
    bytes
        .try_into()
        .map_err(|_| TransportError::InvalidPublicKey)
}

pub fn initiate(endpoint: &Endpoint, public: &[u8; 32]) -> Result<(HandshakeState, Vec<u8>)> {
    if !endpoint.is_http() {
        return Err(TransportError::InvalidEndpoint);
    }
    let mut state = snow::Builder::new(PROFILE.parse()?)
        .remote_public_key(public)?
        .prologue(&endpoint.prologue())?
        .build_initiator()?;
    let mut message = vec![0; 1024];
    let len = state.write_message(&[], &mut message)?;
    message.truncate(len);
    Ok((state, message))
}

pub fn accept(
    endpoint: &Endpoint,
    identity: &Identity,
    message: &[u8],
) -> Result<(TransportState, Vec<u8>)> {
    if !endpoint.is_http() || message.len() > 1024 {
        return Err(TransportError::Channel);
    }
    let mut state = snow::Builder::new(PROFILE.parse()?)
        .local_private_key(identity.private_bytes())?
        .prologue(&endpoint.prologue())?
        .build_responder()?;
    let mut buffer = vec![0; 1024];
    if state.read_message(message, &mut buffer)? != 0 {
        return Err(TransportError::Channel);
    }
    let len = state.write_message(&[], &mut buffer)?;
    buffer.truncate(len);
    Ok((state.into_transport_mode()?, buffer))
}

pub fn finish(mut state: HandshakeState, message: &[u8]) -> Result<TransportState> {
    if message.len() > 1024 {
        return Err(TransportError::Channel);
    }
    let mut buffer = vec![0; 1024];
    if state.read_message(message, &mut buffer)? != 0 {
        return Err(TransportError::Channel);
    }
    Ok(state.into_transport_mode()?)
}

pub fn encrypt(state: &mut TransportState, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_RPC_BYTES {
        return Err(TransportError::Channel);
    }
    let mut output = vec![0; payload.len() + 16];
    let size = state.write_message(payload, &mut output)?;
    output.truncate(size);
    Ok(output)
}

pub fn decrypt(state: &mut TransportState, message: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if message.len() > MAX_RPC_BYTES + 16 {
        return Err(TransportError::Channel);
    }
    let mut payload = Zeroizing::new(vec![0; message.len()]);
    let size = state.read_message(message, &mut payload)?;
    payload.truncate(size);
    Ok(payload)
}

pub fn decode_response(request: &RpcRequest, bytes: &[u8]) -> Result<ResponseBody> {
    if bytes.len() > MAX_RPC_BYTES {
        return Err(TransportError::InvalidResponse);
    }
    let response: RpcResponse =
        serde_json::from_slice(bytes).map_err(|_| TransportError::InvalidResponse)?;
    if response.protocol_version != VERSION || response.request_id != request.request_id {
        return Err(TransportError::InvalidResponse);
    }
    response
        .outcome
        .into_result()
        .map_err(TransportError::Remote)
}

#[cfg(feature = "client")]
pub struct Client {
    endpoint: Endpoint,
    public: Option<[u8; 32]>,
    http: reqwest::blocking::Client,
    channel: Option<ClientChannel>,
}

#[cfg(feature = "client")]
struct ClientChannel {
    id: String,
    state: TransportState,
    created: std::time::Instant,
    touched: std::time::Instant,
}

#[cfg(feature = "client")]
impl ClientChannel {
    fn needs_renewal(&self) -> bool {
        // Account for request transit time and slightly different clock samples.
        let margin = std::time::Duration::from_secs(30);
        self.created.elapsed() >= CHANNEL_MAX - margin
            || self.touched.elapsed() >= CHANNEL_IDLE - margin
    }
}

#[cfg(feature = "client")]
impl Client {
    pub fn new(
        endpoint: Endpoint,
        public: Option<&str>,
        trusted_ca_pem: Option<&str>,
    ) -> Result<Self> {
        let public = if endpoint.is_http() {
            Some(public_key(public.ok_or(TransportError::MissingPublicKey)?)?)
        } else {
            None
        };
        let mut builder = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30));
        if let Some(ca) = trusted_ca_pem {
            let certificates = reqwest::Certificate::from_pem_bundle(ca.as_bytes())
                .map_err(|_| TransportError::InvalidPublicKey)?;
            if certificates.is_empty() {
                return Err(TransportError::InvalidPublicKey);
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let http = builder.build().map_err(|_| TransportError::Network)?;
        Ok(Self {
            endpoint,
            public,
            http,
            channel: None,
        })
    }

    pub fn reset_channel(&mut self) {
        self.channel = None;
    }

    pub fn call(&mut self, request: &RpcRequest) -> Result<ResponseBody> {
        request.validate().map_err(TransportError::Remote)?;
        let result = self.exchange(request);
        // Only repeat reads, never login/logout or a possibly committed mutation.
        // A failed handshake has no channel and is not retried here.
        let retry_read = self.endpoint.is_http()
            && self.channel.is_some()
            && matches!(
                request.command,
                keyrotation_protocol::Command::ServerInfo
                    | keyrotation_protocol::Command::AuthValidate
                    | keyrotation_protocol::Command::VaultMeta
                    | keyrotation_protocol::Command::EntriesList { .. }
                    | keyrotation_protocol::Command::EntriesReadContent { .. }
                    | keyrotation_protocol::Command::OperationsGet { .. }
                    | keyrotation_protocol::Command::RotationReadBatch { .. }
                    | keyrotation_protocol::Command::RotationStatus { .. }
            )
            && matches!(
                &result,
                Err(TransportError::Http(400)
                    | TransportError::Channel
                    | TransportError::Network
                    | TransportError::InvalidResponse)
            );
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, TransportError::Remote(_)))
        {
            self.reset_channel();
        }
        if retry_read {
            let retry = RpcRequest::new(request.command.clone(), request.session_token.clone());
            let result = self.exchange(&retry);
            if result
                .as_ref()
                .is_err_and(|error| !matches!(error, TransportError::Remote(_)))
            {
                self.reset_channel();
            }
            return result;
        }
        result
    }

    fn exchange(&mut self, request: &RpcRequest) -> Result<ResponseBody> {
        let bytes = Zeroizing::new(request.encode().map_err(TransportError::Remote)?);
        if !self.endpoint.is_http() {
            let response = self
                .http
                .post(self.endpoint.join("api/v1/rpc")?)
                .header("content-type", "application/json")
                .body(bytes.to_vec())
                .send()
                .map_err(|_| TransportError::Network)?;
            return decode_response(request, &read_response(response, MAX_RPC_BYTES)?);
        }
        if self
            .channel
            .as_ref()
            .is_some_and(ClientChannel::needs_renewal)
        {
            self.reset_channel();
        }
        if self.channel.is_none() {
            let created = std::time::Instant::now();
            let (state, message) = initiate(
                &self.endpoint,
                &self.public.ok_or(TransportError::MissingPublicKey)?,
            )?;
            let response = self
                .http
                .post(self.endpoint.join("api/v1/channel/handshake")?)
                .header("content-type", "application/octet-stream")
                .body(message)
                .send()
                .map_err(|_| TransportError::Network)?;
            // A rejected handshake has no channel header; keep its status first
            // so it is not reported as a malformed response.
            success_status(&response)?;
            let id = response
                .headers()
                .get(CHANNEL_HEADER)
                .and_then(|id| id.to_str().ok())
                .filter(|id| valid_id(id))
                .ok_or(TransportError::InvalidResponse)?
                .to_owned();
            let message = read_response(response, 1024)?;
            self.channel = Some(ClientChannel {
                id,
                state: finish(state, &message)?,
                created,
                touched: created,
            });
        }
        let channel = self.channel.as_mut().ok_or(TransportError::Channel)?;
        let sent_at = std::time::Instant::now();
        let message = encrypt(&mut channel.state, &bytes)?;
        let response = self
            .http
            .post(self.endpoint.join("api/v1/channel/message")?)
            .header("content-type", "application/octet-stream")
            .header(CHANNEL_HEADER, channel.id.as_str())
            .body(message)
            .send()
            .map_err(|_| TransportError::Network)?;
        let message = read_response(response, MAX_RPC_BYTES + 16)?;
        let payload = decrypt(&mut channel.state, &message)?;
        // Use send time conservatively: the server touches its channel later.
        channel.touched = sent_at;
        decode_response(request, &payload)
    }
}

#[cfg(feature = "client")]
fn success_status(response: &reqwest::blocking::Response) -> Result<()> {
    match response.status() {
        // Keep the status: 404 means the API address is wrong and 503 means the
        // server is busy, neither of which is an unreachable network.
        reqwest::StatusCode::OK => Ok(()),
        status => Err(TransportError::Http(status.as_u16())),
    }
}

#[cfg(feature = "client")]
fn read_response(
    response: reqwest::blocking::Response,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    success_status(&response)?;
    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        return Err(TransportError::InvalidResponse);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TransportError::Network)?;
    if bytes.len() > limit {
        return Err(TransportError::InvalidResponse);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> (TransportState, TransportState) {
        let endpoint = Endpoint::parse("http://localhost:8000/keys/").unwrap();
        let identity = Identity::generate().unwrap();
        let (state, message) = initiate(&endpoint, identity.public_bytes()).unwrap();
        let (server, response) = accept(&endpoint, &identity, &message).unwrap();
        (finish(state, &response).unwrap(), server)
    }
    #[test]
    fn identity_prologue_and_url_rules_are_enforced() {
        let endpoint = Endpoint::parse("http://EXAMPLE.com:80/keys").unwrap();
        assert_eq!(endpoint.as_str(), "http://example.com/keys/");
        for url in [
            "ftp://localhost/",
            "http://user:pass@localhost/",
            "http://localhost/?token=x",
            "http://localhost/#x",
        ] {
            assert!(Endpoint::parse(url).is_err());
        }
        let identity = Identity::generate().unwrap();
        let wrong = Identity::generate().unwrap();
        let (_, message) = initiate(&endpoint, wrong.public_bytes()).unwrap();
        assert!(accept(&endpoint, &identity, &message).is_err());
        let (_, message) = initiate(&endpoint, identity.public_bytes()).unwrap();
        assert!(
            accept(
                &Endpoint::parse("http://example.com/other/").unwrap(),
                &identity,
                &message
            )
            .is_err()
        );
    }
    #[test]
    fn bidirectional_tags_replay_direction_and_session_binding() {
        let (mut client, mut server) = pair();
        let ciphertext = encrypt(&mut client, b"synthetic password and token").unwrap();
        assert!(!ciphertext.windows(9).any(|part| part == b"synthetic"));
        assert_eq!(
            &**decrypt(&mut server, &ciphertext).unwrap(),
            b"synthetic password and token"
        );
        assert!(decrypt(&mut server, &ciphertext).is_err());
        let response = encrypt(&mut server, b"authenticated response").unwrap();
        assert_eq!(
            &**decrypt(&mut client, &response).unwrap(),
            b"authenticated response"
        );
        let (mut other_client, mut other_server) = pair();
        assert!(decrypt(&mut other_server, &ciphertext).is_err());
        assert!(decrypt(&mut other_client, &ciphertext).is_err());
        let mut tampered = encrypt(&mut client, b"new secret").unwrap();
        tampered[0] ^= 1;
        assert!(decrypt(&mut server, &tampered).is_err());
    }
    #[test]
    fn out_of_order_and_size_boundaries_are_rejected() {
        let (mut client, mut server) = pair();
        let first = encrypt(&mut client, b"first").unwrap();
        let second = encrypt(&mut client, b"second").unwrap();
        assert!(decrypt(&mut server, &second).is_err());
        assert!(decrypt(&mut server, &first).is_ok());
        assert!(decrypt(&mut server, &second).is_ok());
        let body = vec![0; MAX_RPC_BYTES];
        assert!(decrypt(&mut server, &encrypt(&mut client, &body).unwrap()).is_ok());
        assert!(encrypt(&mut client, &vec![0; MAX_RPC_BYTES + 1]).is_err());
    }

    #[test]
    fn responses_bind_the_request_number_and_protocol_version() {
        let request = RpcRequest::new(keyrotation_protocol::Command::ServerInfo, None);
        let mut response =
            RpcResponse::new(request.request_id.clone(), Ok(ResponseBody::LoggedOut));
        assert!(decode_response(&request, &response.encode().unwrap()).is_ok());
        response.request_id = keyrotation_protocol::random_id();
        assert!(decode_response(&request, &response.encode().unwrap()).is_err());
        response.request_id = request.request_id.clone();
        response.protocol_version = 2;
        assert!(decode_response(&request, &response.encode().unwrap()).is_err());
    }

    #[cfg(feature = "client")]
    #[test]
    fn non_success_status_is_reported_with_its_http_code() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let identity = Identity::generate().unwrap();
        let mut client = Client::new(
            Endpoint::parse(&format!("http://{address}/")).unwrap(),
            Some(&identity.public_base64()),
            None,
        )
        .unwrap();
        // The first exchange is the Noise handshake; the canned 503 answers it.
        let request = RpcRequest::new(keyrotation_protocol::Command::ServerInfo, None);
        let error = client.call(&request).unwrap_err();
        assert!(matches!(error, TransportError::Http(503)));
        assert_eq!(error.to_string(), "HTTP 503");
        server.join().unwrap();
    }
    // Real TCP + Noise exchanges with a scripted peer; no user files or credentials.
    #[cfg(feature = "client")]
    struct Peer {
        listener: std::net::TcpListener,
        endpoint: Endpoint,
        identity: Identity,
    }
    #[cfg(feature = "client")]
    impl Peer {
        fn new() -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            Self {
                endpoint: Endpoint::parse(&format!("http://{}/", listener.local_addr().unwrap()))
                    .unwrap(),
                listener,
                identity: Identity::generate().unwrap(),
            }
        }
        fn client(&self) -> Client {
            Client::new(
                self.endpoint.clone(),
                Some(&self.identity.public_base64()),
                None,
            )
            .unwrap()
        }
        fn request(&self) -> (std::net::TcpStream, String, Vec<u8>) {
            use std::io::Read;
            let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut stream = loop {
                match self.listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < until, "peer request timed out");
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
                assert!(header.len() < 8192);
            }
            let header = String::from_utf8(header).unwrap();
            let len: usize = header
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            let mut body = vec![0; len];
            stream.read_exact(&mut body).unwrap();
            (stream, header, body)
        }
        fn respond(mut stream: std::net::TcpStream, status: u16, extra: &str, body: &[u8]) {
            use std::io::Write;
            write!(
                stream,
                "HTTP/1.1 {status} Reply\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        }
        fn handshake(&self) -> TransportState {
            let (stream, header, body) = self.request();
            assert!(header.starts_with("POST /api/v1/channel/handshake "));
            let (state, response) = accept(&self.endpoint, &self.identity, &body).unwrap();
            Self::respond(
                stream,
                200,
                &format!(
                    "{CHANNEL_HEADER}: {}\r\n",
                    keyrotation_protocol::random_id()
                ),
                &response,
            );
            state
        }
        fn rpc(
            &self,
            state: &mut TransportState,
            result: std::result::Result<ResponseBody, ApiError>,
        ) -> RpcRequest {
            let (stream, header, body) = self.request();
            assert!(header.starts_with("POST /api/v1/channel/message "));
            let request = RpcRequest::decode(&decrypt(state, &body).unwrap()).unwrap();
            let response = RpcResponse::new(request.request_id.clone(), result)
                .encode()
                .unwrap();
            Self::respond(stream, 200, "", &encrypt(state, &response).unwrap());
            request
        }
    }

    #[cfg(feature = "client")]
    #[test]
    fn requests_renew_idle_and_absolute_expiry_without_replacing_the_token() {
        let peer = Peer::new();
        let mut client = peer.client();
        let server = std::thread::spawn(move || {
            let mut state = peer.handshake();
            for _ in 0..2 {
                let request = peer.rpc(&mut state, Ok(ResponseBody::LoggedOut));
                assert_eq!(request.session_token.as_deref(), Some("synthetic-token"));
            }
            for _ in 0..2 {
                let mut state = peer.handshake();
                let request = peer.rpc(&mut state, Ok(ResponseBody::LoggedOut));
                assert_eq!(request.session_token.as_deref(), Some("synthetic-token"));
            }
        });
        let request = RpcRequest::new(
            keyrotation_protocol::Command::AuthValidate,
            Some("synthetic-token".into()),
        );
        client.call(&request).unwrap();
        let original = client.channel.as_ref().unwrap().id.clone();
        client.call(&request).unwrap();
        assert_eq!(
            client.channel.as_ref().unwrap().id,
            original,
            "live channel is reused"
        );
        client.channel.as_mut().unwrap().touched -= CHANNEL_IDLE;
        client.call(&request).unwrap();
        assert_ne!(client.channel.as_ref().unwrap().id, original);
        client.channel.as_mut().unwrap().created -= CHANNEL_MAX;
        client.call(&request).unwrap();
        server.join().unwrap();
    }

    #[cfg(feature = "client")]
    #[test]
    fn lost_channel_read_retries_once_with_new_request_id_and_original_token() {
        let peer = Peer::new();
        let mut client = peer.client();
        let server = std::thread::spawn(move || {
            let mut state = peer.handshake();
            peer.rpc(&mut state, Ok(ResponseBody::LoggedOut));
            let (stream, _, body) = peer.request();
            let failed = RpcRequest::decode(&decrypt(&mut state, &body).unwrap()).unwrap();
            Peer::respond(stream, 400, "", b"channel failed");
            let mut state = peer.handshake();
            let retried = peer.rpc(&mut state, Ok(ResponseBody::LoggedOut));
            assert_ne!(failed.request_id, retried.request_id);
            assert_eq!(failed.session_token, retried.session_token);
        });
        let request = RpcRequest::new(
            keyrotation_protocol::Command::AuthValidate,
            Some("synthetic-token".into()),
        );
        client.call(&request).unwrap();
        client.call(&request).unwrap();
        server.join().unwrap();
    }

    #[cfg(feature = "client")]
    #[test]
    fn persistent_channel_failure_stops_after_one_read_retry() {
        let peer = Peer::new();
        let mut client = peer.client();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let _state = peer.handshake();
                let (stream, _, _) = peer.request();
                Peer::respond(stream, 400, "", b"channel failed");
            }
        });
        assert!(matches!(
            client.call(&RpcRequest::new(
                keyrotation_protocol::Command::ServerInfo,
                None
            )),
            Err(TransportError::Http(400))
        ));
        assert!(client.channel.is_none());
        server.join().unwrap();
    }

    #[cfg(feature = "client")]
    #[test]
    fn login_logout_and_mutations_are_not_replayed_and_session_expiry_is_not_retried() {
        use keyrotation_protocol::{Command, ErrorCode, WriteContext};
        let commands = [
            Command::AuthLogin {
                username: "synthetic".into(),
                password: "synthetic".into(),
            },
            Command::AuthLogout,
            Command::EntriesDelete {
                write: WriteContext {
                    operation_id: keyrotation_protocol::random_id(),
                    generation: keyrotation_protocol::random_id(),
                    key_epoch: 1,
                    valid_until: 100,
                },
                id: 1,
            },
        ];
        for command in commands {
            let peer = Peer::new();
            let mut client = peer.client();
            let server = std::thread::spawn(move || {
                let _state = peer.handshake();
                let (stream, _, _) = peer.request();
                Peer::respond(stream, 400, "", b"channel failed");
            });
            assert!(matches!(
                client.call(&RpcRequest::new(command, None)),
                Err(TransportError::Http(400))
            ));
            server.join().unwrap();
        }
        let peer = Peer::new();
        let mut client = peer.client();
        let server = std::thread::spawn(move || {
            let mut state = peer.handshake();
            peer.rpc(
                &mut state,
                Err(ApiError {
                    code: ErrorCode::SessionExpired,
                    message: "expired".into(),
                }),
            );
        });
        assert!(matches!(
            client.call(&RpcRequest::new(
                Command::AuthValidate,
                Some("synthetic-token".into())
            )),
            Err(TransportError::Remote(ApiError {
                code: ErrorCode::SessionExpired,
                ..
            }))
        ));
        server.join().unwrap();
    }
}
