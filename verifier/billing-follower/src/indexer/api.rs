use std::{pin::Pin, time::Duration};

use alloy::transports::http::reqwest::{self, Response, StatusCode, header};
use futures_util::{Stream, stream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use url::Url;

const API_VERSION: u32 = 1;
const MAX_BODY: usize = 8 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

pub(super) type BatchStream = Pin<Box<dyn Stream<Item = Result<Batch, ApiError>> + Send>>;

#[derive(Clone)]
pub(super) struct Api {
    http: reqwest::Client,
    base: Url,
    authorization: header::HeaderValue,
}

impl Api {
    pub(super) fn new(mut base: Url, token: String) -> Result<Self, ApiError> {
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(ApiError::Protocol("invalid API base URL"));
        }
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        if token.is_empty() {
            return Err(ApiError::Protocol("empty API token"));
        }
        let mut authorization = header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| ApiError::Protocol("invalid API token"))?;
        authorization.set_sensitive(true);
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(transport_error)?;
        Ok(Self {
            http,
            base,
            authorization,
        })
    }

    pub(super) async fn status(&self) -> Result<Vec<TargetStatus>, ApiError> {
        let response = self
            .request("v1/status")?
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(transport_error)?;
        let status: StatusResponse = json(response).await?;
        version(status.version)?;
        Ok(status.targets)
    }

    pub(super) async fn snapshot(
        &self,
        scope: &Scope,
        cursor: Option<&str>,
    ) -> Result<SnapshotPage, ApiError> {
        let response = self
            .read_request("v1/snapshot", scope, cursor)?
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(transport_error)?;
        let page: SnapshotPage = json(response).await?;
        version(page.version)?;
        Ok(page)
    }

    pub(super) async fn changes(&self, scope: &Scope, cursor: &str) -> Result<Batch, ApiError> {
        let response = self
            .read_request("v1/changes", scope, Some(cursor))?
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(transport_error)?;
        let batch: Batch = json(response).await?;
        version(batch.version)?;
        Ok(batch)
    }

    pub(super) async fn stream(
        &self,
        scope: &Scope,
        cursor: &str,
    ) -> Result<BatchStream, ApiError> {
        let response = tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.read_request("v1/stream", scope, Some(cursor))?.send(),
        )
        .await
        .map_err(|_| ApiError::Timeout)?
        .map_err(transport_error)?;
        status_error(response.status())?;
        if !response.status().is_success() {
            return Err(
                tokio::time::timeout(REQUEST_TIMEOUT, response_error(response))
                    .await
                    .map_err(|_| ApiError::Timeout)?,
            );
        }
        if !response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
        {
            return Err(ApiError::Protocol("expected text/event-stream"));
        }
        Ok(Box::pin(stream::try_unfold(
            SseReader::new(response),
            SseReader::next,
        )))
    }

    fn request(&self, path: &str) -> Result<reqwest::RequestBuilder, ApiError> {
        let url = self
            .base
            .join(path)
            .map_err(|_| ApiError::Protocol("invalid API path"))?;
        Ok(self
            .http
            .get(url)
            .header(header::AUTHORIZATION, self.authorization.clone()))
    }

    fn read_request(
        &self,
        path: &str,
        scope: &Scope,
        cursor: Option<&str>,
    ) -> Result<reqwest::RequestBuilder, ApiError> {
        let url = self
            .base
            .join(path)
            .map_err(|_| ApiError::Protocol("invalid API path"))?;
        Ok(self
            .http
            .post(url)
            .header(header::AUTHORIZATION, self.authorization.clone())
            .json(&ReadRequest {
                scope,
                cursor,
                limit: 1000,
            }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum ApiError {
    #[error("indexer transport failed")]
    Transport,
    #[error("indexer request timed out")]
    Timeout,
    #[error("indexer authorization failed")]
    Unauthorized,
    #[error("indexer requires resynchronization")]
    Resync,
    #[error("invalid indexer response: {0}")]
    Protocol(&'static str),
    #[error("indexer unavailable")]
    Unavailable,
}

fn transport_error(error: reqwest::Error) -> ApiError {
    if error.is_timeout() {
        ApiError::Timeout
    } else {
        ApiError::Transport
    }
}

fn status_error(status: StatusCode) -> Result<(), ApiError> {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(ApiError::Unauthorized),
        StatusCode::CONFLICT | StatusCode::GONE => Err(ApiError::Resync),
        StatusCode::TOO_MANY_REQUESTS => Err(ApiError::Unavailable),
        status if status.is_server_error() => Err(ApiError::Unavailable),
        _ => Ok(()),
    }
}

async fn json<T: DeserializeOwned>(response: Response) -> Result<T, ApiError> {
    status_error(response.status())?;
    let success = response.status().is_success();
    let bytes = body(response).await?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::Protocol("malformed JSON response"))?;
    if value.get("code").and_then(serde_json::Value::as_str) == Some("resync_required") {
        return Err(ApiError::Resync);
    }
    if !success {
        return Err(ApiError::Protocol("unexpected HTTP status"));
    }
    serde_json::from_value(value).map_err(|_| ApiError::Protocol("invalid response schema"))
}

async fn response_error(response: Response) -> ApiError {
    match body(response).await {
        Ok(bytes) => match serde_json::from_slice::<ErrorResponse>(&bytes) {
            Ok(error) => error.classify(),
            Err(_) => ApiError::Protocol("invalid API error"),
        },
        Err(error) => error,
    }
}

async fn body(mut response: Response) -> Result<Vec<u8>, ApiError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
        if chunk.len() > MAX_BODY - bytes.len() {
            return Err(ApiError::Protocol("HTTP body too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn version(version: u32) -> Result<(), ApiError> {
    if version == API_VERSION {
        Ok(())
    } else {
        Err(ApiError::Protocol("unsupported API version"))
    }
}

struct SseReader {
    response: Response,
    chunk: Vec<u8>,
    offset: usize,
    line: Vec<u8>,
    data: String,
    has_data: bool,
    event: String,
    frame_bytes: usize,
}

impl SseReader {
    fn new(response: Response) -> Self {
        Self {
            response,
            chunk: Vec::new(),
            offset: 0,
            line: Vec::new(),
            data: String::new(),
            has_data: false,
            event: String::new(),
            frame_bytes: 0,
        }
    }

    async fn next(mut self) -> Result<Option<(Batch, Self)>, ApiError> {
        loop {
            if self.offset == self.chunk.len() {
                let chunk = tokio::time::timeout(STREAM_IDLE_TIMEOUT, self.response.chunk())
                    .await
                    .map_err(|_| ApiError::Timeout)?
                    .map_err(transport_error)?;
                let Some(chunk) = chunk else {
                    return if self.line.is_empty() && !self.has_data && self.event.is_empty() {
                        Ok(None)
                    } else {
                        Err(ApiError::Protocol("truncated SSE frame"))
                    };
                };
                if chunk.len() > MAX_BODY {
                    return Err(ApiError::Protocol("SSE chunk too large"));
                }
                self.chunk = chunk.to_vec();
                self.offset = 0;
                if self.chunk.is_empty() {
                    continue;
                }
            }
            let byte = self.chunk[self.offset];
            self.offset += 1;
            self.frame_bytes += 1;
            if self.frame_bytes > MAX_BODY {
                return Err(ApiError::Protocol("SSE frame too large"));
            }
            self.line.push(byte);
            if byte != b'\n' {
                continue;
            }
            let line = String::from_utf8(std::mem::take(&mut self.line))
                .map_err(|_| ApiError::Protocol("SSE is not UTF-8"))?;
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                self.frame_bytes = 0;
                if self.has_data {
                    let batch = self.batch()?;
                    self.data.clear();
                    self.has_data = false;
                    self.event.clear();
                    return Ok(Some((batch, self)));
                }
                self.event.clear();
            } else if let Some(data) = line.strip_prefix("data:") {
                if self.has_data {
                    self.data.push('\n');
                }
                self.has_data = true;
                self.data.push_str(data.strip_prefix(' ').unwrap_or(data));
            } else if let Some(event) = line.strip_prefix("event:") {
                self.event = event.trim().to_owned();
            }
        }
    }

    fn batch(&self) -> Result<Batch, ApiError> {
        match self.event.as_str() {
            "error" => {
                let error: ErrorResponse = serde_json::from_str(&self.data)
                    .map_err(|_| ApiError::Protocol("invalid SSE error"))?;
                Err(error.classify())
            }
            "" | "changes" => {
                let batch: Batch = serde_json::from_str(&self.data)
                    .map_err(|_| ApiError::Protocol("invalid SSE batch"))?;
                version(batch.version)?;
                Ok(batch)
            }
            _ => Err(ApiError::Protocol("unexpected SSE event")),
        }
    }
}

#[derive(Serialize)]
struct ReadRequest<'a> {
    scope: &'a Scope,
    cursor: Option<&'a str>,
    limit: usize,
}

#[derive(Deserialize)]
struct ErrorResponse {
    code: String,
}

impl ErrorResponse {
    fn classify(&self) -> ApiError {
        match self.code.as_str() {
            "resync_required" => ApiError::Resync,
            "unavailable" | "overloaded" => ApiError::Unavailable,
            _ => ApiError::Protocol("unexpected API error"),
        }
    }
}

#[derive(Deserialize)]
struct StatusResponse {
    version: u32,
    targets: Vec<TargetStatus>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct Block {
    pub(super) number: u64,
    pub(super) hash: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Health {
    Initializing,
    Ready,
    Stale,
    Unavailable,
    Reconciling,
    RecoveryRequired,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct TargetStatus {
    pub(super) target: String,
    pub(super) generation: String,
    pub(super) chain_id: u64,
    pub(super) genesis_hash: String,
    pub(super) address: String,
    pub(super) start_block: u64,
    pub(super) topic_filter: Option<Vec<Option<Vec<String>>>>,
    pub(super) contract_verified_at: Option<Block>,
    pub(super) startup_head: Option<Block>,
    pub(super) covered_through: Option<Block>,
    pub(super) observed_head: Option<Block>,
    pub(super) canonical: Health,
    pub(super) caught_up: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    Preconfirmed,
    Unsafe,
    Safe,
    Finalized,
    Removed,
    Unresolved,
}

impl Status {
    pub(super) fn canonical(self) -> bool {
        matches!(self, Self::Unsafe | Self::Safe | Self::Finalized)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct Event {
    pub(super) id: String,
    pub(super) target: String,
    pub(super) chain_id: u64,
    pub(super) address: String,
    pub(super) transaction_index: u64,
    pub(super) log_index: u64,
    pub(super) block: Block,
    pub(super) topics: Vec<String>,
    pub(super) data: String,
    pub(super) state: Status,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Change {
    Event {
        previous: Option<Status>,
        event: Box<Event>,
    },
    Progress {
        status: Box<TargetStatus>,
    },
}

#[derive(Debug, Deserialize)]
pub(super) struct Record {
    pub(super) sequence: u64,
    pub(super) change: Change,
}

#[derive(Debug, Deserialize)]
pub(super) struct Batch {
    pub(super) version: u32,
    pub(super) records: Vec<Record>,
    pub(super) cursor: String,
    pub(super) has_more: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct Scope {
    pub(super) filters: Vec<Filter>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct Filter {
    pub(super) target: String,
    pub(super) topics: Vec<Option<Vec<String>>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SnapshotPage {
    pub(super) version: u32,
    pub(super) events: Vec<Event>,
    pub(super) targets: Vec<TargetStatus>,
    pub(super) next_page: Option<String>,
    pub(super) resume_cursor: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use futures_util::StreamExt;
    use serde_json::json;

    async fn serve(app: Router) -> (Api, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (Api::new(base, "test-token".into()).unwrap(), server)
    }

    #[test]
    fn rejects_unsafe_configuration_without_echoing_it() {
        for url in [
            "https://user:private-token@example.com/",
            "https://example.com/?private-token",
            "https://example.com/#private-token",
            "ftp://example.com/",
        ] {
            let error = Api::new(Url::parse(url).unwrap(), "test-token".into())
                .err()
                .unwrap();
            assert_eq!(error, ApiError::Protocol("invalid API base URL"));
            assert!(!format!("{error:?} {error}").contains("private-token"));
        }
        for token in ["", "private-token\r\nheader: value"] {
            assert!(Api::new(Url::parse("https://example.com/").unwrap(), token.into()).is_err());
        }
    }

    #[tokio::test]
    async fn reads_versioned_pages_and_sse_with_bounded_request_bodies() {
        let batch = json!({"version":1,"records":[],"cursor":"resume","has_more":false});
        let batch_json = batch.to_string();
        let app = Router::new()
            .route("/v1/status", get(|| async { Json(json!({"version":1,"targets":[]})) }))
            .route("/v1/snapshot", axum::routing::post(|headers: header::HeaderMap, Json(request): Json<serde_json::Value>| async move {
                assert_eq!(headers[header::AUTHORIZATION], "Bearer test-token");
                assert_eq!(request, json!({"scope":{"filters":[]},"cursor":null,"limit":1000}));
                Json(json!({"version":1,"events":[],"targets":[],"next_page":null,"resume_cursor":"resume"}))
            }))
            .route("/v1/changes", axum::routing::post(move |Json(request): Json<serde_json::Value>| {
                let batch = batch.clone();
                async move {
                    assert_eq!(request["cursor"], "resume");
                    Json(batch)
                }
            }))
            .route("/v1/stream", axum::routing::post(move || {
                let payload = format!(": keepalive\r\n\r\nevent: changes\r\ndata: {batch_json}\r\n\r\n");
                async move { ([(header::CONTENT_TYPE, "text/event-stream")], payload) }
            }));
        let (api, server) = serve(app).await;
        assert!(api.status().await.unwrap().is_empty());
        let scope = Scope::default();
        let page = api.snapshot(&scope, None).await.unwrap();
        assert_eq!(page.resume_cursor, "resume");
        assert_eq!(
            api.changes(&scope, "resume").await.unwrap().cursor,
            "resume"
        );
        let mut stream = api.stream(&scope, "resume").await.unwrap();
        assert_eq!(stream.next().await.unwrap().unwrap().cursor, "resume");
        assert!(stream.next().await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn classifies_http_and_sse_failures_without_provider_payloads() {
        for (status, body, expected) in [
            (401, "private-marker", ApiError::Unauthorized),
            (403, "private-marker", ApiError::Unauthorized),
            (409, "private-marker", ApiError::Resync),
            (410, "private-marker", ApiError::Resync),
            (429, "private-marker", ApiError::Unavailable),
            (503, "private-marker", ApiError::Unavailable),
            (
                400,
                r#"{"code":"resync_required","message":"private-marker"}"#,
                ApiError::Resync,
            ),
            (
                200,
                r#"{"version":2,"targets":[]}"#,
                ApiError::Protocol("unsupported API version"),
            ),
        ] {
            let app = Router::new().route(
                "/v1/status",
                get(move || async move { (StatusCode::from_u16(status).unwrap(), body) }),
            );
            let (api, server) = serve(app).await;
            let error = api.status().await.unwrap_err();
            assert_eq!(error, expected);
            assert!(!format!("{error:?} {error}").contains("private-marker"));
            server.abort();
        }
        let app = Router::new().route("/v1/stream", axum::routing::post(|| async {
            ([(header::CONTENT_TYPE,"text/event-stream")], "event: error\ndata: {\"code\":\"resync_required\",\"message\":\"private-marker\"}\n\n")
        }));
        let (api, server) = serve(app).await;
        let mut stream = api.stream(&Scope::default(), "resume").await.unwrap();
        assert_eq!(stream.next().await.unwrap().unwrap_err(), ApiError::Resync);
        assert!(stream.next().await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn rejects_oversized_http_bodies_and_truncated_sse_frames() {
        let app = Router::new()
            .route("/v1/status", get(|| async { "x".repeat(MAX_BODY + 1) }))
            .route(
                "/v1/stream",
                axum::routing::post(|| async {
                    (
                        [(header::CONTENT_TYPE, "text/event-stream")],
                        "event: changes\ndata: {\"version\":1}",
                    )
                }),
            );
        let (api, server) = serve(app).await;
        assert_eq!(
            api.status().await.unwrap_err(),
            ApiError::Protocol("HTTP body too large")
        );
        let mut stream = api.stream(&Scope::default(), "resume").await.unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap_err(),
            ApiError::Protocol("truncated SSE frame")
        );
        server.abort();
    }

    #[tokio::test]
    async fn rejects_redirects_without_forwarding_authorization() {
        let forwarded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let redirected = forwarded.clone();
        let app = Router::new()
            .route(
                "/v1/status",
                get(|| async { axum::response::Redirect::temporary("/redirected") }),
            )
            .route(
                "/redirected",
                get(move || {
                    redirected.store(true, std::sync::atomic::Ordering::SeqCst);
                    async { Json(json!({"version":1,"targets":[]})) }
                }),
            );
        let (api, server) = serve(app).await;
        assert!(matches!(api.status().await, Err(ApiError::Protocol(_))));
        assert!(!forwarded.load(std::sync::atomic::Ordering::SeqCst));
        server.abort();
    }

    #[tokio::test]
    async fn sse_idle_deadline_is_independent_of_the_header_deadline() {
        let app = Router::new().route(
            "/v1/stream",
            axum::routing::post(|| async {
                let chunks = stream::pending::<Result<Vec<u8>, std::io::Error>>();
                axum::http::Response::builder()
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(axum::body::Body::from_stream(chunks))
                    .unwrap()
            }),
        );
        let (api, server) = serve(app).await;
        let mut stream = api.stream(&Scope::default(), "resume").await.unwrap();
        tokio::time::pause();
        assert_eq!(stream.next().await.unwrap().unwrap_err(), ApiError::Timeout);
        server.abort();
    }

    #[test]
    fn accepts_the_minimal_wire_schema_and_known_lifecycle_states() {
        let target = json!({
            "target":"billing", "generation":"generation", "chain_id":31337,
            "genesis_hash":"genesis", "address":"contract", "start_block":0,
            "covered_through":{"number":1,"hash":"block","timestamp":1},
            "canonical":"ready", "caught_up":true, "preconfirmed":"unsupported"
        });
        let status: TargetStatus = serde_json::from_value(target).unwrap();
        assert_eq!(status.covered_through.unwrap().number, 1);
        assert_eq!(status.topic_filter, None);
        for (name, canonical) in [
            ("preconfirmed", false),
            ("unsafe", true),
            ("safe", true),
            ("finalized", true),
            ("removed", false),
            ("unresolved", false),
        ] {
            let state: Status = serde_json::from_value(json!(name)).unwrap();
            assert_eq!(state.canonical(), canonical);
        }
        assert!(serde_json::from_value::<Status>(json!("uncertain")).is_err());
    }
}
