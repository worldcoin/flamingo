use axum::body::Bytes;
use flamingo_verifier_worker_protocol::{CONTENT_TYPE, MAX_RESPONSE_BYTES, decode_message};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, StatusCode, client::conn::http2::SendRequest, header};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use serde::de::DeserializeOwned;

use crate::WorkerClientError;

// Fixed transport budgets; application bodies have separate, caller-selected limits.
const WINDOW: u32 = 65_535;
const FRAME: u32 = 16_384;
const HEADERS: u32 = 4096;
const RESET_STREAMS: usize = 16;

pub(crate) fn client_builder(
    capacity: u16,
    timeout: std::time::Duration,
) -> hyper::client::conn::http2::Builder<TokioExecutor> {
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .adaptive_window(false)
        .initial_connection_window_size(WINDOW)
        .initial_stream_window_size(WINDOW)
        .initial_max_send_streams(usize::from(capacity))
        .max_concurrent_streams(0)
        .max_frame_size(FRAME)
        .max_header_list_size(HEADERS)
        .header_table_size(0)
        .max_send_buf_size(WINDOW as usize)
        .max_concurrent_reset_streams(RESET_STREAMS)
        .max_pending_accept_reset_streams(RESET_STREAMS)
        .max_local_error_reset_streams(RESET_STREAMS)
        .keep_alive_interval(timeout)
        .keep_alive_timeout(timeout)
        .keep_alive_while_idle(true);

    builder
}

pub(crate) fn server_builder(capacity: u16) -> hyper::server::conn::http2::Builder<TokioExecutor> {
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .adaptive_window(false)
        .initial_connection_window_size(WINDOW)
        .initial_stream_window_size(WINDOW)
        // One spare stream permits explicit 429s while all compute slots are occupied.
        .max_concurrent_streams(u32::from(capacity) + 1)
        .max_frame_size(FRAME)
        .max_header_list_size(HEADERS)
        .header_table_size(0)
        .max_send_buf_size(WINDOW as usize)
        .max_pending_accept_reset_streams(RESET_STREAMS)
        .max_local_error_reset_streams(RESET_STREAMS)
        .auto_date_header(false);

    builder
}

pub(crate) fn request(path: &'static str, payload: Vec<u8>) -> Request<Full<Bytes>> {
    Request::builder()
        .method(if payload.is_empty() { "GET" } else { "POST" })
        .uri(format!("http://worker{path}"))
        .header(header::CONTENT_TYPE, CONTENT_TYPE)
        .body(Full::new(Bytes::from(payload)))
        .expect("static worker HTTP request is valid")
}

pub(crate) async fn exchange<T: DeserializeOwned>(
    mut sender: SendRequest<Full<Bytes>>,
    request: Request<Full<Bytes>>,
) -> Result<T, WorkerClientError> {
    sender.ready().await.map_err(WorkerClientError::transport)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(WorkerClientError::transport)?;

    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        return Err(WorkerClientError::AtCapacity);
    }
    if response.status() != StatusCode::OK {
        return Err(WorkerClientError::HttpStatus(response.status()));
    }
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.as_bytes())
        != Some(CONTENT_TYPE.as_bytes())
    {
        return Err(WorkerClientError::UnexpectedContentType);
    }

    // Limited checks actual chunks, not just the untrusted Content-Length header.
    let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|error| WorkerClientError::ResponseBody(error.into()))?
        .to_bytes();

    decode_message(&body, MAX_RESPONSE_BYTES).map_err(WorkerClientError::Protocol)
}

pub(crate) fn valid_limits(max_request_bytes: usize, max_image_bytes: usize) -> bool {
    max_image_bytes > 0
        && max_image_bytes <= max_request_bytes
        && u32::try_from(max_request_bytes).is_ok()
}

pub(crate) fn valid_timeout(timeout: std::time::Duration) -> bool {
    !timeout.is_zero() && tokio::time::Instant::now().checked_add(timeout).is_some()
}
