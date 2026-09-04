use std::{future::Future, time::Duration};

use axum::body::Bytes;
use flamingo_verifier_worker_protocol::{
    COMPARE_PATH, CONTENT_TYPE, CompareRequest, MAX_RESPONSE_BYTES, READY_PATH, WorkerReady,
    WorkerResult, decode_message, encode_message,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, StatusCode, client::conn::http2::SendRequest, header};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use serde::de::DeserializeOwned;
use tokio::{
    net::UnixStream,
    time::{Instant, timeout_at},
};

use crate::WorkerClientError;

// Fixed transport budgets; application bodies have separate, caller-selected limits.
const WINDOW: u32 = 65_535;
const FRAME: u32 = 16_384;
const HEADERS: u32 = 4096;
const RESET_STREAMS: usize = 16;

/// Typed transport; the session owns admission, deadline selection and the connection driver.
#[derive(Debug, Clone)]
pub(crate) struct WorkerHttpClient {
    sender: SendRequest<Full<Bytes>>,
    max_request_bytes: usize,
}

impl WorkerHttpClient {
    pub(crate) async fn connect(
        stream: UnixStream,
        max_in_flight: u16,
        max_request_bytes: usize,
        keep_alive_timeout: Duration,
    ) -> Result<
        (
            Self,
            impl Future<Output = Result<(), WorkerClientError>> + Send + 'static,
        ),
        WorkerClientError,
    > {
        let (sender, connection) = client_builder(max_in_flight, keep_alive_timeout)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(WorkerClientError::transport)?;

        let client = Self {
            sender,
            max_request_bytes,
        };
        let driver = async move { connection.await.map_err(WorkerClientError::transport) };

        Ok((client, driver))
    }

    pub(crate) async fn ready(&self, deadline: Instant) -> Result<WorkerReady, WorkerClientError> {
        self.exchange(request(Method::GET, READY_PATH, Vec::new()), deadline)
            .await
            .map_err(|error| match error {
                WorkerClientError::RequestTimeout => WorkerClientError::HandshakeTimeout,
                error => error,
            })
    }

    pub(crate) async fn compare(
        &self,
        comparison: CompareRequest,
        deadline: Instant,
    ) -> Result<WorkerResult, WorkerClientError> {
        let payload = encode_message(&comparison, self.max_request_bytes)
            .map_err(WorkerClientError::RequestEncoding)?;
        drop(comparison);

        self.exchange(request(Method::POST, COMPARE_PATH, payload), deadline)
            .await
    }

    async fn exchange<T: DeserializeOwned>(
        &self,
        request: Request<Full<Bytes>>,
        deadline: Instant,
    ) -> Result<T, WorkerClientError> {
        // Encoding is synchronous. Recheck before allowing any socket writes.
        if Instant::now() >= deadline {
            return Err(WorkerClientError::RequestTimeout);
        }

        timeout_at(deadline, async {
            let mut sender = self.sender.clone();
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

            // Check actual chunks, not just the untrusted Content-Length header.
            let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|error| WorkerClientError::ResponseBody(error.into()))?
                .to_bytes();

            decode_message(&body, MAX_RESPONSE_BYTES).map_err(WorkerClientError::Protocol)
        })
        .await
        .map_err(|_| WorkerClientError::RequestTimeout)?
    }
}

fn client_builder(
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

fn request(method: Method, path: &'static str, payload: Vec<u8>) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(format!("http://worker{path}"))
        .header(header::CONTENT_TYPE, CONTENT_TYPE)
        .body(Full::new(Bytes::from(payload)))
        .expect("static worker HTTP request is valid")
}

pub(crate) fn valid_limits(max_request_bytes: usize, max_image_bytes: usize) -> bool {
    max_image_bytes > 0
        && max_image_bytes <= max_request_bytes
        && u32::try_from(max_request_bytes).is_ok()
}

pub(crate) fn valid_timeout(timeout: std::time::Duration) -> bool {
    !timeout.is_zero() && tokio::time::Instant::now().checked_add(timeout).is_some()
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use flamingo_verifier_worker_protocol::{ComparisonScores, WORKER_PROTOCOL_VERSION};
    use hyper::{Response, service::service_fn};
    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn typed_routes_preserve_wire_contract_and_reject_expired_deadlines() {
        let wait = Duration::from_secs(3);
        let ready = WorkerReady {
            protocol_version: WORKER_PROTOCOL_VERSION,
            max_in_flight: 1,
        };
        let comparison = CompareRequest {
            credential_image: vec![1; 8],
            live_image: vec![2; 8],
            challenge_image: vec![3; 8],
        };
        let result = WorkerResult::Compared(ComparisonScores {
            live_similarity: 0.8,
            challenge_similarity: 0.9,
        });
        let requests = Arc::new(AtomicUsize::new(0));
        let (broker, worker) = UnixStream::pair().unwrap();
        let (client, driver) = WorkerHttpClient::connect(broker, 1, 1024, wait)
            .await
            .unwrap();

        let observed_requests = requests.clone();
        let expected_comparison = comparison.clone();
        let server = server_builder(1).serve_connection(
            TokioIo::new(worker),
            service_fn(move |request: Request<hyper::body::Incoming>| {
                let requests = observed_requests.clone();
                let comparison = expected_comparison.clone();

                async move {
                    requests.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(request.headers()[header::CONTENT_TYPE], CONTENT_TYPE);

                    let payload = match request.uri().path() {
                        READY_PATH => {
                            assert_eq!(request.method(), Method::GET);
                            assert!(
                                request
                                    .into_body()
                                    .collect()
                                    .await
                                    .unwrap()
                                    .to_bytes()
                                    .is_empty()
                            );

                            encode_message(&ready, MAX_RESPONSE_BYTES).unwrap()
                        }
                        COMPARE_PATH => {
                            assert_eq!(request.method(), Method::POST);
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            assert_eq!(
                                decode_message::<CompareRequest>(&body, 1024).unwrap(),
                                comparison
                            );

                            encode_message(&result, MAX_RESPONSE_BYTES).unwrap()
                        }
                        path => panic!("unexpected route: {path}"),
                    };

                    Ok::<_, Infallible>(
                        Response::builder()
                            .header(header::CONTENT_TYPE, CONTENT_TYPE)
                            .body(Full::new(Bytes::from(payload)))
                            .unwrap(),
                    )
                }
            }),
        );

        let calls = async {
            assert_eq!(client.ready(Instant::now() + wait).await.unwrap(), ready);

            let expired = Instant::now();
            assert!(matches!(
                client.ready(expired).await,
                Err(WorkerClientError::HandshakeTimeout)
            ));
            assert!(matches!(
                client.compare(comparison.clone(), expired).await,
                Err(WorkerClientError::RequestTimeout)
            ));

            assert_eq!(
                client
                    .compare(comparison.clone(), Instant::now() + wait)
                    .await
                    .unwrap(),
                result
            );
            assert_eq!(requests.load(Ordering::SeqCst), 2);
        };

        tokio::select! {
            result = timeout(wait, calls) => result.unwrap(),
            result = driver => panic!("client connection stopped early: {result:?}"),
            result = server => panic!("server connection stopped early: {result:?}"),
        }
    }
}
