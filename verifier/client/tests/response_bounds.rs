//! Real HTTP framing failures must not bypass the client's body or request bounds.

use std::{io, time::Duration};

use flamingo_verifier_client::{Config, Error, FlamingoVerifierClient, PcrMeasurement};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

/// Sends exact HTTP bytes, optionally withholding EOF until the bounded client disconnects.
async fn assignment_error(response: Vec<u8>, keep_open: bool, request_millis: u64) -> Error {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        timeout(Duration::from_secs(3), async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                assert!(
                    headers.len() < 8192,
                    "fixture request headers exceeded their bound"
                );
                let mut byte = [0];
                socket.read_exact(&mut byte).await.unwrap();
                headers.push(byte[0]);
            }
            assert!(headers.starts_with(b"POST /v1/enclave-assignment HTTP/1.1\r\n"));
            socket.write_all(&response).await.unwrap();

            if keep_open {
                // An early size rejection or timeout must release the unfinished response.
                match socket.read(&mut [0]).await {
                    Ok(0) => {}
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
                    result => panic!("expected client disconnect, got {result:?}"),
                }
            }
        })
        .await
        .expect("HTTP fixture exceeded its own deadline");
    });

    let config = Config::new(
        &format!("http://{address}"),
        vec![vec![PcrMeasurement::new(0, [1; 48])]],
    )
    .unwrap();
    let mut json = serde_json::to_value(config).unwrap();
    json["connect_timeout_millis"] = 50.into();
    json["request_timeout_millis"] = request_millis.into();
    let client =
        FlamingoVerifierClient::new(Config::from_json(&json.to_string()).unwrap()).unwrap();
    let result = timeout(Duration::from_secs(2), client.request_assignment())
        .await
        .expect("client failed to bound its HTTP request");
    server.await.expect("HTTP fixture failed");
    result.expect_err("untrusted fixture response must not produce an assignment")
}

/// Oversized Content-Length is rejected immediately, without waiting for advertised bytes.
#[tokio::test]
async fn rejects_oversized_content_length_before_reading_body() {
    let error = assignment_error(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1073741824\r\n\r\n".to_vec(),
        true,
        500,
    )
    .await;
    assert!(
        matches!(error, Error::ResponseTooLarge),
        "unexpected error: {error}"
    );
}

/// Chunked responses are bounded even when no Content-Length is available.
#[tokio::test]
async fn rejects_oversized_chunked_body() {
    let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10001\r\n".to_vec();
    response.extend(vec![b'x'; 64 * 1024 + 1]);
    response.extend_from_slice(b"\r\n0\r\n\r\n");
    let error = assignment_error(response, false, 500).await;
    assert!(
        matches!(error, Error::ResponseTooLarge),
        "unexpected error: {error}"
    );
}

/// A body cut short is a transport failure, not accepted partial JSON.
#[tokio::test]
async fn rejects_truncated_body() {
    let error = assignment_error(
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}".to_vec(),
        false,
        500,
    )
    .await;
    assert!(
        matches!(error, Error::Request(ref failure) if !failure.is_timeout()),
        "unexpected error: {error}"
    );
}

/// Receiving headers and a partial body cannot reset the whole-request deadline.
#[tokio::test]
async fn stalled_body_hits_request_deadline() {
    let error = assignment_error(
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{".to_vec(),
        true,
        100,
    )
    .await;
    assert!(
        matches!(error, Error::Request(ref failure) if failure.is_timeout()),
        "unexpected error: {error}"
    );
}

/// The inclusive limit reaches JSON validation rather than being rejected one byte early.
#[tokio::test]
async fn accepts_exact_body_limit_for_json_validation() {
    let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n".to_vec();
    response.extend(vec![b' '; 64 * 1024 - 2]);
    response.extend_from_slice(b"{}");
    let error = assignment_error(response, false, 500).await;
    assert!(
        matches!(error, Error::MalformedResponse(_)),
        "unexpected error: {error}"
    );
}
