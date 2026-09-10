//! Bounded server preserving Pontifex 2's type-ID / `MessagePack` wire format.
//!
//! Upstream reads an arbitrary u64 length before invoking handlers and spawns unlimited tasks.
//! Bound those operations here while retaining its public request types and codec.

use std::{io, sync::Arc, time::Duration};

use anyhow::Context;
use flamingo_verifier_enclave_types::{
    Error, GetEncryptionKeyRequest, HealthRequest, MAX_MATCH_CIPHERTEXT_BYTES, MatchRequest,
    MatchResponse,
};
use pontifex::Request;
use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tokio_vsock::{VsockAddr, VsockListener};

use crate::{routes, state::EnclaveState};

const MAX_CONNECTIONS: usize = 32;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(130);

/// A validated bounded frame, holding the sole large-upload slot until its reply is sent.
struct Frame {
    /// The stable hash defined by the pinned Pontifex request trait.
    route: u32,
    /// Empty when a busy match was drained without allocating its body.
    payload: Vec<u8>,
    /// Present only for an admitted match, independent of the broker's blocking-work permit.
    match_permit: Option<OwnedSemaphorePermit>,
}

/// Serves the existing three operations with bounded allocation, concurrency and I/O.
///
/// # Errors
/// Returns an error if the vsock listener cannot bind or accept requests.
pub async fn start(state: Arc<EnclaveState>, port: u32) -> anyhow::Result<()> {
    let listener = VsockListener::bind(VsockAddr::new(u32::MAX, port))
        .context("failed to bind enclave vsock listener")?;
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let matches = Arc::new(Semaphore::new(1));

    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .context("failed to accept vsock request")?;
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            metrics::counter!("enclave_rpc.rejections", "class" => "connection_limit").increment(1);
            continue;
        };
        let state = Arc::clone(&state);
        let matches = Arc::clone(&matches);

        tokio::spawn(async move {
            let _permit = permit;
            let result = timeout(CONNECTION_TIMEOUT, connection(&mut stream, state, matches)).await;
            let failure = match result {
                Ok(Ok(())) => return,
                Err(_) => "connection_timeout",
                Ok(Err(error)) if error.kind() == io::ErrorKind::TimedOut => "read_timeout",
                Ok(Err(error)) if error.kind() == io::ErrorKind::InvalidData => "invalid_frame",
                Ok(Err(error)) if error.kind() == io::ErrorKind::Other => "internal",
                Ok(Err(_)) => "transport",
            };
            metrics::counter!("enclave_rpc.failures", "class" => failure).increment(1);
            if failure == "internal" {
                tracing::error!(failure_class = failure, "enclave RPC handling failed");
            }
        });
    }
}

/// Reads headers before allocation; rejected concurrent matches are drained in bounded space.
async fn read_frame(
    stream: &mut (impl AsyncRead + Unpin + Send),
    matches: Arc<Semaphore>,
) -> io::Result<Frame> {
    let route = stream.read_u32().await?;
    let maximum = if route == MatchRequest::type_id() {
        MAX_MATCH_CIPHERTEXT_BYTES + 16
    } else if route == HealthRequest::type_id() || route == GetEncryptionKeyRequest::type_id() {
        16
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown route"));
    };
    let length = stream.read_u64().await?;
    if length == 0 || length > maximum as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }

    let match_permit = if route == MatchRequest::type_id() {
        matches.try_acquire_owned().ok()
    } else {
        None
    };
    let mut payload = Vec::new();
    if route == MatchRequest::type_id() && match_permit.is_none() {
        let drained = tokio::io::copy(&mut stream.take(length), &mut tokio::io::sink()).await?;
        if drained != length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "partial busy request",
            ));
        }
    } else {
        payload.resize(
            usize::try_from(length).expect("length checked against usize bound"),
            0,
        );
        stream.read_exact(&mut payload).await?;
    }

    Ok(Frame {
        route,
        payload,
        match_permit,
    })
}

/// Dispatches one frame; only this boundary sees framing or decoding failures.
#[expect(
    clippy::significant_drop_tightening,
    reason = "hold the upload permit through the response"
)]
async fn connection(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    state: Arc<EnclaveState>,
    matches: Arc<Semaphore>,
) -> io::Result<()> {
    let frame = timeout(READ_TIMEOUT, read_frame(stream, matches))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request read timed out"))??;

    if frame.route == HealthRequest::type_id() {
        let request = decode(&frame.payload)?;
        reply(stream, &routes::health::handler(state, request).await).await
    } else if frame.route == GetEncryptionKeyRequest::type_id() {
        let request = decode(&frame.payload)?;
        reply(
            stream,
            &routes::encryption_key::handler(state, request).await,
        )
        .await
    } else if frame.match_permit.is_none() {
        metrics::counter!("enclave_rpc.rejections", "class" => "match_busy").increment(1);
        reply(stream, &Err::<MatchResponse, _>(Error::NotReady)).await
    } else {
        let request = decode(&frame.payload)?;
        drop(frame.payload);
        reply(stream, &routes::matches::handler(state, request).await).await
    }
}

/// A bounded cursor limits binary reads; its position rejects every kind of trailing byte.
fn decode<T: DeserializeOwned>(payload: &[u8]) -> io::Result<T> {
    // The pinned decoder uses take(length).read_to_end, so even a false bin32 length can only
    // copy bytes present in this already bounded frame, never preallocate the claimed size.
    let mut decoder = rmp_serde::Deserializer::new(io::Cursor::new(payload));
    decoder.set_max_depth(16);
    let request = serde::Deserialize::deserialize(&mut decoder)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid request"))?;
    if decoder.position() != payload.len() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing request bytes",
        ));
    }

    Ok(request)
}

/// The pinned client expects one u64 big-endian length and a `MessagePack` response.
async fn reply(
    stream: &mut (impl AsyncWrite + Unpin + Send),
    response: &(impl Serialize + Sync),
) -> io::Result<()> {
    let payload = rmp_serde::to_vec(response).map_err(|_| io::Error::other("response encoding"))?;
    if payload.len() > 64 * 1024 {
        return Err(io::Error::other("response exceeds envelope"));
    }
    stream.write_u64(payload.len() as u64).await?;
    stream.write_all(&payload).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{EchoAttestor, state_with};
    use flamingo_verifier_enclave_types::KeyAttestation;

    /// Sends exactly the framing and codec used by the pinned Pontifex client.
    async fn exchange(route: u32, body: Vec<u8>, matches: Arc<Semaphore>) -> Vec<u8> {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            connection(&mut server, state_with(Arc::new(EchoAttestor)), matches).await
        });

        client.write_u32(route).await.unwrap();
        client.write_u64(body.len() as u64).await.unwrap();
        client.write_all(&body).await.unwrap();
        let length = client.read_u64().await.unwrap();
        assert!(length <= 64 * 1024);
        let mut response = vec![0; usize::try_from(length).unwrap()];
        client.read_exact(&mut response).await.unwrap();
        task.await.unwrap().unwrap();
        response
    }

    /// Both control operations retain their existing type IDs and `MessagePack` response shapes.
    #[tokio::test]
    async fn control_roundtrips_preserve_pontifex_wire_format() {
        let health = exchange(
            HealthRequest::type_id(),
            rmp_serde::to_vec(&HealthRequest).unwrap(),
            Arc::new(Semaphore::new(0)),
        )
        .await;
        assert_eq!(
            rmp_serde::from_slice::<Result<(), Error>>(&health).unwrap(),
            Ok(())
        );

        let key = exchange(
            GetEncryptionKeyRequest::type_id(),
            rmp_serde::to_vec(&GetEncryptionKeyRequest).unwrap(),
            Arc::new(Semaphore::new(1)),
        )
        .await;
        assert!(
            rmp_serde::from_slice::<Result<KeyAttestation, Error>>(&key)
                .unwrap()
                .is_ok()
        );
    }

    /// Admitted matches reach the sealed handler and release admission after a normal error.
    #[tokio::test]
    async fn admitted_match_roundtrips_and_releases_upload_slot() {
        let matches = Arc::new(Semaphore::new(1));
        let response = exchange(
            MatchRequest::type_id(),
            rmp_serde::to_vec(&MatchRequest { body: vec![0; 48] }).unwrap(),
            Arc::clone(&matches),
        )
        .await;

        assert_eq!(
            rmp_serde::from_slice::<Result<MatchResponse, Error>>(&response).unwrap(),
            Err(Error::RequestNotOpened)
        );
        assert_eq!(matches.available_permits(), 1);
    }

    /// Saturation drains the bounded request so a client's write-all can complete before 503.
    #[tokio::test]
    async fn a_busy_upload_returns_not_ready_without_allocating_another_body() {
        let matches = Arc::new(Semaphore::new(1));
        let _held = Arc::clone(&matches).try_acquire_owned().unwrap();
        let response = exchange(
            MatchRequest::type_id(),
            rmp_serde::to_vec(&MatchRequest {
                body: vec![1; 16 * 1024],
            })
            .unwrap(),
            matches,
        )
        .await;
        assert_eq!(
            rmp_serde::from_slice::<Result<MatchResponse, Error>>(&response).unwrap(),
            Err(Error::NotReady)
        );
    }

    /// Untrusted length headers are rejected without waiting for or allocating their bodies.
    #[tokio::test]
    async fn oversized_headers_fail_before_body_reads() {
        for (route, length) in [
            (MatchRequest::type_id(), u64::MAX),
            (
                MatchRequest::type_id(),
                (MAX_MATCH_CIPHERTEXT_BYTES + 17) as u64,
            ),
            (HealthRequest::type_id(), 17),
            (HealthRequest::type_id(), 0),
        ] {
            let (mut client, mut server) = tokio::io::duplex(32);
            client.write_u32(route).await.unwrap();
            client.write_u64(length).await.unwrap();
            let result = timeout(
                Duration::from_secs(1),
                read_frame(&mut server, Arc::new(Semaphore::new(1))),
            )
            .await
            .unwrap()
            .map(|_| ());
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
        }
    }

    /// A slow peer cannot hold an upload slot past the shared read deadline.
    #[tokio::test(start_paused = true)]
    async fn incomplete_frames_release_the_slot_at_the_deadline() {
        let (mut client, mut server) = tokio::io::duplex(32);
        let matches = Arc::new(Semaphore::new(1));
        client.write_u32(MatchRequest::type_id()).await.unwrap();
        client.write_u64(32).await.unwrap();
        client.write_all(&[1, 2]).await.unwrap();

        let started = tokio::time::Instant::now();
        let result = connection(
            &mut server,
            state_with(Arc::new(EchoAttestor)),
            Arc::clone(&matches),
        )
        .await;
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        assert_eq!(started.elapsed(), READ_TIMEOUT);
        assert_eq!(matches.available_permits(), 1);
    }

    /// Byte-array declarations cannot reserve memory beyond the already bounded frame.
    #[test]
    fn malformed_messagepack_byte_lengths_are_rejected() {
        // One-field struct containing bin32 with a claimed u32::MAX byte length.
        let result = decode::<MatchRequest>(&[0x91, 0xc6, 0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    }

    /// Trailing complete objects, invalid markers and truncated objects must all fail closed.
    #[test]
    fn trailing_messagepack_bytes_are_rejected() {
        for extra in [&[0xc0][..], &[0xc1], &[0xc6, 0xff], &[0x91], &[0x81]] {
            let mut payload = rmp_serde::to_vec(&HealthRequest).unwrap();
            payload.extend_from_slice(extra);
            assert!(decode::<HealthRequest>(&payload).is_err());
        }
        assert!(decode::<HealthRequest>(&rmp_serde::to_vec(&HealthRequest).unwrap()).is_ok());
    }

    /// Unknown fields cannot turn the small request shape into an attacker-controlled stack.
    #[test]
    fn excessive_messagepack_nesting_is_rejected() {
        let mut payload = vec![0x82, 0xa4];
        payload.extend_from_slice(b"body");
        payload.extend_from_slice(&[0xc4, 1, 0, 0xa7]);
        payload.extend_from_slice(b"unknown");
        payload.extend_from_slice(&[0x91; 32]);
        payload.push(0xc0);

        assert!(decode::<MatchRequest>(&payload).is_err());
    }
}
