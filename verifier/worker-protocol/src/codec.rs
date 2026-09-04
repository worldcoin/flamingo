use std::io::{self, Write};

use serde::{Serialize, de::DeserializeOwned};

use crate::WorkerProtocolError;

/// Serialization sink that rejects writes beyond its byte budget.
struct BoundedBuffer {
    /// Encoded bytes accepted so far.
    bytes: Vec<u8>,
    /// Unused byte budget.
    remaining: usize,
    /// Distinguishes a limit violation from other serialization failures.
    exceeded: bool,
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other("payload limit exceeded"));
        }

        self.bytes.extend_from_slice(bytes);
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Encodes CBOR without extending the payload beyond `max_bytes`.
///
/// # Errors
/// Rejects zero limits, oversized values, and serialization failures.
pub fn encode_message<T: Serialize>(
    message: &T,
    max_bytes: usize,
) -> Result<Vec<u8>, WorkerProtocolError> {
    if max_bytes == 0 {
        return Err(WorkerProtocolError::InvalidLimit);
    }

    let mut buffer = BoundedBuffer {
        bytes: Vec::new(),
        remaining: max_bytes,
        exceeded: false,
    };
    if ciborium::into_writer(message, &mut buffer).is_err() {
        return Err(if buffer.exceeded {
            WorkerProtocolError::TooLarge
        } else {
            WorkerProtocolError::Encoding
        });
    }

    Ok(buffer.bytes)
}

/// Decodes one bounded CBOR value with at most 16 levels of nesting.
///
/// # Errors
/// Rejects zero limits, oversized/truncated/malformed values, and trailing bytes.
pub fn decode_message<T: DeserializeOwned>(
    payload: &[u8],
    max_bytes: usize,
) -> Result<T, WorkerProtocolError> {
    if max_bytes == 0 {
        return Err(WorkerProtocolError::InvalidLimit);
    }
    if payload.len() > max_bytes {
        return Err(WorkerProtocolError::TooLarge);
    }

    let mut remaining = payload;
    let message = ciborium::de::from_reader_with_recursion_limit(&mut remaining, 16)
        .map_err(|_| WorkerProtocolError::Malformed)?;
    if !remaining.is_empty() {
        return Err(WorkerProtocolError::Malformed);
    }

    Ok(message)
}
