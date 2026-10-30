//! Internal Flamingo verifier/engine IPC, carried in Tabernaculum length-prefixed frames.
//!
//! Requests carry an unmodified canonical `world_id_flamingo::Payload` encoding. The caller
//! and engine use that crate directly to validate it; this crate only defines the envelope.
//! Readiness is `FLAMINGO` followed by the version byte. Requests are a nonzero big-endian
//! u64 ID followed by payload bytes. Responses are that ID, one verdict byte (0 = Pass,
//! 1..=6 = ErrorCode), a report-presence byte (0/1), then optional UTF-8 report bytes.
//! Version or framing failures are terminal. Ordinary engine rejections are responses.
//!
//! The verdict and error code bytes are fixed by [`PROTOCOL_VERSION`]. Decoders reject any value
//! they do not know, so adding or changing a code requires a version bump and deploying the
//! verifier and engine together.

pub mod framing;

/// This application protocol is independent of Tabernaculum's bootstrap protocol.
pub const PROTOCOL_VERSION: u8 = 1;
/// Hard IPC ceiling; the verifier additionally enforces the selected manifest's limits.
pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
/// Payload and correlation ID, excluding the frame's four-byte length prefix.
pub const MAX_REQUEST_BYTES: usize = 8 + MAX_PAYLOAD_BYTES;
/// WIP-201 maximum optional report size.
pub const MAX_DEBUG_REPORT_BYTES: usize = 65_536;
/// ID, verdict, report-presence flag and bounded report.
pub const MAX_RESPONSE_BYTES: usize = 10 + MAX_DEBUG_REPORT_BYTES;
/// Exact startup message length.
pub const MAX_READY_BYTES: usize = 9;
const READY: &[u8; MAX_READY_BYTES] = b"FLAMINGO\x01";

/// Bounded engine errors, with no biometric values or diagnostic strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    /// Invalid canonical payload, entry layout or encoded inputs.
    InvalidPayload = 1,
    /// Pipeline or its metadata/hints are unsupported.
    UnsupportedPipeline = 2,
    /// The engine release does not define this strictness.
    UnsupportedMatchStrictness = 3,
    /// Input analysis or fraud checks rejected the request.
    BiometricRejected = 4,
    /// A required comparison failed the release's matching policy.
    MatchRejected = 5,
    /// Engine fault; the verifier must retire this instance.
    Internal = 6,
}

impl TryFrom<u8> for ErrorCode {
    type Error = CodecError;

    fn try_from(byte: u8) -> Result<Self, CodecError> {
        match byte {
            1 => Ok(Self::InvalidPayload),
            2 => Ok(Self::UnsupportedPipeline),
            3 => Ok(Self::UnsupportedMatchStrictness),
            4 => Ok(Self::BiometricRejected),
            5 => Ok(Self::MatchRejected),
            6 => Ok(Self::Internal),
            _ => Err(CodecError::Malformed),
        }
    }
}

/// Only Pass allows the verifier to issue a Flamingo token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Error(ErrorCode),
}

impl Verdict {
    /// Whether the engine instance must be retired after this verdict.
    ///
    /// Both sides apply this: the engine exits after sending it and the verifier discards the
    /// response, never producing a verdict from it. Every other error leaves the engine usable.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        self == Self::Error(ErrorCode::Internal)
    }
}

/// One response. Debug deliberately hides report contents.
#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    pub request_id: u64,
    pub verdict: Verdict,
    /// Optional engine report; neither scores nor embeddings belong in the verdict.
    pub debug_report: Option<String>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("request_id", &self.request_id)
            .field("verdict", &self.verdict)
            .field("report_bytes", &self.debug_report.as_ref().map(String::len))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("malformed engine IPC envelope")]
    Malformed,
    #[error("engine IPC message exceeds its size limit")]
    TooLarge,
}

#[must_use]
pub fn encode_ready() -> Vec<u8> {
    debug_assert_eq!(READY[8], PROTOCOL_VERSION);
    READY.to_vec()
}

#[must_use]
pub fn decode_ready(bytes: &[u8]) -> bool {
    bytes == READY
}

/// Wraps existing payload bytes without parsing, copying fields or re-encoding them.
pub fn encode_request(request_id: u64, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    if request_id == 0 || payload.is_empty() {
        return Err(CodecError::Malformed);
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(CodecError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(8 + payload.len());
    bytes.extend_from_slice(&request_id.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub fn decode_request(bytes: &[u8]) -> Result<(u64, &[u8]), CodecError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(CodecError::TooLarge);
    }
    let (id, payload) = bytes.split_at_checked(8).ok_or(CodecError::Malformed)?;
    let id = request_id(id)?;
    if payload.is_empty() {
        return Err(CodecError::Malformed);
    }
    Ok((id, payload))
}

pub fn encode_response(response: &Response) -> Result<Vec<u8>, CodecError> {
    if response.request_id == 0 {
        return Err(CodecError::Malformed);
    }
    let report = response
        .debug_report
        .as_deref()
        .unwrap_or_default()
        .as_bytes();
    if report.len() > MAX_DEBUG_REPORT_BYTES {
        return Err(CodecError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(10 + report.len());
    bytes.extend_from_slice(&response.request_id.to_be_bytes());
    bytes.push(match response.verdict {
        Verdict::Pass => 0,
        Verdict::Error(code) => code as u8,
    });
    bytes.push(u8::from(response.debug_report.is_some()));
    bytes.extend_from_slice(report);
    Ok(bytes)
}

pub fn decode_response(bytes: &[u8]) -> Result<Response, CodecError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(CodecError::TooLarge);
    }
    let (header, report) = bytes.split_at_checked(10).ok_or(CodecError::Malformed)?;
    let request_id = request_id(&header[..8])?;
    let verdict = match header[8] {
        0 => Verdict::Pass,
        code => Verdict::Error(ErrorCode::try_from(code)?),
    };
    let debug_report = match header[9] {
        0 if report.is_empty() => None,
        1 => Some(
            std::str::from_utf8(report)
                .map_err(|_| CodecError::Malformed)?
                .to_owned(),
        ),
        _ => return Err(CodecError::Malformed),
    };
    Ok(Response {
        request_id,
        verdict,
        debug_report,
    })
}

fn request_id(bytes: &[u8]) -> Result<u64, CodecError> {
    let id = u64::from_be_bytes(bytes.try_into().map_err(|_| CodecError::Malformed)?);
    if id == 0 {
        Err(CodecError::Malformed)
    } else {
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_rejects_legacy_versions_and_trailing_bytes() {
        assert!(decode_ready(&encode_ready()));
        for bytes in [
            &b"\x08\x01"[..],
            b"FLAMINGO\x00",
            b"FLAMINGO\x02",
            b"FLAMINGO\x01\x00",
        ] {
            assert!(!decode_ready(bytes));
        }
    }

    #[test]
    fn payload_bytes_and_correlation_survive_unchanged() {
        let payload = b"canonical CBOR belongs to world-id-flamingo";
        let wire = encode_request(0x0102030405060708, payload).unwrap();
        assert_eq!(&wire[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            decode_request(&wire).unwrap(),
            (0x0102030405060708, &payload[..])
        );
        assert_eq!(encode_request(0, payload), Err(CodecError::Malformed));
        assert_eq!(encode_request(1, b""), Err(CodecError::Malformed));
        assert_eq!(decode_request(&[0; 9]), Err(CodecError::Malformed));
        assert_eq!(decode_request(&[1; 8]), Err(CodecError::Malformed));
        let payload = vec![1; MAX_PAYLOAD_BYTES];
        assert!(decode_request(&encode_request(1, &payload).unwrap()).is_ok());
        assert_eq!(
            encode_request(1, &vec![0; MAX_PAYLOAD_BYTES + 1]),
            Err(CodecError::TooLarge)
        );
        assert_eq!(
            decode_request(&vec![0; MAX_REQUEST_BYTES + 1]),
            Err(CodecError::TooLarge)
        );
    }

    #[test]
    fn verdicts_and_optional_reports_round_trip() {
        for verdict in [
            Verdict::Pass,
            Verdict::Error(ErrorCode::InvalidPayload),
            Verdict::Error(ErrorCode::UnsupportedPipeline),
            Verdict::Error(ErrorCode::UnsupportedMatchStrictness),
            Verdict::Error(ErrorCode::BiometricRejected),
            Verdict::Error(ErrorCode::MatchRejected),
            Verdict::Error(ErrorCode::Internal),
        ] {
            for debug_report in [
                None,
                Some(String::new()),
                Some("{\"status\":\"rejected\"}".into()),
                Some("x".repeat(MAX_DEBUG_REPORT_BYTES)),
            ] {
                let response = Response {
                    request_id: 1,
                    verdict,
                    debug_report,
                };
                assert_eq!(
                    decode_response(&encode_response(&response).unwrap()).unwrap(),
                    response
                );
            }
        }
    }

    #[test]
    fn invalid_or_oversized_responses_fail_closed() {
        let response = Response {
            request_id: 1,
            verdict: Verdict::Pass,
            debug_report: None,
        };
        let wire = encode_response(&response).unwrap();
        for length in 0..wire.len() {
            assert!(decode_response(&wire[..length]).is_err());
        }
        for (index, value) in [(8, 7), (9, 2)] {
            let mut invalid = wire.clone();
            invalid[index] = value;
            assert_eq!(decode_response(&invalid), Err(CodecError::Malformed));
        }
        let mut invalid = wire.clone();
        invalid.push(1);
        assert_eq!(decode_response(&invalid), Err(CodecError::Malformed));
        invalid[9] = 1;
        invalid[10] = 255;
        assert_eq!(decode_response(&invalid), Err(CodecError::Malformed));
        let oversized = Response {
            debug_report: Some("x".repeat(MAX_DEBUG_REPORT_BYTES + 1)),
            ..response.clone()
        };
        assert_eq!(encode_response(&oversized), Err(CodecError::TooLarge));
        assert_eq!(
            decode_response(&vec![0; MAX_RESPONSE_BYTES + 1]),
            Err(CodecError::TooLarge)
        );
        assert!(
            encode_response(&Response {
                request_id: 0,
                ..response
            })
            .is_err()
        );
    }

    #[test]
    fn error_codes_match_their_wire_bytes() {
        for byte in 0..=u8::MAX {
            match ErrorCode::try_from(byte) {
                Ok(code) => assert_eq!(code as u8, byte),
                Err(error) => {
                    assert_eq!(error, CodecError::Malformed);
                    assert!(!(1..=6).contains(&byte));
                }
            }
        }
    }

    #[test]
    fn only_internal_errors_are_terminal() {
        assert!(!Verdict::Pass.is_terminal());
        for byte in 1..=5 {
            let code = ErrorCode::try_from(byte).unwrap();
            assert!(!Verdict::Error(code).is_terminal());
        }
        assert!(Verdict::Error(ErrorCode::Internal).is_terminal());
    }

    #[test]
    fn debug_does_not_expose_report_contents() {
        let response = Response {
            request_id: 1,
            verdict: Verdict::Pass,
            debug_report: Some("private biometric report".into()),
        };
        assert!(!format!("{response:?}").contains("private biometric"));
    }
}
