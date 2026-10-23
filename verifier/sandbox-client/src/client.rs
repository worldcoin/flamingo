// Only the Linux worker drives the codec; elsewhere it is built for its tests.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use flamingo_engine_interface::{self as ipc, ErrorCode, Response, Verdict};
use tabernaculum::ConnectionConfig;

/// Framing limits for canonical Payload bytes. Image and pipeline policy belong to the Engine.
#[derive(Debug, Clone, Copy)]
pub struct EngineLimits {
    pub max_payload_bytes: usize,
}

impl EngineLimits {
    pub fn validate(&self) -> Result<(), SandboxClientError> {
        if self.max_payload_bytes == 0 || self.max_payload_bytes > ipc::MAX_PAYLOAD_BYTES {
            return Err(SandboxClientError::InvalidConfig);
        }
        Ok(())
    }

    /// The worker connection for these limits, with tabernaculum's default timeouts.
    pub fn connection(&self) -> Result<ConnectionConfig, SandboxClientError> {
        self.validate()?;
        Ok(ConnectionConfig {
            max_ready_bytes: ipc::MAX_READY_BYTES,
            max_request_bytes: self.max_payload_bytes + 8,
            max_response_bytes: ipc::MAX_RESPONSE_BYTES,
            ..ConnectionConfig::default()
        })
    }
}

/// One exclusive worker. Every failure other than a [`Rejection`] ends the enclave.
#[cfg(target_os = "linux")]
pub struct SandboxClient {
    worker: tabernaculum::Worker,
    limits: EngineLimits,
    next_id: u64,
}

#[cfg(target_os = "linux")]
impl SandboxClient {
    /// Takes a spawned worker and its readiness frame. Dropping on error kills the worker.
    pub fn new(
        worker: tabernaculum::Worker,
        ready: &[u8],
        limits: EngineLimits,
    ) -> Result<Self, SandboxClientError> {
        limits.validate()?;
        if !ipc::decode_ready(ready) {
            return Err(SandboxClientError::InvalidReady);
        }
        Ok(Self {
            worker,
            limits,
            next_id: 1,
        })
    }

    /// Detects idle worker exits; a dead worker ends the enclave.
    pub fn check_alive(&self) {
        self.worker.check_alive();
    }

    /// Sends the original canonical Payload bytes; no request context or signing keys cross IPC.
    /// Returns success or a recoverable rejection; any other failure ends the enclave.
    #[tracing::instrument(skip_all, fields(dependency = "biometric_worker"))]
    pub fn evaluate(&mut self, payload: &[u8]) -> Result<Option<String>, Rejection> {
        if payload.is_empty() || payload.len() > self.limits.max_payload_bytes {
            return Err(Rejection::InvalidPayload);
        }
        let id = self.next_id;
        let Some(next_id) = id.checked_add(1) else {
            self.fail(&Violation::RequestIdExhausted)
        };
        self.next_id = next_id;
        let request = ipc::encode_request(id, payload).map_err(|_| Rejection::InvalidPayload)?;
        // Only an unsent, oversized request returns here; transport failures are fatal.
        let response = self
            .worker
            .exchange(&request)
            .map_err(|_| Rejection::InvalidPayload)?;
        match decode(&response, id) {
            Ok(response) => match response.verdict {
                Verdict::Pass => Ok(response.debug_report),
                Verdict::Error(code) => Err(Rejection::Engine {
                    code,
                    debug_report: response.debug_report,
                }),
            },
            Err(violation) => self.fail(&violation),
        }
    }

    fn fail(&mut self, violation: &Violation) -> ! {
        tracing::error!(dependency = "biometric_worker", %violation, "worker response rejected");
        self.worker.fail()
    }
}

/// Checks one response. Infrastructure failures invalidate this worker, never produce a verdict.
fn decode(bytes: &[u8], id: u64) -> Result<Response, Violation> {
    let response = ipc::decode_response(bytes).map_err(|_| Violation::Protocol)?;
    if response.request_id != id {
        return Err(Violation::WrongResponse);
    }
    if response.verdict == Verdict::Error(ErrorCode::Internal) {
        return Err(Violation::Protocol);
    }
    Ok(response)
}

/// Client setup failures, before any request is sent.
#[derive(Debug, thiserror::Error)]
pub enum SandboxClientError {
    #[error("invalid worker client configuration")]
    InvalidConfig,
    #[error("invalid worker readiness frame")]
    InvalidReady,
}

/// Recoverable per-request failures; reports are redacted from Debug.
#[derive(Clone, thiserror::Error)]
pub enum Rejection {
    #[error("worker payload violates byte limits")]
    InvalidPayload,
    #[error("worker rejected the payload ({code:?})")]
    Engine {
        code: ErrorCode,
        debug_report: Option<String>,
    },
}

impl std::fmt::Debug for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[derive(Debug, thiserror::Error)]
enum Violation {
    #[error("worker protocol or internal failure")]
    Protocol,
    #[error("worker response ID did not match")]
    WrongResponse,
    #[error("worker request IDs exhausted")]
    RequestIdExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_apply_before_worker_allocation() {
        for max_payload_bytes in [0, ipc::MAX_PAYLOAD_BYTES + 1, usize::MAX] {
            assert!(EngineLimits { max_payload_bytes }.connection().is_err());
        }
        let config = EngineLimits {
            max_payload_bytes: 4096,
        }
        .connection()
        .unwrap();
        assert_eq!(config.max_request_bytes, 4104);
        assert_eq!(config.max_response_bytes, ipc::MAX_RESPONSE_BYTES);
    }

    #[test]
    fn only_a_correlated_success_can_pass() {
        let response = Response {
            request_id: 7,
            verdict: Verdict::Pass,
            debug_report: None,
        };
        let bytes = ipc::encode_response(&response).unwrap();
        assert_eq!(decode(&bytes, 7).unwrap(), response);
        assert!(decode(&bytes, 8).is_err());
        assert!(decode(&bytes[..bytes.len() - 1], 7).is_err());
    }

    #[test]
    fn semantic_rejections_survive_but_internal_errors_are_terminal() {
        for code in [
            ErrorCode::InvalidPayload,
            ErrorCode::UnsupportedPipeline,
            ErrorCode::UnsupportedMatchStrictness,
            ErrorCode::BiometricRejected,
            ErrorCode::MatchRejected,
        ] {
            let response = Response {
                request_id: 1,
                verdict: Verdict::Error(code),
                debug_report: Some("private".into()),
            };
            assert_eq!(
                decode(&ipc::encode_response(&response).unwrap(), 1).unwrap(),
                response
            );
            assert!(
                !format!(
                    "{:?}",
                    Rejection::Engine {
                        code,
                        debug_report: response.debug_report
                    }
                )
                .contains("private")
            );
        }
        let response = Response {
            request_id: 1,
            verdict: Verdict::Error(ErrorCode::Internal),
            debug_report: None,
        };
        assert!(decode(&ipc::encode_response(&response).unwrap(), 1).is_err());
    }
}
