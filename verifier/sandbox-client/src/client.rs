use std::{
    io,
    os::unix::net::UnixStream,
    sync::Arc,
    time::{Duration, Instant},
};

use biometric_engines_protocol::{
    Failure, Request,
    face::{self, face_image::Source},
    failure::Kind,
    protobuf,
    request::Operation,
    response::Outcome,
};

use crate::transport;

/// Replies contain scores or structured failures, never image-sized allocations.
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_READY_BYTES: usize = 64;

/// Broker-owned limits, independent of the worker's more permissive frame reader.
#[derive(Debug, Clone)]
pub struct SandboxClientConfig {
    pub startup_timeout: Duration,
    pub request_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_image_bytes: usize,
}

impl Default for SandboxClientConfig {
    fn default() -> Self {
        Self {
            startup_timeout: Duration::from_secs(120),
            request_timeout: Duration::from_secs(10),
            max_request_bytes: 7 * 1024 * 1024 + 1024,
            max_image_bytes: 4 * 1024 * 1024,
        }
    }
}

impl SandboxClientConfig {
    pub fn validate(&self) -> Result<(), SandboxClientError> {
        if !transport::valid_limits(self.max_request_bytes, self.max_image_bytes)
            || self.max_request_bytes > biometric_engines_protocol::framing::MAX_FRAME_BYTES
            || self.max_image_bytes > face::MAX_IMAGE_BYTES
            || !transport::valid_timeout(self.startup_timeout)
            || !transport::valid_timeout(self.request_timeout)
        {
            return Err(SandboxClientError::InvalidConfig);
        }
        Ok(())
    }
}

/// One exclusive synchronous connection. A fatal failure permanently closes it.
#[derive(Debug)]
pub struct SandboxClient {
    stream: Option<UnixStream>,
    config: SandboxClientConfig,
    failure: Option<SandboxClientError>,
    next_id: u64,
}

impl SandboxClient {
    /// Wait for the upstream versioned readiness frame after spawning the child.
    pub fn new(
        mut stream: UnixStream,
        config: SandboxClientConfig,
    ) -> Result<Self, SandboxClientError> {
        config.validate()?;
        stream
            .set_nonblocking(false)
            .map_err(SandboxClientError::transport)?;
        let ready = transport::read_frame(
            &mut stream,
            MAX_READY_BYTES,
            Instant::now() + config.startup_timeout,
        )
        .map_err(|error| match SandboxClientError::transport(error) {
            SandboxClientError::RequestTimeout => SandboxClientError::StartupTimeout,
            error => error,
        })?;
        if !protobuf::decode_ready(&ready) {
            return Err(SandboxClientError::InvalidReady);
        }
        Ok(Self {
            stream: Some(stream),
            config,
            failure: None,
            next_id: 1,
        })
    }

    #[must_use]
    pub fn failure(&self) -> Option<&SandboxClientError> {
        self.failure.as_ref()
    }

    /// Own this call through completion, including when an async caller is cancelled.
    pub fn evaluate(&mut self, operation: Operation) -> Result<Outcome, SandboxClientError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let deadline = Instant::now() + self.config.request_timeout;
        self.validate_images(&operation)?;
        let kind = match operation {
            Operation::DeepFace(_) => 0,
            Operation::GrayBadge(_) => 1,
            Operation::Embedding(_) => {
                return Err(SandboxClientError::UnsupportedOperation);
            }
        };
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(SandboxClientError::RequestIdExhausted)?;
        let payload = protobuf::encode_request(&Request::new(id, operation));
        if payload.len() > self.config.max_request_bytes {
            return Err(SandboxClientError::InvalidImages);
        }
        let result = self.exchange(&payload, id, kind, deadline);
        if let Err(error) = &result
            && !matches!(error, SandboxClientError::AnalysisFailed(_))
        {
            self.failure = Some(error.clone());
            self.stream.take();
        }
        result
    }

    fn validate_images(&self, operation: &Operation) -> Result<(), SandboxClientError> {
        let image_fields = match operation {
            Operation::DeepFace(r) => vec![&r.credential, &r.live, &r.challenge],
            Operation::GrayBadge(r) => vec![&r.live, &r.challenge],
            Operation::Embedding(_) => return Err(SandboxClientError::UnsupportedOperation),
        };
        let mut total = 0_usize;
        for image in image_fields {
            let source = image
                .as_ref()
                .and_then(|image| image.source.as_ref())
                .ok_or(SandboxClientError::InvalidImages)?;
            let images: &[&[u8]] = match source {
                Source::Orb(bytes) | Source::VanillaSelfie(bytes) | Source::Rtms(bytes) => &[bytes],
                Source::LightGuard(pair) => {
                    if !matches!(
                        face::LightGuardMatchingFrame::try_from(pair.matching_frame),
                        Ok(face::LightGuardMatchingFrame::Illuminated
                            | face::LightGuardMatchingFrame::Unilluminated)
                    ) {
                        return Err(SandboxClientError::InvalidImages);
                    }
                    &[&pair.illuminated, &pair.unilluminated]
                }
            };
            for bytes in images {
                if bytes.is_empty() || bytes.len() > self.config.max_image_bytes {
                    return Err(SandboxClientError::InvalidImages);
                }
                total = total
                    .checked_add(bytes.len())
                    .ok_or(SandboxClientError::InvalidImages)?;
            }
        }
        if total > self.config.max_request_bytes || total > face::MAX_TOTAL_IMAGE_BYTES {
            return Err(SandboxClientError::InvalidImages);
        }
        Ok(())
    }

    fn exchange(
        &mut self,
        payload: &[u8],
        id: u64,
        kind: u8,
        deadline: Instant,
    ) -> Result<Outcome, SandboxClientError> {
        let stream = self
            .stream
            .as_mut()
            .expect("failed clients return before exchange");
        transport::write_frame(stream, payload, deadline).map_err(SandboxClientError::transport)?;
        let bytes = transport::read_frame(stream, MAX_RESPONSE_BYTES, deadline)
            .map_err(SandboxClientError::transport)?;
        let response = protobuf::decode_response(&bytes).map_err(SandboxClientError::protocol)?;
        transport::remaining(deadline).map_err(SandboxClientError::transport)?;
        if response.request_id != id {
            return Err(SandboxClientError::WrongResponse);
        }
        let mut result = response.outcome.ok_or(SandboxClientError::WrongResponse)?;
        let scores = match (&mut result, kind) {
            (Outcome::DeepFace(r), 0) => {
                r.debug_report = None;
                vec![
                    r.similarity_credential_live,
                    r.similarity_credential_challenge,
                    r.similarity_live_challenge,
                ]
            }
            (Outcome::GrayBadge(r), 1) => {
                r.debug_report = None;
                vec![r.similarity_live_challenge]
            }
            (Outcome::Failure(failure), _) => {
                if let Some(Kind::Face(error)) = &mut failure.kind {
                    error.debug_report = None;
                    if error.code != face::FailureCode::Internal as i32 {
                        return Err(SandboxClientError::AnalysisFailed(error.clone()));
                    }
                }
                return Err(SandboxClientError::protocol(failure.clone()));
            }
            _ => return Err(SandboxClientError::WrongResponse),
        };
        if scores
            .iter()
            .any(|s| !s.is_some_and(|s| s.is_finite() && (-1.0..=1.0).contains(&s)))
        {
            return Err(SandboxClientError::InvalidScore);
        }
        Ok(result)
    }
}

/// Payload-free errors; only input/biological failures leave the connection reusable.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SandboxClientError {
    #[error("worker protocol failure")]
    Protocol(Failure),
    #[error("worker socket I/O failed: {0}")]
    Transport(Arc<io::Error>),
    #[error("invalid worker client configuration")]
    InvalidConfig,
    #[error("worker images violate byte limits")]
    InvalidImages,
    #[error("worker request timed out")]
    RequestTimeout,
    #[error("worker startup timed out")]
    StartupTimeout,
    #[error("invalid worker readiness frame")]
    InvalidReady,
    #[error("worker returned an invalid similarity score")]
    InvalidScore,
    #[error("worker response ID or operation did not match")]
    WrongResponse,
    #[error("worker image analysis failed")]
    AnalysisFailed(face::Failure),
    #[error("worker operation is not enabled")]
    UnsupportedOperation,
    #[error("worker request IDs exhausted")]
    RequestIdExhausted,
}

impl SandboxClientError {
    fn protocol(mut failure: Failure) -> Self {
        if let Some(Kind::Face(error)) = &mut failure.kind {
            error.debug_report = None;
        }
        Self::Protocol(failure)
    }

    fn transport(error: io::Error) -> Self {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            Self::RequestTimeout
        } else {
            Self::Transport(Arc::new(error))
        }
    }
}
