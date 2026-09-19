use std::{
    io,
    os::unix::net::UnixStream,
    sync::Arc,
    time::{Duration, Instant},
};

use biometric_engines_protocol::{
    Failure, Operation, Request, ResponseBody,
    face::{self, FaceImagePayload, LiveCapture},
    protobuf,
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
    pub fn evaluate(&mut self, operation: Operation) -> Result<ResponseBody, SandboxClientError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let deadline = Instant::now() + self.config.request_timeout;
        self.validate_images(&operation)?;
        let kind = match operation {
            Operation::DeepFace(_) => 0,
            Operation::GrayBadge(_) => 1,
            Operation::GenerateEmbedding(_) => {
                return Err(SandboxClientError::UnsupportedOperation);
            }
        };
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(SandboxClientError::RequestIdExhausted)?;
        let payload = protobuf::encode_request(Request {
            request_id: id,
            operation,
        })
        .map_err(SandboxClientError::RequestEncoding)?;
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
        let mut images = Vec::with_capacity(4);
        let live = match operation {
            Operation::DeepFace(r) => {
                images.extend([&r.orb_credential, &r.rtms_challenge]);
                Some(&r.live)
            }
            Operation::GrayBadge(r) => {
                images.push(&r.rtms_challenge);
                Some(&r.live)
            }
            Operation::GenerateEmbedding(r) => {
                match &r.image {
                    FaceImagePayload::OrbCredential(i)
                    | FaceImagePayload::VanillaSelfie(i)
                    | FaceImagePayload::RtmsChallenge(i) => images.push(i),
                    FaceImagePayload::LightGuardSelfie {
                        illuminated,
                        unilluminated,
                        ..
                    } => images.extend([illuminated, unilluminated]),
                }
                None
            }
        };
        match live {
            Some(LiveCapture::Vanilla(i)) => images.push(i),
            Some(LiveCapture::LightGuard {
                illuminated,
                unilluminated,
                ..
            }) => images.extend([illuminated, unilluminated]),
            None => {}
        }
        if images
            .iter()
            .any(|i| i.0.is_empty() || i.0.len() > self.config.max_image_bytes)
            || images.iter().map(|i| i.0.len()).sum::<usize>() > self.config.max_request_bytes
        {
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
    ) -> Result<ResponseBody, SandboxClientError> {
        let stream = self
            .stream
            .as_mut()
            .expect("failed clients return before exchange");
        transport::write_frame(stream, payload, deadline).map_err(SandboxClientError::transport)?;
        let bytes = transport::read_frame(stream, MAX_RESPONSE_BYTES, deadline)
            .map_err(SandboxClientError::transport)?;
        let response = protobuf::decode_response(&bytes).map_err(SandboxClientError::Protocol)?;
        transport::remaining(deadline).map_err(SandboxClientError::transport)?;
        if response.request_id != id {
            return Err(SandboxClientError::WrongResponse);
        }
        let result = match response.outcome {
            Ok(result) => result,
            Err(Failure::Face(error)) if error.code != face::FailureCode::Internal => {
                return Err(SandboxClientError::AnalysisFailed(error));
            }
            Err(error) => return Err(SandboxClientError::Protocol(error)),
        };
        let scores = match (&result, kind) {
            (ResponseBody::DeepFace(r), 0) => vec![
                r.similarity_orb_selfie,
                r.similarity_orb_challenge,
                r.similarity_selfie_challenge,
            ],
            (ResponseBody::GrayBadge(r), 1) => vec![r.similarity_selfie_challenge],
            _ => return Err(SandboxClientError::WrongResponse),
        };
        if scores
            .iter()
            .any(|s| !s.is_finite() || !(-1.0..=1.0).contains(s))
        {
            return Err(SandboxClientError::InvalidScore);
        }
        Ok(result)
    }
}

/// Payload-free errors; only input/biological failures leave the connection reusable.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SandboxClientError {
    #[error("worker request encoding failed: {0}")]
    RequestEncoding(Failure),
    #[error("worker protocol failure: {0}")]
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
    #[error("worker image analysis failed: {0}")]
    AnalysisFailed(face::Failure),
    #[error("worker operation is not enabled")]
    UnsupportedOperation,
    #[error("worker request IDs exhausted")]
    RequestIdExhausted,
}

impl SandboxClientError {
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
