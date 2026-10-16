// Only the Linux worker drives the codec; elsewhere it is built for its tests.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use biometric_engines_protocol::{
    face::{self, face_image::Source},
    failure::Kind,
    protobuf,
    request::Operation,
    response::Outcome,
};
use tabernaculum::ConnectionConfig;

/// Allows worker diagnostics (LightGuard rejections exceed 40 KiB).
/// Keep allocation bounded before reading the response body.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_READY_BYTES: usize = 64;

/// Enclave-owned face limits, independent of the worker's more permissive frame reader.
#[derive(Debug, Clone, Copy)]
pub struct FaceLimits {
    pub max_request_bytes: usize,
    pub max_image_bytes: usize,
}

impl FaceLimits {
    pub fn validate(&self) -> Result<(), SandboxClientError> {
        if self.max_image_bytes == 0
            || self.max_image_bytes > self.max_request_bytes
            || u32::try_from(self.max_request_bytes).is_err()
            || self.max_request_bytes > biometric_engines_protocol::framing::MAX_FRAME_BYTES
            || self.max_image_bytes > face::MAX_IMAGE_BYTES
        {
            return Err(SandboxClientError::InvalidConfig);
        }

        Ok(())
    }

    /// The worker connection for these limits, with tabernaculum's default timeouts.
    pub fn connection(&self) -> Result<ConnectionConfig, SandboxClientError> {
        self.validate()?;
        Ok(ConnectionConfig {
            max_ready_bytes: MAX_READY_BYTES,
            max_request_bytes: self.max_request_bytes,
            max_response_bytes: MAX_RESPONSE_BYTES,
            ..ConnectionConfig::default()
        })
    }
}

/// One exclusive worker. Every failure other than a [`Rejection`] ends the enclave.
#[cfg(target_os = "linux")]
pub struct SandboxClient {
    worker: tabernaculum::Worker,
    limits: FaceLimits,
    next_id: u64,
}

#[cfg(target_os = "linux")]
impl SandboxClient {
    /// Takes a spawned worker and its readiness frame. Dropping on error kills the worker.
    pub fn new(
        worker: tabernaculum::Worker,
        ready: &[u8],
        limits: FaceLimits,
    ) -> Result<Self, SandboxClientError> {
        limits.validate()?;
        if !protobuf::decode_ready(ready) {
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

    /// Returns success or a recoverable rejection; any other failure ends the enclave.
    #[tracing::instrument(skip_all, fields(dependency = "biometric_worker"))]
    pub fn evaluate(&mut self, operation: Operation) -> Result<Outcome, Rejection> {
        let Some(expected) = Expected::of(&operation) else {
            self.fail(&Violation::UnsupportedOperation)
        };
        validate_images(&self.limits, &operation)?;
        let id = self.next_id;
        let Some(next_id) = id.checked_add(1) else {
            self.fail(&Violation::RequestIdExhausted)
        };
        self.next_id = next_id;
        let request =
            protobuf::encode_request(&biometric_engines_protocol::Request::new(id, operation));
        if request.len() > self.limits.max_request_bytes {
            return Err(Rejection::InvalidImages);
        }

        // Only an unsent, oversized request returns here; transport failures are fatal.
        let response = self
            .worker
            .exchange(&request)
            .map_err(|_| Rejection::InvalidImages)?;
        match decode(&response, id, expected) {
            Ok(result) => result,
            Err(violation) => self.fail(&violation),
        }
    }

    fn fail(&mut self, violation: &Violation) -> ! {
        tracing::error!(dependency = "biometric_worker", %violation, "worker response rejected");
        self.worker.fail()
    }
}

/// The response operation a request expects.
#[derive(Clone, Copy)]
enum Expected {
    DeepFace,
    GrayBadge,
}

impl Expected {
    const fn of(operation: &Operation) -> Option<Self> {
        match operation {
            Operation::DeepFace(_) => Some(Self::DeepFace),
            Operation::GrayBadge(_) => Some(Self::GrayBadge),
            Operation::Embedding(_) => None,
        }
    }
}

/// Checks every image locally, before anything reaches the worker.
fn validate_images(limits: &FaceLimits, operation: &Operation) -> Result<(), Rejection> {
    let image_fields = match operation {
        Operation::DeepFace(r) => vec![&r.credential, &r.live, &r.challenge],
        Operation::GrayBadge(r) => vec![&r.live, &r.challenge],
        Operation::Embedding(_) => return Err(Rejection::InvalidImages),
    };
    let mut total = 0_usize;
    for image in image_fields {
        let source = image
            .as_ref()
            .and_then(|image| image.source.as_ref())
            .ok_or(Rejection::InvalidImages)?;
        let images: &[&[u8]] = match source {
            Source::Orb(bytes) | Source::VanillaSelfie(bytes) | Source::Rtms(bytes) => &[bytes],
            Source::LightGuard(pair) => {
                if !matches!(
                    face::LightGuardMatchingFrame::try_from(pair.matching_frame),
                    Ok(face::LightGuardMatchingFrame::Illuminated
                        | face::LightGuardMatchingFrame::Unilluminated)
                ) {
                    return Err(Rejection::InvalidImages);
                }
                &[&pair.illuminated, &pair.unilluminated]
            }
        };
        for bytes in images {
            if bytes.is_empty() || bytes.len() > limits.max_image_bytes {
                return Err(Rejection::InvalidImages);
            }
            total = total
                .checked_add(bytes.len())
                .ok_or(Rejection::InvalidImages)?;
        }
    }

    if total > limits.max_request_bytes || total > face::MAX_TOTAL_IMAGE_BYTES {
        return Err(Rejection::InvalidImages);
    }

    Ok(())
}

/// Checks one response. The outer error means the worker can no longer be trusted.
fn decode(
    bytes: &[u8],
    id: u64,
    expected: Expected,
) -> Result<Result<Outcome, Rejection>, Violation> {
    let response = protobuf::decode_response(bytes).map_err(|_| Violation::Protocol)?;
    if response.request_id != id {
        return Err(Violation::WrongResponse);
    }

    let result = response.outcome.ok_or(Violation::WrongResponse)?;
    let scores = match (&result, expected) {
        (Outcome::DeepFace(r), Expected::DeepFace) => vec![
            r.similarity_credential_live,
            r.similarity_credential_challenge,
            r.similarity_live_challenge,
        ],
        (Outcome::GrayBadge(r), Expected::GrayBadge) => vec![r.similarity_live_challenge],
        (Outcome::Failure(failure), _) => {
            return match &failure.kind {
                Some(Kind::Face(error)) if error.code != face::FailureCode::Internal as i32 => {
                    Ok(Err(Rejection::AnalysisFailed(error.clone())))
                }
                _ => Err(Violation::Protocol),
            };
        }
        _ => return Err(Violation::WrongResponse),
    };
    if scores
        .iter()
        .any(|s| !s.is_some_and(|s| s.is_finite() && (-1.0..=1.0).contains(&s)))
    {
        return Err(Violation::InvalidScore);
    }

    Ok(Ok(result))
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
    #[error("worker images violate byte limits")]
    InvalidImages,
    #[error("worker image analysis failed")]
    AnalysisFailed(face::Failure),
}

impl std::fmt::Debug for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Error diagnostics must not expose worker reports in logs.
        std::fmt::Display::fmt(self, f)
    }
}

/// Fatal response or request violations; logged without worker reports, then the worker fails.
#[derive(Debug, thiserror::Error)]
enum Violation {
    #[error("worker protocol failure")]
    Protocol,
    #[error("worker returned an invalid similarity score")]
    InvalidScore,
    #[error("worker response ID or operation did not match")]
    WrongResponse,
    #[error("worker operation is not enabled")]
    UnsupportedOperation,
    #[error("worker request IDs exhausted")]
    RequestIdExhausted,
}

#[cfg(test)]
mod tests {
    use biometric_engines_protocol::{
        EmptyReason, Response,
        face::{
            DeepFaceRequest, DeepFaceResult, FaceImage, Failure as FaceFailure, FailureCode,
            GrayBadgeResult, ImageRole, LightGuard, LightGuardMatchingFrame, ValidationReason,
            ValidationTarget,
        },
        protocol_failure,
    };

    use super::*;

    fn limits() -> FaceLimits {
        FaceLimits {
            max_request_bytes: 4096,
            max_image_bytes: 100,
        }
    }

    fn request() -> Operation {
        Operation::DeepFace(DeepFaceRequest {
            credential: Some(FaceImage {
                source: Some(Source::Orb(vec![1])),
            }),
            live: Some(FaceImage {
                source: Some(Source::VanillaSelfie(vec![2])),
            }),
            challenge: Some(FaceImage {
                source: Some(Source::Rtms(vec![3])),
            }),
        })
    }

    fn scores() -> Outcome {
        Outcome::DeepFace(DeepFaceResult {
            similarity_credential_live: Some(0.8),
            similarity_credential_challenge: Some(0.9),
            similarity_live_challenge: Some(0.85),
            debug_report: None,
        })
    }

    fn encoded(id: u64, outcome: Outcome) -> Vec<u8> {
        protobuf::encode_response(&Response::new(id, outcome))
    }

    #[test]
    fn readiness_requires_a_compatible_frame() {
        assert!(protobuf::decode_ready(&protobuf::encode_ready()));
        for bytes in [&[][..], &[8, 2], b"FWR1"] {
            assert!(!protobuf::decode_ready(bytes));
        }
        assert!(protobuf::encode_ready().len() <= MAX_READY_BYTES);
    }

    #[test]
    fn limits_must_fit_the_protocol() {
        limits().validate().unwrap();
        let connection = limits().connection().unwrap();
        assert_eq!(connection.max_request_bytes, 4096);
        assert_eq!(connection.max_response_bytes, MAX_RESPONSE_BYTES);
        connection.validate().unwrap();
        for invalid in [
            FaceLimits {
                max_image_bytes: 0,
                ..limits()
            },
            FaceLimits {
                max_image_bytes: 4097,
                ..limits()
            },
            FaceLimits {
                max_request_bytes: biometric_engines_protocol::framing::MAX_FRAME_BYTES + 1,
                max_image_bytes: 100,
            },
            FaceLimits {
                max_request_bytes: biometric_engines_protocol::framing::MAX_FRAME_BYTES,
                max_image_bytes: face::MAX_IMAGE_BYTES + 1,
            },
        ] {
            assert!(matches!(
                invalid.connection(),
                Err(SandboxClientError::InvalidConfig)
            ));
        }
    }

    #[test]
    fn deepface_graybadge_and_typed_biological_failure_decode() {
        assert_eq!(
            decode(&encoded(1, scores()), 1, Expected::DeepFace)
                .unwrap()
                .unwrap(),
            scores()
        );
        let gray = Outcome::GrayBadge(GrayBadgeResult {
            similarity_live_challenge: Some(0.7),
            debug_report: None,
        });
        assert_eq!(
            decode(&encoded(2, gray.clone()), 2, Expected::GrayBadge)
                .unwrap()
                .unwrap(),
            gray
        );
        assert!(matches!(
            decode(
                &encoded(
                    3,
                    Outcome::Failure(FaceFailure::new(FailureCode::InvalidImage).into())
                ),
                3,
                Expected::DeepFace
            ),
            Ok(Err(Rejection::AnalysisFailed(_)))
        ));
    }

    #[test]
    fn large_lightguard_report_survives_as_a_rejection() {
        let failure = FaceFailure {
            // Size observed in a real worker's LightGuard rejection on Nitro.
            debug_report: Some("x".repeat(41_739)),
            ..FaceFailure::validation(
                ValidationReason::LightGuardScoreTooLow,
                ValidationTarget::LightGuardPair,
            )
            .at_image(ImageRole::Live)
        };
        let response = encoded(1, Outcome::Failure(failure.clone().into()));
        assert_eq!(response.len(), 41_765);
        assert!(response.len() <= MAX_RESPONSE_BYTES);
        let Ok(Err(Rejection::AnalysisFailed(decoded))) = decode(&response, 1, Expected::DeepFace)
        else {
            panic!("expected a recoverable LightGuard rejection")
        };
        assert_eq!(decoded, failure);
    }

    #[test]
    fn corrupt_responses_are_violations() {
        for case in 0..10 {
            let mut response = Response::new(1, scores());
            let bytes = match case {
                0 => {
                    response.request_id += 1;
                    protobuf::encode_response(&response)
                }
                1 => encoded(
                    1,
                    Outcome::GrayBadge(GrayBadgeResult {
                        similarity_live_challenge: Some(0.8),
                        debug_report: None,
                    }),
                ),
                2..=4 => {
                    let Some(Outcome::DeepFace(ref mut scores)) = response.outcome else {
                        unreachable!()
                    };
                    scores.similarity_live_challenge =
                        Some([f64::NAN, f64::INFINITY, 1.1][case - 2]);
                    protobuf::encode_response(&response)
                }
                5 => encoded(
                    1,
                    Outcome::Failure(FaceFailure::new(FailureCode::Internal).into()),
                ),
                6 => encoded(
                    1,
                    Outcome::Failure(
                        protocol_failure::Reason::UnsupportedVersion(EmptyReason {}).into(),
                    ),
                ),
                7 => vec![0xff],
                8 => {
                    response.outcome = None;
                    protobuf::encode_response(&response)
                }
                9 => {
                    response.protocol_version += 1;
                    protobuf::encode_response(&response)
                }
                _ => unreachable!(),
            };
            assert!(
                decode(&bytes, 1, Expected::DeepFace).is_err(),
                "case {case}"
            );
        }

        let mut missing = Response::new(1, scores());
        let Some(Outcome::DeepFace(ref mut result)) = missing.outcome else {
            unreachable!()
        };
        result.similarity_credential_live = None;
        let unknown_code = encoded(
            1,
            Outcome::Failure(
                FaceFailure {
                    code: 999,
                    ..FaceFailure::default()
                }
                .into(),
            ),
        );
        let mut unknown_outcome = Response::new(1, scores());
        unknown_outcome.outcome = None;
        let mut unknown_outcome = protobuf::encode_response(&unknown_outcome);
        unknown_outcome.extend([0x3a, 0]); // Unknown future outcome field 7.
        for bytes in [
            protobuf::encode_response(&missing),
            unknown_code,
            unknown_outcome,
        ] {
            assert!(decode(&bytes, 1, Expected::DeepFace).is_err());
        }
    }

    #[test]
    fn reports_survive_rejections_but_never_error_formatting() {
        let failure = FaceFailure {
            debug_report: Some("sensitive image diagnostic".to_owned()),
            ..FaceFailure::new(FailureCode::InvalidImage)
        };
        let Ok(Err(rejection)) = decode(
            &encoded(1, Outcome::Failure(failure.into())),
            1,
            Expected::DeepFace,
        ) else {
            panic!("expected a recoverable rejection")
        };
        assert!(!format!("{rejection} {rejection:?}").contains("sensitive"));
        let Rejection::AnalysisFailed(failure) = rejection else {
            panic!("expected an analysis failure")
        };
        assert_eq!(
            failure.debug_report.as_deref(),
            Some("sensitive image diagnostic")
        );

        let mut result = scores();
        if let Outcome::DeepFace(result) = &mut result {
            result.debug_report = Some("sensitive model diagnostic".to_owned());
        }
        assert_eq!(
            decode(&encoded(1, result.clone()), 1, Expected::DeepFace)
                .unwrap()
                .unwrap(),
            result
        );
    }

    #[test]
    fn malformed_or_oversized_image_sources_are_rejected_locally() {
        validate_images(&limits(), &request()).unwrap();
        for image in [
            None,
            Some(FaceImage { source: None }),
            Some(FaceImage {
                source: Some(Source::Orb(vec![])),
            }),
            Some(FaceImage {
                source: Some(Source::Orb(vec![0; 101])),
            }),
            Some(FaceImage {
                source: Some(Source::LightGuard(LightGuard {
                    illuminated: vec![1],
                    unilluminated: vec![2],
                    matching_frame: 0,
                })),
            }),
            Some(FaceImage {
                source: Some(Source::LightGuard(LightGuard {
                    illuminated: vec![1],
                    unilluminated: vec![2; 101],
                    matching_frame: LightGuardMatchingFrame::Illuminated as i32,
                })),
            }),
        ] {
            let Operation::DeepFace(mut input) = request() else {
                unreachable!()
            };
            input.live = image;
            assert!(matches!(
                validate_images(&limits(), &Operation::DeepFace(input)),
                Err(Rejection::InvalidImages)
            ));
        }
    }
}
