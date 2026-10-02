//! Conversion from public worker failures to sealed API failures.
use crate::biometric_engine::BiometricError;
use biometric_engines_protocol::face::{self, FailureCode, failure::Location};
use flamingo_verifier_sealed_types::{
    ComparisonRole, FailureReason, ImageFailureReason, ImageRole, InputFailureReason,
    ValidationTarget,
};

impl From<face::Failure> for BiometricError {
    fn from(failure: face::Failure) -> Self {
        match worker_failure(&failure) {
            FailureReason::Internal => Self::Internal,
            reason => Self::AnalysisRejected {
                reason,
                debug_report: failure.debug_report.into(),
            },
        }
    }
}

/// Preserve semantic locations while keeping backend infrastructure failures distinct.
#[must_use]
fn worker_failure(failure: &face::Failure) -> FailureReason {
    let Ok(code) = FailureCode::try_from(failure.code) else {
        return FailureReason::Internal;
    };
    if (code == FailureCode::InvalidRequest) != failure.invalid_request_reason.is_some()
        || (code == FailureCode::ValidationFailed) != failure.validation_failure.is_some()
    {
        return FailureReason::Internal;
    }

    let mut target = None;
    let reason = match code {
        FailureCode::Unspecified | FailureCode::Internal => return FailureReason::Internal,
        FailureCode::InvalidRequest => return invalid_request(failure),

        FailureCode::MatchingFailed => {
            return match failure.location {
                Some(Location::Comparison(role)) => match face::ComparisonRole::try_from(role) {
                    Ok(face::ComparisonRole::CredentialLive) => {
                        FailureReason::MatchingFailed(ComparisonRole::OrbSelfie)
                    }

                    Ok(face::ComparisonRole::CredentialChallenge) => {
                        FailureReason::MatchingFailed(ComparisonRole::OrbChallenge)
                    }

                    Ok(face::ComparisonRole::LiveChallenge) => {
                        FailureReason::MatchingFailed(ComparisonRole::SelfieChallenge)
                    }
                    _ => FailureReason::Internal,
                },
                _ => FailureReason::Internal,
            };
        }
        FailureCode::InvalidImage => ImageFailureReason::InvalidImage,
        FailureCode::TemplateFailed => ImageFailureReason::TemplateFailed,
        FailureCode::ValidationFailed => {
            let Some(validation) = failure.validation_failure else {
                return FailureReason::Internal;
            };
            target = Some(match face::ValidationTarget::try_from(validation.target) {
                Ok(face::ValidationTarget::Image) => ValidationTarget::Image,
                Ok(face::ValidationTarget::IlluminatedFrame) => ValidationTarget::IlluminatedFrame,
                Ok(face::ValidationTarget::UnilluminatedFrame) => {
                    ValidationTarget::UnilluminatedFrame
                }
                Ok(face::ValidationTarget::LightGuardPair) => ValidationTarget::LightGuardPair,
                _ => return FailureReason::Internal,
            });

            let Ok(reason) = face::ValidationReason::try_from(validation.reason) else {
                return FailureReason::Internal;
            };
            let Some(reason) = validation_reason(reason) else {
                return FailureReason::Internal;
            };
            reason
        }
    };
    let image = match failure.location {
        Some(Location::Image(role)) => match face::ImageRole::try_from(role) {
            Ok(face::ImageRole::Credential) => ImageRole::OrbCredential,
            Ok(face::ImageRole::Live) => ImageRole::LiveSelfie,
            Ok(face::ImageRole::Challenge) => ImageRole::RtmsChallenge,
            _ => return FailureReason::Internal,
        },
        _ => return FailureReason::Internal,
    };
    FailureReason::ImageRejected {
        image,
        reason,
        target,
    }
}

fn invalid_request(failure: &face::Failure) -> FailureReason {
    use face::invalid_request_reason::Reason;
    let (reason, limit_bytes) = match failure
        .invalid_request_reason
        .and_then(|details| details.reason)
    {
        Some(Reason::MissingImage(_)) => (InputFailureReason::MissingImage, None),
        Some(Reason::MissingSource(_)) => (InputFailureReason::MissingSource, None),
        Some(Reason::InvalidMatchingFrame(_)) => (InputFailureReason::InvalidMatchingFrame, None),
        Some(Reason::EmptyImage(_)) => (InputFailureReason::EmptyImage, None),
        Some(Reason::ImageTooLarge(limit)) => {
            (InputFailureReason::ImageTooLarge, Some(limit.limit_bytes))
        }
        Some(Reason::TotalImagesTooLarge(limit)) => (
            InputFailureReason::TotalImagesTooLarge,
            Some(limit.limit_bytes),
        ),
        None => return FailureReason::Internal,
    };
    let image = match failure.location {
        None => None,
        Some(Location::Image(role)) => match image_role(role) {
            Some(role) => Some(role),
            None => return FailureReason::Internal,
        },
        Some(Location::Comparison(_)) => return FailureReason::Internal,
    };
    FailureReason::InputRejected {
        reason,
        image,
        limit_bytes,
    }
}

fn image_role(role: i32) -> Option<ImageRole> {
    match face::ImageRole::try_from(role).ok()? {
        face::ImageRole::Credential => Some(ImageRole::OrbCredential),
        face::ImageRole::Live => Some(ImageRole::LiveSelfie),
        face::ImageRole::Challenge => Some(ImageRole::RtmsChallenge),
        _ => None,
    }
}

const fn validation_reason(reason: face::ValidationReason) -> Option<ImageFailureReason> {
    Some(match reason {
        face::ValidationReason::Unspecified => return None,
        face::ValidationReason::TooManyFaces => ImageFailureReason::TooManyFaces,
        face::ValidationReason::ImageTooDark => ImageFailureReason::ImageTooDark,
        face::ValidationReason::ImageTooBright => ImageFailureReason::ImageTooBright,
        face::ValidationReason::IlluminationVariance => ImageFailureReason::IlluminationVariance,
        face::ValidationReason::FaceTooSmall => ImageFailureReason::FaceTooSmall,
        face::ValidationReason::FaceTooBig => ImageFailureReason::FaceTooBig,
        face::ValidationReason::FaceResolutionTooLow => ImageFailureReason::FaceResolutionTooLow,
        face::ValidationReason::FaceTooHigh => ImageFailureReason::FaceTooHigh,
        face::ValidationReason::FaceTooLow => ImageFailureReason::FaceTooLow,
        face::ValidationReason::FaceTooFarLeft => ImageFailureReason::FaceTooFarLeft,
        face::ValidationReason::FaceTooFarRight => ImageFailureReason::FaceTooFarRight,
        face::ValidationReason::HeadPoseYaw => ImageFailureReason::HeadPoseYaw,
        face::ValidationReason::HeadPosePitchTooHigh => ImageFailureReason::HeadPosePitchTooHigh,
        face::ValidationReason::HeadPosePitchTooLow => ImageFailureReason::HeadPosePitchTooLow,
        face::ValidationReason::HeadPoseRoll => ImageFailureReason::HeadPoseRoll,
        face::ValidationReason::LowQuality => ImageFailureReason::LowQuality,
        face::ValidationReason::SunglassesOcclusionDetected => {
            ImageFailureReason::SunglassesOcclusionDetected
        }
        face::ValidationReason::GlassesOcclusionDetected => {
            ImageFailureReason::GlassesOcclusionDetected
        }
        face::ValidationReason::MaskOcclusionDetected => ImageFailureReason::MaskOcclusionDetected,
        face::ValidationReason::OtherOcclusionDetected => {
            ImageFailureReason::OtherOcclusionDetected
        }
        face::ValidationReason::HairOcclusionDetected => ImageFailureReason::HairOcclusionDetected,
        face::ValidationReason::FasOcclusionDetected => ImageFailureReason::FasOcclusionDetected,
        face::ValidationReason::SpoofDetected => ImageFailureReason::SpoofDetected,
        face::ValidationReason::DepthSpoofDetected => ImageFailureReason::DepthSpoofDetected,
        face::ValidationReason::ThermalSpoofDetected => ImageFailureReason::ThermalSpoofDetected,
        face::ValidationReason::AgeBelowThreshold => ImageFailureReason::AgeBelowThreshold,
        face::ValidationReason::NoFaceDetected => ImageFailureReason::NoFaceDetected,
        face::ValidationReason::EyesClosed => ImageFailureReason::EyesClosed,
        face::ValidationReason::NonNeutralExpression => ImageFailureReason::NonNeutralExpression,
        face::ValidationReason::LandmarksAlignment => ImageFailureReason::LandmarksAlignment,
        face::ValidationReason::FaceOverexposed => ImageFailureReason::FaceOverexposed,
        face::ValidationReason::FaceUnderexposed => ImageFailureReason::FaceUnderexposed,
        face::ValidationReason::SegmentationOcclusionProportion => {
            ImageFailureReason::SegmentationOcclusionProportion
        }
        face::ValidationReason::BrightArtifacts => ImageFailureReason::BrightArtifacts,
        face::ValidationReason::LightGuardScoreTooLow => ImageFailureReason::LightGuardScoreTooLow,
        face::ValidationReason::LowContrast => ImageFailureReason::LowContrast,
        face::ValidationReason::MeshExpressionScore => ImageFailureReason::MeshExpressionScore,
        face::ValidationReason::HighColorDistortion => ImageFailureReason::HighColorDistortion,
        face::ValidationReason::UnevenLighting => ImageFailureReason::UnevenLighting,
        face::ValidationReason::BlurryFace => ImageFailureReason::BlurryFace,
        face::ValidationReason::NoisyThermalImage => ImageFailureReason::NoisyThermalImage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_errors_preserve_image_reason_and_comparison() {
        let failure = face::Failure::validation(
            face::ValidationReason::EyesClosed,
            face::ValidationTarget::Image,
        )
        .at_image(face::ImageRole::Live);
        assert_eq!(
            worker_failure(&failure),
            FailureReason::ImageRejected {
                image: ImageRole::LiveSelfie,
                reason: ImageFailureReason::EyesClosed,
                target: Some(ValidationTarget::Image),
            }
        );
        assert_eq!(
            worker_failure(
                &face::Failure::new(FailureCode::MatchingFailed)
                    .at_comparison(face::ComparisonRole::LiveChallenge)
            ),
            FailureReason::MatchingFailed(ComparisonRole::SelfieChallenge)
        );
        assert_eq!(
            worker_failure(&face::Failure::new(FailureCode::InvalidImage)),
            FailureReason::Internal
        );
    }

    #[test]
    fn incomplete_or_unknown_worker_failures_are_internal() {
        for failure in [
            face::Failure::default(),
            face::Failure {
                code: 999,
                ..face::Failure::default()
            },
            face::Failure::new(FailureCode::InvalidRequest),
            face::Failure::new(FailureCode::ValidationFailed).at_image(face::ImageRole::Live),
            face::Failure::validation(
                face::ValidationReason::Unspecified,
                face::ValidationTarget::Image,
            )
            .at_image(face::ImageRole::Live),
            face::Failure::validation(
                face::ValidationReason::EyesClosed,
                face::ValidationTarget::Unspecified,
            )
            .at_image(face::ImageRole::Live),
            face::Failure::new(FailureCode::InvalidImage).at_image(face::ImageRole::Unspecified),
            face::Failure::new(FailureCode::InvalidImage).at_image(face::ImageRole::EmbeddingInput),
            face::Failure::new(FailureCode::MatchingFailed)
                .at_comparison(face::ComparisonRole::Unspecified),
            face::Failure {
                location: Some(Location::Image(999)),
                ..face::Failure::new(FailureCode::InvalidImage)
            },
            face::Failure {
                validation_failure: Some(face::ValidationFailure {
                    reason: 999,
                    target: 1,
                }),
                ..face::Failure::new(FailureCode::ValidationFailed).at_image(face::ImageRole::Live)
            },
        ] {
            assert_eq!(worker_failure(&failure), FailureReason::Internal);
        }
    }

    #[test]
    fn invalid_request_reasons_preserve_location_and_limits() {
        use face::invalid_request_reason::Reason;
        for (reason, expected) in [
            (
                Reason::EmptyImage(face::EmptyReason {}),
                InputFailureReason::EmptyImage,
            ),
            (
                Reason::ImageTooLarge(face::ByteLimitExceeded { limit_bytes: 1 }),
                InputFailureReason::ImageTooLarge,
            ),
            (
                Reason::TotalImagesTooLarge(face::ByteLimitExceeded { limit_bytes: 2 }),
                InputFailureReason::TotalImagesTooLarge,
            ),
            (
                Reason::MissingSource(face::EmptyReason {}),
                InputFailureReason::MissingSource,
            ),
        ] {
            let limit_bytes = match reason {
                Reason::ImageTooLarge(limit) | Reason::TotalImagesTooLarge(limit) => {
                    Some(limit.limit_bytes)
                }
                _ => None,
            };
            let failure = face::Failure::invalid(reason).at_image(face::ImageRole::Live);
            assert_eq!(
                worker_failure(&failure),
                FailureReason::InputRejected {
                    reason: expected,
                    image: Some(ImageRole::LiveSelfie),
                    limit_bytes
                }
            );
        }
    }
    #[test]
    fn lightguard_targets_and_report_survive_worker_rejection() {
        for (worker_target, expected) in [
            (face::ValidationTarget::Image, ValidationTarget::Image),
            (
                face::ValidationTarget::IlluminatedFrame,
                ValidationTarget::IlluminatedFrame,
            ),
            (
                face::ValidationTarget::UnilluminatedFrame,
                ValidationTarget::UnilluminatedFrame,
            ),
            (
                face::ValidationTarget::LightGuardPair,
                ValidationTarget::LightGuardPair,
            ),
        ] {
            let mut failure =
                face::Failure::validation(face::ValidationReason::EyesClosed, worker_target)
                    .at_image(face::ImageRole::Live);
            failure.debug_report = Some("{\"frame\":1}".to_owned());
            let response = BiometricError::from(failure).into_result().unwrap();
            assert_eq!(
                response.outcome,
                flamingo_verifier_sealed_types::MatchResult::Failed(FailureReason::ImageRejected {
                    image: ImageRole::LiveSelfie,
                    reason: ImageFailureReason::EyesClosed,
                    target: Some(expected),
                })
            );
            assert_eq!(
                response.debug_report,
                Some("{\"frame\":1}".to_owned()).into()
            );
        }
    }
}
