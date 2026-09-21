//! Conversion from public worker failures to sealed API failures.
use biometric_engines_protocol::face::{self, FailureCode, failure::Location};
use flamingo_verifier_sealed_types::{
    ComparisonRole, FailureReason, ImageFailureReason, ImageRole,
};
/// Preserve semantic locations while keeping backend infrastructure failures distinct.
#[must_use]
pub fn worker_failure(failure: &face::Failure) -> FailureReason {
    let Ok(code) = FailureCode::try_from(failure.code) else {
        return FailureReason::Internal;
    };
    if (code == FailureCode::InvalidRequest) != failure.invalid_request_reason.is_some()
        || (code == FailureCode::ValidationFailed) != failure.validation_failure.is_some()
    {
        return FailureReason::Internal;
    }
    let reason = match code {
        FailureCode::Unspecified | FailureCode::Internal => return FailureReason::Internal,
        FailureCode::InvalidRequest => {
            return match failure
                .invalid_request_reason
                .and_then(|details| details.reason)
            {
                Some(face::invalid_request_reason::Reason::EmptyImage(_)) => {
                    FailureReason::EmptyImage
                }
                Some(
                    face::invalid_request_reason::Reason::ImageTooLarge(_)
                    | face::invalid_request_reason::Reason::TotalImagesTooLarge(_),
                ) => FailureReason::InputTooLarge,
                Some(_) => FailureReason::MalformedInputs,
                None => FailureReason::Internal,
            };
        }
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
            if matches!(
                face::ValidationTarget::try_from(validation.target),
                Err(_) | Ok(face::ValidationTarget::Unspecified)
            ) {
                return FailureReason::Internal;
            }
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
    FailureReason::ImageRejected { image, reason }
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
                reason: ImageFailureReason::EyesClosed
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
    fn invalid_request_reasons_preserve_public_mapping_without_diagnostics() {
        use face::invalid_request_reason::Reason;
        for (reason, expected) in [
            (
                Reason::EmptyImage(face::EmptyReason {}),
                FailureReason::EmptyImage,
            ),
            (
                Reason::ImageTooLarge(face::ByteLimitExceeded { limit_bytes: 1 }),
                FailureReason::InputTooLarge,
            ),
            (
                Reason::TotalImagesTooLarge(face::ByteLimitExceeded { limit_bytes: 2 }),
                FailureReason::InputTooLarge,
            ),
            (
                Reason::MissingSource(face::EmptyReason {}),
                FailureReason::MalformedInputs,
            ),
        ] {
            let mut failure = face::Failure::invalid(reason);
            failure.debug_report = Some("must never reach the API".to_owned());
            assert_eq!(worker_failure(&failure), expected);
        }
    }
}
