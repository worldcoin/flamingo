//! Conversion from public worker failures to sealed API failures.
use biometric_engines_protocol::face::{self, FailureCode, FailureLocation};
use flamingo_verifier_sealed_types::{
    ComparisonRole, FailureReason, ImageFailureReason, ImageRole,
};
/// Preserve semantic locations while keeping backend infrastructure failures distinct.
#[must_use]
pub const fn worker_failure(failure: face::Failure) -> FailureReason {
    let reason = match failure.code {
        FailureCode::Internal => return FailureReason::Internal,
        FailureCode::InvalidRequest(reason) => {
            return match reason {
                face::InvalidRequestReason::EmptyImage => FailureReason::EmptyImage,
                face::InvalidRequestReason::ImageTooLarge { .. }
                | face::InvalidRequestReason::TotalImagesTooLarge { .. } => {
                    FailureReason::InputTooLarge
                }
                _ => FailureReason::MalformedInputs,
            };
        }
        FailureCode::MatchingFailed => {
            return match failure.location {
                Some(FailureLocation::Comparison(role)) => {
                    FailureReason::MatchingFailed(match role {
                        face::ComparisonRole::OrbSelfie => ComparisonRole::OrbSelfie,
                        face::ComparisonRole::OrbChallenge => ComparisonRole::OrbChallenge,
                        face::ComparisonRole::SelfieChallenge => ComparisonRole::SelfieChallenge,
                    })
                }
                _ => FailureReason::Internal,
            };
        }
        FailureCode::InvalidImage => ImageFailureReason::InvalidImage,
        FailureCode::TemplateFailed => ImageFailureReason::TemplateFailed,
        FailureCode::ValidationFailed(validation) => validation_reason(validation.reason),
    };
    let image = match failure.location {
        Some(FailureLocation::Image(role)) => match role {
            face::ImageRole::OrbCredential => ImageRole::OrbCredential,
            face::ImageRole::LiveSelfie => ImageRole::LiveSelfie,
            face::ImageRole::RtmsChallenge => ImageRole::RtmsChallenge,
            face::ImageRole::EmbeddingInput => return FailureReason::Internal,
        },
        _ => return FailureReason::Internal,
    };
    FailureReason::ImageRejected { image, reason }
}

const fn validation_reason(reason: face::ValidationReason) -> ImageFailureReason {
    match reason {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_errors_preserve_image_reason_and_comparison() {
        let failure = face::Failure::image(
            FailureCode::ValidationFailed(face::ValidationFailure {
                reason: face::ValidationReason::EyesClosed,
                target: face::ValidationTarget::Image,
            }),
            face::ImageRole::LiveSelfie,
        );
        assert_eq!(
            worker_failure(failure),
            FailureReason::ImageRejected {
                image: ImageRole::LiveSelfie,
                reason: ImageFailureReason::EyesClosed
            }
        );
        assert_eq!(
            worker_failure(face::Failure::comparison(
                FailureCode::MatchingFailed,
                face::ComparisonRole::SelfieChallenge
            )),
            FailureReason::MatchingFailed(ComparisonRole::SelfieChallenge)
        );
        assert_eq!(
            worker_failure(face::Failure::new(FailureCode::InvalidImage)),
            FailureReason::Internal
        );
    }
}
