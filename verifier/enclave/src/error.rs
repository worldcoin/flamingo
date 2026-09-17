//! Conversion from engine errors to public match failures.
use face_engine::io::errors::ValidationError;
use flamingo_verifier_sealed_types::{FailureReason, ImageFailureReason, ImageRole};

/// Attach the input image to an approved reason, omitting engine diagnostics.
pub const fn image_failure(error: &ValidationError, image: ImageRole) -> FailureReason {
    let reason = match error {
        ValidationError::TooManyFacesError { .. } => ImageFailureReason::TooManyFaces,
        ValidationError::ImageTooDarkError { .. } => ImageFailureReason::ImageTooDark,
        ValidationError::ImageTooBrightError { .. } => ImageFailureReason::ImageTooBright,
        ValidationError::IlluminationVarianceError { .. } => {
            ImageFailureReason::IlluminationVariance
        }
        ValidationError::FaceTooSmallError { .. } => ImageFailureReason::FaceTooSmall,
        ValidationError::FaceTooBigError { .. } => ImageFailureReason::FaceTooBig,
        ValidationError::FaceResolutionTooLowError { .. } => {
            ImageFailureReason::FaceResolutionTooLow
        }
        ValidationError::FaceTooHighError { .. } => ImageFailureReason::FaceTooHigh,
        ValidationError::FaceTooLowError { .. } => ImageFailureReason::FaceTooLow,
        ValidationError::FaceTooFarLeftError { .. } => ImageFailureReason::FaceTooFarLeft,
        ValidationError::FaceTooFarRightError { .. } => ImageFailureReason::FaceTooFarRight,
        ValidationError::HeadPoseYawError { .. } => ImageFailureReason::HeadPoseYaw,
        ValidationError::HeadPosePitchTooHighError { .. } => {
            ImageFailureReason::HeadPosePitchTooHigh
        }
        ValidationError::HeadPosePitchTooLowError { .. } => ImageFailureReason::HeadPosePitchTooLow,
        ValidationError::HeadPoseRollError { .. } => ImageFailureReason::HeadPoseRoll,
        ValidationError::LowQualityError { .. } => ImageFailureReason::LowQuality,
        ValidationError::SunglassesOcclusionDetectedError { .. } => {
            ImageFailureReason::SunglassesOcclusionDetected
        }
        ValidationError::GlassesOcclusionDetectedError { .. } => {
            ImageFailureReason::GlassesOcclusionDetected
        }
        ValidationError::MaskOcclusionDetectedError { .. } => {
            ImageFailureReason::MaskOcclusionDetected
        }
        ValidationError::OtherOcclusionDetectedError { .. } => {
            ImageFailureReason::OtherOcclusionDetected
        }
        ValidationError::HairOcclusionDetectedError { .. } => {
            ImageFailureReason::HairOcclusionDetected
        }
        ValidationError::FasOcclusionDetectedError { .. } => {
            ImageFailureReason::FasOcclusionDetected
        }
        ValidationError::SpoofDetectedError { .. } => ImageFailureReason::SpoofDetected,
        ValidationError::DepthSpoofDetectedError { .. } => ImageFailureReason::DepthSpoofDetected,
        ValidationError::ThermalSpoofDetectedError { .. } => {
            ImageFailureReason::ThermalSpoofDetected
        }
        ValidationError::AgeBelowThresholdError { .. } => ImageFailureReason::AgeBelowThreshold,
        ValidationError::NoFaceDetectedError => ImageFailureReason::NoFaceDetected,
        ValidationError::EyesClosedError { .. } => ImageFailureReason::EyesClosed,
        ValidationError::NonNeutralExpressionError { .. } => {
            ImageFailureReason::NonNeutralExpression
        }
        ValidationError::LandmarksAlignmentError { .. } => ImageFailureReason::LandmarksAlignment,
        ValidationError::FaceOverexposedError { .. } => ImageFailureReason::FaceOverexposed,
        ValidationError::FaceUnderexposedError { .. } => ImageFailureReason::FaceUnderexposed,
        ValidationError::SegmentationOcclusionProportionError { .. } => {
            ImageFailureReason::SegmentationOcclusionProportion
        }
        ValidationError::BrightArtifactsError { .. } => ImageFailureReason::BrightArtifacts,
        ValidationError::LightGuardScoreTooLowError { .. } => {
            ImageFailureReason::LightGuardScoreTooLow
        }
        ValidationError::LowContrastError { .. } => ImageFailureReason::LowContrast,
        ValidationError::MeshExpressionScoreError { .. } => ImageFailureReason::MeshExpressionScore,
        ValidationError::HighColorDistortionError { .. } => ImageFailureReason::HighColorDistortion,
        ValidationError::UnevenLightingError { .. } => ImageFailureReason::UnevenLighting,
        ValidationError::BlurryFaceError { .. } => ImageFailureReason::BlurryFace,
        ValidationError::NoisyThermalImageError { .. } => ImageFailureReason::NoisyThermalImage,
        ValidationError::UnknownError
        | ValidationError::RocTemplateError { .. }
        | ValidationError::ValidatorUpdateParametersError { .. } => {
            return FailureReason::Internal;
        }
    };
    FailureReason::ImageRejected { image, reason }
}
