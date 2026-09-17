//! Approved validation feedback matching the biometric engine protocol.
use face_engine::io::errors::ValidationError;
use flamingo_verifier_sealed_types::{
    AnalysisFailure, FailureReason, ImageRole, ValidationFailure, ValidationReason,
    ValidationTarget,
};
/// Translate approved validation reasons without carrying diagnostics.
pub const fn failure(error: &ValidationError, image: ImageRole) -> FailureReason {
    let reason = match error {
        ValidationError::TooManyFacesError { .. } => ValidationReason::TooManyFaces,
        ValidationError::ImageTooDarkError { .. } => ValidationReason::ImageTooDark,
        ValidationError::ImageTooBrightError { .. } => ValidationReason::ImageTooBright,
        ValidationError::IlluminationVarianceError { .. } => ValidationReason::IlluminationVariance,
        ValidationError::FaceTooSmallError { .. } => ValidationReason::FaceTooSmall,
        ValidationError::FaceTooBigError { .. } => ValidationReason::FaceTooBig,
        ValidationError::FaceResolutionTooLowError { .. } => ValidationReason::FaceResolutionTooLow,
        ValidationError::FaceTooHighError { .. } => ValidationReason::FaceTooHigh,
        ValidationError::FaceTooLowError { .. } => ValidationReason::FaceTooLow,
        ValidationError::FaceTooFarLeftError { .. } => ValidationReason::FaceTooFarLeft,
        ValidationError::FaceTooFarRightError { .. } => ValidationReason::FaceTooFarRight,
        ValidationError::HeadPoseYawError { .. } => ValidationReason::HeadPoseYaw,
        ValidationError::HeadPosePitchTooHighError { .. } => ValidationReason::HeadPosePitchTooHigh,
        ValidationError::HeadPosePitchTooLowError { .. } => ValidationReason::HeadPosePitchTooLow,
        ValidationError::HeadPoseRollError { .. } => ValidationReason::HeadPoseRoll,
        ValidationError::LowQualityError { .. } => ValidationReason::LowQuality,
        ValidationError::SunglassesOcclusionDetectedError { .. } => {
            ValidationReason::SunglassesOcclusionDetected
        }
        ValidationError::GlassesOcclusionDetectedError { .. } => {
            ValidationReason::GlassesOcclusionDetected
        }
        ValidationError::MaskOcclusionDetectedError { .. } => {
            ValidationReason::MaskOcclusionDetected
        }
        ValidationError::OtherOcclusionDetectedError { .. } => {
            ValidationReason::OtherOcclusionDetected
        }
        ValidationError::HairOcclusionDetectedError { .. } => {
            ValidationReason::HairOcclusionDetected
        }
        ValidationError::FasOcclusionDetectedError { .. } => ValidationReason::FasOcclusionDetected,
        ValidationError::SpoofDetectedError { .. } => ValidationReason::SpoofDetected,
        ValidationError::DepthSpoofDetectedError { .. } => ValidationReason::DepthSpoofDetected,
        ValidationError::ThermalSpoofDetectedError { .. } => ValidationReason::ThermalSpoofDetected,
        ValidationError::AgeBelowThresholdError { .. } => ValidationReason::AgeBelowThreshold,
        ValidationError::NoFaceDetectedError => ValidationReason::NoFaceDetected,
        ValidationError::EyesClosedError { .. } => ValidationReason::EyesClosed,
        ValidationError::NonNeutralExpressionError { .. } => ValidationReason::NonNeutralExpression,
        ValidationError::LandmarksAlignmentError { .. } => ValidationReason::LandmarksAlignment,
        ValidationError::FaceOverexposedError { .. } => ValidationReason::FaceOverexposed,
        ValidationError::FaceUnderexposedError { .. } => ValidationReason::FaceUnderexposed,
        ValidationError::SegmentationOcclusionProportionError { .. } => {
            ValidationReason::SegmentationOcclusionProportion
        }
        ValidationError::BrightArtifactsError { .. } => ValidationReason::BrightArtifacts,
        ValidationError::LightGuardScoreTooLowError { .. } => {
            ValidationReason::LightGuardScoreTooLow
        }
        ValidationError::LowContrastError { .. } => ValidationReason::LowContrast,
        ValidationError::MeshExpressionScoreError { .. } => ValidationReason::MeshExpressionScore,
        ValidationError::HighColorDistortionError { .. } => ValidationReason::HighColorDistortion,
        ValidationError::UnevenLightingError { .. } => ValidationReason::UnevenLighting,
        ValidationError::BlurryFaceError { .. } => ValidationReason::BlurryFace,
        ValidationError::NoisyThermalImageError { .. } => ValidationReason::NoisyThermalImage,
        ValidationError::UnknownError
        | ValidationError::RocTemplateError { .. }
        | ValidationError::ValidatorUpdateParametersError { .. } => return FailureReason::Internal,
    };
    FailureReason::ImageAnalysisFailed {
        image,
        reason: AnalysisFailure::ValidationFailed(ValidationFailure {
            reason,
            target: ValidationTarget::Image,
        }),
    }
}
