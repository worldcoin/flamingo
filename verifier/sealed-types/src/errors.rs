//! Local codec errors and public failures carried by sealed responses.

use serde::{Deserialize, Serialize};

/// Why a sealed match payload could not be encoded or decoded. Local only, never travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes were not the CBOR framing this crate writes.
    Malformed,
    /// CBOR encoding failed.
    Encoding,
    /// An encoded match result exceeded its fixed sealed-response envelope.
    ResponseTooLarge,
}

/// Semantic location of an image failure, matching the worker vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageRole {
    /// Orb thumbnail.
    OrbCredential,
    /// Live capture.
    LiveSelfie,
    /// RTMS image.
    RtmsChallenge,
}

/// Semantic comparison location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonRole {
    /// Orb/live.
    OrbSelfie,
    /// Orb/challenge.
    OrbChallenge,
    /// Live/challenge.
    SelfieChallenge,
}

/// All request-derived failures remain encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    /// Invalid CBOR shape.
    MalformedInputs,
    /// Invalid or oversized PCP hashes.
    InvalidHashesJson,
    /// PCP image binding failed.
    ThumbnailHashMismatch,
    /// Nonfinite or out-of-range threshold.
    InvalidThreshold,
    /// Empty image buffer.
    EmptyImage,
    /// Image or aggregate budget exceeded.
    InputTooLarge,
    /// A named comparison did not meet policy.
    MatchBelowThreshold(ComparisonRole),
    /// Image analysis rejection with semantic location.
    ImageRejected {
        /// Which input failed.
        image: ImageRole,
        /// Approved reason.
        reason: ImageFailureReason,
    },
    /// Matching failed on a named comparison.
    MatchingFailed(ComparisonRole),
    /// Backend infrastructure failed, distinct from biological rejection.
    Internal,
}

/// Stable public reason codes for client-owned feedback and localization.
/// Engine implementation/configuration failures are not validation reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ImageFailureReason {
    /// Image could not be decoded within limits.
    InvalidImage,
    /// Template generation failed.
    TemplateFailed,
    /// Too many faces.
    TooManyFaces,
    /// Image too dark.
    ImageTooDark,
    /// Image too bright.
    ImageTooBright,
    /// Illumination variance.
    IlluminationVariance,
    /// Face too small.
    FaceTooSmall,
    /// Face too big.
    FaceTooBig,
    /// Face resolution too low.
    FaceResolutionTooLow,
    /// Face too high.
    FaceTooHigh,
    /// Face too low.
    FaceTooLow,
    /// Face too far left.
    FaceTooFarLeft,
    /// Face too far right.
    FaceTooFarRight,
    /// Head pose yaw.
    HeadPoseYaw,
    /// Head pose pitch too high.
    HeadPosePitchTooHigh,
    /// Head pose pitch too low.
    HeadPosePitchTooLow,
    /// Head pose roll.
    HeadPoseRoll,
    /// Low quality.
    LowQuality,
    /// Sunglasses occlusion detected.
    SunglassesOcclusionDetected,
    /// Glasses occlusion detected.
    GlassesOcclusionDetected,
    /// Mask occlusion detected.
    MaskOcclusionDetected,
    /// Other occlusion detected.
    OtherOcclusionDetected,
    /// Hair occlusion detected.
    HairOcclusionDetected,
    /// Fas occlusion detected.
    FasOcclusionDetected,
    /// Spoof detected.
    SpoofDetected,
    /// Depth spoof detected.
    DepthSpoofDetected,
    /// Thermal spoof detected.
    ThermalSpoofDetected,
    /// Age below threshold.
    AgeBelowThreshold,
    /// No face detected.
    NoFaceDetected,
    /// Eyes closed.
    EyesClosed,
    /// Non neutral expression.
    NonNeutralExpression,
    /// Landmarks alignment.
    LandmarksAlignment,
    /// Face overexposed.
    FaceOverexposed,
    /// Face underexposed.
    FaceUnderexposed,
    /// Segmentation occlusion proportion.
    SegmentationOcclusionProportion,
    /// Bright artifacts.
    BrightArtifacts,
    /// Light guard score too low.
    LightGuardScoreTooLow,
    /// Low contrast.
    LowContrast,
    /// Mesh expression score.
    MeshExpressionScore,
    /// High color distortion.
    HighColorDistortion,
    /// Uneven lighting.
    UnevenLighting,
    /// Blurry face.
    BlurryFace,
    /// Noisy thermal image.
    NoisyThermalImage,
}
