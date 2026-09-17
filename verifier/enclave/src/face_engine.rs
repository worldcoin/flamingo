//! Face Engine initialization and in-enclave embedding comparison.

use std::{io::Cursor, sync::Arc};

use face_engine::{
    components::{
        captured_image_analyzer::CapturedImageAnalyzer, template_generator::TemplateGenerator,
    },
    io::rgb_image::RgbImage,
    matchers::cosine_similarity::CosineSimilarity,
    nodes::{subject_extraction::SubjectFace, template_generation::EmbeddingVector},
};
use flamingo_verifier_protocol::match_token::{DeepFaceScores, GrayBadgeScores, valid_similarity};
use flamingo_verifier_sealed_types::{
    AnalysisFailure, ComparisonRole, FailureReason, ImageRole, LiveCapture, MatchInputs,
};
use image::ImageReader;

const FACE_ANALYZER_CONFIG: &str = include_str!("../config/face_analyzer.yaml");
const FACE_TEMPLATE_GENERATOR_CONFIG: &str = include_str!("../config/face_template_generator.yaml");

// TODO: Inject production Face Engine configs and model artifacts at runtime instead of compiling
// the prototype configs and fixed `/models` paths into the enclave.
/// Inference results mirror Tobi's operation-specific results.
pub enum ComparisonScores {
    /// All three pairwise scores.
    DeepFace(DeepFaceScores),
    /// Live versus challenge.
    GrayBadge(GrayBadgeScores),
}

/// Small execution seam: the public request survives a future worker replacement unchanged.
pub trait FaceComparator: Send + Sync {
    /// Consume input buffers without cloning them. PCP and policy stay in the broker.
    /// # Errors
    /// Returns structured analysis failures or infrastructure faults.
    fn evaluate(&self, inputs: MatchInputs) -> Result<ComparisonScores, FailureReason>;
}

/// Face Engine implementation backed by the configured ONNX models.
pub struct FaceEngine {
    template_generator: TemplateGenerator,
    analyzer: CapturedImageAnalyzer,
    matcher: CosineSimilarity,
}

impl Default for FaceEngine {
    fn default() -> Self {
        Self {
            template_generator: TemplateGenerator::new(FACE_TEMPLATE_GENERATOR_CONFIG)
                .expect("built-in Face Engine template generator config and model should load"),
            analyzer: CapturedImageAnalyzer::new(FACE_ANALYZER_CONFIG)
                .expect("built-in Face Engine analyzer config and model should load"),
            matcher: CosineSimilarity {
                normalize_score: false,
            },
        }
    }
}

impl FaceEngine {
    fn generate_embedding(
        &self,
        image_bytes: &[u8],
        role: ImageRole,
    ) -> Result<EmbeddingVector, FailureReason> {
        let rgb_image = decode_image(image_bytes, role)?;

        let analysis = self
            .analyzer
            .run_inference_rgb(&rgb_image)
            .map_err(|_| FailureReason::Internal)?;
        if let Some(error) = analysis.error {
            tracing::warn!(?error, "Face Engine image analysis failed");
            return Err(crate::validation::failure(&error, role));
        }

        let subject_metadata = analysis.subject_face_extracted.ok_or_else(|| {
            tracing::warn!("Face Engine did not extract a subject");
            FailureReason::ImageAnalysisFailed {
                image: role,
                reason: AnalysisFailure::NoFaceDetected,
            }
        })?;
        let subject = SubjectFace {
            input_image: Arc::new(rgb_image),
            metadata: subject_metadata,
        };

        let output = self
            .template_generator
            .run_inference(&subject)
            .map_err(|_| FailureReason::Internal)?;
        if let Some(error) = output.metadata.error {
            tracing::warn!(?error, "Face Engine rejected the generated template");
            return Err(crate::validation::failure(&error, role));
        }

        output.embedding_vector.ok_or_else(|| {
            tracing::error!("Face Engine returned no embedding");
            FailureReason::ImageAnalysisFailed {
                image: role,
                reason: AnalysisFailure::TemplateFailed,
            }
        })
    }

    fn compute_score(
        &self,
        probe: &EmbeddingVector,
        reference: &EmbeddingVector,
        role: ComparisonRole,
    ) -> Result<f64, FailureReason> {
        let score = f64::from(
            self.matcher
                .compute_score(probe, reference)
                .map_err(|_| FailureReason::MatchingFailed(role))?,
        );
        if !valid_similarity(score) {
            return Err(FailureReason::MatchingFailed(role));
        }
        Ok(score)
    }
    fn live_embedding(&self, live: LiveCapture) -> Result<EmbeddingVector, FailureReason> {
        match live {
            LiveCapture::Vanilla(bytes) => self.generate_embedding(&bytes, ImageRole::LiveSelfie),
            LiveCapture::LightGuard { .. } => Err(FailureReason::UnsupportedCapture),
        }
    }
}

impl FaceComparator for FaceEngine {
    fn evaluate(&self, inputs: MatchInputs) -> Result<ComparisonScores, FailureReason> {
        match inputs {
            MatchInputs::DeepFace(inputs) => {
                let orb =
                    self.generate_embedding(&inputs.orb_credential, ImageRole::OrbCredential)?;
                drop(inputs.orb_credential);
                drop(inputs.hashes_json);
                let live = self.live_embedding(inputs.live)?;
                let challenge =
                    self.generate_embedding(&inputs.rtms_challenge, ImageRole::RtmsChallenge)?;
                Ok(ComparisonScores::DeepFace(DeepFaceScores {
                    similarity_orb_selfie: self.compute_score(
                        &orb,
                        &live,
                        ComparisonRole::OrbSelfie,
                    )?,
                    similarity_orb_challenge: self.compute_score(
                        &orb,
                        &challenge,
                        ComparisonRole::OrbChallenge,
                    )?,
                    similarity_selfie_challenge: self.compute_score(
                        &live,
                        &challenge,
                        ComparisonRole::SelfieChallenge,
                    )?,
                }))
            }
            MatchInputs::GrayBadge(inputs) => {
                let live = self.live_embedding(inputs.live)?;
                let challenge =
                    self.generate_embedding(&inputs.rtms_challenge, ImageRole::RtmsChallenge)?;
                Ok(ComparisonScores::GrayBadge(GrayBadgeScores {
                    similarity_selfie_challenge: self.compute_score(
                        &live,
                        &challenge,
                        ComparisonRole::SelfieChallenge,
                    )?,
                }))
            }
        }
    }
}

fn decode_image(bytes: &[u8], role: ImageRole) -> Result<RgbImage, FailureReason> {
    let invalid = || FailureReason::ImageAnalysisFailed {
        image: role,
        reason: AnalysisFailure::InvalidImage,
    };
    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| invalid())?;
    let format = reader.format().ok_or_else(invalid)?;
    if !matches!(format, image::ImageFormat::Jpeg | image::ImageFormat::Png) {
        return Err(invalid());
    }
    let (width, height) = reader.into_dimensions().map_err(|_| invalid())?;
    if width == 0
        || height == 0
        || width > 8192
        || height > 8192
        || u64::from(width) * u64::from(height) > 16 * 1024 * 1024
    {
        return Err(invalid());
    }
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(256 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode().map_err(|_| invalid())?.into_rgb8();
    RgbImage::new(image.into_raw(), height, width, None).map_err(|_| invalid())
}
