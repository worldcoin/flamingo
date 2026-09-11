use std::{io::Cursor, path::Path, sync::Arc};

use face_engine::{
    components::{
        captured_image_analyzer::CapturedImageAnalyzer, template_generator::TemplateGenerator,
    },
    io::{ml_model_files::MlModelFiles, rgb_image::RgbImage},
    matchers::cosine_similarity::CosineSimilarity,
    nodes::{subject_extraction::SubjectFace, template_generation::EmbeddingVector},
};
use flamingo_verifier_worker_protocol::ComparisonScores;
use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};

use crate::MAX_IMAGE_BYTES;

/// Embedded graph, with model files supplied by the trusted runtime bundle.
const ANALYZER_CONFIG: &str = include_str!("../config/face_analyzer.yaml");
/// Embedding generation only; thresholds and authentication belong to the broker.
const TEMPLATE_CONFIG: &str = include_str!("../config/face_template_generator.yaml");
/// Strict per-axis bound, applied before decoding pixels.
const MAX_DIMENSION: u32 = 4096;
/// Strict total pixel bound, including unusually wide/tall inputs.
const MAX_PIXELS: u64 = 8 * 1024 * 1024;
/// Decoder allocation budget; the sandbox's address-space limit is the hard process bound.
const MAX_DECODE_BYTES: u64 = 128 * 1024 * 1024;

/// Redacted failures: no image, embedding or third-party error payload is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ComparisonError {
    /// Invalid image or a model-reported input validation failure; the session is reusable.
    #[error("image analysis failed")]
    AnalysisFailed,
    /// Missing, corrupt or incompatible model/configuration; terminal.
    #[error("model initialization failed")]
    Initialization,
    /// Unexpected analyzer/backend failure; terminal.
    #[error("face detection failed")]
    Detection,
    /// Unexpected embedding/backend failure; terminal.
    #[error("embedding generation failed")]
    Embedding,
    /// Missing output or an invalid score from the model; terminal.
    #[error("model output violated its contract")]
    InvalidOutput,
}

/// The two pinned ONNX graphs and their cosine matcher, reused across requests.
pub struct FaceEngine {
    /// Produces an embedding from the extracted subject.
    template_generator: TemplateGenerator,
    /// Detects and extracts the largest face in the image.
    analyzer: CapturedImageAnalyzer,
    /// Raw cosine similarity, in the inclusive range [-1, 1].
    matcher: CosineSimilarity,
}

impl FaceEngine {
    /// Loads models from a trusted immutable directory; never downloads or searches for them.
    pub fn load(model_dir: &Path) -> Result<Self, ComparisonError> {
        let paths = MlModelFiles {
            rgbnet: Some(
                model_dir
                    .join("rgbnet.onnx")
                    .to_str()
                    .ok_or(ComparisonError::Initialization)?
                    .to_owned(),
            ),
            face_embedding_generator: Some(
                model_dir
                    .join("face_embedding_generator.onnx")
                    .to_str()
                    .ok_or(ComparisonError::Initialization)?
                    .to_owned(),
            ),
            ..Default::default()
        };
        let analyzer_config = paths
            .apply_to_yaml(ANALYZER_CONFIG)
            .map_err(|_| ComparisonError::Initialization)?;
        let template_config = paths
            .apply_to_yaml(TEMPLATE_CONFIG)
            .map_err(|_| ComparisonError::Initialization)?;

        Ok(Self {
            analyzer: CapturedImageAnalyzer::new(&analyzer_config)
                .map_err(|_| ComparisonError::Initialization)?,
            template_generator: TemplateGenerator::new(&template_config)
                .map_err(|_| ComparisonError::Initialization)?,
            matcher: CosineSimilarity::default(),
        })
    }

    /// Generates each embedding once, decoding one image at a time, and returns only scores.
    pub fn compare(
        &self,
        credential_image: &[u8],
        live_image: &[u8],
        challenge_image: &[u8],
    ) -> Result<ComparisonScores, ComparisonError> {
        let reference = self.generate_embedding(credential_image)?;
        let live = self.generate_embedding(live_image)?;
        let challenge = self.generate_embedding(challenge_image)?;

        Ok(ComparisonScores {
            live_similarity: compute_score(&self.matcher, &live, &reference)?,
            challenge_similarity: compute_score(&self.matcher, &challenge, &reference)?,
        })
    }

    /// Distinguishes expected validation failures from broken graphs/backends.
    fn generate_embedding(&self, image_bytes: &[u8]) -> Result<EmbeddingVector, ComparisonError> {
        let image = decode_image(image_bytes)?;
        let width = image.width();
        let height = image.height();
        let rgb_image = RgbImage::new(image.into_raw(), height, width, None);
        let rgb_image = rgb_image.map_err(|_| ComparisonError::InvalidOutput)?;
        let analysis = self
            .analyzer
            .run_inference_rgb(&rgb_image)
            .map_err(|_| ComparisonError::Detection)?;
        if analysis.error.is_some() {
            return Err(ComparisonError::AnalysisFailed);
        }
        let subject = SubjectFace {
            input_image: Arc::new(rgb_image),
            metadata: analysis
                .subject_face_extracted
                .ok_or(ComparisonError::InvalidOutput)?,
        };
        let output = self
            .template_generator
            .run_inference(&subject)
            .map_err(|_| ComparisonError::Embedding)?;
        if output.metadata.error.is_some() {
            return Err(ComparisonError::AnalysisFailed);
        }

        output
            .embedding_vector
            .ok_or(ComparisonError::InvalidOutput)
    }
}

/// Bounds compressed bytes, dimensions, pixels and decoded storage before RGB conversion.
fn decode_image(bytes: &[u8]) -> Result<image::RgbImage, ComparisonError> {
    if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
        return Err(ComparisonError::AnalysisFailed);
    }
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| ComparisonError::AnalysisFailed)?;
    if !matches!(
        reader.format(),
        Some(ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP)
    ) {
        return Err(ComparisonError::AnalysisFailed);
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_BYTES);
    reader.limits(limits);
    let decoder = reader
        .into_decoder()
        .map_err(|_| ComparisonError::AnalysisFailed)?;
    let dimensions = decoder.dimensions();
    if dimensions.0 == 0
        || dimensions.1 == 0
        || u64::from(dimensions.0) * u64::from(dimensions.1) > MAX_PIXELS
        || decoder.total_bytes() > MAX_DECODE_BYTES
    {
        return Err(ComparisonError::AnalysisFailed);
    }

    DynamicImage::from_decoder(decoder)
        .map(|image| image.into_rgb8())
        .map_err(|_| ComparisonError::AnalysisFailed)
}

/// Allows only endpoint roundoff; non-finite or genuinely out-of-domain scores are terminal.
fn compute_score(
    matcher: &CosineSimilarity,
    probe: &EmbeddingVector,
    reference: &EmbeddingVector,
) -> Result<f32, ComparisonError> {
    let score = matcher
        .compute_score(probe, reference)
        .map_err(|_| ComparisonError::InvalidOutput)?;
    // The pinned f32 matcher can slightly exceed 1 even for identical 512-D vectors.
    if !score.is_finite() || !(-1.0 - 1e-6..=1.0 + 1e-6).contains(&score) {
        return Err(ComparisonError::InvalidOutput);
    }
    Ok(score.clamp(-1.0, 1.0))
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};

    use super::*;

    /// Encodes a synthetic, non-biometric image using the production format set.
    fn encoded_image(width: u32, height: u32, format: ImageFormat) -> Vec<u8> {
        let image = DynamicImage::ImageRgb8(image::RgbImage::new(width, height));
        let mut bytes = Cursor::new(Vec::new());
        image.write_to(&mut bytes, format).unwrap();
        bytes.into_inner()
    }

    /// All supported encodings reach the same bounded RGB representation.
    #[test]
    fn accepts_jpeg_png_webp() {
        for format in [ImageFormat::Jpeg, ImageFormat::Png, ImageFormat::WebP] {
            let image = decode_image(&encoded_image(4, 3, format)).unwrap();
            assert_eq!(image.dimensions(), (4, 3));
            assert_eq!(image.len(), 36);
        }
    }

    /// Malformed input is recoverable and its contents never appear in the error.
    #[test]
    fn rejects_invalid_and_truncated_images() {
        for bytes in [b"".as_slice(), b"private-image-payload", b"GIF89a"] {
            assert_eq!(
                decode_image(bytes).unwrap_err(),
                ComparisonError::AnalysisFailed
            );
        }
        for format in [ImageFormat::Jpeg, ImageFormat::Png, ImageFormat::WebP] {
            let bytes = encoded_image(4, 3, format);
            assert_eq!(
                decode_image(&bytes[..bytes.len() / 2]).unwrap_err(),
                ComparisonError::AnalysisFailed
            );
        }
    }

    /// Strict dimensions and pixel counts reject decompression bombs before pixel decoding.
    #[test]
    fn rejects_oversized_images() {
        for (width, height) in [(MAX_DIMENSION + 1, 1), (1, MAX_DIMENSION + 1), (4096, 2049)] {
            assert_eq!(
                decode_image(&encoded_image(width, height, ImageFormat::Png)).unwrap_err(),
                ComparisonError::AnalysisFailed
            );
        }
        assert_eq!(
            decode_image(&vec![0; MAX_IMAGE_BYTES + 1]).unwrap_err(),
            ComparisonError::AnalysisFailed
        );
    }

    /// Encodes the Face Engine's fixed-width bincode length and little-endian floats.
    fn embedding(values: &[f32]) -> EmbeddingVector {
        let mut bytes = (values.len() as u64).to_le_bytes().to_vec();
        bytes.extend(values.iter().flat_map(|value| value.to_le_bytes()));
        EmbeddingVector {
            vector: STANDARD.encode(bytes),
            ..Default::default()
        }
    }

    /// Exercises the actual Face Engine matcher, including terminal non-finite output.
    #[test]
    fn cosine_scores_are_raw_and_finite() {
        let matcher = CosineSimilarity::default();
        let reference = embedding(&[1.0, 0.0]);
        for (values, expected) in [([1.0, 0.0], 1.0), ([0.0, 1.0], 0.0), ([-1.0, 0.0], -1.0)] {
            let score = compute_score(&matcher, &embedding(&values), &reference).unwrap();
            assert!((score - expected).abs() < 1e-6);
        }
        for value in [f32::NAN, f32::INFINITY] {
            assert_eq!(
                compute_score(&matcher, &embedding(&[value, 0.0]), &reference),
                Err(ComparisonError::InvalidOutput)
            );
        }
        let invalid = EmbeddingVector {
            vector: "private-embedding".into(),
            ..Default::default()
        };
        let error = compute_score(&matcher, &invalid, &reference).unwrap_err();
        assert_eq!(error, ComparisonError::InvalidOutput);
        assert!(!error.to_string().contains("private-embedding"));
    }

    /// Identical realistic-size vectors must remain usable despite cosine roundoff.
    #[test]
    fn identical_embeddings_stay_in_range() {
        let matcher = CosineSimilarity::default();
        for offset in 0..32 {
            let values: Vec<_> = (0..512)
                .map(|index| ((index * 17 + offset) % 101) as f32 / 100.0)
                .collect();
            let vector = embedding(&values);
            let score = compute_score(&matcher, &vector, &vector).unwrap();
            assert!((score - 1.0).abs() < 1e-6);
        }
    }
}
