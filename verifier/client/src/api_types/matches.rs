//! Bounds for the opaque binary match exchange.
/// Media type for encrypted match request and response bodies.
pub const MATCH_CONTENT_TYPE: &str = "application/octet-stream";
/// Maximum encoded bytes in one image.
pub const MAX_IMAGE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum encoded image bytes across all frames (unchanged intended image budget).
pub const MAX_TOTAL_IMAGE_BYTES: usize = 7 * 1024 * 1024;
/// Maximum raw PCP hashes.json bytes.
pub const MAX_HASHES_JSON_BYTES: usize = 64 * 1024;
/// Image/PCP budget plus bounded CBOR structural overhead.
pub const MAX_MATCH_PLAINTEXT_BYTES: usize = MAX_TOTAL_IMAGE_BYTES + MAX_HASHES_JSON_BYTES + 4096;
/// Plaintext budget plus room for the Pontifex channel envelope.
pub const MAX_MATCH_BODY_BYTES: usize = MAX_MATCH_PLAINTEXT_BYTES + 4096;
/// Bounded encrypted response (16 KiB padded plaintext plus channel overhead).
pub const MAX_MATCH_RESPONSE_BYTES: usize = 16 * 1024 + 4096;
