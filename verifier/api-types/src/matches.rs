//! Bounds for the opaque binary match exchange.
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
/// Fixed plaintext budget for the version 3 response.
pub const MATCH_RESPONSE_ENVELOPE_LEN: usize = 256 * 1024;
/// Maximum UTF-8 bytes in a worker report delivered to clients.
pub const MAX_DEBUG_REPORT_BYTES: usize = 192 * 1024;
/// Bounded encrypted response including channel overhead.
pub const MAX_MATCH_RESPONSE_BYTES: usize = MATCH_RESPONSE_ENVELOPE_LEN + 4096;
