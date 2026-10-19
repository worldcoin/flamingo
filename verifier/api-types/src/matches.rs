//! Bounds for the opaque binary match exchange.

/// Maximum bytes in one entry's `data`.
pub const MAX_ENTRY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum `data` bytes across all entries (unchanged intended image budget).
pub const MAX_TOTAL_ENTRY_BYTES: usize = 7 * 1024 * 1024;
/// Entry data plus every `meta`, the request fields and bounded CBOR structural overhead.
pub const MAX_MATCH_PLAINTEXT_BYTES: usize = MAX_TOTAL_ENTRY_BYTES + 8 * 1024;
/// Plaintext budget plus room for the Pontifex channel envelope.
pub const MAX_MATCH_BODY_BYTES: usize = MAX_MATCH_PLAINTEXT_BYTES + 4096;
/// Fixed plaintext budget for the version 3 response.
pub const MATCH_RESPONSE_ENVELOPE_LEN: usize = 256 * 1024;
/// Maximum UTF-8 bytes in a worker report delivered to clients.
pub const MAX_DEBUG_REPORT_BYTES: usize = 192 * 1024;
/// Bounded encrypted response including channel overhead.
pub const MAX_MATCH_RESPONSE_BYTES: usize = MATCH_RESPONSE_ENVELOPE_LEN + 4096;
