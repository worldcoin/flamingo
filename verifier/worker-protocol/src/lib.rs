//! Public CBOR payloads for the sandboxed biometric worker. Transport lives in worker-rpc.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod codec;
mod error;
mod messages;

pub use codec::{decode_message, encode_message};
pub use error::WorkerProtocolError;
pub use messages::{CompareRequest, ComparisonScores, WorkerReady, WorkerResult};

/// Protocol version; incompatible versions require replacing the whole worker session.
pub const WORKER_PROTOCOL_VERSION: u16 = 1;
/// Maximum encoded startup or comparison response.
pub const MAX_RESPONSE_BYTES: usize = 1024;
/// CBOR media type required on all successful responses and comparison requests.
pub const CONTENT_TYPE: &str = "application/cbor";
/// Startup capability endpoint, served only after model initialization.
pub const READY_PATH: &str = "/v1/ready";
/// Three-image comparison endpoint.
pub const COMPARE_PATH: &str = "/v1/compare";
