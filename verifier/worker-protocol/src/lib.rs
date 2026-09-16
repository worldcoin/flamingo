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
pub use messages::{CompareRequest, ComparisonScores, WorkerResult};

/// Maximum encoded comparison response.
pub const MAX_RESPONSE_BYTES: usize = 1024;
