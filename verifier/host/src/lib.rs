//! HTTP host for the Flamingo Verifier — the untrusted side of the enclave boundary.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod app_state;
mod engine_provider;
mod environment;

pub mod enclave;
pub mod error;
pub mod routes;
pub mod server;

pub use app_state::AppState;
pub use engine_provider::{
    ENGINE_METADATA_PATH, MAX_ENGINE_METADATA_BYTES, PublishedMetadata, PublishedMetadataError,
};
pub use environment::{Environment, HostConfig};
