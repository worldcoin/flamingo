//! Client for the Flamingo Verifier's enclave-assignment flow.
//!
//! Fetches an assignment, verifies the AWS Nitro attestation document it carries, and yields
//! a `ChannelConsumer` bound to the separately supplied public key. The signed document
//! commits to that key; Pontifex checks the commitment, measurements, signature and freshness.
//!
//! The default `http` feature enables the client and all shared types. Without default
//! features, only [`api_types`] is enabled. Enable `protocol` for signed claims or
//! `sealed-types` for sealed payloads (which also enables `protocol`).
//!
//! ```no_run
//! # #[cfg(feature = "http")]
//! # {
//! use flamingo_verifier_client::{Config, FlamingoVerifierClient, PcrMeasurement};
//! use flamingo_verifier_client::sealed_types::MatchInputs;
//!
//! # async fn example(inputs: &MatchInputs, pcr0: [u8; 48]) -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::new(
//!     "https://verifier.example.com",
//!     vec![vec![PcrMeasurement::new(0, pcr0)]],
//! )?;
//! let client = FlamingoVerifierClient::new(config)?;
//! let assignment = client.request_assignment().await?;
//! let result = client.request_match(&assignment, inputs).await?;
//! # Ok(())
//! # }
//! # }
//! ```

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

#[cfg(feature = "http")]
mod client;
#[cfg(feature = "http")]
mod config;
#[cfg(feature = "http")]
mod error;

#[cfg(feature = "http")]
pub use client::{FlamingoVerifierClient, VerifiedAssignment, VerifiedMatch, VerifiedMatchResult};
#[cfg(feature = "http")]
pub use config::Config;
#[cfg(feature = "http")]
pub use error::Error;
#[cfg(feature = "http")]
pub use pontifex::{ChannelConsumer, PcrMeasurement};

/// HTTP request and response types shared with the host.
pub mod api_types;

/// Signed match claims and token verification.
#[cfg(feature = "protocol")]
pub mod protocol;

/// Sealed client-to-enclave match requests and responses.
#[cfg(feature = "sealed-types")]
pub mod sealed_types;
