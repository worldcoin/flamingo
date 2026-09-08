//! Client for the Flamingo Verifier's enclave-assignment flow.
//!
//! Fetches an assignment, verifies the AWS Nitro attestation document it carries, and yields
//! a [`ChannelConsumer`] bound to the separately supplied public key. The signed document
//! commits to that key; Pontifex checks the commitment, measurements, signature and freshness.
//!
//! ```no_run
//! use flamingo_verifier_client::{Config, FlamingoVerifierClient, PcrMeasurement};
//! use flamingo_verifier_sealed_types::MatchInputs;
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
//! ```

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod client;
mod config;
mod error;

pub use client::{FlamingoVerifierClient, VerifiedAssignment};
pub use config::Config;
pub use error::Error;
pub use pontifex::{ChannelConsumer, PcrMeasurement};
