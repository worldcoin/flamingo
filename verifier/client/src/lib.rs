//! Client for the Flamingo Verifier host.
//!
//! Opens a WebSocket session, verifies the AWS Nitro attestation document that commits to the
//! enclave's encryption key, and runs one sealed match over the verified channel. The session
//! yields a [`ChannelConsumer`] bound to that key; Pontifex checks the commitment, measurements,
//! signature and freshness.
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
//! let session = client.connect().await?;
//! let result = session.request_match(inputs).await?;
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
#![cfg_attr(target_arch = "wasm32", allow(clippy::future_not_send))]

mod client;
mod config;
mod error;
#[cfg(not(target_arch = "wasm32"))]
mod session;
#[cfg(target_arch = "wasm32")]
mod session_browser;

pub use client::{FlamingoVerifierClient, VerifiedAssignment, VerifiedMatch, VerifiedMatchResult};
pub use config::Config;
pub use error::Error;
pub use pontifex::{ChannelConsumer, PcrMeasurement};
#[cfg(not(target_arch = "wasm32"))]
pub use session::FlamingoVerifierSession;
#[cfg(target_arch = "wasm32")]
pub use session_browser::FlamingoVerifierSession;
