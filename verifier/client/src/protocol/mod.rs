//! The `Verifier` match statement: the signed claim a held match produces.
//!
//! [`match_token`] holds the statement itself. What it travels in — the sealed request and
//! response of one exchange — is `sealed_types` (with the `sealed-types` feature).
//!
//! Work in progress — no external security review yet, and the token format is provisional
//! pending protocol sign-off. Not production ready.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub mod error;
pub mod match_token;

pub use error::Error;
