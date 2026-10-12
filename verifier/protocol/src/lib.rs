//! The Flamingo Token: the signed claim a passing comparison produces ([`flamingo_token`]).
//!
//! What it travels in — the sealed request and response of one exchange — is
//! `flamingo-verifier-sealed-types`.
//!
//! Work in progress — no external security review yet, and the token format follows the WIP-201
//! draft. Not production ready.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub mod error;
pub mod flamingo_token;

pub use ark_babyjubjub::Fq;
pub use eddsa_babyjubjub::EdDSAPublicKey;
pub use error::Error;
