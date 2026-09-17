//! Internal sealed-types crate, sharing its implementation with the published client.

// Match the sibling module names used when these sources compile inside the client.
use flamingo_verifier_api_types as api_types;
use flamingo_verifier_protocol as protocol;

#[path = "../../client/src/sealed_types/mod.rs"]
mod sealed_types;

pub use sealed_types::*;
