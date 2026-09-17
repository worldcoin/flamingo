//! Internal protocol crate, sharing its implementation with the published client.

#[path = "../../client/src/protocol/mod.rs"]
mod protocol;

pub use protocol::*;
