//! Blocking, single-request CBOR RPC over an inherited Unix socket; no handshake or retry.

mod client;
mod server;
mod transport;

pub use client::{WorkerClient, WorkerClientConfig, WorkerClientError};
pub use server::{WorkerServerConfig, WorkerServerError, serve_worker};
