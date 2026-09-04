//! Bounded HTTP/2 RPC over one inherited Unix socket; no listener or reconnect.

mod client;
mod http;
mod server;
mod session;

pub use client::{WorkerClient, WorkerClientConfig, WorkerClientError, WorkerSession};
pub use server::{WorkerServerConfig, WorkerServerError, serve_worker};
