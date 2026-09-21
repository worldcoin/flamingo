//! Blocking execution that remains supervised after a caller disconnects.

use std::panic::{AssertUnwindSafe, catch_unwind};

use flamingo_verifier_enclave_types::Error;

pub async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Error> {
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _entered = span.enter();
        catch_unwind(AssertUnwindSafe(work)).unwrap_or_else(|_| {
            tracing::error!("blocking enclave task panicked");
            std::process::exit(1);
        })
    })
    .await
    .map_err(|_| Error::Internal)
}
