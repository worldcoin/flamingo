use std::{
    error::Error,
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    panic::{AssertUnwindSafe, catch_unwind},
};

use flamingo_verifier_worker_protocol::{
    CompareRequest, MAX_RESPONSE_BYTES, WorkerProtocolError, WorkerResult, decode_message,
    encode_message,
};

use crate::transport;

/// Worker-enforced limits, independent of the broker's configuration.
#[derive(Debug, Clone, Copy)]
pub struct WorkerServerConfig {
    /// Maximum encoded request body, excluding its length prefix.
    pub max_request_bytes: usize,
    /// Maximum bytes per nonempty encoded image; decoded-pixel limits belong to the model.
    pub max_image_bytes: usize,
}

/// Reads, computes and replies sequentially. The callback may initialize its model lazily.
/// Infrastructure errors and panics terminate the connection; the worker entry point must exit.
/// A stuck callback cannot be interrupted here: the broker must kill the process.
pub fn serve_worker<F>(
    mut stream: UnixStream,
    config: WorkerServerConfig,
    mut comparator: F,
) -> Result<(), WorkerServerError>
where
    F: FnMut(CompareRequest) -> Result<WorkerResult, Box<dyn Error + Send + Sync>>,
{
    if !transport::valid_limits(config.max_request_bytes, config.max_image_bytes) {
        return Err(WorkerServerError::InvalidConfig);
    }
    stream.set_nonblocking(false)?;

    let result = run(&mut stream, config, &mut comparator);
    if let Err(error) = &result {
        tracing::warn!(
            dependency = "biometric_model",
            %error,
            "worker server stopped"
        );
    }
    result
}

/// Keeps exactly one decoded request and computation alive at a time.
fn run<F>(
    stream: &mut UnixStream,
    config: WorkerServerConfig,
    comparator: &mut F,
) -> Result<(), WorkerServerError>
where
    F: FnMut(CompareRequest) -> Result<WorkerResult, Box<dyn Error + Send + Sync>>,
{
    // The trusted broker owns deadlines and kills this process if I/O or inference stalls.
    loop {
        let mut length = [0; 4];
        loop {
            match stream.read(&mut length[..1]) {
                Ok(0) => return Ok(()),
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        stream.read_exact(&mut length[1..])?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > config.max_request_bytes {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "invalid worker frame length").into(),
            );
        }
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload)?;
        let request: CompareRequest = decode_message(&payload, config.max_request_bytes)?;
        drop(payload);
        if !request.valid_image_sizes(config.max_image_bytes) {
            return Err(WorkerServerError::InvalidImages);
        }

        let span = tracing::info_span!("worker.infer", dependency = "biometric_model");
        let _entered = span.enter();
        let result = catch_unwind(AssertUnwindSafe(|| comparator(request)));
        let response = result
            .map_err(|_| WorkerServerError::ModelPanic)?
            .map_err(WorkerServerError::Model)?;

        let payload = encode_message(&response, MAX_RESPONSE_BYTES)?;
        stream.write_all(&(payload.len() as u32).to_be_bytes())?;
        stream.write_all(&payload)?;
    }
}

/// Terminal worker failures; ordinary image analysis failures use `WorkerResult::AnalysisFailed`.
#[derive(Debug, thiserror::Error)]
pub enum WorkerServerError {
    /// Invalid body limits.
    #[error("invalid worker server configuration")]
    InvalidConfig,
    /// Socket or framing failure.
    #[error("worker socket I/O failed: {0}")]
    Transport(#[from] io::Error),
    /// Malformed request or response serialization failure.
    #[error("worker CBOR failed: {0}")]
    Protocol(#[from] WorkerProtocolError),
    /// An encoded image was empty or too large.
    #[error("worker images violate byte limits")]
    InvalidImages,
    /// The callback failed; Display omits its potentially sensitive error contents.
    #[error("worker model failed")]
    Model(#[source] Box<dyn Error + Send + Sync>),
    /// The callback panicked; its potentially sensitive panic payload is not retained.
    #[error("worker model panicked")]
    ModelPanic,
}
