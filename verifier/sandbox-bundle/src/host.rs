//! Host-side APIs shared by the provisioner and the manual sandbox-bundle CLI.
//!
//! Network I/O is asynchronous: dropping a provisioning future closes its owned
//! socket. No blocking network task survives cancellation. The caller bounds the
//! whole bootstrap; each socket operation also has an I/O deadline.

use std::{
    future::Future,
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use sha2::{Digest, Sha384};
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use crate::{MAX_BUNDLE_BYTES, MAX_MANIFEST_BYTES, Manifest};

/// Bounded diagnostics: no paths, manifest contents or arbitrary peer output.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Local file or network operation failed.
    #[error("sandbox bundle {stage} failed ({kind:?}, errno {errno:?})")]
    Io {
        /// Fixed operation name supplied by this library.
        stage: &'static str,
        /// Portable I/O category.
        kind: io::ErrorKind,
        /// Native errno, where available.
        errno: Option<i32>,
    },
    /// One network operation exceeded its deadline.
    #[error("sandbox bundle {0} timed out")]
    Timeout(&'static str),
    /// Metadata or file type violates the existing bundle contract.
    #[error("invalid sandbox bundle")]
    InvalidBundle,
    /// File contents changed after preparation.
    #[error("sandbox bundle executable changed during transfer")]
    Changed,
    /// The receiver returned a nonzero or malformed acknowledgement.
    #[error("sandbox bundle initialization acknowledgement is invalid")]
    Acknowledgement,
    /// The broker's health request failed.
    #[error("enclave health check failed")]
    Health,
    /// No alternate transport is permitted on unsupported platforms.
    #[error("enclave provisioning requires Linux vsock")]
    Unsupported,
}

fn io_error(stage: &'static str, error: io::Error) -> Error {
    Error::Io {
        stage,
        kind: error.kind(),
        errno: error.raw_os_error(),
    }
}

async fn checked<T>(
    stage: &'static str,
    deadline: Duration,
    operation: impl Future<Output = io::Result<T>>,
) -> Result<T, Error> {
    timeout(deadline, operation)
        .await
        .map_err(|_| Error::Timeout(stage))?
        .map_err(|error| io_error(stage, error))
}

/// An executable plus verified metadata, not an intermediate bundle file.
pub struct Bundle {
    executable: PathBuf,
    manifest: Manifest,
}

impl Bundle {
    /// Hashes one regular executable and validates its size and release metadata.
    pub async fn prepare(release_id: &str, executable: &Path) -> Result<Self, Error> {
        let mut file = open(executable).await?;
        let size = file
            .metadata()
            .await
            .map_err(|error| io_error("metadata", error))?
            .len();

        if size == 0 || size > MAX_BUNDLE_BYTES {
            return Err(Error::InvalidBundle);
        }

        let mut digest = Sha384::new();
        let mut remaining = size;
        let mut buffer = [0; 64 * 1024];

        while remaining != 0 {
            let length = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..length])
                .await
                .map_err(|error| io_error("hash", error))?;
            digest.update(&buffer[..length]);
            remaining -= length as u64;
        }

        if file
            .read(&mut [0])
            .await
            .map_err(|error| io_error("hash", error))?
            != 0
        {
            return Err(Error::Changed);
        }

        let manifest = Manifest {
            manifest_version: 3,
            release_id: release_id.to_owned(),
            sha384: hex::encode(digest.finalize()),
            size,
        };
        manifest
            .validate(MAX_BUNDLE_BYTES)
            .map_err(|_| Error::InvalidBundle)?;

        Ok(Self {
            executable: executable.to_owned(),
            manifest,
        })
    }

    /// Exact metadata bytes used by both CLI packaging and direct transmission.
    pub fn manifest(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&self.manifest).map_err(|_| Error::InvalidBundle)
    }

    /// Connects once, streams the bundle and waits for successful initialization.
    /// Only connection refusal before transfer is retried, as in the existing CLI.
    pub async fn provision(&self, cid: u32, io_timeout: Duration) -> Result<(), Error> {
        let stream = connect(cid, io_timeout).await?;
        self.deliver(stream, io_timeout).await
    }

    async fn deliver(
        &self,
        mut stream: impl AsyncRead + AsyncWrite + Unpin,
        deadline: Duration,
    ) -> Result<(), Error> {
        self.transfer(&mut stream, deadline).await?;
        acknowledge(&mut stream, deadline).await
    }

    async fn transfer(
        &self,
        stream: &mut (impl AsyncWrite + Unpin),
        deadline: Duration,
    ) -> Result<(), Error> {
        let mut file = open(&self.executable).await?;
        let manifest = self.manifest()?;

        checked(
            "transfer",
            deadline,
            stream.write_all(&(manifest.len() as u32).to_be_bytes()),
        )
        .await?;
        checked("transfer", deadline, stream.write_all(&manifest)).await?;

        let mut digest = Sha384::new();
        let mut remaining = self.manifest.size;
        let mut buffer = [0; 64 * 1024];

        while remaining != 0 {
            let length = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..length])
                .await
                .map_err(|error| io_error("read", error))?;
            digest.update(&buffer[..length]);
            checked("transfer", deadline, stream.write_all(&buffer[..length])).await?;
            remaining -= length as u64;
        }

        if file
            .read(&mut [0])
            .await
            .map_err(|error| io_error("read", error))?
            != 0
            || hex::encode(digest.finalize()) != self.manifest.sha384
        {
            return Err(Error::Changed);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;

async fn open(path: &Path) -> Result<File, Error> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|error| io_error("metadata", error))?;

    if !metadata.is_file() {
        return Err(Error::InvalidBundle);
    }

    File::open(path)
        .await
        .map_err(|error| io_error("open", error))
}

/// Sends a previously packed file; preserves the standalone CLI's interface.
pub async fn send(cid: u32, path: &Path, io_timeout: Duration) -> Result<(), Error> {
    let mut file = open(path).await?;
    let size = file
        .metadata()
        .await
        .map_err(|error| io_error("metadata", error))?
        .len();

    if size == 0 || size > MAX_BUNDLE_BYTES + MAX_MANIFEST_BYTES as u64 + 4 {
        return Err(Error::InvalidBundle);
    }

    let mut stream = connect(cid, io_timeout).await?;
    let mut remaining = size;
    let mut buffer = [0; 64 * 1024];

    while remaining != 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..length])
            .await
            .map_err(|error| io_error("read", error))?;
        checked("transfer", io_timeout, stream.write_all(&buffer[..length])).await?;
        remaining -= length as u64;
    }

    if file
        .read(&mut [0])
        .await
        .map_err(|error| io_error("read", error))?
        != 0
    {
        return Err(Error::Changed);
    }

    acknowledge(&mut stream, io_timeout).await
}

async fn acknowledge(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    deadline: Duration,
) -> Result<(), Error> {
    checked("write-shutdown", deadline, stream.shutdown()).await?;

    let mut acknowledgement = [0xff];
    checked(
        "ack-read",
        deadline,
        stream.read_exact(&mut acknowledgement),
    )
    .await?;

    if acknowledgement != [0] {
        return Err(Error::Acknowledgement);
    }

    if checked("ack-close", deadline, stream.read(&mut [0])).await? != 0 {
        return Err(Error::Acknowledgement);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn connect(cid: u32, deadline: Duration) -> Result<tokio_vsock::VsockStream, Error> {
    use tokio_vsock::{VsockAddr, VsockStream};

    if cid <= 2 || deadline.is_zero() || deadline > Duration::from_secs(900) {
        return Err(Error::InvalidBundle);
    }

    loop {
        match checked(
            "connect",
            deadline,
            VsockStream::connect(VsockAddr::new(cid, 1001)),
        )
        .await
        {
            Ok(stream) => return Ok(stream),
            Err(Error::Io {
                kind: io::ErrorKind::ConnectionRefused,
                ..
            }) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn connect(_: u32, _: Duration) -> Result<tokio::io::DuplexStream, Error> {
    Err(Error::Unsupported)
}

/// Checks the initialized broker over its normal serving port, never bootstrap.
pub async fn health(cid: u32) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        timeout(
            Duration::from_secs(2),
            pontifex::client::send(
                pontifex::client::ConnectionDetails::new(cid, 1000),
                &flamingo_verifier_enclave_types::HealthRequest,
            ),
        )
        .await
        .map_err(|_| Error::Timeout("health"))?
        .map_err(|_| Error::Health)?
        .map_err(|_| Error::Health)?;

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = cid;
        Err(Error::Unsupported)
    }
}
