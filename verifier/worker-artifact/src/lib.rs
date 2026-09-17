//! Hash-checked single-executable bundles. No executable fallback.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use tempfile::TempDir;

mod config;
pub use config::BootstrapConfig;

/// The only executable entry point accepted by the public broker.
pub const WORKER_PATH: &str = "bin/verifier-worker";
/// Maximum declared JSON bytes, before parsing or artifact allocation.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Hard format ceiling; the measured boot configuration must choose its own smaller budget.
pub const MAX_BUNDLE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Deployment metadata for one executable. It provides integrity, not authenticity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Version 3 contains one unsigned executable; older signed formats are not accepted.
    pub manifest_version: u32,
    /// Deployment-assigned diagnostic identifier, not an anti-rollback counter.
    pub release_id: String,
    /// Lowercase hex SHA-384 of the entire executable.
    pub sha384: String,
    /// Exact nonzero executable bytes following the declared metadata.
    pub size: u64,
}

/// Verified executable and its fixed sandbox root, held for the worker lifetime.
pub struct VerifiedRuntime {
    /// Read-only executable descriptor passed directly to Minijail.
    pub binary: File,
    /// Fresh root containing only the verified executable; no write handles survive.
    pub root: TempDir,
    /// Deployment-supplied diagnostic release identifier.
    pub release_id: String,
    /// SHA-384 checked against the transferred executable (not a publisher identity).
    pub sha384: String,
}

/// Redacted failures; no untrusted paths, manifest text or model bytes are included.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O, truncation or socket timeout failure.
    #[error("worker bundle I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Unusable public limits.
    #[error("worker bundle limits are not configured")]
    InvalidConfig,
    /// Length, fields, hash or executable size violate the contract.
    #[error("invalid worker executable manifest")]
    InvalidManifest,
    /// Executable bytes differ from the declared hash.
    #[error("worker artifact digest mismatch")]
    DigestMismatch,
    /// Wrong executable format or architecture.
    #[error("worker must be an x86_64 little-endian Linux ELF executable")]
    InvalidExecutable,
    /// A declared bundle must end exactly at its declared executable.
    #[error("trailing data after worker bundle")]
    TrailingData,
}

impl Manifest {
    /// Validates declared metadata and the executable budget before creating any files.
    pub fn validate(&self, max_bundle_bytes: u64) -> Result<(), Error> {
        if max_bundle_bytes == 0 || max_bundle_bytes > MAX_BUNDLE_BYTES {
            return Err(Error::InvalidConfig);
        }
        if self.manifest_version != 3
            || self.release_id.is_empty()
            || self.release_id.len() > 128
            || !self
                .release_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || self.size == 0
            || self.size > max_bundle_bytes
            || self.sha384.len() != 96
            || !self
                .sha384
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidManifest);
        }
        Ok(())
    }
}

/// Verifies declared metadata, then streams one executable to a broker-chosen path.
/// For socket readers, the caller configures a fixed read timeout before calling this
/// function and a write timeout for the subsequent acknowledgement. The sender must
/// close its write half: receiving the executable alone does not complete the transfer.
/// Socket timeouts bound individual I/O operations, not the full transfer. The bootstrap
/// supervisor owns the overall startup timeout and terminates the provisioner and enclave
/// before retrying. Any I/O error, including `WouldBlock`, abandons this receive attempt.
/// Limits come from the measured image. The parent deployment selects the executable.
pub fn receive(
    reader: &mut impl Read,
    max_bundle_bytes: u64,
    parent: &Path,
) -> Result<VerifiedRuntime, Error> {
    if max_bundle_bytes == 0 || max_bundle_bytes > MAX_BUNDLE_BYTES {
        return Err(Error::InvalidConfig);
    }
    let manifest_bytes = read_frame(reader, MAX_MANIFEST_BYTES)?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| Error::InvalidManifest)?;
    manifest.validate(max_bundle_bytes)?;

    let root = tempfile::Builder::new()
        .prefix("worker-runtime-")
        .tempdir_in(parent)?;
    let worker_path = root.path().join(WORKER_PATH);
    let bin = root.path().join("bin");
    fs::create_dir(&bin)?;
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&worker_path)?;
    let mut digest = Sha384::new();
    let mut remaining = manifest.size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..length])?;
        digest.update(&buffer[..length]);
        file.write_all(&buffer[..length])?;
        remaining -= length as u64;
    }
    if hex::encode(digest.finalize()) != manifest.sha384 {
        return Err(Error::DigestMismatch);
    }
    file.set_permissions(fs::Permissions::from_mode(0o555))?;
    drop(file);
    if reader.read(&mut [0])? != 0 {
        return Err(Error::TrailingData);
    }
    let mut binary = File::open(&worker_path)?;
    let mut header = [0_u8; 20];
    binary.read_exact(&mut header)?;
    if &header[..7] != b"\x7fELF\x02\x01\x01"
        || ![2, 3].contains(&u16::from_le_bytes([header[16], header[17]]))
        || u16::from_le_bytes([header[18], header[19]]) != 62
    {
        return Err(Error::InvalidExecutable);
    }
    // Only now allow the unprivileged worker to traverse its root. Minijail binds it read-only.
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755))?;
    Ok(VerifiedRuntime {
        binary,
        root,
        release_id: manifest.release_id,
        sha384: manifest.sha384,
    })
}

/// Writes an already declared executable, checking its exact size and hash while streaming.
/// The deployment pipeline owns artifact authenticity.
pub fn package(
    writer: &mut impl Write,
    manifest_bytes: &[u8],
    executable: &Path,
) -> Result<(), Error> {
    if manifest_bytes.is_empty() || manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Error::InvalidManifest);
    }
    let manifest: Manifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| Error::InvalidManifest)?;
    manifest.validate(MAX_BUNDLE_BYTES)?;
    writer.write_all(&(manifest_bytes.len() as u32).to_be_bytes())?;
    writer.write_all(manifest_bytes)?;
    // The publisher supplies one regular executable, never a directory or symlink.
    if !fs::symlink_metadata(executable)?.is_file() {
        return Err(Error::InvalidManifest);
    }
    let mut file = File::open(executable)?;
    let mut digest = Sha384::new();
    let mut remaining = manifest.size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..length])?;
        digest.update(&buffer[..length]);
        writer.write_all(&buffer[..length])?;
        remaining -= length as u64;
    }
    if file.read(&mut [0])? != 0 || hex::encode(digest.finalize()) != manifest.sha384 {
        return Err(Error::DigestMismatch);
    }
    Ok(())
}

/// Bounds the bootstrap metadata frame before allocating them.
fn read_frame(reader: &mut impl Read, maximum: usize) -> Result<Vec<u8>, Error> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > maximum {
        return Err(Error::InvalidManifest);
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
