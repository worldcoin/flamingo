//! Publisher-authenticated runtime bundles. No model code or executable fallback.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use tempfile::TempDir;

mod config;
pub mod transport;
pub use config::BootstrapConfig;

/// The only executable entry point accepted by the public broker.
pub const WORKER_PATH: &str = "bin/verifier-worker";
/// Maximum signed JSON bytes, before parsing or artifact allocation.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Hard format ceiling; the measured boot configuration must choose its own smaller budget.
pub const MAX_BUNDLE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// P-384 ASN.1 DER signatures require at most 104 bytes.
pub const MAX_SIGNATURE_BYTES: usize = 104;

/// Immutable release inventory; the signature covers these exact JSON bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Bundle format only, not worker protocol negotiation.
    pub manifest_version: u32,
    /// Publisher-assigned diagnostic identifier, not an anti-rollback counter.
    pub release_id: String,
    /// Artifact bytes follow in this exact order, without archive metadata or symlinks.
    pub artifacts: Vec<Artifact>,
}

/// One exact file in the worker's isolated runtime root.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Restricted relative path, never a host path.
    pub logical_path: String,
    /// Only the worker and its runtime linker/library closure are supported.
    pub role: Role,
    /// Lowercase hex SHA-384 of the entire file.
    pub sha384: String,
    /// Exact nonzero bytes following the signed inventory.
    pub size: u64,
}

/// Models and graph configuration belong inside the biometrics executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The sole worker executable.
    Worker,
    /// Its ELF interpreter, when dynamically linked.
    Loader,
    /// A runtime shared library or linker data file.
    Library,
}

/// Fully verified files, held until the broker and worker have terminated.
pub struct VerifiedRuntime {
    /// Read-only executable descriptor passed directly to Minijail.
    pub binary: File,
    /// Fresh tree containing only verified regular files; no write handles survive.
    pub root: TempDir,
    /// The authenticated release identifier.
    pub release_id: String,
}

/// Redacted failures; no untrusted paths, manifest text or model bytes are included.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O, truncation or deadline failure.
    #[error("worker bundle I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Unconfigured trust or unusable public limits.
    #[error("worker bundle trust or limits are not configured")]
    InvalidConfig,
    /// Length, fields, paths, roles or aggregate size violate the contract.
    #[error("invalid worker runtime manifest")]
    InvalidManifest,
    /// No measured publisher key authorized these exact manifest bytes.
    #[error("worker manifest signature verification failed")]
    InvalidSignature,
    /// Artifact data differs from the signed inventory.
    #[error("worker artifact digest mismatch")]
    DigestMismatch,
    /// Wrong executable format or architecture.
    #[error("worker must be an x86_64 little-endian Linux ELF executable")]
    InvalidExecutable,
    /// A signed bundle must end exactly at its declared last artifact.
    #[error("trailing data after worker bundle")]
    TrailingData,
}

impl Manifest {
    /// Validates paths and the whole resource budget before creating any files.
    pub fn validate(&self, max_bundle_bytes: u64) -> Result<(), Error> {
        if max_bundle_bytes == 0 || max_bundle_bytes > MAX_BUNDLE_BYTES {
            return Err(Error::InvalidConfig);
        }
        if self.manifest_version != 1
            || self.release_id.is_empty()
            || self.release_id.len() > 128
            || !self
                .release_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || self.artifacts.is_empty()
            || self.artifacts.len() > 128
        {
            return Err(Error::InvalidManifest);
        }
        let mut paths = BTreeSet::new();
        let mut total = 0_u64;
        let mut workers = 0;
        let mut loaders = 0;
        for artifact in &self.artifacts {
            let path = &artifact.logical_path;
            if path.len() > 256
                || path.split('/').count() > 16
                || path.split('/').any(|part| {
                    part.is_empty()
                        || part == "."
                        || part == ".."
                        || !part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
                })
                || !paths.insert(path)
                || artifact.size == 0
                || artifact.sha384.len() != 96
                || !artifact
                    .sha384
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Error::InvalidManifest);
            }
            total = total
                .checked_add(artifact.size)
                .ok_or(Error::InvalidManifest)?;
            if total > max_bundle_bytes {
                return Err(Error::InvalidManifest);
            }
            match artifact.role {
                Role::Worker if path == WORKER_PATH => workers += 1,
                Role::Loader | Role::Library
                    if path.starts_with("lib/")
                        || path.starts_with("lib64/")
                        || path.starts_with("nix/store/") =>
                {
                    if artifact.role == Role::Loader {
                        loaders += 1;
                    }
                }
                _ => return Err(Error::InvalidManifest),
            }
        }
        if workers != 1 || loaders > 1 {
            return Err(Error::InvalidManifest);
        }
        // Reject a file that would also need to be another file's parent directory.
        for path in &paths {
            for (index, _) in path.match_indices('/') {
                if paths.contains(&path[..index].to_string()) {
                    return Err(Error::InvalidManifest);
                }
            }
        }
        Ok(())
    }
}

/// Reads and verifies one framed manifest, then streams exact artifacts into a fresh tree.
/// The caller supplies a deadline-bound reader and must require sender write-half EOF.
/// Trust and limits come only from the measured image, never this untrusted stream.
pub fn receive(
    reader: &mut impl Read,
    publisher_keys: &[VerifyingKey],
    max_bundle_bytes: u64,
    parent: &Path,
) -> Result<VerifiedRuntime, Error> {
    if publisher_keys.is_empty()
        || publisher_keys.len() > 8
        || max_bundle_bytes == 0
        || max_bundle_bytes > MAX_BUNDLE_BYTES
    {
        return Err(Error::InvalidConfig);
    }
    let manifest_bytes = read_frame(reader, MAX_MANIFEST_BYTES)?;
    let signature_bytes = read_frame(reader, MAX_SIGNATURE_BYTES)?;
    let signature = Signature::from_der(&signature_bytes).map_err(|_| Error::InvalidSignature)?;
    if !publisher_keys
        .iter()
        .any(|key| key.verify(&manifest_bytes, &signature).is_ok())
    {
        return Err(Error::InvalidSignature);
    }
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| Error::InvalidManifest)?;
    manifest.validate(max_bundle_bytes)?;

    let root = tempfile::Builder::new()
        .prefix("worker-runtime-")
        .tempdir_in(parent)?;
    let mut buffer = [0_u8; 64 * 1024];
    for artifact in &manifest.artifacts {
        let path = root.path().join(&artifact.logical_path);
        fs::create_dir_all(path.parent().ok_or(Error::InvalidManifest)?)?;
        // Ignore a hardened broker umask for loader traversal after dropping the worker UID.
        // The top-level temporary root remains 0700 until every artifact verifies.
        for directory in path.parent().ok_or(Error::InvalidManifest)?.ancestors() {
            if directory == root.path() {
                break;
            }
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let mut digest = Sha384::new();
        let mut remaining = artifact.size;
        while remaining != 0 {
            let length = remaining.min(buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..length])?;
            digest.update(&buffer[..length]);
            file.write_all(&buffer[..length])?;
            remaining -= length as u64;
        }
        if hex::encode(digest.finalize()) != artifact.sha384 {
            return Err(Error::DigestMismatch);
        }
        file.set_permissions(fs::Permissions::from_mode(0o555))?;
    }
    if reader.read(&mut [0])? != 0 {
        return Err(Error::TrailingData);
    }
    let worker_path = root.path().join(WORKER_PATH);
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
    })
}

/// Writes an already signed release, validating its inventory before streaming local bytes.
/// No signing secret is needed by the packager or startup provisioner.
pub fn package(
    writer: &mut impl Write,
    manifest_bytes: &[u8],
    signature: &[u8],
    root: &Path,
) -> Result<(), Error> {
    if manifest_bytes.is_empty()
        || manifest_bytes.len() > MAX_MANIFEST_BYTES
        || signature.is_empty()
        || signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(Error::InvalidManifest);
    }
    Signature::from_der(signature).map_err(|_| Error::InvalidSignature)?;
    let manifest: Manifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| Error::InvalidManifest)?;
    manifest.validate(MAX_BUNDLE_BYTES)?;
    for bytes in [manifest_bytes, signature] {
        writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
        writer.write_all(bytes)?;
    }
    for artifact in manifest.artifacts {
        let path = root.join(&artifact.logical_path);
        // Packaging accepts only regular files, never links or devices; root is publisher-controlled.
        if !fs::symlink_metadata(&path)?.is_file() {
            return Err(Error::InvalidManifest);
        }
        let mut file = File::open(path)?;
        let mut digest = Sha384::new();
        let mut remaining = artifact.size;
        let mut buffer = [0_u8; 64 * 1024];
        while remaining != 0 {
            let length = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..length])?;
            digest.update(&buffer[..length]);
            writer.write_all(&buffer[..length])?;
            remaining -= length as u64;
        }
        if file.read(&mut [0])? != 0 || hex::encode(digest.finalize()) != artifact.sha384 {
            return Err(Error::DigestMismatch);
        }
    }
    Ok(())
}

/// Bounds both bootstrap metadata frames before allocating them.
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
