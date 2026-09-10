//! Offline release inventory/packaging and one-shot bounded host-to-enclave provisioning.

use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

use flamingo_verifier_worker_artifact::{
    Artifact, BootstrapConfig, MAX_BUNDLE_BYTES, MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES, Manifest,
    Role, WORKER_PATH,
};
use sha2::{Digest, Sha384};

/// Never handles a signing secret; the publisher signs the exact emitted manifest offline.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("validate-config") if args.len() == 3 => {
            BootstrapConfig::load_from(Path::new(&args[2]))?.validate()?;
        }
        Some("manifest") if args.len() == 4 => {
            let root = Path::new(&args[3]);
            if !fs::symlink_metadata(root)?.is_dir() {
                return Err("artifact root must be a directory, not a symlink".into());
            }
            let mut manifest = Manifest {
                manifest_version: 1,
                release_id: args[2].clone(),
                artifacts: Vec::new(),
            };
            let mut pending = vec![root.to_path_buf()];
            let mut entries = 0;
            let mut aggregate_bytes = 0_u64;
            while let Some(directory) = pending.pop() {
                for entry in fs::read_dir(directory)? {
                    entries += 1;
                    if entries > 2048 {
                        return Err("too many runtime entries".into());
                    }
                    let entry = entry?;
                    let path = entry.path();
                    let relative = path
                        .strip_prefix(root)?
                        .to_str()
                        .ok_or("non-UTF-8 artifact path")?
                        .to_owned();
                    if relative.len() > 256 || relative.split('/').count() > 16 {
                        return Err("runtime path exceeds limits".into());
                    }
                    if entry.file_type()?.is_dir() {
                        pending.push(path);
                        continue;
                    }
                    if !entry.file_type()?.is_file() {
                        return Err(
                            "stage regular files only; symlinks/devices are not supported".into(),
                        );
                    }
                    let mut file = File::open(path)?;
                    let size = file.metadata()?.len();
                    if size == 0 || size > MAX_BUNDLE_BYTES {
                        return Err("artifact size exceeds format limits".into());
                    }
                    aggregate_bytes = aggregate_bytes
                        .checked_add(size)
                        .ok_or("runtime size overflow")?;
                    if manifest.artifacts.len() >= 128 || aggregate_bytes > MAX_BUNDLE_BYTES {
                        return Err("runtime inventory exceeds artifact or byte limits".into());
                    }
                    let mut hash = Sha384::new();
                    let mut buffer = [0; 64 * 1024];
                    let mut total = 0_u64;
                    loop {
                        let count = file.read(&mut buffer)?;
                        if count == 0 {
                            break;
                        }
                        total += count as u64;
                        if total > size {
                            return Err("artifact changed during hashing".into());
                        }
                        hash.update(&buffer[..count]);
                    }
                    if total != size {
                        return Err("artifact changed during hashing".into());
                    }
                    manifest.artifacts.push(Artifact {
                        role: if relative == WORKER_PATH {
                            Role::Worker
                        } else {
                            Role::Library
                        },
                        logical_path: relative,
                        sha384: hex::encode(hash.finalize()),
                        size,
                    });
                }
            }
            manifest
                .artifacts
                .sort_by(|a, b| a.logical_path.cmp(&b.logical_path));
            manifest.validate(MAX_BUNDLE_BYTES)?;
            // No trailing newline: these exact bytes are what the publisher must sign.
            std::io::stdout().write_all(&serde_json::to_vec(&manifest)?)?;
        }
        Some("pack") if args.len() == 6 => {
            let mut manifest = Vec::new();
            File::open(&args[2])?
                .take(MAX_MANIFEST_BYTES as u64 + 1)
                .read_to_end(&mut manifest)?;
            let mut signature = Vec::new();
            File::open(&args[3])?
                .take(MAX_SIGNATURE_BYTES as u64 + 1)
                .read_to_end(&mut signature)?;
            let output = Path::new(&args[5]);
            let parent = output
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            flamingo_verifier_worker_artifact::package(
                &mut temporary,
                &manifest,
                &signature,
                Path::new(&args[4]),
            )?;
            temporary.as_file().sync_all()?;
            temporary.persist_noclobber(output)?;
        }
        Some("send") if args.len() == 5 => send(&args[2], &args[3], &args[4])?,
        _ => {
            return Err(concat!(
                "usage: worker-bundle manifest RELEASE_ID ARTIFACT_ROOT | ",
                "pack MANIFEST SIGNATURE_DER ARTIFACT_ROOT OUTPUT | ",
                "send CID BUNDLE TIMEOUT_SECONDS | validate-config CONFIG_PATH"
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/// One transfer; only pre-transfer connection establishment may be retried by the caller.
fn send(cid: &str, bundle: &str, timeout: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};
    let cid: u32 = cid.parse()?;
    let timeout: u64 = timeout.parse()?;
    if cid <= 2 || !(1..=900).contains(&timeout) {
        return Err("invalid enclave CID or provisioning timeout".into());
    }
    let mut bundle = File::open(bundle)?;
    let metadata = bundle.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_BUNDLE_BYTES + MAX_MANIFEST_BYTES as u64 + 112 {
        return Err("invalid bundle file or size".into());
    }
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut stream = flamingo_verifier_worker_artifact::transport::connect(cid, 1001, deadline)?;
    let sent = std::io::copy(&mut (&mut bundle).take(metadata.len()), &mut stream)?;
    if sent != metadata.len() || bundle.read(&mut [0])? != 0 {
        return Err("bundle changed during transfer".into());
    }
    stream.stream.shutdown(std::net::Shutdown::Write)?;
    let mut acknowledgement = [0xff];
    stream.read_exact(&mut acknowledgement)?;
    if acknowledgement != [0] {
        return Err("enclave refused worker startup".into());
    }
    if stream.read(&mut [0])? != 0 {
        return Err("invalid trailing startup acknowledgement".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
/// No TCP or unsandboxed substitution for Nitro vsock provisioning.
fn send(_: &str, _: &str, _: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("worker provisioning requires x86_64 Linux vsock".into())
}
