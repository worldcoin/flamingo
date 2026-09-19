//! Executable integrity metadata/packaging and one-shot host-to-enclave provisioning.
//! Socket timeouts bound individual I/O operations. The supervisor owns the overall
//! startup timeout, including connection establishment, and enclave cleanup before retry.

use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

use flamingo_verifier_sandbox_bundle::{
    BootstrapConfig, MAX_BUNDLE_BYTES, MAX_MANIFEST_BYTES, Manifest,
};
use sha2::{Digest, Sha384};

/// Deployment pipelines pin the emitted executable digest.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("validate-config") if args.len() == 3 => {
            BootstrapConfig::load_from(Path::new(&args[2]))?.validate()?;
        }
        Some("manifest") if args.len() == 4 => {
            let executable = Path::new(&args[3]);
            if !fs::symlink_metadata(executable)?.is_file() {
                return Err(
                    "worker must be a regular executable, not a directory or symlink".into(),
                );
            }
            let mut file = File::open(executable)?;
            let size = file.metadata()?.len();
            if size == 0 || size > MAX_BUNDLE_BYTES {
                return Err("executable size exceeds format limits".into());
            }
            let mut hash = Sha384::new();
            let mut buffer = [0; 64 * 1024];
            let mut remaining = size;
            while remaining != 0 {
                let length = remaining.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..length])?;
                hash.update(&buffer[..length]);
                remaining -= length as u64;
            }
            if file.read(&mut [0])? != 0 {
                return Err("executable changed during hashing".into());
            }
            let manifest = Manifest {
                manifest_version: 3,
                release_id: args[2].clone(),
                sha384: hex::encode(hash.finalize()),
                size,
            };
            manifest.validate(MAX_BUNDLE_BYTES)?;
            // Emit exact metadata bytes for the bundle.
            std::io::stdout().write_all(&serde_json::to_vec(&manifest)?)?;
        }
        Some("pack") if args.len() == 5 => {
            let mut manifest = Vec::new();
            File::open(&args[2])?
                .take(MAX_MANIFEST_BYTES as u64 + 1)
                .read_to_end(&mut manifest)?;
            let output = Path::new(&args[4]);
            let parent = output
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            flamingo_verifier_sandbox_bundle::package(
                &mut temporary,
                &manifest,
                Path::new(&args[3]),
            )?;
            temporary.as_file().sync_all()?;
            temporary.persist_noclobber(output)?;
        }
        Some("health") if args.len() == 3 => health(&args[2])?,
        Some("send") if args.len() == 5 => send(&args[2], &args[3], &args[4])?,
        _ => {
            return Err(concat!(
                "usage: sandbox-bundle manifest RELEASE_ID EXECUTABLE | ",
                "pack MANIFEST EXECUTABLE OUTPUT | ",
                "send CID BUNDLE IO_TIMEOUT_SECONDS | health CID | validate-config CONFIG_PATH"
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/// One transfer; only pre-transfer connection establishment may be retried by the caller.
fn send(cid: &str, bundle: &str, io_timeout: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;
    let cid: u32 = cid.parse()?;
    let io_timeout: u64 = io_timeout.parse()?;
    if cid <= 2 || !(1..=900).contains(&io_timeout) {
        return Err("invalid enclave CID or provisioning I/O timeout".into());
    }
    let mut bundle = File::open(bundle)?;
    let metadata = bundle.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_BUNDLE_BYTES + MAX_MANIFEST_BYTES as u64 + 4 {
        return Err("invalid bundle file or size".into());
    }
    // Only retry connection refusal before transferring any bytes. The carrier watchdog
    // covers this loop as well as transfer and model initialization.
    let mut stream = loop {
        match vsock::VsockStream::connect_with_cid_port(cid, 1001) {
            Ok(stream) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::thread::sleep(Duration::from_millis(200))
            }
            Err(error) => return Err(format!("worker bootstrap connect failed: {error}").into()),
        }
    };
    let timeout = Some(Duration::from_secs(io_timeout));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    let sent = std::io::copy(&mut (&mut bundle).take(metadata.len()), &mut stream)
        .map_err(|error| format!("worker bundle transfer failed: {error}"))?;
    if sent != metadata.len() || bundle.read(&mut [0])? != 0 {
        return Err("bundle changed during transfer".into());
    }
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut acknowledgement = [0xff];
    stream
        .read_exact(&mut acknowledgement)
        .map_err(|error| format!("worker initialization acknowledgement failed: {error}"))?;
    if acknowledgement != [0] {
        return Err("enclave refused worker startup".into());
    }
    if stream
        .read(&mut [0])
        .map_err(|error| format!("worker acknowledgement close failed: {error}"))?
        != 0
    {
        return Err("invalid trailing startup acknowledgement".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
/// No TCP or unsandboxed substitution for Nitro vsock provisioning.
fn send(_: &str, _: &str, _: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("worker provisioning requires x86_64 Linux vsock".into())
}

#[cfg(target_os = "linux")]
fn health(cid: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cid: u32 = cid.parse()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            pontifex::client::send(
                pontifex::client::ConnectionDetails::new(cid, 1000),
                &flamingo_verifier_enclave_types::HealthRequest,
            ),
        )
        .await?;
        result
            .map_err(|_| "broker transport unavailable")?
            .map_err(|_| "broker not ready")?;
        Ok(())
    })
}

#[cfg(not(target_os = "linux"))]
fn health(_: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("worker health requires Linux vsock".into())
}
