//! Single-threaded authenticated runtime provisioning before broker keys or serving threads.

use anyhow::{Context, bail};
pub use flamingo_verifier_worker_artifact::BootstrapConfig as Config;

/// Owns the verified runtime and the unacknowledged startup transfer.
pub struct BootWorker {
    /// All runtime bytes have been verified against the measured publisher key set.
    pub runtime: flamingo_verifier_worker_artifact::VerifiedRuntime,
    /// Public, measured address-space budget.
    pub address_space_bytes: u64,
    /// Public, measured thread budget.
    pub max_threads: u32,
    /// The one-shot provisioner waits for acknowledgement after successful broker startup.
    provisioner: flamingo_verifier_worker_artifact::transport::DeadlineStream<vsock::VsockStream>,
}

impl BootWorker {
    /// Acknowledges verified launch/key setup, not successful model inference.
    ///
    /// # Errors
    /// Returns an error on timeout, write failure, or shutdown failure.
    pub fn acknowledge(&mut self) -> anyhow::Result<()> {
        use std::io::Write;
        self.provisioner
            .write_all(&[0])
            .context("failed to acknowledge worker startup")?;
        self.provisioner.stream.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }
}

/// Accepts exactly one bounded bundle from the parent host, then permanently closes bootstrap.
///
/// # Errors
/// Returns an error for invalid measured configuration, transport failure, or an invalid artifact.
pub fn receive() -> anyhow::Result<BootWorker> {
    use flamingo_verifier_worker_artifact::transport::{DeadlineStream, wait};
    use std::{
        fs::File,
        io,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, PermissionsExt},
        },
        path::Path,
        time::{Duration, Instant},
    };

    let config = Config::load_from(Path::new("/etc/flamingo/worker-bootstrap.json"))?;
    let keys = config.validate()?;
    // Nitro init mounts /tmp noexec. Stage on the executable root filesystem instead;
    // execveat retains the original descriptor's mount flags across the worker's bind mount.
    let runtime_parent = Path::new("/worker-runtime");
    let temporary = std::fs::symlink_metadata(runtime_parent)?;
    if !temporary.is_dir() || temporary.uid() != 0 {
        bail!("worker staging must be a real root-owned directory");
    }
    let directory = File::open(runtime_parent)?;
    // SAFETY: fstatvfs writes only this initialized buffer for a live directory descriptor.
    let mut filesystem: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), &raw mut filesystem) } != 0 {
        return Err(io::Error::last_os_error()).context("failed to inspect worker staging mount");
    }
    if filesystem.f_flag & (libc::ST_NOEXEC | libc::ST_RDONLY) != 0 {
        bail!("worker staging requires an executable, writable root filesystem");
    }
    drop(directory);
    // Nix normalizes directory modes; restore private write access before receiving bytes.
    std::fs::set_permissions(runtime_parent, std::fs::Permissions::from_mode(0o700))?;
    let deadline = Instant::now() + Duration::from_secs(config.bootstrap_timeout_seconds);
    let listener = vsock::VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, 1001)?;
    listener.set_nonblocking(true)?;
    let (socket, peer) = loop {
        wait(listener.as_raw_fd(), libc::POLLIN, deadline)?;
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error.into()),
        }
    };
    drop(listener);
    if peer.cid() != libc::VMADDR_CID_HOST {
        bail!("worker provisioner must be the parent host");
    }
    let mut provisioner = DeadlineStream::new(socket, deadline)?;
    let runtime = flamingo_verifier_worker_artifact::receive(
        &mut provisioner,
        &keys,
        config.max_bundle_bytes,
        runtime_parent,
    )
    .context("worker runtime authentication failed")?;
    Ok(BootWorker {
        runtime,
        address_space_bytes: config.address_space_bytes,
        max_threads: config.max_threads,
        provisioner,
    })
}
