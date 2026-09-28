//! Single-threaded runtime provisioning before broker keys or serving threads.

use anyhow::{Context, bail};
pub use flamingo_verifier_sandbox_bundle::BootstrapConfig as Config;

/// Nitro uses CID 3 for the parent EC2 instance.
const NITRO_PARENT_CID: u32 = 3;

/// Owns the verified runtime and the unacknowledged startup transfer.
pub struct BootWorker {
    /// Runtime bytes have been checked against their deployment-supplied digest.
    pub runtime: flamingo_verifier_sandbox_bundle::VerifiedRuntime,
    /// Public, measured address-space budget.
    pub address_space_bytes: u64,
    /// Public, measured thread budget.
    pub max_threads: u32,
    /// The one-shot provisioner waits for acknowledgement after successful broker startup.
    provisioner: vsock::VsockStream,
}

impl BootWorker {
    /// Acknowledges verified launch, model initialization and broker key setup.
    ///
    /// # Errors
    /// Returns an error on timeout, write failure, or shutdown failure.
    pub fn acknowledge(&mut self) -> anyhow::Result<()> {
        use std::io::Write;
        self.provisioner
            .write_all(&[0])
            .context("failed to acknowledge worker startup")?;
        self.provisioner.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }
}

/// Accepts one size-bounded bundle from the parent host, then permanently closes bootstrap.
///
/// Fixed socket timeouts bound individual reads/writes after accept. The deployment
/// supervisor must bound total startup, including accept, and tear down the enclave on failure.
///
/// # Errors
/// Returns an error for invalid measured configuration, transport failure, or an invalid artifact.
pub fn receive() -> anyhow::Result<BootWorker> {
    use std::{
        fs::File,
        io,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, PermissionsExt},
        },
        path::Path,
        time::Duration,
    };

    let config = Config::default();
    config.validate()?;
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
    let listener = vsock::VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, 1001)?;
    let (mut provisioner, peer) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    };
    drop(listener);
    if peer.cid() != NITRO_PARENT_CID {
        bail!("worker provisioner must be the parent host");
    }

    let timeout = Some(Duration::from_secs(config.provisioning_io_timeout_seconds));
    provisioner.set_read_timeout(timeout)?;
    provisioner.set_write_timeout(timeout)?;
    let runtime = flamingo_verifier_sandbox_bundle::receive(
        &mut provisioner,
        config.max_bundle_bytes,
        runtime_parent,
    )
    .context("worker runtime integrity check failed")?;
    tracing::info!(release_id = %runtime.release_id, worker_sha384 = %runtime.sha384, "worker executable provisioned");
    Ok(BootWorker {
        runtime,
        address_space_bytes: config.address_space_bytes,
        max_threads: config.max_threads,
        provisioner,
    })
}
