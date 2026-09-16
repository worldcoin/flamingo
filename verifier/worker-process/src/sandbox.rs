use std::{
    fs::File,
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

use minijail::Minijail;

use crate::WorkerError;

/// Reserved exclusively for the worker inside the enclave, never the broker.
pub const WORKER_UID: u32 = 65532;

/// Trusted boot configuration, not values supplied by the private worker manifest.
pub struct SandboxConfig<'a> {
    /// Minimal, root-owned runtime tree containing only approved libraries/config/models.
    /// Provisioning must keep the entire tree and its ancestors immutable during launch.
    pub root: &'a Path,
    /// Hard virtual-address-space ceiling; leave physical memory for the broker and kernel.
    pub address_space_bytes: u64,
    /// Hard per-UID task ceiling, including the main thread (1..=256).
    pub max_threads: u32,
}

impl SandboxConfig<'_> {
    /// Builds the same fail-closed sandbox for production and adversarial fixtures.
    pub(crate) fn create_jail(&self) -> Result<Minijail, WorkerError> {
        if self.address_space_bytes == 0
            || self.address_space_bytes > isize::MAX as u64
            || !(1..=256).contains(&self.max_threads)
        {
            return Err(WorkerError::InvalidSandbox("invalid resource limits"));
        }
        let root = self.root.canonicalize()?;
        let metadata = root.metadata()?;
        if root == Path::new("/")
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(WorkerError::InvalidSandbox(
                "runtime root must be a dedicated root-owned directory, not group/world writable",
            ));
        }

        // TSYNC makes Minijail select KILL_PROCESS. Refuse its catchable SIGSYS fallback
        // on old kernels: a forbidden syscall in an inference thread must kill all threads.
        let mut action = libc::SECCOMP_RET_KILL_PROCESS;
        // SAFETY: The kernel reads one initialized u32 and retains no pointer.
        if unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_GET_ACTION_AVAIL,
                0,
                &mut action,
            )
        } != 0
        {
            return Err(WorkerError::UnsupportedKernel(io::Error::last_os_error()));
        }

        let mut jail = Minijail::new()?;
        jail.no_new_privs();
        jail.reset_signal_mask();
        jail.namespace_pids();
        // The worker is PID 1, not a Minijail supervisor. Do not mount /proc.
        jail.run_as_init();
        jail.namespace_net();
        jail.namespace_ipc();
        jail.namespace_cgroups();
        jail.set_remount_mode(libc::MS_PRIVATE);
        // Init establishes the broker's mount root before launch. Minijail resets cwd;
        // closed FDs, zero capabilities and seccomp confine the worker to its own root.
        jail.enter_chroot(&root)?;
        // Non-recursive bind excludes any host submounts (notably proc/dev/sys).
        jail.mount(&root, "/", "", libc::MS_BIND as usize)?;
        jail.mount(
            "none",
            "/",
            "",
            (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV)
                as usize,
        )?;
        jail.change_uid(WORKER_UID);
        jail.change_gid(WORKER_UID);
        jail.set_supplementary_gids(&[]);
        jail.use_caps(0);
        for (resource, limit) in [
            (libc::RLIMIT_AS, self.address_space_bytes),
            (libc::RLIMIT_NPROC, u64::from(self.max_threads)),
            (libc::RLIMIT_NOFILE, 64),
            (libc::RLIMIT_CORE, 0),
            (libc::RLIMIT_FSIZE, 0),
            (libc::RLIMIT_MEMLOCK, 0),
        ] {
            jail.set_rlimit(resource as i32, limit, limit)?;
        }

        // Embed the policy in the measured public binary; never accept a worker policy path.
        // Minijail's Rust parser takes a path, so expose these bytes through a private memfd.
        // SAFETY: The name is NUL-terminated; the returned FD is checked and owned below.
        let fd = unsafe { libc::memfd_create(c"worker-seccomp".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: memfd_create returned a newly owned descriptor.
        let mut policy = unsafe { File::from_raw_fd(fd) };
        policy.write_all(include_bytes!("../worker.policy"))?;
        jail.set_seccomp_filter_tsync();
        jail.parse_seccomp_filters(format!("/proc/self/fd/{}", policy.as_raw_fd()))?;
        jail.use_seccomp_filter();
        Ok(jail)
    }
}
