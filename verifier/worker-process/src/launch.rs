use std::{
    ffi::OsStr,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
};

use crate::WorkerProcessError;

/// Launches with only null stdio and the broker socket at FD 3 surviving exec.
pub(crate) fn spawn(
    program: &Path,
    args: &[impl AsRef<OsStr>],
    socket: UnixStream,
) -> Result<Child, WorkerProcessError> {
    // Keep the source above stdio, even if the parent started with FD 0/1/2 closed.
    // Occupying FD 3 also prevents std::process from assigning it to its exec-error pipe.
    let fd = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(WorkerProcessError::io(
            "reserve worker descriptor",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fcntl returned a new, exclusively owned descriptor.
    let inherited = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // SAFETY: Only async-signal-safe descriptor operations run between fork and exec.
    // The captured descriptor remains owned by Command until after spawn returns.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(inherited.as_raw_fd(), 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }

            // Preserve Rust's exec-error pipe until exec, but inherit only FD 3 and null stdio.
            #[cfg(target_os = "linux")]
            mark_linux_descriptors()?;
            #[cfg(not(target_os = "linux"))]
            for fd in close_fds::iter_open_fds(4) {
                if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    command
        .spawn()
        .map_err(|e| WorkerProcessError::io("launch worker", e))
}

/// Supports Nitro's 4.14 kernel without allocating after fork or hiding enumeration failures.
#[cfg(target_os = "linux")]
fn mark_linux_descriptors() -> io::Result<()> {
    // SAFETY: Constant path and flags, no borrowed data retained by the syscall.
    let raw = unsafe {
        libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a new descriptor. Drop only closes it.
    let directory = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut buffer = [0u8; 4096];

    loop {
        // SAFETY: The buffer is writable for exactly the supplied length.
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                directory.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Ok(());
        }
        let entries = buffer
            .get(..count as usize)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;

        visit_linux_descriptors(entries, |fd| {
            // SAFETY: Enumeration runs in the single-threaded child; FDs cannot be concurrently closed.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })?;
    }
}

#[cfg(any(target_os = "linux", test))]
/// Validates Linux directory records before visiting numeric descriptors above FD 3.
fn visit_linux_descriptors(
    mut entries: &[u8],
    mut visit: impl FnMut(i32) -> io::Result<()>,
) -> io::Result<()> {
    let invalid = || io::Error::from_raw_os_error(libc::EIO);
    while !entries.is_empty() {
        // linux_dirent64: u64 inode, i64 offset, u16 record length, u8 type, C name.
        let length = entries.get(16..18).ok_or_else(invalid)?;
        let length = usize::from(u16::from_ne_bytes([length[0], length[1]]));
        let record = entries
            .get(..length)
            .filter(|entry| entry.len() >= 20)
            .ok_or_else(invalid)?;
        let name = std::ffi::CStr::from_bytes_until_nul(&record[19..])
            .map_err(|_| invalid())?
            .to_bytes();
        if name != b"." && name != b".." {
            if name.is_empty() {
                return Err(invalid());
            }
            let mut fd = 0i32;
            for &byte in name {
                if !byte.is_ascii_digit() {
                    return Err(invalid());
                }
                fd = fd
                    .checked_mul(10)
                    .and_then(|fd| fd.checked_add(i32::from(byte - b'0')))
                    .ok_or_else(invalid)?;
            }
            if fd >= 4 {
                visit(fd)?;
            }
        }
        entries = &entries[length..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds one synthetic linux_dirent64 record.
    fn entry(name: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 20 + name.len()];
        let length = (bytes.len() as u16).to_ne_bytes();
        bytes[16..18].copy_from_slice(&length);
        bytes[19..19 + name.len()].copy_from_slice(name);
        bytes
    }

    #[test]
    /// Enumeration must not assume ordered or low-numbered descriptors.
    fn linux_enumeration_handles_high_and_unordered_descriptors() {
        let entries = [
            entry(b"."),
            entry(b".."),
            entry(b"3"),
            entry(b"70000"),
            entry(b"4"),
        ]
        .concat();
        let mut found = Vec::new();
        visit_linux_descriptors(&entries, |fd| {
            found.push(fd);
            Ok(())
        })
        .unwrap();
        assert_eq!(found, [70000, 4]);
    }

    #[test]
    /// Malformed records and failed descriptor updates abort enumeration.
    fn linux_enumeration_rejects_invalid_records_and_propagates_failures() {
        let valid = entry(b"42");
        for length in 1..valid.len() {
            assert!(visit_linux_descriptors(&valid[..length], |_| Ok(())).is_err());
        }
        for name in [b"".as_slice(), b"-1", b"2147483648", b"nope"] {
            assert!(visit_linux_descriptors(&entry(name), |_| Ok(())).is_err());
        }
        let mut zero = valid.clone();
        zero[16..18].fill(0);
        assert!(visit_linux_descriptors(&zero, |_| Ok(())).is_err());
        let mut unterminated = valid.clone();
        *unterminated.last_mut().unwrap() = b'1';
        assert!(visit_linux_descriptors(&unterminated, |_| Ok(())).is_err());

        let error =
            visit_linux_descriptors(&valid, |_| Err(io::Error::from_raw_os_error(libc::EPERM)))
                .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    }
}
