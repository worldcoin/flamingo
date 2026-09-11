//! One absolute deadline for bootstrap accept, partial I/O, upload and acknowledgement.

use std::{
    io::{self, Read, Write},
    os::fd::AsRawFd,
    time::Instant,
};

/// A nonblocking stream with bounded synchronous I/O; never resets its deadline on progress.
pub struct DeadlineStream<S> {
    /// Exclusively owned descriptor; no concurrent readers or writers.
    pub stream: S,
    /// Shared across every read and write in this startup attempt.
    deadline: Instant,
}

impl<S: AsRawFd> DeadlineStream<S> {
    /// Takes exclusive ownership and enables nonblocking syscalls before any network operation.
    pub fn new(stream: S, deadline: Instant) -> io::Result<Self> {
        // SAFETY: fcntl operates only on the live owned descriptor and retains no pointers.
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { stream, deadline })
    }
}

impl<S: Read + AsRawFd> Read for DeadlineStream<S> {
    /// Bounds partial reads and peer stalls with the original bootstrap deadline.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            wait(self.stream.as_raw_fd(), libc::POLLIN, self.deadline)?;
            match self.stream.read(buffer) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

impl<S: Write + AsRawFd> Write for DeadlineStream<S> {
    /// Bounds backpressure and partial writes without restarting the deadline.
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            wait(self.stream.as_raw_fd(), libc::POLLOUT, self.deadline)?;
            match self.stream.write(buffer) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }

    /// These unbuffered socket streams have no user-space pending writes.
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Polls one owned descriptor under an absolute deadline, including EINTR retries.
pub fn wait(fd: std::os::fd::RawFd, events: libc::c_short, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "worker bootstrap deadline exceeded",
                )
            })?;
        let timeout = i32::try_from(remaining.as_millis().saturating_add(1)).unwrap_or(i32::MAX);
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: poll borrows one initialized descriptor for this bounded call.
        match unsafe { libc::poll(&mut descriptor, 1, timeout) } {
            -1 => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            0 => {}
            _ if descriptor.revents & libc::POLLNVAL != 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid bootstrap descriptor",
                ));
            }
            _ => return Ok(()),
        }
    }
}

#[cfg(target_os = "linux")]
/// Connects without letting an absent vsock listener block beyond the caller's deadline.
pub fn connect(
    cid: u32,
    port: u32,
    deadline: Instant,
) -> io::Result<DeadlineStream<vsock::VsockStream>> {
    use std::os::fd::FromRawFd;
    // SAFETY: creates a new checked descriptor with nonblocking connect and no inherited handle.
    let fd = unsafe {
        libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the new descriptor has exactly one owner from this point onward.
    let socket = unsafe { vsock::VsockStream::from_raw_fd(fd) };
    // SAFETY: all-zero sockaddr_vm is valid initialization before setting its fields.
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_cid = cid;
    address.svm_port = port;
    // SAFETY: address remains valid and is the advertised sockaddr_vm size.
    if unsafe {
        libc::connect(
            fd,
            std::ptr::from_ref(&address).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if ![Some(libc::EINPROGRESS), Some(libc::EWOULDBLOCK)].contains(&error.raw_os_error()) {
            return Err(error);
        }
        wait(fd, libc::POLLOUT, deadline)?;
        let mut status: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&status) as libc::socklen_t;
        // SAFETY: both output buffers are live for the duration of getsockopt.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                std::ptr::from_mut(&mut status).cast(),
                &mut size,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
    }
    DeadlineStream::new(socket, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::net::UnixStream, thread, time::Duration};

    /// Partial bytes cannot extend a slow sender's total budget.
    #[test]
    fn slow_drip_and_silent_peer_are_bounded() {
        let pair = UnixStream::pair().unwrap();
        let mut stream =
            DeadlineStream::new(pair.0, Instant::now() + Duration::from_millis(100)).unwrap();
        let mut peer = pair.1;
        let sender = thread::spawn(move || {
            for _ in 0..10 {
                if peer.write_all(&[1]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(30));
            }
        });
        let error = stream.read_exact(&mut [0; 10]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(stream);
        sender.join().unwrap();
    }

    /// A peer that never reads cannot stall a bootstrap upload indefinitely.
    #[test]
    fn blocked_upload_is_bounded() {
        let pair = UnixStream::pair().unwrap();
        let mut stream =
            DeadlineStream::new(pair.0, Instant::now() + Duration::from_millis(50)).unwrap();
        let error = stream.write_all(&vec![0; 8 * 1024 * 1024]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(pair.1);
    }
}
