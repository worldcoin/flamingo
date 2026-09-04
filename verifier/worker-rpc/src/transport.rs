use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

/// Rejects limits that cannot fit the wire length or contain even one image.
pub(crate) fn valid_limits(max_request_bytes: usize, max_image_bytes: usize) -> bool {
    max_image_bytes > 0
        && max_image_bytes <= max_request_bytes
        && u32::try_from(max_request_bytes).is_ok()
}

/// Rejects zero or overflowing deadlines.
pub(crate) fn valid_timeout(timeout: Duration) -> bool {
    !timeout.is_zero() && Instant::now().checked_add(timeout).is_some()
}

/// Returns the unused whole-operation budget, never a zero socket timeout.
pub(crate) fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "worker frame deadline exceeded"))
}

/// Reads exactly these bytes without allowing partial progress to reset the deadline.
fn read_all(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated worker frame",
                ));
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    remaining(deadline).map(|_| ())
}

/// Writes all bytes under the original deadline, including backpressure and interruptions.
fn write_all(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "worker socket accepted no bytes",
                ));
            }
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    remaining(deadline).map(|_| ())
}

/// Writes a four-byte big-endian length followed by the bounded CBOR payload.
pub(crate) fn write_frame(
    stream: &mut UnixStream,
    payload: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    let length = u32::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker frame exceeds u32 length",
        )
    })?;
    write_all(stream, &length.to_be_bytes(), deadline)?;
    write_all(stream, payload, deadline)
}

/// Validates the untrusted length before allocating or reading its body.
fn read_body(
    stream: &mut UnixStream,
    length: [u8; 4],
    limit: usize,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "worker frame length violates byte limit",
        ));
    }

    let mut body = vec![0; length];
    read_all(stream, &mut body, deadline)?;
    Ok(body)
}

/// Reads one complete reply without reading ahead into a subsequent frame.
pub(crate) fn read_frame(
    stream: &mut UnixStream,
    limit: usize,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    read_all(stream, &mut length, deadline)?;
    read_body(stream, length, limit, deadline)
}

/// Allows idle workers to wait indefinitely; the frame budget starts at its first byte.
/// EOF between requests is graceful, but EOF inside a request is an error.
pub(crate) fn read_request(
    stream: &mut UnixStream,
    limit: usize,
    timeout: Duration,
) -> io::Result<Option<(Vec<u8>, Instant)>> {
    stream.set_read_timeout(None)?;
    let mut length = [0; 4];
    loop {
        match stream.read(&mut length[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    let deadline = Instant::now() + timeout;
    read_all(stream, &mut length[1..], deadline)?;
    Ok(Some((
        read_body(stream, length, limit, deadline)?,
        deadline,
    )))
}
