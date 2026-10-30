//! Four-byte unsigned big-endian length, followed by exactly that many bytes.
//! EOF between frames is graceful; EOF within a frame is an error.
use std::io::{self, Read, Write};

/// Reads one length-prefixed frame, returning `None` for EOF before its header.
///
/// # Errors
/// Returns an error for invalid lengths, failed allocation, truncated frames, or I/O failure.
pub fn read_frame(reader: &mut impl Read, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0; 4];

    // Read the first byte of the header, handling EOF and interrupt signals.
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None), // EOF before first byte -> no frame
            Ok(_) => break,           // First header byte read
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {} // retry
            Err(error) => return Err(error), // I/O failure
        }
    }

    // Read remaining three header bytes and interpret as frame length.
    reader.read_exact(&mut header[1..])?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IPC frame length",
        ));
    }

    // Read the remaining frame as the actual message.
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::other("IPC frame allocation failed"))?;
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

/// Writes a length-prefixed frame and flushes the writer.
///
/// # Errors
/// Returns an error for an empty or oversized payload, or any write/flush failure.
pub fn write_frame(writer: &mut impl Write, bytes: &[u8], max_bytes: usize) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid IPC frame length",
        ));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "IPC frame length exceeds u32"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_preserve_boundaries_and_eof() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"one", 3).unwrap();
        write_frame(&mut wire, b"two", 3).unwrap();
        let mut reader = wire.as_slice();
        assert_eq!(read_frame(&mut reader, 3).unwrap(), Some(b"one".to_vec()));
        assert_eq!(read_frame(&mut reader, 3).unwrap(), Some(b"two".to_vec()));
        assert_eq!(read_frame(&mut reader, 3).unwrap(), None);
    }
    #[test]
    fn oversized_prefix_is_rejected_before_body_read_or_allocation() {
        for n in [0u32, 4, u32::MAX] {
            assert_eq!(
                read_frame(&mut n.to_be_bytes().as_slice(), 3)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut wire = Vec::new();
        assert!(write_frame(&mut wire, b"four", 3).is_err());
        assert!(wire.is_empty());
    }
    #[test]
    fn truncated_frames_are_errors() {
        for bytes in [&[0][..], &[0, 0, 0, 2, 1][..]] {
            assert_eq!(
                read_frame(&mut &*bytes, 3).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }
}
