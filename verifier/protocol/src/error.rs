//! The crate's error type.

/// Why a protocol operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes were not the CBOR or `COSE_Sign1` framing this crate writes.
    Malformed,
    /// CBOR encoding failed.
    Encoding,
    /// Serializing a key or signature failed.
    KeyEncoding,
    /// A token's protected header did not name
    /// [`crate::flamingo_token::COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2`].
    UnexpectedAlgorithm,
    /// A token's signature did not verify under the supplied public key.
    SignatureInvalid,
}
