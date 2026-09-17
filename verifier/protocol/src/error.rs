//! The crate's error type.

/// Why a protocol operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes were not the CBOR or `COSE_Sign1` framing this crate writes.
    Malformed,
    /// CBOR encoding failed.
    Encoding,
    /// A token declared an encoding version other than
    /// [`crate::match_token::TOKEN_VERSION`].
    UnsupportedTokenVersion,
    /// A similarity or threshold was nonfinite, out of range, or inconsistent with success.
    UnrepresentableCoefficient,
    /// Serializing a key or signature failed.
    KeyEncoding,
    /// A token's protected header did not name
    /// [`crate::match_token::COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2`].
    UnexpectedAlgorithm,
    /// A token's signature did not verify under the supplied public key.
    SignatureInvalid,
}
