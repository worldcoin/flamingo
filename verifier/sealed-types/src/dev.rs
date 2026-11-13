//! The unsigned stand-in for a Nitro attestation that a `dev` Verifier serves for both its keys.
//! No enclave produces it, and only a client built with its own `dev` feature accepts it.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::Error;

/// The fields of a Nitro attestation document the client binds, without a signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevAttestation {
    /// The attested key binding: the raw signing key or the channel key commitment.
    pub public_key: ByteBuf,
    /// The loaded `release_hash` for the channel key, once a release is loaded; none otherwise.
    pub user_data: Option<ByteBuf>,
    /// When the document was produced, in milliseconds since the Unix epoch.
    pub timestamp_millis: u64,
}

impl DevAttestation {
    /// Encodes the document as CBOR.
    ///
    /// # Errors
    /// Returns [`Error::Encoding`] if CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|_| Error::Encoding)?;
        Ok(encoded)
    }

    /// Decodes a document [`Self::to_cbor`] wrote.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] for anything else, a Nitro document included.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|_| Error::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::DevAttestation;
    use crate::{ByteBuf, Error};

    #[test]
    fn round_trips_and_rejects_other_bytes() {
        let document = DevAttestation {
            public_key: ByteBuf::from([1; 32]),
            user_data: Some(ByteBuf::from([2; 32])),
            timestamp_millis: 1_783_446_000_000,
        };
        let encoded = document.to_cbor().unwrap();
        assert_eq!(DevAttestation::from_cbor(&encoded), Ok(document));
        assert_eq!(DevAttestation::from_cbor(b"\x84"), Err(Error::Malformed));
    }
}
