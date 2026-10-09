//! The WIP-201 request and the attested statement a passing request produces.
//!
//! The Verifier interprets none of the payload: roles come from the pipeline's `compare`
//! positions. Field order follows deterministic CBOR (RFC 8949 §4.2.1), so serde writes the
//! canonical encoding.

use crate::{AatInputs, DebugReport, Error, FailureReason, InputFailureReason};
use flamingo_verifier_api_types::{
    MAX_ENTRY_BYTES, MAX_MATCH_PLAINTEXT_BYTES, MAX_TOTAL_ENTRY_BYTES,
};
use flamingo_verifier_protocol::{
    Fq,
    flamingo_token::{
        self, AatClaims, FlamingoClaims, FlamingoToken, canonical_field, digest_to_field,
        engine_config_hash,
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_bytes::{ByteArray, ByteBuf};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The only request version.
pub const REQUEST_VERSION: u64 = 1;
/// Entries per request.
pub const MAX_ENTRIES: usize = 8;
/// Compared entries per request, fixed by the Flamingo Token layout.
pub const MAX_COMPARED: usize = flamingo_token::MAX_COMPARED;
/// Maximum bytes in the request-level `hints`.
pub const MAX_HINTS_BYTES: usize = 1024;
/// Maximum bytes in one entry's `meta`.
pub const MAX_ENTRY_META_BYTES: usize = 256;

/// The sealed request. `payload` is nested as bytes so its exact encoding can be committed to.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The RP's `rpId`, a canonical field element.
    pub aud: ByteArray<32>,
    /// The RP's single-use nonce, a nonzero canonical field element.
    pub nonce: ByteArray<32>,
    /// The encoded [`Payload`].
    pub payload: ByteBuf,
    /// [`REQUEST_VERSION`].
    pub version: u64,
    /// The Authenticator Assertion, if the Authenticator Provider issues AATs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aat_inputs: Option<AatInputs>,
}

/// What the Engine receives, unchanged.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    /// Request-level Engine hints that never weaken `match_strictness`.
    pub hints: ByteBuf,
    /// Distinct indices into `entries`; the Engine compares every pair.
    pub compare: Vec<u8>,
    /// Inputs to the Engine.
    pub entries: Vec<Entry>,
    /// Engine-defined pipeline, nonzero.
    pub pipeline: u16,
    /// SHA-256 of the Engine bundle that must run the request.
    pub engine_hash: ByteArray<32>,
    /// Matching strictness level defined by the Engine Provider.
    pub match_strictness: u8,
}

/// One Engine input.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// An encoded image or an embedding.
    pub data: ByteBuf,
    /// How the Engine reads `data`.
    pub meta: ByteBuf,
}

impl Request {
    /// Encodes `payload` and binds it to the RP's request and an optional AAT.
    ///
    /// # Errors
    /// Fails when the payload or request is out of bounds or cannot be encoded.
    pub fn new(
        payload: &Payload,
        aud: [u8; 32],
        nonce: [u8; 32],
        aat_inputs: Option<AatInputs>,
    ) -> Result<Self, Error> {
        payload.validate().map_err(|_| Error::Malformed)?;
        let request = Self {
            aud: aud.into(),
            nonce: nonce.into(),
            // Moved, not copied: the payload is the request's largest buffer.
            payload: ByteBuf::from(std::mem::take(&mut *encode(payload, payload.data_len())?)),
            version: REQUEST_VERSION,
            aat_inputs,
        };
        request.validate().map_err(|_| Error::Malformed)?;
        Ok(request)
    }

    /// Encodes the request as sealed plaintext.
    ///
    /// # Errors
    /// Fails when the encoding exceeds the plaintext budget.
    pub fn to_cbor(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        encode(self, self.payload.len())
    }

    /// Decodes exactly one request.
    ///
    /// # Errors
    /// Returns [`FailureReason::MalformedInputs`] for any other shape or trailing bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, FailureReason> {
        decode(bytes)
    }

    /// Checks the version and the RP's field elements.
    ///
    /// # Errors
    /// Returns [`FailureReason::MalformedInputs`] on any violation.
    pub fn validate(&self) -> Result<(), FailureReason> {
        let nonce = canonical_field(&self.nonce).map_err(|_| FailureReason::MalformedInputs)?;
        if self.version != REQUEST_VERSION
            || canonical_field(&self.aud).is_err()
            || nonce == Fq::from(0u64)
        {
            return Err(FailureReason::MalformedInputs);
        }
        Ok(())
    }

    /// Verifies the AAT, if any, against this request's exact payload bytes.
    ///
    /// # Errors
    /// Returns [`FailureReason::AatRejected`] for an AAT that does not verify.
    pub fn verify_aat(&self) -> Result<Option<AatClaims>, FailureReason> {
        let field = |bytes| canonical_field(bytes).map_err(|_| FailureReason::MalformedInputs);
        self.aat_inputs
            .map(|inputs| inputs.verify(field(&self.aud)?, field(&self.nonce)?, &self.payload))
            .transpose()
    }

    /// Decodes and validates the nested payload.
    ///
    /// # Errors
    /// Returns the first violated payload bound.
    pub fn payload(&self) -> Result<Payload, FailureReason> {
        let payload: Payload = decode(&self.payload)?;
        payload.validate()?;
        Ok(payload)
    }
}

impl Payload {
    /// Checks every WIP-201 bound and the entry budgets.
    ///
    /// # Errors
    /// Returns [`FailureReason::MalformedInputs`] for a shape violation, or
    /// [`FailureReason::InputRejected`] for an entry budget.
    pub fn validate(&self) -> Result<(), FailureReason> {
        let distinct = self
            .compare
            .iter()
            .enumerate()
            .all(|(i, index)| !self.compare[..i].contains(index));
        if self.pipeline == 0
            || self.hints.len() > MAX_HINTS_BYTES
            || !(1..=MAX_ENTRIES).contains(&self.entries.len())
            || self
                .entries
                .iter()
                .any(|entry| entry.meta.len() > MAX_ENTRY_META_BYTES)
            || !(2..=MAX_COMPARED).contains(&self.compare.len())
            || !distinct
            || self
                .compare
                .iter()
                .any(|&index| usize::from(index) >= self.entries.len())
        {
            return Err(FailureReason::MalformedInputs);
        }

        let mut total = 0;
        for entry in &self.entries {
            if entry.data.len() > MAX_ENTRY_BYTES {
                return Err(rejected(InputFailureReason::ImageTooLarge, MAX_ENTRY_BYTES));
            }
            total += entry.data.len();
        }
        if total > MAX_TOTAL_ENTRY_BYTES {
            return Err(rejected(
                InputFailureReason::TotalImagesTooLarge,
                MAX_TOTAL_ENTRY_BYTES,
            ));
        }
        Ok(())
    }

    fn data_len(&self) -> usize {
        self.entries.iter().map(|entry| entry.data.len()).sum()
    }

    /// The entries `compare` names, in order.
    pub fn compared(&self) -> impl Iterator<Item = &Entry> {
        self.compare
            .iter()
            .map(|&index| &self.entries[usize::from(index)])
    }

    /// The claims a Flamingo Token for this payload carries.
    ///
    /// # Panics
    /// Panics if `compare` names an entry out of range; call [`Self::validate`] first.
    #[must_use]
    pub fn claims(&self, aud: Fq, nonce: Fq, aat: Option<AatClaims>) -> FlamingoClaims {
        let mut compared_entry_hashes = [Fq::from(0u64); MAX_COMPARED];
        for (hash, entry) in compared_entry_hashes.iter_mut().zip(self.compared()) {
            *hash = digest_to_field(&Sha256::digest(&entry.data).into());
        }
        FlamingoClaims {
            compared_entry_hashes,
            aud,
            nonce,
            aat,
            engine_config_hash: engine_config_hash(
                &self.engine_hash,
                u32::from(self.pipeline),
                self.match_strictness,
            ),
        }
    }
}

const fn rejected(reason: InputFailureReason, limit: usize) -> FailureReason {
    FailureReason::InputRejected {
        reason,
        image: None,
        limit_bytes: Some(limit as u64),
    }
}

/// `capacity` covers the byte strings, so the buffer never reallocates around a copy of them.
fn encode(value: &impl Serialize, capacity: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity + 16 * 1024));
    ciborium::into_writer(value, &mut *encoded).map_err(|_| Error::Encoding)?;
    if encoded.len() > MAX_MATCH_PLAINTEXT_BYTES {
        return Err(Error::Malformed);
    }
    Ok(encoded)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, FailureReason> {
    if bytes.len() > MAX_MATCH_PLAINTEXT_BYTES {
        return Err(FailureReason::MalformedInputs);
    }
    let mut reader = bytes;
    let value = ciborium::from_reader(&mut reader).map_err(|_| FailureReason::MalformedInputs)?;
    if !reader.is_empty() {
        return Err(FailureReason::MalformedInputs);
    }
    Ok(value)
}

/// A Flamingo Token with the attestation of the key that signed it, carried together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedStatement {
    /// The signed Flamingo Token.
    pub token: FlamingoToken,
    /// NSM document attesting the token's signing key.
    #[serde(with = "serde_bytes")]
    pub signing_key_attestation: Vec<u8>,
}

/// The sealed response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MatchResult {
    /// The Engine passed and the Verifier signed a Flamingo Token.
    Success {
        /// Token and signing-key attestation.
        statement: AttestedStatement,
        /// Engine diagnostics outside the token.
        debug_report: DebugReport,
    },
    /// No token was issued.
    Failed {
        /// Why the request failed.
        reason: FailureReason,
        /// Engine diagnostics, if produced.
        debug_report: DebugReport,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The WIP-201 Appendix A1 payload.
    fn payload() -> Payload {
        let entry = |data: &[u8]| Entry {
            data: data.to_vec().into(),
            meta: ByteBuf::new(),
        };
        Payload {
            hints: ByteBuf::new(),
            compare: vec![0, 1, 2],
            entries: vec![
                entry(b"credential image"),
                entry(b"live image"),
                entry(b"challenge image"),
            ],
            pipeline: 1,
            engine_hash: [0x2a; 32].into(),
            match_strictness: 2,
        }
    }

    fn request(payload: &Payload) -> Request {
        let mut nonce = [0; 32];
        nonce[31] = 42;
        Request::new(payload, [0; 32], nonce, None).unwrap()
    }

    #[test]
    fn payload_and_claims_match_the_wip_201_vectors() {
        let payload = payload();
        let encoded = encode(&payload, 0).unwrap();
        assert_eq!(
            hex::encode(&*encoded),
            "a66568696e74734067636f6d706172658300010267656e747269657383a264646174615063726564656e7469616c20696d616765646d65746140a264646174614a6c69766520696d616765646d65746140a264646174614f6368616c6c656e676520696d616765646d6574614068706970656c696e65016b656e67696e655f6861736858202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a706d617463685f7374726963746e65737302"
        );
        let claims = payload.claims(Fq::from(1_928_118u64), Fq::from(42u64), None);
        assert_eq!(
            hex::encode(flamingo_token::field_to_bytes(claims.digest())),
            "046b836383d9d9fd350fbed1197e1c1c17f2b187fb6ef1571e5f9b42ec6fc8fc"
        );
    }

    #[test]
    fn requests_round_trip() {
        let request = request(&payload());
        let decoded = Request::from_cbor(&request.to_cbor().unwrap()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(*decoded.payload, *request.payload);
        assert_eq!(decoded.payload().unwrap().compare, vec![0, 1, 2]);
    }

    #[test]
    fn rejects_requests_of_any_other_shape() {
        let mut encoded = request(&payload()).to_cbor().unwrap();
        encoded.push(0);
        assert!(Request::from_cbor(&encoded).is_err());

        let mut unknown = ciborium::Value::serialized(&request(&payload())).unwrap();
        unknown
            .as_map_mut()
            .unwrap()
            .push(("unknown".into(), ciborium::Value::Map(vec![])));
        let mut encoded = Vec::new();
        ciborium::into_writer(&unknown, &mut encoded).unwrap();
        assert!(Request::from_cbor(&encoded).is_err());

        let changes: [fn(&mut Request); 4] = [
            |r| r.version = 2,
            |r| r.nonce = [0; 32].into(),
            |r| r.aud = [0xff; 32].into(),
            |r| r.nonce = [0xff; 32].into(),
        ];
        for change in changes {
            let mut request = request(&payload());
            change(&mut request);
            assert_eq!(request.validate(), Err(FailureReason::MalformedInputs));
        }
    }

    #[test]
    fn rejects_payloads_out_of_bounds() {
        let entry = || Entry {
            data: vec![1].into(),
            meta: ByteBuf::new(),
        };
        let changes: [fn(&mut Payload); 9] = [
            |p| p.pipeline = 0,
            |p| p.hints = vec![0; MAX_HINTS_BYTES + 1].into(),
            |p| p.entries.clear(),
            |p| p.entries[0].meta = vec![0; MAX_ENTRY_META_BYTES + 1].into(),
            |p| p.compare = vec![0],
            |p| p.compare = vec![0, 1, 2, 0, 1],
            |p| p.compare = vec![0, 0],
            |p| p.compare = vec![0, 3],
            |p| {
                p.entries.resize_with(MAX_ENTRIES + 1, || Entry {
                    data: ByteBuf::new(),
                    meta: ByteBuf::new(),
                });
            },
        ];
        for change in changes {
            let mut payload = payload();
            change(&mut payload);
            assert_eq!(payload.validate(), Err(FailureReason::MalformedInputs));
        }

        let mut payload = payload();
        payload.entries.push(entry());
        payload.entries[0].data = vec![0; MAX_ENTRY_BYTES + 1].into();
        assert!(matches!(
            payload.validate(),
            Err(FailureReason::InputRejected {
                reason: InputFailureReason::ImageTooLarge,
                ..
            })
        ));
        payload.entries[0].data = vec![0; MAX_ENTRY_BYTES].into();
        payload.entries[1].data = vec![0; MAX_TOTAL_ENTRY_BYTES - MAX_ENTRY_BYTES + 1].into();
        assert!(matches!(
            payload.validate(),
            Err(FailureReason::InputRejected {
                reason: InputFailureReason::TotalImagesTooLarge,
                ..
            })
        ));
    }

    #[test]
    fn claims_hash_each_compared_entry_in_compare_order() {
        let mut payload = payload();
        payload.compare = vec![2, 0];
        let claims = payload.claims(Fq::from(1u64), Fq::from(2u64), None);
        let hash = |data: &[u8]| digest_to_field(&Sha256::digest(data).into());
        assert_eq!(
            claims.compared_entry_hashes,
            [
                hash(b"challenge image"),
                hash(b"credential image"),
                Fq::from(0u64),
                Fq::from(0u64)
            ]
        );
    }
}
