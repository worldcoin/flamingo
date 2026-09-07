//! PCP binding: ties a credential image to its `hashes.json` commitment.
//!
//! Derives `credential_claim = SHA256(hashes.json)` once the image hashes to the
//! `thumbnail.png` value that `hashes.json` commits.
//!
//! This is a hash binding, not a signature check. The module performs **no**
//! orb-attestation signature verification and makes **no** provenance claim: a caller
//! can trivially fabricate a self-consistent `{image, hashes.json}` pair, so the claim
//! is a commitment, not proof of genuine Orb enrollment. Provenance is re-anchored
//! downstream, where the ZK circuit binds `credential_claim` to an issuer-signed,
//! registry-included credential.
//!
//! The binding is nonetheless load-bearing and must not be dropped alongside the
//! signature chain. The credential commits `H(hashes.json)`, and the circuit only
//! checks `claims == credential_claim`.

use flamingo_verifier_sealed_types::FailureReason;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Subset of `hashes.json` we consume — the committed thumbnail hash.
#[derive(Deserialize)]
struct HashesJson {
    #[serde(rename = "thumbnail.png")]
    thumbnail_png: String,
}

/// Binds `credential_image` to the `thumbnail.png` hash committed in `hashes_json`
/// and returns `credential_claim = SHA256(hashes_json)`.
///
/// Fail-closed: any parse, decode, length, or mismatch error returns an `Err` and no
/// claim. The claim is computed over the raw `hashes_json` bytes but returned only
/// after the binding holds.
pub(crate) fn bind_credential_claim(
    credential_image: &[u8],
    hashes_json: &[u8],
) -> Result<[u8; 32], FailureReason> {
    // Commitment is over the raw bytes, taken before parsing.
    let credential_claim: [u8; 32] = Sha256::digest(hashes_json).into();

    let parsed: HashesJson =
        serde_json::from_slice(hashes_json).map_err(|_| FailureReason::InvalidHashesJson)?;

    let committed: [u8; 32] = hex::decode(&parsed.thumbnail_png)
        .map_err(|_| FailureReason::InvalidHashesJson)?
        .try_into()
        .map_err(|_| FailureReason::InvalidHashesJson)?;

    let observed: [u8; 32] = Sha256::digest(credential_image).into();
    if observed != committed {
        return Err(FailureReason::ThumbnailHashMismatch);
    }

    Ok(credential_claim)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::{FailureReason, bind_credential_claim};

    fn hashes_json_for(image: &[u8]) -> Vec<u8> {
        let hash = hex::encode(Sha256::digest(image));
        format!(r#"{{"thumbnail.png":"{hash}","version":"1"}}"#).into_bytes()
    }

    #[test]
    fn binding_succeeds_and_returns_claim() {
        let image = b"credential-thumbnail";
        let hashes_json = hashes_json_for(image);

        let claim = bind_credential_claim(image, &hashes_json).expect("binding should succeed");

        assert_eq!(claim, <[u8; 32]>::from(Sha256::digest(&hashes_json)));
    }

    #[test]
    fn credential_claim_is_hash_of_raw_hashes_json() {
        let image = b"another-image";
        let hashes_json = hashes_json_for(image);

        let claim = bind_credential_claim(image, &hashes_json).expect("binding should succeed");

        // Independent recompute over the raw bytes guards against hashing a
        // parsed/re-serialized form.
        let expected: [u8; 32] = Sha256::digest(&hashes_json).into();
        assert_eq!(claim, expected);
    }

    #[test]
    fn rejects_thumbnail_mismatch() {
        let hashes_json = hashes_json_for(b"the-enrolled-image");

        let result = bind_credential_claim(b"a-different-image", &hashes_json);

        assert_eq!(result, Err(FailureReason::ThumbnailHashMismatch));
    }

    #[test]
    fn rejects_malformed_hashes_json() {
        let result = bind_credential_claim(b"image", b"not valid json");

        assert_eq!(result, Err(FailureReason::InvalidHashesJson));
    }

    #[test]
    fn rejects_missing_thumbnail_entry() {
        // Absent `thumbnail.png` is now a deserialization failure (required field).
        let result = bind_credential_claim(b"image", br#"{"version":"1"}"#);

        assert_eq!(result, Err(FailureReason::InvalidHashesJson));
    }

    #[test]
    fn rejects_bad_thumbnail_hex() {
        let result = bind_credential_claim(b"image", br#"{"thumbnail.png":"zz"}"#);

        assert_eq!(result, Err(FailureReason::InvalidHashesJson));
    }

    #[test]
    fn rejects_wrong_length_thumbnail_hash() {
        // Valid hex, but only 2 bytes instead of 32.
        let result = bind_credential_claim(b"image", br#"{"thumbnail.png":"abcd"}"#);

        assert_eq!(result, Err(FailureReason::InvalidHashesJson));
    }
}
