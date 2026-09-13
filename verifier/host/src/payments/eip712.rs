//! EIP-712 digest and signer recovery for payment authorizations.
//!
//! The struct and domain below are the fee escrow contract's, declared once through `sol!` so
//! the digest cannot drift from what the contract verifies.

use alloy_primitives::{Address, B256, FixedBytes, Signature};
use alloy_sol_types::{Eip712Domain, SolStruct, eip712_domain, sol};
use flamingo_verifier_api_types::ChannelNonce;

sol! {
    /// One unit of spend, signed by the channel's spend key.
    ///
    /// It binds a nonce to a channel and epoch and nothing else, so whoever holds the signature
    /// can spend that nonce on any request. Single admission per nonce is what limits it.
    struct PaymentAuthorization {
        bytes32 channelId;
        uint64 epoch;
        uint96 channelNonce;
    }
}

/// A signature that cannot be attributed to a signer.
///
/// The variants are separate because they mean different things operationally: a malformed or
/// non-canonical signature is a client bug, while a recovery failure is a mismatched digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// `v` was not 27 or 28.
    #[error("recovery byte must be 27 or 28")]
    InvalidRecoveryByte,
    /// `s` was in the upper half of the curve order, so the signature is malleable.
    #[error("signature s value must be in the lower half of the curve order")]
    HighS,
    /// `r` or `s` was not a valid scalar.
    #[error("signature is malformed")]
    Malformed,
    /// No public key recovers from this digest and signature.
    #[error("no signer recovers from this digest")]
    NotRecoverable,
}

/// Builds the fee escrow's signing domain for a deployment.
#[must_use]
pub const fn domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    eip712_domain! {
        name: "WorldIDFeeEscrow",
        version: "1",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    }
}

/// Returns the EIP-712 digest a relying party signs to authorize one unit of spend.
#[must_use]
pub fn digest(domain: &Eip712Domain, channel_id: B256, epoch: u64, nonce: ChannelNonce) -> B256 {
    PaymentAuthorization {
        channelId: channel_id,
        epoch,
        channelNonce: nonce.get(),
    }
    .eip712_signing_hash(domain)
}

/// Recovers the address that signed this authorization.
///
/// # Errors
///
/// Returns [`SignatureError`] when the signature is malformed, malleable, or recovers nothing.
pub fn recover_signer(
    domain: &Eip712Domain,
    channel_id: B256,
    epoch: u64,
    nonce: ChannelNonce,
    signature: &FixedBytes<65>,
) -> Result<Address, SignatureError> {
    // Checked on the raw bytes: `Signature::from_raw` also accepts 0 and 1, and the escrow only
    // ever sees the 27/28 encoding.
    if !matches!(signature[64], 27 | 28) {
        return Err(SignatureError::InvalidRecoveryByte);
    }

    let parsed =
        Signature::from_raw(signature.as_slice()).map_err(|_| SignatureError::Malformed)?;

    // A high `s` is a second valid signature over the same digest. Accepting it would let the
    // same authorization arrive twice under two different bytes.
    if parsed.normalize_s().is_some() {
        return Err(SignatureError::HighS);
    }

    let prehash = digest(domain, channel_id, epoch, nonce);
    let address = parsed
        .recover_address_from_prehash(&prehash)
        .map_err(|_| SignatureError::NotRecoverable)?;

    // Unreachable for a recovered key, and the one address no signer can hold, so a hit means
    // the recovery above is wrong rather than that the caller sent something odd.
    if address.is_zero() {
        return Err(SignatureError::NotRecoverable);
    }

    Ok(address)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, FixedBytes, address, b256};
    use alloy_sol_types::Eip712Domain;
    use flamingo_verifier_api_types::ChannelNonce;
    use k256::ecdsa::SigningKey;

    use super::{SignatureError, digest, domain, recover_signer};

    const CHANNEL_ID: B256 =
        b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
    const EPOCH: u64 = 7;
    const LANE: u32 = 2;
    const COUNTER: u64 = 5;

    /// The escrow deployment the cross-repo vectors were generated against.
    const FEE_ESCROW: Address = address!("0x0000000000000000000000000000000000FeE5c0");
    const VECTOR_CHANNEL_ID: B256 =
        b256!("0x2445d3989582ca28df4e2dc71b1e21dc0f752bbc6398d7461a71f676011eb4c5");

    /// World Chain Sepolia against an unset escrow address, which is the local default.
    fn test_domain() -> Eip712Domain {
        domain(4801, Address::ZERO)
    }

    fn nonce(lane: u32, counter: u64) -> ChannelNonce {
        ChannelNonce::new(lane, counter)
    }

    /// A fixed key rather than a random one, so a failure reproduces from the test name alone.
    fn signing_key(scalar: B256) -> SigningKey {
        SigningKey::from_slice(scalar.as_slice()).expect("scalar should be a valid key")
    }

    /// The key behind the `cast wallet address` vector below.
    fn known_key() -> SigningKey {
        signing_key(b256!(
            "0x0000000000000000000000000000000000000000000000000000000000000002"
        ))
    }

    fn test_key() -> SigningKey {
        signing_key(b256!(
            "0x0000000000000000000000000000000000000000000000000000000000000009"
        ))
    }

    /// Signs `prehash` and returns `r || s || v`, the encoding the escrow expects.
    fn sign(key: &SigningKey, prehash: &B256) -> FixedBytes<65> {
        let (signature, recovery_id) = key
            .sign_prehash_recoverable(prehash.as_slice())
            .expect("signing should succeed");

        encode(&signature, recovery_id.to_byte())
    }

    /// Packs a `k256` signature and its recovery id into the escrow's 65-byte encoding.
    fn encode(signature: &k256::ecdsa::Signature, parity: u8) -> FixedBytes<65> {
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = parity + 27;

        FixedBytes(bytes)
    }

    fn authorization_digest() -> B256 {
        digest(&test_domain(), CHANNEL_ID, EPOCH, nonce(LANE, COUNTER))
    }

    fn recover(signature: &FixedBytes<65>) -> Result<Address, SignatureError> {
        recover_signer(
            &test_domain(),
            CHANNEL_ID,
            EPOCH,
            nonce(LANE, COUNTER),
            signature,
        )
    }

    /// From `contracts/test/vectors/fee-escrow.json` in world-id-protocol, where the Solidity
    /// side computes it. Reproduced here with `cast`:
    ///
    /// ```text
    /// cast keccak "$(cast abi-encode 'f(bytes32,bytes32,bytes32,uint256,address)' \
    ///   $(cast keccak "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)") \
    ///   $(cast keccak "WorldIDFeeEscrow") $(cast keccak "1") 4801 \
    ///   0x0000000000000000000000000000000000FeE5c0)"
    /// ```
    ///
    /// The two repositories have to agree on this or a payment signed for one is refused by the
    /// other, so it is pinned rather than derived.
    #[test]
    fn the_domain_separator_matches_the_contract() {
        assert_eq!(
            domain(4801, FEE_ESCROW).separator(),
            b256!("0x9f429a61ffdfe791688ddf302376b5d04006d31a9bc008b9484edcd93d262408")
        );
    }

    /// Same source. Pins the `sol!` field order, the `uint64`/`uint96` widths, and the lane and
    /// counter packing in one value: lane 3 and counter 42 are `0x3000000000000002a`.
    #[test]
    fn the_payment_digest_matches_the_contract() {
        assert_eq!(
            nonce(3, 42).get(),
            alloy_primitives::aliases::U96::from(0x3_0000_0000_0000_002a_u128)
        );

        assert_eq!(
            digest(
                &domain(4801, FEE_ESCROW),
                VECTOR_CHANNEL_ID,
                7,
                nonce(3, 42)
            ),
            b256!("0xe48a4f68fee8fe87bfd02bbb52eaad7786f3471f385b2dd9542ec87495609df7")
        );
    }

    /// The local default deployment, cross-checked with `cast` the same way as above. Kept
    /// beside the contract's vector so a change to either domain field is caught twice.
    #[test]
    fn the_local_domain_separator_matches_cast() {
        assert_eq!(
            test_domain().separator(),
            b256!("0x8fc6482344b0227fe6880d546e32096e5db08b4f524ed07f3789f13ba29418c3")
        );
    }

    /// `cast wallet address --private-key 0x0..02`, so recovery is checked against something
    /// other than itself.
    #[test]
    fn recovery_returns_the_address_of_a_known_key() {
        let signature = sign(&known_key(), &authorization_digest());

        assert_eq!(
            recover(&signature),
            Ok(address!("0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"))
        );
    }

    /// Every field is in the digest, so a signature over one authorization does not carry to
    /// another.
    #[test]
    fn changing_any_field_changes_the_digest() {
        let baseline = authorization_digest();
        let elsewhere = b256!("0x1212121212121212121212121212121212121212121212121212121212121212");

        let variants = [
            digest(&test_domain(), elsewhere, EPOCH, nonce(LANE, COUNTER)),
            digest(&test_domain(), CHANNEL_ID, EPOCH + 1, nonce(LANE, COUNTER)),
            digest(&test_domain(), CHANNEL_ID, EPOCH, nonce(LANE + 1, COUNTER)),
            digest(&test_domain(), CHANNEL_ID, EPOCH, nonce(LANE, COUNTER + 1)),
            digest(
                &domain(1, Address::ZERO),
                CHANNEL_ID,
                EPOCH,
                nonce(LANE, COUNTER),
            ),
            digest(
                &domain(4801, FEE_ESCROW),
                CHANNEL_ID,
                EPOCH,
                nonce(LANE, COUNTER),
            ),
        ];

        for (index, variant) in variants.into_iter().enumerate() {
            assert_ne!(
                variant, baseline,
                "variant {index} should change the digest"
            );
        }
    }

    /// The lane and counter share one `uint96`, so a shift that dropped a bit would let two
    /// different reservations sign the same digest.
    #[test]
    fn the_lane_and_counter_do_not_alias() {
        let one_lane_up = digest(&test_domain(), CHANNEL_ID, EPOCH, nonce(1, 0));
        let counter_at_the_boundary = digest(&test_domain(), CHANNEL_ID, EPOCH, nonce(0, u64::MAX));

        assert_ne!(one_lane_up, counter_at_the_boundary);
    }

    #[test]
    fn a_high_s_signature_is_rejected() {
        let (signature, recovery_id) = test_key()
            .sign_prehash_recoverable(authorization_digest().as_slice())
            .expect("signing should succeed");

        // Negating `s` gives the other valid signature over the same digest, which is exactly
        // the malleability the low-s rule exists to refuse. The recovered parity flips with it.
        let malleable = k256::ecdsa::Signature::from_scalars(
            signature.r().to_bytes(),
            (-*signature.s()).to_bytes(),
        )
        .expect("negating s should stay a valid signature");

        assert_eq!(
            recover(&encode(&malleable, 1 - recovery_id.to_byte())),
            Err(SignatureError::HighS)
        );
    }

    #[test]
    fn a_recovery_byte_outside_27_and_28_is_rejected() {
        let signature = sign(&test_key(), &authorization_digest());

        for byte in [0u8, 1, 26, 29, 255] {
            let mut malformed = signature;
            malformed[64] = byte;

            assert_eq!(
                recover(&malformed),
                Err(SignatureError::InvalidRecoveryByte),
                "v={byte} should be rejected"
            );
        }
    }

    #[test]
    fn a_signature_over_another_authorization_recovers_a_different_signer() {
        let signer = recover(&sign(&test_key(), &authorization_digest()))
            .expect("the signature should recover");

        let elsewhere = digest(&test_domain(), CHANNEL_ID, EPOCH, nonce(LANE, COUNTER + 1));

        assert_ne!(recover(&sign(&test_key(), &elsewhere)), Ok(signer));
    }

    /// `Signature::from_raw` stores `r` and `s` as integers and does not check them against the
    /// curve order, so a zeroed signature is caught by recovery rather than by parsing. Both
    /// answers are a refusal, and the route maps them to the same status.
    #[test]
    fn a_zeroed_signature_is_rejected() {
        let mut signature = FixedBytes::<65>::ZERO;
        signature[64] = 27;

        assert_eq!(recover(&signature), Err(SignatureError::NotRecoverable));
    }
}
