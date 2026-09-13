use alloy_primitives::{B256, FixedBytes, aliases::U96};
use serde::{Deserialize, Serialize};

/// Widest `uint96` a channel nonce can hold, as hex digits.
const NONCE_HEX_DIGITS: usize = 24;

/// A `uint96` channel nonce: the lane in the high 32 bits, the per-lane counter in the low 64.
///
/// One type for both halves, because the escrow contract and the signed authorization agree on
/// this packing and a client that splits it itself would be free to disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChannelNonce(U96);

impl ChannelNonce {
    /// Packs a lane and a per-lane counter into a nonce.
    #[must_use]
    pub fn new(lane: u32, counter: u64) -> Self {
        Self((U96::from(lane) << 64usize) | U96::from(counter))
    }

    /// Returns the lane.
    #[must_use]
    pub fn lane(self) -> u32 {
        // The lane occupies bits 64..96, so the shifted value always fits.
        (self.0 >> 64usize).wrapping_to::<u32>()
    }

    /// Returns the per-lane counter.
    #[must_use]
    pub fn counter(self) -> u64 {
        // The counter is the low 64 bits, which is exactly what wrapping keeps.
        self.0.wrapping_to::<u64>()
    }

    /// Returns the packed value.
    #[must_use]
    pub const fn get(self) -> U96 {
        self.0
    }
}

impl From<U96> for ChannelNonce {
    fn from(value: U96) -> Self {
        Self(value)
    }
}

impl Serialize for ChannelNonce {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:#x}", self.0))
    }
}

/// Hand-written rather than `U96`'s own, which also accepts JSON numbers, decimal strings and
/// unprefixed hex. A nonce above 2^53 does not survive a round trip through a JSON number.
impl<'de> Deserialize<'de> for ChannelNonce {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let text = String::deserialize(deserializer)?;
        let digits = text
            .strip_prefix("0x")
            .ok_or_else(|| D::Error::custom("expected a 0x-prefixed hex quantity"))?;

        // A `uint96` is 24 hex digits, so the length bound is the range check.
        if digits.is_empty() || digits.len() > NONCE_HEX_DIGITS {
            return Err(D::Error::custom(
                "expected between 1 and 24 hex digits for a uint96",
            ));
        }

        U96::from_str_radix(digits, 16)
            .map(Self)
            .map_err(|_| D::Error::custom("expected a hex quantity"))
    }
}

/// A bearer authorization for one verification, signed by a channel's spend key.
///
/// It names a channel nonce and nothing else. Any holder of these bytes can spend that nonce
/// once, which is why the verifier admits each nonce a single time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payment {
    /// Identifier of the channel in the fee escrow contract.
    pub channel_id: B256,
    /// Epoch the nonce belongs to.
    pub epoch: u64,
    /// Lane and counter this payment spends.
    pub channel_nonce: ChannelNonce,
    /// `r || s || v` over the EIP-712 digest, with `v` in `{27, 28}`.
    pub signature: FixedBytes<65>,
}

/// `POST /v1/channels/{channel_id}/nonces` request.
///
/// Signed, because a reservation holds capacity for its lifetime and an unsigned one would let
/// anyone starve a channel they do not fund. A retry takes another lane rather than the same
/// counter, and the lane it abandons frees itself at `expires_by`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveNonceRequestBody {
    /// Epoch the reservation belongs to.
    pub epoch: u64,
    /// Unix seconds the relying party signed at. Must sit near the verifier's clock.
    pub issued_at: u64,
    /// The spend key's EIP-712 signature over `(channelId, epoch, issuedAt)`.
    pub signature: FixedBytes<65>,
}

/// An authorization the channel's spend key signed, without the channel and epoch that the
/// enclosing response already names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentAuthorizationBody {
    /// Lane and counter the authorization was signed over.
    pub channel_nonce: ChannelNonce,
    /// `r || s || v` over the EIP-712 digest, with `v` in `{27, 28}`.
    pub signature: FixedBytes<65>,
}

/// A lane's highest authorization, as a capacity refusal reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneAuthorizationBody {
    /// Lane the authorization belongs to. Also the high 32 bits of `channel_nonce`.
    pub lane: u32,
    /// Lane and counter the authorization was signed over.
    pub channel_nonce: ChannelNonce,
    /// `r || s || v` over the EIP-712 digest, with `v` in `{27, 28}`.
    pub signature: FixedBytes<65>,
}

/// `POST /v1/channels/{channel_id}/nonces` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveNonceResponseBody {
    /// Lane the counter was reserved on.
    pub lane: u32,
    /// Counter reserved on that lane.
    pub counter: u64,
    /// Unix seconds after which the reservation may be reissued to another request.
    pub expires_by: u64,
    /// The authorization for `counter - 1` on this lane, or null at counter 1.
    pub previous: Option<PaymentAuthorizationBody>,
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, FixedBytes, aliases::U96, b256, fixed_bytes};

    use super::{
        ChannelNonce, LaneAuthorizationBody, Payment, PaymentAuthorizationBody,
        ReserveNonceRequestBody, ReserveNonceResponseBody,
    };

    const CHANNEL_ID: B256 =
        b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
    const CHANNEL_ID_HEX: &str =
        "0x1111111111111111111111111111111111111111111111111111111111111111";

    const SIGNATURE: FixedBytes<65> = fixed_bytes!(
        "0x3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"
    );
    const SIGNATURE_HEX: &str = "0x3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333";

    /// Pins the wire names. A round trip alone would not: a rename moves both ends together.
    fn assert_wire<T>(body: &T, json: &serde_json::Value)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        assert_eq!(&serde_json::to_value(body).expect("should serialize"), json);
        assert_eq!(
            &serde_json::from_value::<T>(json.clone()).expect("should deserialize"),
            body
        );
    }

    #[test]
    fn the_nonce_packs_the_lane_above_the_counter() {
        let nonce = ChannelNonce::new(2, 5);

        assert_eq!(nonce.lane(), 2);
        assert_eq!(nonce.counter(), 5);
        assert_eq!(nonce.get(), (U96::from(2) << 64usize) | U96::from(5));
        assert_eq!(ChannelNonce::from(nonce.get()), nonce);
    }

    /// The widest lane and counter together are exactly the widest `uint96`, and a hex quantity
    /// one digit longer is not a nonce at all.
    #[test]
    fn the_nonce_refuses_values_wider_than_a_uint96() {
        assert_eq!(ChannelNonce::new(u32::MAX, u64::MAX).get(), U96::MAX);

        let too_wide = serde_json::json!(format!("0x1{}", "0".repeat(24)));
        assert!(serde_json::from_value::<ChannelNonce>(too_wide).is_err());
    }

    /// `U96`'s own deserializer takes JSON numbers, and a nonce above 2^53 would not survive one.
    #[test]
    fn the_nonce_is_a_hex_quantity_and_never_a_number() {
        assert_wire(&ChannelNonce::new(0, 0), &serde_json::json!("0x0"));
        assert_wire(&ChannelNonce::new(0, 1), &serde_json::json!("0x1"));

        for rejected in [
            serde_json::json!(1),
            serde_json::json!("0"),
            serde_json::json!(""),
            serde_json::json!("0x"),
            serde_json::json!("0xzz"),
        ] {
            assert!(
                serde_json::from_value::<ChannelNonce>(rejected.clone()).is_err(),
                "{rejected} should be rejected"
            );
        }
    }

    /// Alloy's byte types are length-checked, so a short or long id cannot reach a handler.
    #[test]
    fn hex_byte_arrays_reject_a_wrong_length() {
        for rejected in [
            format!("0x{}", "11".repeat(31)),
            format!("0x{}", "11".repeat(33)),
        ] {
            let json = serde_json::json!({
                "channel_id": rejected,
                "epoch": 7,
                "channel_nonce": "0x1",
                "signature": SIGNATURE_HEX,
            });
            assert!(
                serde_json::from_value::<Payment>(json).is_err(),
                "{rejected} should be rejected"
            );
        }
    }

    /// The epoch is a JSON number and the nonce a hex quantity, because the epoch fits a double
    /// and the nonce does not.
    #[test]
    fn a_payment_keeps_its_wire_names() {
        assert_wire(
            &Payment {
                channel_id: CHANNEL_ID,
                epoch: 7,
                channel_nonce: ChannelNonce::new(2, 5),
                signature: SIGNATURE,
            },
            &serde_json::json!({
                "channel_id": CHANNEL_ID_HEX,
                "epoch": 7,
                "channel_nonce": "0x20000000000000005",
                "signature": SIGNATURE_HEX,
            }),
        );
    }

    #[test]
    fn reserving_a_nonce_keeps_its_wire_names() {
        assert_wire(
            &ReserveNonceRequestBody {
                epoch: 7,
                issued_at: 1_700_000_000,
                signature: SIGNATURE,
            },
            &serde_json::json!({
                "epoch": 7,
                "issued_at": 1_700_000_000u64,
                "signature": SIGNATURE_HEX,
            }),
        );

        assert_wire(
            &ReserveNonceResponseBody {
                lane: 2,
                counter: 5,
                expires_by: 1_700_000_600,
                previous: Some(PaymentAuthorizationBody {
                    channel_nonce: ChannelNonce::new(2, 4),
                    signature: SIGNATURE,
                }),
            },
            &serde_json::json!({
                "lane": 2,
                "counter": 5,
                "expires_by": 1_700_000_600u64,
                "previous": {
                    "channel_nonce": "0x20000000000000004",
                    "signature": SIGNATURE_HEX,
                },
            }),
        );
    }

    /// The first reservation on a lane has nothing to settle, and `null` is how that is said.
    #[test]
    fn a_first_reservation_carries_a_null_previous() {
        assert_wire(
            &ReserveNonceResponseBody {
                lane: 0,
                counter: 1,
                expires_by: 600,
                previous: None,
            },
            &serde_json::json!({
                "lane": 0,
                "counter": 1,
                "expires_by": 600,
                "previous": serde_json::Value::Null,
            }),
        );
    }

    #[test]
    fn a_lane_authorization_keeps_its_wire_names() {
        assert_wire(
            &LaneAuthorizationBody {
                lane: 2,
                channel_nonce: ChannelNonce::new(2, 5),
                signature: SIGNATURE,
            },
            &serde_json::json!({
                "lane": 2,
                "channel_nonce": "0x20000000000000005",
                "signature": SIGNATURE_HEX,
            }),
        );
    }
}
