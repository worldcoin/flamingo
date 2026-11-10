//! Release manifests for tests. The Verifier and Authenticators do not verify manifest
//! signatures (WIP-201 §4.3.4), so these carry a zero signature.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// `iss` of [`manifest`].
pub const TEST_ISS: &str = "https://engines.example.com";

/// `engine_hash` of the bundle [`manifest`] names.
pub const TEST_ENGINE_HASH: [u8; 48] = [0x2a; 48];

/// Response slots of [`manifest`]: the first is immediate, so tests not about timing stay fast.
pub const TEST_SLOTS: &[u64] = &[1, 15, 252, 4000];

/// A release manifest of [`TEST_ENGINE_HASH`] with [`TEST_SLOTS`].
#[must_use]
pub fn manifest(engine_hash: [u8; 48], version: u64) -> String {
    manifest_with_slots(engine_hash, version, TEST_SLOTS)
}

/// A release manifest with two pipelines whose response slots are `slots`:
/// - pipeline 1 checks one live frame;
/// - pipeline 2 checks the two frames of a `LightGuard` capture.
///
/// Levels 1 to 3 are defined.
#[must_use]
pub fn manifest_with_slots(engine_hash: [u8; 48], version: u64, slots: &[u64]) -> String {
    let live_frame = serde_json::json!({ "role": "live_frame", "media_types": ["image/jpeg"] });
    let payload = serde_json::json!({
        "iss": TEST_ISS,
        "engine_hash": hex::encode(engine_hash),
        "version": version,
        "match_strictness_levels": [1, 2, 3],
        "pipelines": [
            { "pipeline_id": 1, "inputs": [live_frame], "response_slots": slots },
            { "pipeline_id": 2, "inputs": [live_frame, live_frame], "response_slots": slots },
        ],
    });
    with_payload(&payload)
}

/// A manifest JWS with `payload` and a zero signature.
#[must_use]
pub fn with_payload(payload: &serde_json::Value) -> String {
    let header = r#"{"alg":"ES256","kid":"test","typ":"world-id-engine-manifest"}"#;
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload.to_string()),
        URL_SAFE_NO_PAD.encode([0u8; 64])
    )
}
