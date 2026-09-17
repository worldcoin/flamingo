//! Browser runtime checks for the HTTP/encrypted-channel boundary.
use super::*;
use flamingo_verifier_sealed_types::{AttestedStatement, FailureReason};
use pontifex::ChannelEnclave;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen(inline_js = r#"
let originalFetch;
let last;
export function installFetch(body, status, hang) {
    originalFetch = globalThis.fetch;
    globalThis.fetch = async request => {
        last = { credentials: request.credentials, cache: request.cache, body: await request.text() };
        if (hang) return await new Promise((_, reject) => {
            const abort = () => reject(request.signal.reason);
            if (request.signal.aborted) abort();
            else request.signal.addEventListener('abort', abort, { once: true });
        });
        const response = new Response(body, { status, headers: { 'Content-Type': 'application/json' } });
        Object.defineProperty(response, 'url', { value: request.url });
        return response;
    };
}
export function restoreFetch() { globalThis.fetch = originalFetch; }
export function lastRequest() { return JSON.stringify(last); }
"#)]
extern "C" {
    fn installFetch(body: &str, status: u16, hang: bool);
    fn restoreFetch();
    fn lastRequest() -> String;
}

struct FetchGuard;
impl Drop for FetchGuard {
    fn drop(&mut self) {
        restoreFetch();
    }
}

fn stub(body: &str, status: u16, hang: bool) -> FetchGuard {
    installFetch(body, status, hang);
    FetchGuard
}

fn client() -> FlamingoVerifierClient {
    // No network-accessible verifier bypass: test code lives in this private module.
    let config = Config::from_json(
        &serde_json::json!({
            "host_url": "https://flamingo.invalid",
            "allowed_pcr_configs": [[{"index": 0, "value": "01".repeat(48)}]],
            "request_timeout_millis": 20
        })
        .to_string(),
    )
    .unwrap();
    FlamingoVerifierClient::new(config).unwrap()
}

fn exchange(
    answer: &MatchResult,
    foreign_reply: bool,
) -> (String, String, pontifex::ResponseOpener) {
    let enclave = ChannelEnclave::generate(ChannelDomain::new(MATCH_CHANNEL_DOMAIN)).unwrap();
    let consumer = ChannelConsumer::from_unverified_public_key(
        ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
        &enclave.public_key(),
    )
    .unwrap();
    let (sealed, opener) = consumer.seal_to_enclave(b"private-image-marker").unwrap();
    let (plaintext, sealer) = enclave.open(&sealed).unwrap();
    assert_eq!(&*plaintext, b"private-image-marker");
    let sealer = if foreign_reply {
        let (other, _) = consumer.seal_to_enclave(b"another request").unwrap();
        enclave.open(&other).unwrap().1
    } else {
        sealer
    };
    let response = sealer.seal(&answer.to_padded_cbor().unwrap()).unwrap();
    (
        STANDARD.encode(sealed),
        serde_json::json!({"response_ciphertext": STANDARD.encode(response)}).to_string(),
        opener,
    )
}

#[wasm_bindgen_test]
async fn encrypted_response_and_browser_request_policy() {
    let answer = MatchResult::Failed(FailureReason::MatchBelowThreshold);
    let (ciphertext, response, opener) = exchange(&answer, false);
    let _guard = stub(&response, 200, false);
    let client = client();
    let request = client
        .configure_request(client.http.post("https://flamingo.invalid/v1/matches"))
        .json(&MatchRequestBody { ciphertext });
    assert_eq!(
        client.request_match_with(request, opener).await.unwrap(),
        answer
    );
    let observed: serde_json::Value = serde_json::from_str(&lastRequest()).unwrap();
    assert_eq!(observed["credentials"], "include");
    assert_eq!(observed["cache"], "no-store");
    assert!(
        !observed["body"]
            .as_str()
            .unwrap()
            .contains("private-image-marker")
    );
    let body: serde_json::Value = serde_json::from_str(observed["body"].as_str().unwrap()).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 1);
}

#[wasm_bindgen_test]
async fn unrelated_response_is_rejected() {
    let (ciphertext, response, opener) =
        exchange(&MatchResult::Failed(FailureReason::MalformedInputs), true);
    let _guard = stub(&response, 200, false);
    let client = client();
    let request = client
        .configure_request(client.http.post("https://flamingo.invalid/v1/matches"))
        .json(&MatchRequestBody { ciphertext });
    assert!(matches!(
        client.request_match_with(request, opener).await,
        Err(Error::Channel(_))
    ));
}

#[wasm_bindgen_test]
async fn invalid_signing_attestation_is_rejected() {
    let answer = MatchResult::Success(AttestedStatement {
        token: match_token::MatchToken::from_bytes(vec![1, 2, 3]),
        signing_key_attestation: vec![0; 8],
    });
    let (ciphertext, response, opener) = exchange(&answer, false);
    let _guard = stub(&response, 200, false);
    let client = client();
    let request = client
        .configure_request(client.http.post("https://flamingo.invalid/v1/matches"))
        .json(&MatchRequestBody { ciphertext });
    assert!(matches!(
        client.request_match_with(request, opener).await,
        Err(Error::Attestation(_))
    ));
}

#[wasm_bindgen_test]
async fn untrusted_assignment_and_stale_routing_fail_closed() {
    let _guard = stub(r#"{"attestation":"AA==","public_key":"AA=="}"#, 200, false);
    assert!(matches!(
        client().request_assignment().await,
        Err(Error::Channel(_))
    ));
    drop(_guard);
    let _guard = stub(
        r#"{"allowRetry":true,"error":{"code":"reassign_required","message":"stale"}}"#,
        409,
        false,
    );
    let (ciphertext, _, opener) =
        exchange(&MatchResult::Failed(FailureReason::MalformedInputs), false);
    let client = client();
    let request = client
        .configure_request(client.http.post("https://flamingo.invalid/v1/matches"))
        .json(&MatchRequestBody { ciphertext });
    assert!(matches!(
        client.request_match_with(request, opener).await,
        Err(Error::ReassignRequired)
    ));
}

#[wasm_bindgen_test]
async fn browser_fetch_is_aborted_at_the_deadline() {
    let _guard = stub("", 200, true);
    let error = client().request_assignment().await.unwrap_err();
    assert!(matches!(error, Error::Request(error) if error.is_timeout()));
}
