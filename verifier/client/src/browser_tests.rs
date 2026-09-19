//! Browser runtime checks for the HTTP/encrypted-channel boundary.
#![expect(
    clippy::future_not_send,
    reason = "browser tests execute Fetch futures on a single worker"
)]
use super::*;
use flamingo_verifier_sealed_types::{AttestedStatement, ComparisonRole, FailureReason};
use pontifex::ChannelEnclave;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen(inline_js = r#"
let originalFetch;
let last;
export function installFetch(body, status, contentType, contentLength, hang) {
    originalFetch = globalThis.fetch;
    const responseBody = body.slice();
    globalThis.fetch = async request => {
        last = { credentials: request.credentials, cache: request.cache,
            contentType: request.headers.get('content-type'), accept: request.headers.get('accept'),
            body: Array.from(new Uint8Array(await request.arrayBuffer())) };
        if (hang) return await new Promise((_, reject) => {
            const abort = () => reject(request.signal.reason);
            if (request.signal.aborted) abort();
            else request.signal.addEventListener('abort', abort, { once: true });
        });
        const headers = { 'Content-Type': contentType };
        if (contentLength !== undefined) headers['Content-Length'] = String(contentLength);
        const response = new Response(responseBody, { status, headers });
        Object.defineProperty(response, 'url', { value: request.url });
        return response;
    };
}
export function restoreFetch() { globalThis.fetch = originalFetch; }
export function lastRequest() { return JSON.stringify(last); }
"#)]
extern "C" {
    fn installFetch(
        body: &[u8],
        status: u16,
        content_type: &str,
        content_length: Option<u32>,
        hang: bool,
    );
    fn restoreFetch();
    fn lastRequest() -> String;
}

struct FetchGuard;
impl Drop for FetchGuard {
    fn drop(&mut self) {
        restoreFetch();
    }
}

fn stub(
    body: &[u8],
    status: u16,
    content_type: &str,
    content_length: Option<u32>,
    hang: bool,
) -> FetchGuard {
    installFetch(body, status, content_type, content_length, hang);
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
) -> (Vec<u8>, Vec<u8>, pontifex::ResponseOpener) {
    let enclave = ChannelEnclave::generate(ChannelDomain::new(MATCH_CHANNEL_DOMAIN)).unwrap();
    let consumer = ChannelConsumer::from_unverified_public_key(
        ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
        &enclave.public_key(),
    )
    .unwrap();
    let (request_ciphertext, opener) = consumer.seal_to_enclave(b"private-image-marker").unwrap();
    let (plaintext, sealer) = enclave.open(&request_ciphertext).unwrap();
    assert_eq!(&*plaintext, b"private-image-marker");
    let sealer = if foreign_reply {
        let (other, _) = consumer.seal_to_enclave(b"another request").unwrap();
        enclave.open(&other).unwrap().1
    } else {
        sealer
    };
    let response = sealer.seal(&answer.to_padded_cbor().unwrap()).unwrap();
    (request_ciphertext, response, opener)
}

fn binary_request(client: &FlamingoVerifierClient, ciphertext: Vec<u8>) -> reqwest::RequestBuilder {
    client
        .configure_request(client.http.post("https://flamingo.invalid/v1/matches"))
        .header(reqwest::header::CONTENT_TYPE, MATCH_CONTENT_TYPE)
        .header(reqwest::header::ACCEPT, MATCH_CONTENT_TYPE)
        .body(ciphertext)
}

#[wasm_bindgen_test]
async fn encrypted_response_and_browser_request_policy() {
    let reason = FailureReason::MatchBelowThreshold(ComparisonRole::SelfieChallenge);
    let answer = MatchResult::Failed(reason);
    let (ciphertext, response, opener) = exchange(&answer, false);
    let _guard = stub(&response, 200, MATCH_CONTENT_TYPE, None, false);
    let client = client();
    let request = binary_request(&client, ciphertext.clone());
    assert_eq!(
        client.request_match_with(request, opener).await.unwrap(),
        VerifiedMatchResult::Failed(reason)
    );
    let observed: serde_json::Value = serde_json::from_str(&lastRequest()).unwrap();
    assert_eq!(observed["credentials"], "include");
    assert_eq!(observed["cache"], "no-store");
    assert_eq!(observed["contentType"], MATCH_CONTENT_TYPE);
    assert_eq!(observed["accept"], MATCH_CONTENT_TYPE);
    let body: Vec<u8> = serde_json::from_value(observed["body"].clone()).unwrap();
    assert_eq!(
        body, ciphertext,
        "the body is raw ciphertext, not a JSON/base64 envelope"
    );
    assert!(
        !body
            .windows(b"private-image-marker".len())
            .any(|bytes| bytes == b"private-image-marker")
    );
}

#[wasm_bindgen_test]
async fn unrelated_response_is_rejected() {
    let (ciphertext, response, opener) =
        exchange(&MatchResult::Failed(FailureReason::MalformedInputs), true);
    let _guard = stub(&response, 200, MATCH_CONTENT_TYPE, None, false);
    let client = client();
    let request = binary_request(&client, ciphertext);
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
    let _guard = stub(&response, 200, MATCH_CONTENT_TYPE, None, false);
    let client = client();
    let request = binary_request(&client, ciphertext);
    assert!(matches!(
        client.request_match_with(request, opener).await,
        Err(Error::Attestation(_))
    ));
}

#[wasm_bindgen_test]
async fn untrusted_assignment_and_stale_routing_fail_closed() {
    let fetch_guard = stub(
        br#"{"attestation":"AA==","public_key":"AA=="}"#,
        200,
        "application/json",
        None,
        false,
    );
    assert!(matches!(
        client().request_assignment().await,
        Err(Error::Channel(_))
    ));
    drop(fetch_guard);
    let _guard = stub(
        br#"{"allowRetry":true,"error":{"code":"reassign_required","message":"stale"}}"#,
        409,
        "application/json",
        None,
        false,
    );
    let (ciphertext, _, opener) =
        exchange(&MatchResult::Failed(FailureReason::MalformedInputs), false);
    let client = client();
    let request = binary_request(&client, ciphertext);
    assert!(matches!(
        client.request_match_with(request, opener).await,
        Err(Error::ReassignRequired)
    ));
}

#[wasm_bindgen_test]
async fn browser_fetch_is_aborted_at_the_deadline() {
    let _guard = stub(b"", 200, "application/json", None, true);
    let error = client().request_assignment().await.unwrap_err();
    assert!(matches!(error, Error::Request(error) if error.is_timeout()));
}

#[wasm_bindgen_test]
async fn response_type_and_size_limits_are_enforced() {
    let too_large = u32::try_from(MAX_MATCH_RESPONSE_BYTES + 1).unwrap();
    for (body, content_type, content_length) in [
        (Vec::new(), "application/json", None),
        (Vec::new(), MATCH_CONTENT_TYPE, Some(too_large)),
        (
            vec![0; MAX_MATCH_RESPONSE_BYTES + 1],
            MATCH_CONTENT_TYPE,
            None,
        ),
    ] {
        let (ciphertext, _, opener) =
            exchange(&MatchResult::Failed(FailureReason::MalformedInputs), false);
        let _guard = stub(&body, 200, content_type, content_length, false);
        let client = client();
        let request = binary_request(&client, ciphertext);
        assert!(matches!(
            client.request_match_with(request, opener).await,
            Err(Error::MalformedResult)
        ));
    }
}
