# API and client

The host exposes these routes:

| Route | Purpose |
| --- | --- |
| `GET /.well-known/world-id-engine.json` | Public WIP-201 Engine Provider metadata, when configured. `HEAD` is also supported. |
| `GET /health` | Host liveness. |
| `GET /ready` | Returns `200` when the enclave answers a health request and has loaded a release manifest, otherwise `503`. |
| `GET /v1/matches` | WebSocket match: one assignment text frame, then one sealed binary match frame. |

## Engine Provider discovery

Set `ENGINE_PROVIDER_METADATA` to the complete JSON document defined by
[WIP-201 §3.5.2](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-201.md#352-release-manifests):
`version: 1`, `provider_id`, `release_keys` (public P-256 JWKs and statuses), and
`manifests` (exact compact JWS strings). The host uses the validated
[`PublishedMetadata`](../verifier/host/src/engine_provider.rs) type and returns
`application/json` with `Cache-Control: no-store`. Only `GET` and `HEAD` are served;
the deployment must expose this exact path without match authentication over HTTPS.

Absent configuration returns `404`; invalid configuration prevents host startup.
The JSON is limited to 64 KiB. Private JWK material, ambiguous key identifiers,
duplicate manifest entries, malformed keys and invalid manifest signatures are rejected.
Keys of every status are published, as are manifests signed by retired or revoked keys,
including when no manifest is listed. The handler does not contact the enclave or change its loaded release;
external service routing still follows deployment readiness.

Clients must establish provider trust independently and use only manifests
verified under active trusted keys. This document advertises provider policy;
the match assignment separately identifies releases actually loaded by the enclave.
See the deployment repository's [release and key operations](https://github.com/worldcoin/flamingo-deploy/blob/main/docs/engine-releases.md).

## Client configuration

Use [`flamingo-verifier-client`](../verifier/client) to verify attestation, encrypt requests, and check signed results. Save this configuration as `client.json`, replacing the PCR0–2 placeholders with the values from `target/eif/verifier-pcr.json` or a trusted release:

```json
{
  "host_url": "http://localhost:8000",
  "allowed_pcr_configs": [
    [
      { "index": 0, "value": "<96-character PCR0 hex>" },
      { "index": 1, "value": "<96-character PCR1 hex>" },
      { "index": 2, "value": "<96-character PCR2 hex>" }
    ]
  ],
  "max_attestation_age_millis": 3600000,
  "connect_timeout_millis": 5000,
  "request_timeout_millis": 60000
}
```

Only `host_url` and `allowed_pcr_configs` are required. The other fields default to the values shown. `max_attestation_age_millis` must be nonzero and at most the WIP-201 `MAX_ATTESTATION_AGE` of 3 hours. Each PCR configuration must include nonzero, 48-byte PCR0, PCR1 and PCR2; every measurement must be 48 bytes and each index must be unique. An attestation must match one complete configuration. Debug enclaves report zero measurements and are rejected.

## Matches

The WebSocket session carries the assignment and match on one connection, so the enclave that answered the assignment serves the match. The client verifies the assignment document's signature, certificate chain, measurements, and age, then checks the encryption key against the attested commitment. Identity and certificate expiry come from the verified document.

The sealed plaintext is the [WIP-201](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-201.md) request, encoded by [`world-id-flamingo`](https://github.com/worldcoin/world-id-protocol/tree/main/crates/flamingo): `version` (`2`), `aud`, `nonce`, optional `aat_inputs`, `billing_nullifier` and the nested `payload` (`pipeline`, `match_strictness`, `hints`, `entries`, `compare`, `release_hash`). The enclave rejects any other shape, a `release_hash` it did not load, a `pipeline` or `match_strictness` the release does not define, a request above the pipeline's `max_request_bytes`, and an (`aud`, `nonce`) it already processed. `aat_inputs` carry a WIP-106 TAKT and AAT; the enclave verifies them with `cdh = R(SHA-256(payload))` before the Engine runs and signs their public values into the token. `billing_nullifier` is the WIP-107 nullifier of the Authenticator's registration for `aud`, or `0` if it holds none. It stays outside `payload`, so the Engine never sees it; see [Billing](architecture.md#billing). The interim pipelines are:

| `pipeline` | `compare` positions | Engine operation |
| --- | --- | --- |
| `1` | Credential image, live capture, challenge | DeepFace |
| `2` | Live capture, challenge | GrayBadge |

A LightGuard live capture marks the compared frame's `meta` as `illuminated` or `unilluminated` and adds the other frame as the one uncompared entry. All other `meta` is empty. `match_strictness` levels `1`, `2` and `3` require similarities of `0.85`, `0.9` and `0.95` for every compared pair.

The enclave releases every opened request's response at the first of its pipeline's `response_slots` at which the Engine has finished, counted from arrival; a request rejected before its pipeline is known waits for the latest first slot of any pipeline. An Engine still running at the last slot fails the request with `engine_timeout`; the enclave then reports not ready and exits to reset the worker.

A binary result frame contains a padded, encrypted success or rejection. A success includes the [Flamingo Token](architecture.md#flamingo-tokens) and signing-key attestation. The client verifies both and checks that the claims equal those its request implies. A rejection contains a failure reason and no signed statement. Both variants carry `debug_report` (`Available`, `NotProduced`, or `OmittedTooLarge`); available worker JSON is capped at the WIP-201 `MAX_DEBUG_REPORT` of 64 KiB. Responses use a 96 KiB padded envelope with a four-byte length prefix on the WIP-201 channel (`WORLD-ID/WIP-201/CHANNEL`, key commitment domain `WORLD-ID/WIP-201/CHANNEL-KEY\0`).

The release manifest's `max_request_bytes` bounds each sealed request; the host additionally caps it at the [API constants](../verifier/api-types/src/matches.rs), which also define the response limits.

### WebSocket session

`GET /v1/matches` upgrades to a WebSocket. A session runs exactly two client frames in order, and the host closes after the second:

1. An assignment request text frame, `{"type":"assignment_request"}`. The host answers with an assignment text frame, `{"type":"assignment","attestation":"…","public_key":"…","release_hashes":["…"]}`, carrying the enclave's attestation, its encryption key, and the lowercase-hex `release_hash` of each loaded release. The release hashes are not attested.
2. One sealed match binary frame, to which the host answers with one sealed result binary frame.

The client verifies the assignment, seals the match to that key, and verifies the result and its claims without a second round trip for ordering. `FlamingoVerifierClient::connect` returns a session whose `request_match` runs the exchange; the session owns the socket and the verified assignment, so a match cannot be sent over a connection whose assignment was not verified. For authenticated gateways, call `build_request()`, add an `Authorization` header with `with_header`, then pass the builder to `connect_with()`.

The upgrade is refused with an HTTP `503 at_capacity` envelope while the host serves `WS_MAX_CONNECTIONS` sessions. Within a session, each phase has `WS_IDLE_TIMEOUT_SECS` to complete; the deadline restarts after a valid assignment exchange and ends when the match frame arrives.

## Errors and retries

Host and transport failures use the JSON error envelope defined in [`api-types`](../verifier/api-types/src/error.rs). The Rust client returns `ReassignRequired` to the caller; it does not retry automatically. The host allows 2 seconds for assignment and health calls, and the release's latest response slot plus 5 seconds for a match. The host fetches that deadline from the enclave's loaded-release metadata before each match; it does not read or load a manifest file. Set the client's `request_timeout_millis` above that slot plus the control-call and transport margin too.

A session reports failures as `ErrorEnvelope` text frames, then closes; the same envelope shape is used for HTTP upgrade errors. The upgrade is the only failure reported with an HTTP status.

| Status | Code | Meaning | Caller action |
| --- | --- | --- | --- |
| `503` | `at_capacity` | The host is at `WS_MAX_CONNECTIONS`; the upgrade was refused. | Retry with backoff. |
| `408` | `idle_timeout` | A phase idled past `WS_IDLE_TIMEOUT_SECS`. | Reconnect and resend. |
| `400` | `invalid_message` | A text frame was not a message this API understands. | Fix the client. |
| `400` | `protocol_error` | A frame arrived out of order for the session. | Fix the client. |
| `400` | `invalid_request` | The sealed match frame was empty. | Repair the payload. |
| `413` | `request_too_large` | The sealed frame exceeded the body limit. | Reduce the payload. |
| `400` | `client_disconnected` | The peer closed while the host was sending. | Reconnect. |
| `503` | `enclave_unreachable` | The enclave is unreachable. | Retry with backoff. |
| `503` | `enclave_not_ready` | The enclave answered but cannot serve requests yet. | Retry with backoff. |
| `504` | `enclave_timeout` | The enclave did not answer in time. | Retry. |
| `500` | `internal_error` | A host-side invariant failed. | Retry. |
| `409` | `reassign_required` | The enclave could not decrypt the frame. | Re-assign over a new session, re-seal, and retry at most once. |

The client classifies `reassign_required` as `Error::ReassignRequired` and other host envelopes, including `at_capacity` on upgrade and `idle_timeout` within a session, as `Error::ApiFrame { code, allow_retry }`. Its own request deadlines produce `Error::Timeout`; a closed socket produces `Error::ConnectionClosed`. The connection attempt is bounded by `connect_timeout_millis`; the assignment phase and match phase each have a separate `request_timeout_millis` deadline. There is no single deadline for the complete session.
