# API and client

The host exposes three routes:

| Route | Purpose |
| --- | --- |
| `GET /health` | Host liveness. |
| `GET /ready` | Returns `200` when the enclave answers a health request, otherwise `503`. |
| `GET /v1/matches` | WebSocket match: one assignment text frame, then one sealed binary match frame. |

## Client configuration

Use [`flamingo-verifier-client`](../verifier/client) to verify attestation, encrypt requests, and check signed results. Save this configuration as `client.json`, replacing the PCR0 placeholder with the value from `target/eif/verifier-pcr.json` or a trusted release:

```json
{
  "host_url": "http://localhost:8000",
  "allowed_pcr_configs": [
    [{ "index": 0, "value": "<96-character PCR0 hex>" }]
  ],
  "max_attestation_age_millis": 3600000,
  "connect_timeout_millis": 5000,
  "request_timeout_millis": 60000
}
```

Only `host_url` and `allowed_pcr_configs` are required. The other fields default to the values shown. Each PCR configuration must include a nonzero, 48-byte PCR0; every measurement must be 48 bytes and each index must be unique. An attestation must match one complete configuration. Debug enclaves report zero measurements and are rejected.

## Matches

The WebSocket session carries the assignment and match on one connection, so the enclave that answered the assignment serves the match. The client verifies the assignment document's signature, certificate chain, measurements, and age, then checks the encryption key against the attested commitment. `max_attestation_age_millis` may not exceed the WIP-201 `MAX_ATTESTATION_AGE` of 24 hours. Identity and certificate expiry come from the verified document.

The sealed plaintext is the [WIP-201](https://github.com/worldcoin/world-id-protocol/pull/979) request: `version`, `aud`, `nonce` and the nested `payload` (`pipeline`, `match_strictness`, `meta`, `entries`, `compare`, `engine_hash`). The enclave rejects any other shape and an `engine_hash` it did not load. Optional `aat_inputs` carry a WIP-106 Authenticator Assertion; the enclave verifies it with `cdh = R(SHA-256(payload))` before the Engine runs and signs its public values (`has_aat`, `now`, `authenticator_provider_key_hash`, `aat_flags`) into the token. The interim pipelines are:

| `pipeline` | `compare` positions | Engine operation |
| --- | --- | --- |
| `1` | Credential image, live capture, challenge | DeepFace |
| `2` | Live capture, challenge | GrayBadge |

A LightGuard live capture marks the compared frame's `meta` as `illuminated` or `unilluminated` and adds the other frame as the one uncompared entry. All other `meta` is empty. `match_strictness` levels `1`, `2` and `3` require similarities of `0.85`, `0.9` and `0.95` for every compared pair.

A binary result frame contains a padded, encrypted success or rejection. A success includes the [Flamingo Token](architecture.md#flamingo-tokens) and signing-key attestation. The client verifies both and checks that the claims equal those its request implies. A rejection contains a failure reason and no signed statement. Both variants carry `debug_report` (`Available`, `NotProduced`, or `OmittedTooLarge`); available worker JSON is capped at the WIP-201 `MAX_DEBUG_REPORT` of 64 KiB. Responses use a 96 KiB padded envelope with a four-byte length prefix on the WIP-201 channel: `info` is `WORLD-ID/WIP-201/CHANNEL` plus a direction byte, and the attestation commits to `SHA-256("WORLD-ID/WIP-201/CHANNEL-KEY\0" || channel_key)`.

Entry `data` is limited to 4 MiB per entry and 7 MiB across all entries. The [API constants](../verifier/api-types/src/matches.rs) define the complete request and response limits, including encoding overhead.

### WebSocket session

`GET /v1/matches` upgrades to a WebSocket. A session runs exactly two client frames in order, and the host closes after the second:

1. An assignment request text frame, `{"type":"assignment_request"}`. The host answers with an assignment text frame, `{"type":"assignment","attestation":"…","public_key":"…","engine_hashes":["…"]}`, carrying the enclave's attestation, encryption key and the lowercase hex SHA-256 of each loaded Engine bundle. The Engine list is not attested; a wrong list only makes requests fail.
2. One sealed match binary frame, to which the host answers with one sealed result binary frame.

The client verifies the assignment, seals the match to that key, and verifies the result and its claims without a second round trip for ordering. `FlamingoVerifierClient::connect` returns a session whose `request_match` runs the exchange; the session owns the socket and the verified assignment, so a match cannot be sent over a connection whose assignment was not verified. For authenticated gateways, call `build_request()`, add an `Authorization` header with `with_header`, then pass the builder to `connect_with()`.

The upgrade is refused with an HTTP `503 at_capacity` envelope while the host serves `WS_MAX_CONNECTIONS` sessions. Within a session, each phase has `WS_IDLE_TIMEOUT_SECS` to complete; the deadline restarts after a valid assignment exchange and ends when the match frame arrives.

## Errors and retries

Host and transport failures use the JSON error envelope defined in [`api-types`](../verifier/api-types/src/error.rs). The Rust client returns `ReassignRequired` to the caller; it does not retry automatically. The host allows 2 seconds for assignment and health calls, and 30 seconds for a match.

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
