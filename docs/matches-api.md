# Flamingo matches contract

This is a breaking update to `/v1/matches`. CBOR is retained inside the encrypted
channel; request and response HTTP bodies are raw ciphertext. Assignment is unchanged.

## Transport

Send `Content-Type: application/octet-stream` and `Accept: application/octet-stream`.
Successful exchanges return `200`, the same content type and `Cache-Control: no-store`.
The body contains the exact Pontifex sealed bytes. The match channel domain is
`flamingo-verifier/matches/v2`; the URL remains `/v1/matches`. The domain change prevents
accidental interpretation of the old payload under the new contract.

HTTP 200 does not imply a biometric match. The encrypted CBOR response is still
`Success(AttestedStatement)` or `Failed(FailureReason)`, padded to a 16 KiB plaintext.
The statement contains the COSE token and signing-key attestation. Biological failures,
input errors, PCP failures and unsupported captures remain encrypted. Fatal internal faults
use the existing infrastructure error path. HTTP errors use the existing JSON error envelope:
400 unreadable/empty body, 409 reassignment, 413 body too large, 415 wrong content type,
and existing timeout/unavailability/internal statuses. Reassignment is retried once.

## Requests

Readable JSON notation below stands for CBOR maps; `<bytes>` are CBOR byte strings,
never base64, integer arrays or strings.

```json
{"deep_face": {
  "orb_credential": "<bytes>",
  "live": {"vanilla": "<bytes>"},
  "rtms_challenge": "<bytes>",
  "hashes_json": "<exact original PCP bytes>",
  "match_threshold": 0.8
}}
```

```json
{"gray_badge": {
  "live": {"vanilla": "<bytes>"},
  "rtms_challenge": "<bytes>",
  "match_threshold": 0.8
}}
```

Either `live` field can instead contain:

```json
{"light_guard": {
  "illuminated": "<bytes>",
  "unilluminated": "<bytes>",
  "matching_frame": "unilluminated"
}}
```

The other matching-frame value is `illuminated`. The current in-process adapter
explicitly rejects LightGuard; this schema does not advertise implemented LightGuard inference.
Embedding generation is not part of this change.

Field names and score meanings follow biometric-engines `face.proto` at
`6c2856a0494f97d04aba289fb903c7144241eb34`. Flamingo adds PCP binding, thresholds,
attestation and signing. Worker wire IDs and framing are not public API fields.

Thresholds and scores are finite raw cosine similarities in [-1, 1], represented as f64.
All three DeepFace comparisons must meet the threshold, including selfie/challenge.
GrayBadge requires only selfie/challenge. No score normalization or silent LightGuard fallback.
The existing inference configurations remain prototype configurations; this API change does
not certify liveness, quality policy or production biometric performance.

## Bounds and memory

Shared constants in `api-types` define 4 MiB per encoded image, 7 MiB total image bytes,
64 KiB PCP hashes.json, 4 KiB CBOR overhead and 4 KiB channel overhead. Binary transport
removes base64 expansion without increasing the intended image budget. Worker transport must
accept at least these broker-validated bounds; a worker's larger limits do not expand this API.
Decoded images are also bounded to 8192 pixels per dimension and 16 million pixels.

The client borrows image buffers during CBOR serialization and reserves the output once.
Ciphertext moves into the HTTP body. Axum's Bytes body moves into the internal relay request
without a Vec conversion. CBOR decoding creates owned image buffers; the source plaintext
is zeroized/dropped before inference. Context hashing borrows image bytes, and inference
receives ownership without cloning. Encoding, encryption, IPC framing and decoded RGB/model
buffers still allocate. This is not a zero-copy pipeline. The allocation regression test measures
only CBOR and encoded image ownership, not crypto, models or full enclave RSS.

## Signed claims V2

COSE_Sign1 retains algorithm -65537 and the attested BabyJubJub signing key. Its payload
is now the deterministic CBOR array `[2, MatchClaims]`, not the old single-score CWT map.
`MatchClaims` is an externally tagged `deep_face` or `gray_badge` enum. Fields are serialized
in Rust declaration order, using ciborium's preferred scalar encodings. Decoding must
re-encode identically and reject trailing, duplicate or unknown fields. Frozen vectors in
protocol tests pin this encoding. No arbitrary protobuf bytes participate in signing.

Both variants contain `context` (live capture commitment, RTMS image hash and threshold)
and named `scores`. DeepFace also contains `orb_credential` (image SHA-256) and
`credential_claim` (SHA-256 of the original hashes.json bytes). Capture commitments bind
vanilla mode and its image hash, or LightGuard mode, both hashes and the selected frame.
All input hashes are over exact encoded bytes, not decoded/re-encoded images.

Digest construction:

1. Encode the versioned claim payload as above and take SHA-256.
2. Split the digest into two unsigned 128-bit big-endian limbs, each mapped losslessly to Fq.
3. Form a width-8 Poseidon2 state: `[Fq("WORLD_ID_FM_V2" big-endian), hi, lo, 0, 0, 0, 0, 0]`.
4. Apply the existing BN254 t8 Poseidon2 permutation and sign output element 1 using
   BabyJubJub EdDSA. The exact f64 score and threshold values are authenticated via the
   deterministic payload; no unsigned fixed-point coercion loses negative scores.

PCP binding proves the thumbnail matches hashes.json, not that an Orb issued the credential.
Issuer provenance remains a proof/credential-consumer responsibility. The RP must compare the
signed RTMS image hash to its own retained challenge, and enforce its intended threshold;
a requester choosing a weak threshold is not authorization to weaken the RP's policy.

The client verifies attestation and signature once and exposes `VerifiedMatchResult` with
operation-specific `MatchClaims`. Its `request_match` method also compares signed context,
operation and PCP/image commitments to the submitted request. The lower-level customizable
`request_match_with` verifies the statement but leaves request-context comparison to its caller.

V2 is deliberately incompatible with V1 proof encoding. No Flamingo token proof consumer was
found in the inspected local world-id-protocol source or WalletKit; WalletKit currently stores
an opaque token for future proof integration. Protocol/circuit owners must implement and qualify
this V2 digest/claim parsing before using these statements inside a proof. Passing Rust signature
tests is not a claim that an existing circuit understands V2.

## Validation

Contract tests cover both operations, exact input binding, all three comparisons, negative
scores, NaN/range rejection, PCP mismatch, unsupported LightGuard, response padding, binary HTTP,
reassignment and attestation rejection. WalletKit uses UniFFI operation/capture enums, moves image
Vecs into the client, retains one reassignment retry and exposes already-verified scores.

The E2E command in README supports `MATCH_OPERATION=gray_badge` in addition to default DeepFace.
A dev deployment of this revision with approved PCRs and actual model artifacts is required to
qualify real biometric E2E; mock inference tests establish the encrypted contract only.
