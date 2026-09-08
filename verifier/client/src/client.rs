//! HTTP client for the embedding verifier host.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use flamingo_verifier_api_types::{
    ApiErrorResponse, EnclaveAssignmentResponse, MatchRequestBody, MatchResponseBody,
};
use flamingo_verifier_protocol::match_token::{self, EdDSAPublicKey};
use flamingo_verifier_sealed_types::{MATCH_CHANNEL_DOMAIN, MatchInputs, MatchResult};
use pontifex::attestation::{VerifiedAttestation, Verifier};
use pontifex::{ChannelConsumer, ChannelDomain};

use crate::config::Config;
use crate::error::Error;

/// Error code the host uses for a request that did not open.
const REASSIGN_REQUIRED: &str = "reassign_required";

/// An assignment whose attestation verified and whose encryption key is ready for sealing.
#[derive(Debug, Clone)]
pub struct VerifiedAssignment {
    /// Metadata read from the signed attestation document.
    attestation: VerifiedAttestation,
    consumer: ChannelConsumer,
}

impl VerifiedAssignment {
    /// Metadata from the verified channel-key attestation.
    #[must_use]
    pub const fn attestation(&self) -> &VerifiedAttestation {
        &self.attestation
    }

    /// The channel consumer bound to this assignment's verified key.
    #[must_use]
    pub const fn consumer(&self) -> &ChannelConsumer {
        &self.consumer
    }
}

/// Calls the Flamingo verifier host and verifies the attestation documents it relays.
///
/// Nothing is returned until the enclave that produced it has been verified, so callers
/// cannot accidentally use an unattested key.
#[derive(Debug)]
pub struct FlamingoVerifierClient {
    config: Config,
    http: reqwest::Client,
    verifier: Verifier,
}

impl FlamingoVerifierClient {
    /// Builds a client from `config`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the configuration is invalid or the HTTP client cannot be built.
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::with_http_client_builder(config, reqwest::Client::builder())
    }

    /// Builds a client using an externally configured HTTP client builder.
    ///
    /// The configured cookie store, connection timeout, and request timeout are applied to the
    /// supplied builder.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the configuration is invalid or the HTTP client cannot be built.
    pub fn with_http_client_builder(
        config: Config,
        http: reqwest::ClientBuilder,
    ) -> Result<Self, Error> {
        let http = http
            // Replays the ALB's affinity cookie, so the match reaches the enclave that was assigned.
            .cookie_store(true)
            .connect_timeout(config.connect_timeout())
            .timeout(config.request_timeout())
            .build()
            .map_err(Error::Transport)?;

        Ok(Self {
            verifier: config.verifier()?,
            http,
            config,
        })
    }

    /// Creates the assignment request without sending it.
    ///
    /// Callers may customize the returned builder before passing it to
    /// [`Self::request_assignment_with`].
    pub fn build_assignment_request(&self) -> reqwest::RequestBuilder {
        let url = format!(
            "{}/v1/enclave-assignment",
            self.config.host_url().as_str().trim_end_matches('/')
        );
        self.http.post(url)
    }

    /// Requests an assignment and returns it only if its attestation verifies.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the request fails, the host answers with an error status,
    /// or the attestation document does not verify.
    pub async fn request_assignment(&self) -> Result<VerifiedAssignment, Error> {
        self.request_assignment_with(self.build_assignment_request())
            .await
    }

    /// Sends a caller-customizable assignment request and verifies its response.
    ///
    /// The `request` should be created from [`Self::build_assignment_request`] so it uses this
    /// client's configured cookie store and timeouts.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the request fails, the host answers with an error status,
    /// or the attestation document does not verify.
    pub async fn request_assignment_with(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<VerifiedAssignment, Error> {
        let response = request.send().await.map_err(Error::Request)?;

        let status = response.status();
        if !status.is_success() {
            return Err(Error::Status(status.as_u16()));
        }

        let assignment: EnclaveAssignmentResponse =
            response.json().await.map_err(Error::MalformedResponse)?;

        let document = STANDARD
            .decode(&assignment.attestation)
            .map_err(|_| Error::MalformedAssignment)?;
        let public_key = STANDARD
            .decode(&assignment.public_key)
            .map_err(|_| Error::MalformedAssignment)?;
        let (consumer, attestation) = ChannelConsumer::from_attestation(
            ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
            &self.verifier,
            &document,
            &public_key,
        )
        .map_err(Error::Channel)?;

        Ok(VerifiedAssignment {
            attestation,
            consumer,
        })
    }

    /// Creates a sealed match request without sending it.
    ///
    /// Callers may customize the returned builder before passing it to
    /// [`Self::request_match_with`]. The returned opener must be passed alongside that builder.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if serializing or sealing the request fails.
    pub fn build_match_request(
        &self,
        assignment: &VerifiedAssignment,
        inputs: &MatchInputs,
    ) -> Result<(reqwest::RequestBuilder, pontifex::ResponseOpener), Error> {
        let plaintext = inputs.to_cbor().map_err(|_| Error::MalformedResult)?;
        let (sealed, opener) = assignment
            .consumer()
            .seal_to_enclave(&plaintext)
            .map_err(Error::Channel)?;
        let url = format!(
            "{}/v1/matches",
            self.config.host_url().as_str().trim_end_matches('/')
        );
        let request = self.http.post(url).json(&MatchRequestBody {
            ciphertext: STANDARD.encode(sealed),
        });

        Ok((request, opener))
    }

    /// Runs a match against the enclave `assignment` names.
    ///
    /// [`MatchResult::Failed`] is a normal return, not an error. A statement is verified against the
    /// attested signing key first; call [`match_token::verify`] again to read its claims.
    ///
    /// The caller supplies all three frames in `inputs`, challenge image included.
    ///
    /// # Errors
    ///
    /// [`Error::ReassignRequired`] on a stale assignment — retry once with a fresh one.
    pub async fn request_match(
        &self,
        assignment: &VerifiedAssignment,
        inputs: &MatchInputs,
    ) -> Result<MatchResult, Error> {
        let (request, opener) = self.build_match_request(assignment, inputs)?;
        self.request_match_with(request, opener).await
    }

    /// Sends a caller-customizable match request and verifies its response.
    ///
    /// The `request` and `opener` must come from the same call to [`Self::build_match_request`].
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the request fails or its response cannot be verified.
    pub async fn request_match_with(
        &self,
        request: reqwest::RequestBuilder,
        opener: pontifex::ResponseOpener,
    ) -> Result<MatchResult, Error> {
        let response = request.send().await.map_err(Error::Request)?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.ok();
            return Err(Self::api_error(status.as_u16(), body.as_deref()));
        }

        let body: MatchResponseBody = response.json().await.map_err(Error::MalformedResponse)?;

        let ciphertext = STANDARD
            .decode(body.response_ciphertext.trim())
            .map_err(|_| Error::MalformedCiphertext)?;
        let plaintext = opener
            .open_from_enclave(&ciphertext)
            .map_err(Error::Channel)?;
        let result =
            MatchResult::from_padded_cbor(&plaintext).map_err(|_| Error::MalformedResult)?;

        // Only a statement needs the key, so a rejection skips the attestation entirely.
        if let MatchResult::Success(statement) = &result {
            // Response encryption alone does not authenticate the signing key.
            let attested = self
                .verifier
                .verify_attestation_document(&statement.signing_key_attestation)?;
            let signing_key = <[u8; 32]>::try_from(
                attested
                    .document()
                    .public_key
                    .as_ref()
                    .ok_or(Error::InvalidSigningKey)?
                    .as_slice(),
            )
            .map_err(|_| Error::InvalidSigningKey)
            .and_then(|bytes| {
                EdDSAPublicKey::from_compressed_bytes(bytes).map_err(|_| Error::InvalidSigningKey)
            })?;

            match_token::verify(&statement.token, &signing_key)
                .map_err(|_| Error::StatementInvalid)?;
        }

        Ok(result)
    }

    /// Classifies a non-success response, reading the error envelope when there is one.
    fn api_error(status: u16, body: Option<&str>) -> Error {
        let Some(envelope) =
            body.and_then(|body| serde_json::from_str::<ApiErrorResponse>(body).ok())
        else {
            return Error::Status(status);
        };

        if envelope.error.code == REASSIGN_REQUIRED {
            return Error::ReassignRequired;
        }

        Error::Api {
            status,
            code: envelope.error.code,
            allow_retry: envelope.allow_retry,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Json, Router};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use flamingo_verifier_protocol::match_token::MatchToken;
    use flamingo_verifier_sealed_types::{
        AttestedStatement, FailureReason, MATCH_CHANNEL_DOMAIN, MatchInputs, MatchResult,
    };
    use hex_literal::hex;
    use pontifex::{ChannelConsumer, ChannelDomain, ChannelEnclave};
    use serde_json::{Value, json};

    use super::{FlamingoVerifierClient, MatchRequestBody};
    use crate::{Config, Error, PcrMeasurement};

    fn config(base_url: &str) -> Config {
        let pcrs = vec![PcrMeasurement::new(
            0,
            hex!(
                "108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
            ),
        )];

        Config::new(base_url, vec![pcrs]).expect("config should be valid")
    }

    fn inputs() -> MatchInputs {
        MatchInputs {
            live_image: b"liveness-frame".to_vec(),
            credential_image: b"credential-thumbnail".to_vec(),
            light_guard_image: None,
            hashes_json: br#"{"thumbnail.png":"aa"}"#.to_vec(),
            challenge_image: b"challenge-frame".to_vec(),
            match_threshold: 0.5,
        }
    }

    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("should bind an ephemeral port");
        let address = listener
            .local_addr()
            .expect("listener should have an address");

        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("stub should run");
        });

        format!("http://{address}")
    }

    #[derive(Clone)]
    struct Enclave {
        responder: Arc<ChannelEnclave>,
        answer: MatchResult,
        seen: Arc<Mutex<Option<Value>>>,
        foreign_reply: bool,
    }

    fn consumer_for(enclave: &ChannelEnclave) -> ChannelConsumer {
        ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
            &enclave.public_key(),
        )
        .expect("valid key")
    }

    async fn request_match_with_consumer(
        client: &FlamingoVerifierClient,
        consumer: &ChannelConsumer,
        inputs: &MatchInputs,
    ) -> Result<MatchResult, Error> {
        let plaintext = inputs.to_cbor().map_err(|_| Error::MalformedResult)?;
        let (sealed, opener) = consumer
            .seal_to_enclave(&plaintext)
            .map_err(Error::Channel)?;
        let url = format!(
            "{}/v1/matches",
            client.config.host_url().as_str().trim_end_matches('/')
        );
        let request = client.http.post(url).json(&MatchRequestBody {
            ciphertext: STANDARD.encode(sealed),
        });

        client.request_match_with(request, opener).await
    }

    async fn serve_enclave(
        answer: MatchResult,
        foreign_reply: bool,
    ) -> (String, Arc<ChannelEnclave>, Arc<Mutex<Option<Value>>>) {
        let responder = Arc::new(
            ChannelEnclave::generate(ChannelDomain::new(MATCH_CHANNEL_DOMAIN))
                .expect("channel key"),
        );
        let seen = Arc::new(Mutex::new(None));
        let state = Enclave {
            responder: Arc::clone(&responder),
            answer,
            seen: Arc::clone(&seen),
            foreign_reply,
        };

        let router = Router::new()
            .route(
                "/v1/matches",
                post(
                    |State(state): State<Enclave>, Json(body): Json<Value>| async move {
                        *state.seen.lock().expect("lock should be held") = Some(body.clone());

                        let ciphertext = STANDARD
                            .decode(
                                body["ciphertext"]
                                    .as_str()
                                    .expect("ciphertext should be a string"),
                            )
                            .expect("ciphertext should be base64");
                        let (_, own_sealer) = state
                            .responder
                            .open(&ciphertext)
                            .expect("the enclave should open a request sealed to its own key");

                        let sealer = if state.foreign_reply {
                            let stranger = ChannelConsumer::from_unverified_public_key(
                                ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
                                &state.responder.public_key(),
                            )
                            .expect("key should decode");
                            let (other, _) = stranger
                                .seal_to_enclave(b"unrelated")
                                .expect("sealing should succeed");
                            state
                                .responder
                                .open(&other)
                                .expect("the enclave opens its own")
                                .1
                        } else {
                            own_sealer
                        };

                        let encoded = state
                            .answer
                            .to_padded_cbor()
                            .expect("result should fit the envelope");
                        let response = sealer.seal(&encoded).expect("sealing should succeed");

                        Json(json!({
                            "response_ciphertext": STANDARD.encode(response),
                        }))
                    },
                ),
            )
            .with_state(state);

        (serve(router).await, responder, seen)
    }

    async fn serve_error(status: StatusCode, code: &'static str, allow_retry: bool) -> String {
        let router = Router::new().route(
            "/v1/matches",
            post(move || async move {
                (
                    status,
                    Json(json!({
                        "allowRetry": allow_retry,
                        "error": { "code": code, "message": "stub" },
                    })),
                )
            }),
        );

        serve(router).await
    }

    #[tokio::test]
    async fn a_sealed_rejection_round_trips() {
        let answer = MatchResult::Failed(FailureReason::MatchBelowThreshold);
        let (base_url, responder, seen) = serve_enclave(answer.clone(), false).await;
        let client = FlamingoVerifierClient::new(config(&base_url)).expect("client should build");

        let result = request_match_with_consumer(&client, &consumer_for(&responder), &inputs())
            .await
            .expect("a rejection is a normal return");

        assert_eq!(result, answer);

        let body = seen.lock().expect("lock should be held").clone().unwrap();
        assert!(
            STANDARD
                .decode(body["ciphertext"].as_str().unwrap())
                .is_ok(),
            "the sealed request must be base64"
        );
        assert_eq!(
            body.as_object().map(serde_json::Map::len),
            Some(1),
            "the request carries the ciphertext and nothing else"
        );
    }

    #[tokio::test]
    async fn a_reply_from_another_exchange_cannot_be_opened() {
        let (base_url, responder, _) =
            serve_enclave(MatchResult::Failed(FailureReason::MalformedInputs), true).await;
        let client = FlamingoVerifierClient::new(config(&base_url)).expect("client should build");

        let error = request_match_with_consumer(&client, &consumer_for(&responder), &inputs())
            .await
            .expect_err("a reply sealed on another exchange must not open");

        assert!(matches!(error, Error::Channel(_)), "got {error:?}");
    }

    #[tokio::test]
    async fn a_stale_assignment_asks_for_a_reassignment() {
        let base_url = serve_error(StatusCode::CONFLICT, "reassign_required", true).await;
        let client = FlamingoVerifierClient::new(config(&base_url)).expect("client should build");
        let responder = ChannelEnclave::generate(ChannelDomain::new(MATCH_CHANNEL_DOMAIN))
            .expect("channel key");

        let error = request_match_with_consumer(&client, &consumer_for(&responder), &inputs())
            .await
            .expect_err("a 409 is an error, not a result");

        assert!(
            matches!(error, Error::ReassignRequired),
            "a 409 must be distinguishable so the caller can retry once, got {error:?}"
        );
    }

    #[tokio::test]
    async fn other_envelopes_keep_their_code_and_retry_flag() {
        let base_url = serve_error(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large", false).await;
        let client = FlamingoVerifierClient::new(config(&base_url)).expect("client should build");
        let responder = ChannelEnclave::generate(ChannelDomain::new(MATCH_CHANNEL_DOMAIN))
            .expect("channel key");

        let error = request_match_with_consumer(&client, &consumer_for(&responder), &inputs())
            .await
            .expect_err("a 413 is an error");

        match error {
            Error::Api {
                status,
                code,
                allow_retry,
            } => {
                assert_eq!(status, 413);
                assert_eq!(code, "request_too_large");
                assert!(!allow_retry);
            }
            other => panic!("expected an envelope, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_status_without_an_envelope_still_surfaces() {
        let router = Router::new().route(
            "/v1/matches",
            post(|| async { (StatusCode::BAD_GATEWAY, "not json") }),
        );
        let base_url = serve(router).await;
        let client = FlamingoVerifierClient::new(config(&base_url)).expect("client should build");
        let responder = ChannelEnclave::generate(ChannelDomain::new(MATCH_CHANNEL_DOMAIN))
            .expect("channel key");

        let error = request_match_with_consumer(&client, &consumer_for(&responder), &inputs())
            .await
            .expect_err("a 502 is an error");

        assert!(matches!(error, Error::Status(502)), "got {error:?}");
    }

    #[tokio::test]
    async fn a_statement_whose_attestation_does_not_verify_is_rejected() {
        for attestation in [Vec::new(), b"not a COSE attestation document".to_vec()] {
            let answer = MatchResult::Success(AttestedStatement {
                token: MatchToken::from_bytes(b"cose-sign1".to_vec()),
                signing_key_attestation: attestation,
            });
            let (base_url, responder, _) = serve_enclave(answer, false).await;
            let client =
                FlamingoVerifierClient::new(config(&base_url)).expect("client should build");

            let error = request_match_with_consumer(&client, &consumer_for(&responder), &inputs())
                .await
                .expect_err("an unverifiable attestation must not yield a statement");

            assert!(
                matches!(error, Error::Attestation(_)),
                "expected an attestation failure, got {error:?}"
            );
        }
    }
}
