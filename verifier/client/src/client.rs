//! HTTP client for the Flamingo Verifier host.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use flamingo_verifier_api_types::{
    EnclaveAssignmentResponse, ErrorEnvelope, MATCH_CONTENT_TYPE, MAX_MATCH_BODY_BYTES,
    MAX_MATCH_RESPONSE_BYTES,
};
use flamingo_verifier_protocol::match_token::{self, EdDSAPublicKey, MatchClaims};
use flamingo_verifier_sealed_types::{MATCH_CHANNEL_DOMAIN, MatchInputs, MatchResult};
use futures_util::StreamExt as _;
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

/// Calls the Flamingo Verifier host and verifies the attestation documents it relays.
///
/// Nothing is returned until the enclave that produced it has been verified, so callers
/// cannot accidentally use an unattested key.
#[derive(Debug)]
pub struct FlamingoVerifierClient {
    config: Config,
    http: reqwest::Client,
    verifier: Verifier,
}

#[cfg_attr(
    target_arch = "wasm32",
    expect(
        clippy::future_not_send,
        reason = "Fetch and JavaScript futures stay on their originating browser worker"
    )
)]
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
    /// Native clients use a cookie store and connection/request timeouts. Browser clients
    /// use Fetch credentials and a per-request deadline; the browser manages connections.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the configuration is invalid or the HTTP client cannot be built.
    pub fn with_http_client_builder(
        config: Config,
        http: reqwest::ClientBuilder,
    ) -> Result<Self, Error> {
        #[cfg(not(target_arch = "wasm32"))]
        let http = http
            // Replays the ALB's affinity cookie, so the match reaches the enclave that was assigned.
            .cookie_store(true)
            .connect_timeout(config.connect_timeout())
            .timeout(config.request_timeout());
        let http = http.build().map_err(Error::Transport)?;

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
    #[must_use]
    pub fn build_assignment_request(&self) -> reqwest::RequestBuilder {
        let url = format!(
            "{}/v1/enclave-assignment",
            self.config.host_url().as_str().trim_end_matches('/')
        );
        self.configure_request(self.http.post(url))
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

        assignment_status(response.status())?;
        let assignment = response.json().await.map_err(Error::MalformedResponse)?;
        self.verify_assignment(assignment)
    }

    fn verify_assignment(
        &self,
        assignment: EnclaveAssignmentResponse,
    ) -> Result<VerifiedAssignment, Error> {
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
        self.build_match_request_for_consumer(assignment.consumer(), inputs)
    }

    fn build_match_request_for_consumer(
        &self,
        consumer: &ChannelConsumer,
        inputs: &MatchInputs,
    ) -> Result<(reqwest::RequestBuilder, pontifex::ResponseOpener), Error> {
        let plaintext = inputs.to_cbor().map_err(|_| Error::MalformedResult)?;
        let (sealed, opener) = consumer
            .seal_to_enclave(&plaintext)
            .map_err(Error::Channel)?;
        let url = format!(
            "{}/v1/matches",
            self.config.host_url().as_str().trim_end_matches('/')
        );
        if sealed.len() > MAX_MATCH_BODY_BYTES {
            return Err(Error::MalformedResult);
        }

        let request = self
            .configure_request(self.http.post(url))
            .header(reqwest::header::CONTENT_TYPE, MATCH_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, MATCH_CONTENT_TYPE)
            .body(sealed);

        Ok((request, opener))
    }

    /// Runs a match against the enclave `assignment` names.
    ///
    /// [`VerifiedMatchResult::Failed`] is a normal return, not an error. A statement and its claims are verified against the
    /// attested signing key once, then returned together.
    ///
    /// The caller supplies the operation's frames, including the downloaded challenge.
    ///
    /// # Errors
    ///
    /// [`Error::ReassignRequired`] on a stale assignment — retry once with a fresh one.
    pub async fn request_match(
        &self,
        assignment: &VerifiedAssignment,
        inputs: &MatchInputs,
    ) -> Result<VerifiedMatchResult, Error> {
        let (request, opener) = self.build_match_request(assignment, inputs)?;
        let result = self.request_match_with(request, opener).await?;
        if let VerifiedMatchResult::Success(verified) = &result
            && !inputs.matches_claims(&verified.claims)
        {
            return Err(Error::StatementInvalid);
        }

        Ok(result)
    }

    /// Execute a typed `DeepFace` request and return verified claims or a sealed rejection.
    /// # Errors
    /// Returns transport, attestation or contract errors.
    pub async fn deep_face(
        &self,
        assignment: &VerifiedAssignment,
        inputs: flamingo_verifier_sealed_types::DeepFaceInputs,
    ) -> Result<VerifiedMatchResult, Error> {
        self.request_match(assignment, &MatchInputs::DeepFace(inputs))
            .await
    }

    /// Submit a typed `GrayBadge` request without credential fields.
    /// Supports vanilla and `LightGuard` captures and verifies a credential-free statement.
    /// # Errors
    /// Returns transport, attestation or contract errors.
    pub async fn gray_badge(
        &self,
        assignment: &VerifiedAssignment,
        inputs: flamingo_verifier_sealed_types::GrayBadgeInputs,
    ) -> Result<VerifiedMatchResult, Error> {
        self.request_match(assignment, &MatchInputs::GrayBadge(inputs))
            .await
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
    ) -> Result<VerifiedMatchResult, Error> {
        let response = request.send().await.map_err(Error::Request)?;

        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        let length = response.content_length();
        self.handle_match_response(
            status,
            content_type.as_deref(),
            length,
            response.bytes_stream(),
            opener,
        )
        .await
    }

    async fn handle_match_response<S, B>(
        &self,
        status: reqwest::StatusCode,
        content_type: Option<&str>,
        length: Option<u64>,
        stream: S,
        opener: pontifex::ResponseOpener,
    ) -> Result<VerifiedMatchResult, Error>
    where
        S: futures_util::Stream<Item = Result<B, reqwest::Error>>,
        B: AsRef<[u8]>,
    {
        if !status.is_success() {
            let bytes = bounded_response(length, stream).await?;
            let body = std::str::from_utf8(&bytes).ok();
            return Err(Self::api_error(status.as_u16(), body));
        }

        if content_type != Some(MATCH_CONTENT_TYPE) {
            return Err(Error::MalformedResult);
        }
        let ciphertext = bounded_response(length, stream).await?;
        let plaintext = opener
            .open_from_enclave(&ciphertext)
            .map_err(Error::Channel)?;
        let result =
            MatchResult::from_padded_cbor(&plaintext).map_err(|_| Error::MalformedResult)?;

        // Only a statement needs the key, so a rejection skips the attestation entirely.
        if let MatchResult::Success(statement) = result {
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

            let claims = match_token::verify(&statement.token, &signing_key)
                .map_err(|_| Error::StatementInvalid)?;
            return Ok(VerifiedMatchResult::Success(Box::new(VerifiedMatch {
                statement,
                claims,
            })));
        }

        match result {
            MatchResult::Failed(reason) => Ok(VerifiedMatchResult::Failed(reason)),
            MatchResult::Success(_) => unreachable!("success was verified above"),
        }
    }

    /// Classifies a non-success response, reading the error envelope when there is one.
    fn api_error(status: u16, body: Option<&str>) -> Error {
        let Some(envelope) = body.and_then(|body| serde_json::from_str::<ErrorEnvelope>(body).ok())
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

    /// Applies the transport policy to a request before it is sent.
    ///
    /// The browser fetch policy ("include" credentials, "no-store" cache, AbortSignal deadline)
    /// is enforced here. Those settings are not wire-visible, so they are covered by walletkit's
    /// browser integration, not by unit tests.
    fn configure_request(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        #[cfg(target_arch = "wasm32")]
        let request = request.fetch_credentials_include().fetch_cache_no_store();
        request.timeout(self.config.request_timeout())
    }
}

#[cfg_attr(
    target_arch = "wasm32",
    expect(
        clippy::future_not_send,
        reason = "Fetch response streams stay on the originating browser worker"
    )
)]
async fn bounded_response<S, B>(length: Option<u64>, stream: S) -> Result<Vec<u8>, Error>
where
    S: futures_util::Stream<Item = Result<B, reqwest::Error>>,
    B: AsRef<[u8]>,
{
    if length.is_some_and(|length| length > MAX_MATCH_RESPONSE_BYTES as u64) {
        return Err(Error::MalformedResult);
    }

    let mut bytes = Vec::new();
    // bytes_stream is available on both native and browser clients. Keep the limit
    // incremental so a missing Content-Length cannot force a full-body allocation.
    let mut stream = Box::pin(stream);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(Error::MalformedResponse)?;
        let chunk = chunk.as_ref();
        if chunk.len() > MAX_MATCH_RESPONSE_BYTES - bytes.len() {
            return Err(Error::MalformedResult);
        }
        bytes.extend_from_slice(chunk);
    }

    Ok(bytes)
}

/// A statement whose attestation and signature have been verified by the client.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedMatch {
    /// Encoded statement and attestation for proof consumers.
    pub statement: flamingo_verifier_sealed_types::AttestedStatement,
    /// Already-verified operation-specific claims.
    pub claims: MatchClaims,
}

/// Verified success or an encrypted unsigned rejection.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifiedMatchResult {
    /// Attested signed result and parsed claims.
    Success(Box<VerifiedMatch>),
    /// No statement issued.
    Failed(flamingo_verifier_sealed_types::FailureReason),
}
fn assignment_status(status: reqwest::StatusCode) -> Result<(), Error> {
    if status.is_success() {
        Ok(())
    } else {
        Err(Error::Status(status.as_u16()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PcrMeasurement;
    use flamingo_verifier_protocol::match_token::MatchToken;
    use flamingo_verifier_sealed_types::{AttestedStatement, FailureReason};
    use futures_util::stream;
    use pontifex::ChannelEnclave;
    use reqwest::StatusCode;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    fn client() -> FlamingoVerifierClient {
        let config = Config::new(
            "https://verifier.example/",
            vec![vec![PcrMeasurement::new(0, [1; 48])]],
        )
        .unwrap();
        FlamingoVerifierClient::new(config).unwrap()
    }

    fn inputs() -> MatchInputs {
        MatchInputs::GrayBadge(flamingo_verifier_sealed_types::GrayBadgeInputs {
            live: flamingo_verifier_sealed_types::LiveCapture::Vanilla(
                b"private-image-marker".to_vec().into(),
            ),
            rtms_challenge: b"challenge".to_vec().into(),
            match_threshold: 0.5,
        })
    }

    fn exchange(answer: &MatchResult, foreign: bool) -> (Vec<u8>, pontifex::ResponseOpener) {
        let enclave = ChannelEnclave::generate(ChannelDomain::new(MATCH_CHANNEL_DOMAIN)).unwrap();
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
            &enclave.public_key(),
        )
        .unwrap();
        let (request, opener) = client()
            .build_match_request_for_consumer(&consumer, &inputs())
            .unwrap();
        let request = request.build().unwrap();
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().path(), "/v1/matches");
        assert_eq!(
            request.headers()[reqwest::header::CONTENT_TYPE],
            MATCH_CONTENT_TYPE
        );
        assert_eq!(
            request.headers()[reqwest::header::ACCEPT],
            MATCH_CONTENT_TYPE
        );
        let body = request.body().unwrap().as_bytes().unwrap();
        assert!(serde_json::from_slice::<serde_json::Value>(body).is_err());
        assert!(
            !body
                .windows(b"private-image-marker".len())
                .any(|w| w == b"private-image-marker")
        );
        let (plaintext, sealer) = enclave.open(body).unwrap();
        assert_eq!(&*plaintext, inputs().to_cbor().unwrap().as_slice());
        assert!(matches!(
            MatchInputs::from_cbor(&plaintext),
            Ok(MatchInputs::GrayBadge(_))
        ));
        let sealer = if foreign {
            let (other, _) = consumer.seal_to_enclave(b"unrelated").unwrap();
            enclave.open(&other).unwrap().1
        } else {
            sealer
        };
        (
            sealer.seal(&answer.to_padded_cbor().unwrap()).unwrap(),
            opener,
        )
    }

    async fn response(
        status: StatusCode,
        body: Vec<u8>,
        opener: pontifex::ResponseOpener,
    ) -> Result<VerifiedMatchResult, Error> {
        client()
            .handle_match_response(
                status,
                Some(MATCH_CONTENT_TYPE),
                None,
                stream::iter([Ok(body)]),
                opener,
            )
            .await
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn a_reply_from_another_exchange_cannot_be_opened() {
        let (body, opener) = exchange(&MatchResult::Failed(FailureReason::MalformedInputs), true);
        assert!(matches!(
            response(StatusCode::OK, body, opener).await,
            Err(Error::Channel(_))
        ));
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn error_statuses_preserve_envelopes_and_fallback() {
        for (status, body) in [
            (
                409,
                br#"{"allowRetry":true,"error":{"code":"reassign_required","message":"stub"}}"#
                    .as_slice(),
            ),
            (
                413,
                br#"{"allowRetry":false,"error":{"code":"request_too_large","message":"stub"}}"#
                    .as_slice(),
            ),
            (502, b"not json".as_slice()),
            (502, &[255]),
        ] {
            let (_, opener) = exchange(&MatchResult::Failed(FailureReason::MalformedInputs), false);
            let error = response(StatusCode::from_u16(status).unwrap(), body.to_vec(), opener)
                .await
                .unwrap_err();
            match status {
                409 => assert!(matches!(error, Error::ReassignRequired)),
                413 => match error {
                    Error::Api {
                        status,
                        code,
                        allow_retry,
                    } => {
                        assert_eq!(status, 413);
                        assert_eq!(code, "request_too_large");
                        assert!(!allow_retry);
                    }
                    other => panic!("unexpected error: {other:?}"),
                },
                _ => assert!(matches!(error, Error::Status(502))),
            }
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn a_statement_whose_attestation_does_not_verify_is_rejected() {
        for attestation in [Vec::new(), b"not a COSE attestation document".to_vec()] {
            let answer = MatchResult::Success(AttestedStatement {
                token: MatchToken::from_bytes(b"cose-sign1".to_vec()),
                signing_key_attestation: attestation,
            });
            let (body, opener) = exchange(&answer, false);
            assert!(matches!(
                response(StatusCode::OK, body, opener).await,
                Err(Error::Attestation(_))
            ));
        }
    }

    mod assignment {
        use super::*;

        #[cfg_attr(not(target_arch = "wasm32"), test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        fn rejects_an_assignment_whose_attestation_does_not_verify() {
            let error = client()
                .verify_assignment(EnclaveAssignmentResponse {
                    attestation: "hEBAQEA=".into(),
                    public_key: "a2V5".into(),
                })
                .unwrap_err();
            assert!(matches!(error, Error::Channel(_)));
        }

        #[cfg_attr(not(target_arch = "wasm32"), test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        fn rejects_malformed_base64_in_either_assignment_field() {
            for (document, key) in [("!", "a2V5"), ("hEBAQEA=", "!")] {
                let error = client()
                    .verify_assignment(EnclaveAssignmentResponse {
                        attestation: document.into(),
                        public_key: key.into(),
                    })
                    .unwrap_err();
                assert!(matches!(error, Error::MalformedAssignment));
            }
        }

        #[cfg_attr(not(target_arch = "wasm32"), test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        fn surfaces_a_host_error_status() {
            let request = client().build_assignment_request().build().unwrap();
            assert_eq!(request.method(), reqwest::Method::POST);
            assert_eq!(request.url().path(), "/v1/enclave-assignment");
            assert!(matches!(
                assignment_status(StatusCode::SERVICE_UNAVAILABLE),
                Err(Error::Status(503))
            ));
            assert!(assignment_status(StatusCode::OK).is_ok());
        }
    }

    mod match_exchange {
        use super::*;
        use std::task::Poll;

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        async fn a_sealed_exchange_round_trips_over_raw_ciphertext() {
            let reason = FailureReason::MatchBelowThreshold(
                flamingo_verifier_sealed_types::ComparisonRole::SelfieChallenge,
            );
            let (body, opener) = exchange(&MatchResult::Failed(reason), false);
            assert_eq!(
                response(StatusCode::OK, body, opener).await.unwrap(),
                VerifiedMatchResult::Failed(reason)
            );
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        async fn a_response_of_the_wrong_type_is_rejected() {
            for content_type in [
                None,
                Some("application/json"),
                Some("application/octet-stream; charset=utf-8"),
            ] {
                let (_, opener) =
                    exchange(&MatchResult::Failed(FailureReason::MalformedInputs), false);
                let stream =
                    stream::poll_fn(|_| -> Poll<Option<Result<Vec<u8>, reqwest::Error>>> {
                        panic!("must reject content type before polling the body")
                    });
                assert!(matches!(
                    client()
                        .handle_match_response(StatusCode::OK, content_type, None, stream, opener)
                        .await,
                    Err(Error::MalformedResult)
                ));
            }
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        async fn an_oversized_streamed_response_is_rejected_before_it_is_buffered() {
            for status in [StatusCode::OK, StatusCode::BAD_GATEWAY] {
                let (_, opener) =
                    exchange(&MatchResult::Failed(FailureReason::MalformedInputs), false);
                let mut polls = 0;
                let stream = stream::poll_fn(|_| {
                    polls += 1;
                    Poll::Ready(Some(Ok::<_, reqwest::Error>(match polls {
                        1 => vec![0; MAX_MATCH_RESPONSE_BYTES],
                        2 => vec![0],
                        _ => panic!("must stop polling immediately after the oversized chunk"),
                    })))
                });
                assert!(matches!(
                    client()
                        .handle_match_response(
                            status,
                            Some(MATCH_CONTENT_TYPE),
                            None,
                            stream,
                            opener
                        )
                        .await,
                    Err(Error::MalformedResult)
                ));
                assert_eq!(polls, 2);
            }
            let bytes =
                bounded_response(None, stream::iter([Ok(vec![0; MAX_MATCH_RESPONSE_BYTES])]))
                    .await
                    .unwrap();
            assert_eq!(bytes.len(), MAX_MATCH_RESPONSE_BYTES);
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        async fn an_oversized_declared_length_is_rejected_before_it_is_buffered() {
            for status in [StatusCode::OK, StatusCode::BAD_GATEWAY] {
                let (_, opener) =
                    exchange(&MatchResult::Failed(FailureReason::MalformedInputs), false);
                let stream =
                    stream::poll_fn(|_| -> Poll<Option<Result<Vec<u8>, reqwest::Error>>> {
                        panic!("must reject declared length without polling the body")
                    });
                assert!(matches!(
                    client()
                        .handle_match_response(
                            status,
                            Some(MATCH_CONTENT_TYPE),
                            Some(MAX_MATCH_RESPONSE_BYTES as u64 + 1),
                            stream,
                            opener
                        )
                        .await,
                    Err(Error::MalformedResult)
                ));
            }
        }
    }
}
