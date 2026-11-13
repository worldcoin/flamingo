//! WIP-202 end to end: an in-process Verifier issues a Flamingo Token, the Authenticator turns it
//! into a Proof of Embedding Similarity, and an RP verifies it.

#![deny(clippy::all, clippy::pedantic, clippy::nursery, dead_code)]
#![recursion_limit = "256"]

use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_primitives::Bytes;
use async_trait::async_trait;
use eyre::{Result, bail, eyre};
use flamingo_verifier_client::{Config, FlamingoVerifierClient, VerifiedMatchResult};
use flamingo_verifier_enclave::{dev, pipeline::PIPELINE_DEEPFACE, state::EnclaveState};
use flamingo_verifier_enclave_types::{
    BillingStatus, BillingUpdateRequest, KeyAttestation, MatchRequest, MatchResponse,
};
use flamingo_verifier_host::{
    AppState, HostConfig,
    enclave::{self, EnclaveClient},
    routes,
};
use flamingo_verifier_sealed_types::{FailureReason, dev::DevAttestation, testing};
use tokio::net::TcpListener;
use world_id_core::{
    EdDSAPublicKey, EmbeddingSimilarityImages, FieldElement, FlamingoResult,
    artifacts::{ZkArtifactSourceExt as _, embedded::EmbeddedZkArtifacts},
    embedding_similarity::{
        EmbeddingSimilarityVerificationError as VerifyError, FlamingoAttestationVerifier,
    },
    flamingo_request,
    requests::{ProofRequest, ProofType},
};
use world_id_flamingo::{FlamingoToken, ReleaseManifest, engine_config_hash};
use world_id_test_utils::embedding_similarity::{EmbeddingSimilarityFixture, image_hash};

/// Response slots of the dev release, in milliseconds: the stub Engine answers at once.
const SLOTS: &[u64] = &[1, 500];

/// The dev Verifier's release.
fn manifest() -> String {
    testing::manifest_with_slots(testing::TEST_ENGINE_HASH, 1, SLOTS)
}

/// Calls the dev enclave operations in-process, where the host would use vsock.
struct DevEnclave(Arc<EnclaveState>);

#[async_trait]
impl EnclaveClient for DevEnclave {
    async fn health(&self) -> Result<(), enclave::Error> {
        dev::health(Arc::clone(&self.0))
            .await
            .map_err(enclave::Error::Operation)
    }

    async fn encryption_key_attestation(&self) -> Result<KeyAttestation, enclave::Error> {
        dev::encryption_key(Arc::clone(&self.0))
            .await
            .map_err(enclave::Error::Operation)
    }

    async fn run_match(&self, request: MatchRequest) -> Result<MatchResponse, enclave::Error> {
        dev::run_match(Arc::clone(&self.0), request)
            .await
            .map_err(enclave::Error::Operation)
    }

    async fn update_billing(
        &self,
        request: BillingUpdateRequest,
    ) -> Result<BillingStatus, enclave::Error> {
        dev::update_billing(Arc::clone(&self.0), request)
            .await
            .map_err(enclave::Error::Operation)
    }
}

/// Reads the dev signing key attestation, an unsigned [`DevAttestation`] of the raw key.
struct DevKeyAttestation;

impl FlamingoAttestationVerifier for DevKeyAttestation {
    fn attested_key(&self, attestation: &[u8]) -> Result<EdDSAPublicKey, String> {
        let document =
            DevAttestation::from_cbor(attestation).map_err(|error| format!("{error:?}"))?;
        let key = document
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| "not a 32-byte key".to_string())?;
        EdDSAPublicKey::from_compressed_bytes(key).map_err(|error| error.to_string())
    }
}

/// Serves a fresh dev Verifier on a local port and returns its URL.
///
/// Fresh per call, because the Verifier rejects a replayed request nonce.
async fn serve_verifier() -> Result<String> {
    let state = dev::verifier(&manifest()).map_err(|error| eyre!("dev verifier: {error:?}"))?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("http://{}", listener.local_addr()?);
    let app = routes::handler().with_state(AppState::new(
        HostConfig::default(),
        Arc::new(DevEnclave(state)),
    ));
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the dev host stopped");
    });
    Ok(url)
}

/// Sends the Authenticator's Flamingo request for `proof_request` to a fresh dev Verifier.
async fn flamingo_call(
    proof_request: &ProofRequest,
    match_strictness: u8,
    images: EmbeddingSimilarityImages,
) -> Result<VerifiedMatchResult> {
    let url = serve_verifier().await?;
    let client = FlamingoVerifierClient::new(Config::dangerously_accept_dev_attestation(&url)?)?;
    let session = client.connect().await?;
    let request = flamingo_request(
        proof_request,
        session.assignment().release(),
        match_strictness,
        images,
        FieldElement::ZERO,
        now_secs(),
    )?;
    Ok(session.request_match(&request).await?)
}

/// What the Authenticator keeps of a successful match.
fn flamingo_result(result: VerifiedMatchResult) -> Result<FlamingoResult> {
    let VerifiedMatchResult::Success { verified, .. } = result else {
        bail!("expected a token, got {result:?}");
    };
    let statement = verified.statement;
    Ok(FlamingoResult {
        token: FlamingoToken::from_cwt(&statement.token)?,
        verifier_key: DevKeyAttestation
            .attested_key(&statement.signing_key_attestation)
            .map_err(|error| eyre!(error))?,
        signing_key_attestation: Bytes::from(statement.signing_key_attestation),
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
}

// One test, since each fixture spawns anvil, containers and OPRF nodes.
#[tokio::test(flavor = "multi_thread")]
async fn wip202_proof_from_a_flamingo_token() -> Result<()> {
    let fixture = Box::pin(EmbeddingSimilarityFixture::spawn(Arc::new(
        EmbeddedZkArtifacts.cached(),
    )))
    .await?;
    let images = EmbeddingSimilarityImages {
        credential_image: fixture.credential_image.clone(),
        live_capture: b"live capture".to_vec(),
        challenge: fixture.challenge.clone(),
    };

    // Strictness 3 needs more than the stub Engine's score, so no token is issued.
    let below = flamingo_call(&fixture.proof_request, 3, images.clone()).await?;
    assert!(
        matches!(
            below,
            VerifiedMatchResult::Failed {
                reason: FailureReason::MatchBelowThreshold(_),
                ..
            }
        ),
        "{below:?}"
    );

    let result = flamingo_result(flamingo_call(&fixture.proof_request, 2, images).await?)?;
    let response = fixture.prove(&result).await?;

    // `flamingo_request` picks the release's first single live frame pipeline.
    let release = ReleaseManifest::from_jws(&manifest())?;
    let dev_engine = engine_config_hash(&release.release_hash(), PIPELINE_DEEPFACE, 2);
    let policy = fixture.policy(DevKeyAttestation, [dev_engine].into());
    fixture
        .verify(&fixture.proof_request, &response, &policy)
        .await?;

    // The RP sent another challenge than the one the token compared.
    let mut other_challenge = fixture.proof_request.clone();
    let ProofType::EmbeddingSimilarity(params) = &mut other_challenge.proof_type else {
        bail!("the fixture requests a Proof of Embedding Similarity");
    };
    params.challenge_hash = image_hash(b"another frame");
    let error = fixture
        .verify(&other_challenge, &response, &policy)
        .await
        .expect_err("another challenge");
    assert!(matches!(error, VerifyError::Proof(_)), "{error:?}");

    // The RP does not accept the dev release.
    let other_engine = fixture.policy(DevKeyAttestation, [FieldElement::from(1u64)].into());
    let error = fixture
        .verify(&fixture.proof_request, &response, &other_engine)
        .await
        .expect_err("another engine");
    assert!(
        matches!(error, VerifyError::EngineNotAccepted(hash) if hash == dev_engine),
        "{error:?}"
    );
    Ok(())
}
