//! WIP-202 end to end: an in-process Verifier issues a Flamingo Token, the Authenticator turns it
//! into a Proof of Embedding Similarity, and an RP verifies it. Unbilled, and for an RP the WIP-107
//! Billing Contract bills, with the host following the contract on anvil.

#![deny(clippy::all, clippy::pedantic, clippy::nursery, dead_code)]
#![recursion_limit = "256"]

use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::Bytes;
use async_trait::async_trait;
use eyre::{Result, bail, eyre};
use flamingo_verifier_billing_follower::RpcUrl;
use flamingo_verifier_client::{
    Config, FlamingoVerifierClient, VerifiedMatch, VerifiedMatchResult,
};
use flamingo_verifier_enclave::{
    billing::BillingConfig, dev, pipeline::PIPELINE_DEEPFACE, state::EnclaveState,
};
use flamingo_verifier_enclave_types::{
    BillingStatus, BillingUpdateRequest, KeyAttestation, MatchRequest, MatchResponse,
};
use flamingo_verifier_host::{
    AppState, HostConfig, billing,
    enclave::{self, EnclaveClient},
    routes,
};
use flamingo_verifier_sealed_types::{ComparisonRole, FailureReason, dev::DevAttestation, testing};
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
use world_id_test_utils::embedding_similarity::{
    EmbeddingSimilarityFixture, FixtureBilling, image_hash,
};

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

/// Serves a fresh dev Verifier on a local port and returns its URL. With `billing`, the host
/// follows that Billing Contract into the Verifier, which serves once it has caught up.
///
/// Fresh per call, because the Verifier rejects a replayed request nonce.
async fn serve_verifier(billing: Option<&FixtureBilling>) -> Result<String> {
    let state = dev::verifier(
        &manifest(),
        billing.map(|_| BillingConfig {
            max_registrations: 16,
        }),
    )
    .map_err(|error| eyre!("dev verifier: {error:?}"))?;
    let enclave: Arc<dyn EnclaveClient> = Arc::new(DevEnclave(Arc::clone(&state)));
    if let Some(fixture_billing) = billing {
        let config = billing::BillingConfig {
            rpc_url: RpcUrl(fixture_billing.rpc_url.parse()?),
            chain_id: fixture_billing.chain_id,
            contract: fixture_billing.contract,
            deploy_block: fixture_billing.deploy_block,
        };
        let follower_enclave = Arc::clone(&enclave);
        tokio::spawn(async move {
            let error = billing::run(config, follower_enclave).await;
            panic!("the billing follower stopped: {error:?}");
        });
        tokio::time::timeout(Duration::from_secs(60), async {
            while !state.billing().is_ready() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| eyre!("the Verifier's billing state did not catch up within 60 s"))?;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("http://{}", listener.local_addr()?);
    let app = routes::handler().with_state(AppState::new(HostConfig::default(), enclave));
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the dev host stopped");
    });
    Ok(url)
}

/// What a Flamingo request returned, and the salt its `nonce` was derived with.
struct Attempt {
    result: VerifiedMatchResult,
    nonce_salt: FieldElement,
}

/// Sends the Authenticator's Flamingo request for `proof_request` to a fresh dev Verifier, billing
/// with `billing` if set.
async fn flamingo_call(
    proof_request: &ProofRequest,
    match_strictness: u8,
    images: EmbeddingSimilarityImages,
    billing: Option<&FixtureBilling>,
    billing_nullifier: FieldElement,
) -> Result<Attempt> {
    let url = serve_verifier(billing).await?;
    let client = FlamingoVerifierClient::new(Config::dangerously_accept_dev_attestation(&url)?)?;
    let session = client.connect().await?;
    let attempt = flamingo_request(
        proof_request,
        session.assignment().release(),
        match_strictness,
        images,
        billing_nullifier,
        now_secs(),
    )?;
    Ok(Attempt {
        result: session.request_match(&attempt.request).await?,
        nonce_salt: attempt.nonce_salt,
    })
}

/// Asserts that `result` failed with `expected`.
fn assert_failed(result: &VerifiedMatchResult, expected: FailureReason) {
    assert!(
        matches!(result, VerifiedMatchResult::Failed { reason, .. } if *reason == expected),
        "expected {expected:?}, got {result:?}"
    );
}

/// What the Authenticator keeps of a successful match.
fn flamingo_result(Attempt { result, nonce_salt }: Attempt) -> Result<FlamingoResult> {
    let VerifiedMatchResult::Success { verified, .. } = result else {
        bail!("expected a token, got {result:?}");
    };
    let VerifiedMatch {
        statement,
        verifier_key,
        ..
    } = *verified;
    Ok(FlamingoResult {
        token: FlamingoToken::from_cwt(&statement.token)?,
        verifier_key,
        signing_key_attestation: Bytes::from(statement.signing_key_attestation),
        nonce_salt,
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
    let fixture = Box::pin(EmbeddingSimilarityFixture::spawn_billed(Arc::new(
        EmbeddedZkArtifacts.cached(),
    )))
    .await?;
    let billing = fixture
        .billing
        .as_ref()
        .ok_or_else(|| eyre!("the fixture bills the RP"))?;
    let images = EmbeddingSimilarityImages {
        credential_image: fixture.credential_image.clone(),
        live_capture: b"live capture".to_vec(),
        challenge: fixture.challenge.clone(),
    };
    let call = |match_strictness, billing, billing_nullifier| {
        flamingo_call(
            &fixture.proof_request,
            match_strictness,
            images.clone(),
            billing,
            billing_nullifier,
        )
    };

    // Strictness 3 needs more than the stub Engine's score, so no token is issued.
    let below = call(3, None, FieldElement::ZERO).await?.result;
    assert_failed(
        &below,
        FailureReason::MatchBelowThreshold(ComparisonRole::OrbSelfie),
    );

    // A Verifier that bills nothing signs `billing_nullifier = 0`.
    let unbilled = flamingo_result(call(2, None, FieldElement::ZERO).await?)?;
    assert_eq!(
        unbilled.token.claims().billing_nullifier,
        FieldElement::ZERO
    );
    // The Verifier sees only the nonce derived from the RP's nonce and the attempt's salt.
    assert_ne!(unbilled.token.claims().nonce, fixture.proof_request.nonce);
    let response = fixture.prove(&unbilled, None).await?;

    // The proof binds the token's nonce to the RP's through the salt, so another salt fails.
    let mut wrong_salt = unbilled.clone();
    wrong_salt.nonce_salt = FieldElement::from(1u64);
    assert!(
        fixture.prove(&wrong_salt, None).await.is_err(),
        "a proof with another salt"
    );

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

    // A Verifier following the Billing Contract rejects the billed RP's request without a
    // registration (WIP-107 §4.7).
    let required = call(2, Some(billing), FieldElement::ZERO).await?.result;
    assert_failed(&required, FailureReason::BillingNullifierRequired);
    let unregistered = call(2, Some(billing), FieldElement::from(1u64))
        .await?
        .result;
    assert_failed(&unregistered, FailureReason::BillingUnregistered);

    // Once registered, it signs the registration's nullifier, and the proof binds it.
    let witness = fixture.register_billing().await?;
    let billed = flamingo_result(call(2, Some(billing), witness.billing_nullifier).await?)?;
    assert_eq!(
        billed.token.claims().billing_nullifier,
        witness.billing_nullifier
    );
    let response = fixture.prove(&billed, Some(&witness)).await?;
    fixture
        .verify(&fixture.proof_request, &response, &policy)
        .await?;
    Ok(())
}
