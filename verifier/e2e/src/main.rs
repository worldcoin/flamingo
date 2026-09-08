use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use flamingo_verifier_client::{Config, FlamingoVerifierClient, VerifiedAssignment};
use flamingo_verifier_enclave_types::MatchRequest;
use flamingo_verifier_protocol::match_token::{self, EdDSAPublicKey};
use flamingo_verifier_sealed_types::{MatchInputs, MatchResult};
use pontifex::client::ConnectionDetails;
use sha2::{Digest, Sha256};

const DEFAULT_ENCLAVE_PORT: u32 = 1000;
const DEFAULT_MATCH_THRESHOLD: f32 = 0.9;

#[tokio::main]
async fn main() -> Result<()> {
    let image_paths = image_paths()?;
    let credential_image = read_image(&image_paths.credential, "credential")?;
    let live_image = read_image(&image_paths.live, "live")?;
    let challenge_image = read_image(&image_paths.challenge, "challenge")?;

    let match_threshold = optional_f32("MATCH_THRESHOLD", DEFAULT_MATCH_THRESHOLD)?;

    let config = load_config()?;
    let verifier = config.verifier()?;

    let client = FlamingoVerifierClient::new(config).context("failed to build the client")?;
    let assignment = client
        .request_assignment()
        .await
        .context("enclave assignment did not verify")?;

    let hashes_json = hashes_json_for(&credential_image);
    let inputs = MatchInputs {
        live_image: live_image.clone(),
        credential_image: credential_image.clone(),
        // Vanilla mode. The harness asserts on a signed statement, and the LightGuard flow cannot
        // produce one yet — sending a second frame would only reach the enclave's `unimplemented!`.
        light_guard_image: None,
        hashes_json: hashes_json.clone(),
        // Stands in for the phone, which downloads this frame from the RP and seals it.
        challenge_image: challenge_image.clone(),
        match_threshold,
    };
    let result = match env::var("VERIFIER_E2E_TRANSPORT").as_deref() {
        Err(env::VarError::NotPresent) | Ok("http") => {
            client.request_match(&assignment, &inputs).await?
        }
        Ok("vsock") => request_match_vsock(&assignment, &inputs).await?,
        _ => bail!("VERIFIER_E2E_TRANSPORT must be http or vsock"),
    };

    // The sealed result is the only account of what happened; the host reported nothing but success.
    let attested = match result {
        MatchResult::Success(attested) => attested,
        MatchResult::Failed(reason) => bail!("no statement was issued: {reason:?}"),
    };

    // The whole chain: pinned measurements, then the key the document attests, then its signature.
    let signing_key = verifier
        .verify_attestation_document(&attested.signing_key_attestation)
        .context("the signing-key attestation document did not verify")?
        .into_document()
        .public_key
        .context("attestation omitted the signing key")?;
    let signing_key = <[u8; 32]>::try_from(signing_key.as_slice())
        .map_err(|_| anyhow!("attested signing public key was not 32 bytes"))?;
    let signing_key = EdDSAPublicKey::from_compressed_bytes(signing_key)
        .map_err(|error| anyhow!("attested signing public key did not decode: {error:?}"))?;

    let statement = match_token::verify(&attested.token, &signing_key)
        .map_err(|error| anyhow!("the match statement did not verify: {error:?}"))?;
    let live_image_hash: [u8; 32] = Sha256::digest(&live_image).into();
    let challenge_image_hash: [u8; 32] = Sha256::digest(&challenge_image).into();
    let hashes_json_hash: [u8; 32] = Sha256::digest(&hashes_json).into();
    ensure!(
        statement.match_coefficient >= match_threshold,
        "credential/live score {} did not meet threshold {}",
        statement.match_coefficient,
        match_threshold
    );
    ensure!(
        statement.live_image_hash == live_image_hash,
        "statement did not commit to the live image"
    );
    ensure!(
        statement.challenger_image_hash == challenge_image_hash,
        "statement did not commit to the challenge image"
    );
    ensure!(
        statement.credential_claim == hashes_json_hash,
        "statement did not commit to hashes.json"
    );

    println!(
        "match succeeded: credential/live similarity={:.6}, threshold={:.6}",
        statement.match_coefficient, match_threshold
    );
    Ok(())
}

/// Exercises the internal host-to-enclave transport with the same verified assignment.
async fn request_match_vsock(
    assignment: &VerifiedAssignment,
    inputs: &MatchInputs,
) -> Result<MatchResult> {
    let connection = ConnectionDetails::new(
        required_u32("ENCLAVE_CID")?,
        optional_u32("ENCLAVE_PORT", DEFAULT_ENCLAVE_PORT)?,
    );
    let plaintext = inputs
        .to_cbor()
        .map_err(|error| anyhow!("failed to encode the match inputs: {error:?}"))?;
    let (sealed, opener) = assignment
        .consumer()
        .seal_to_enclave(&plaintext)
        .map_err(|error| anyhow!("failed to seal the match request: {error:?}"))?;

    let response = pontifex::client::send(connection, &MatchRequest { body: sealed })
        .await
        .context("failed to call the enclave matches route")?
        .map_err(|error| anyhow!("enclave rejected the match request: {error:?}"))?;

    let sealed_outcome = opener
        .open_from_enclave(&response.ciphertext)
        .map_err(|error| anyhow!("failed to open the sealed response: {error:?}"))?;
    MatchResult::from_padded_cbor(&sealed_outcome)
        .map_err(|error| anyhow!("failed to decode the sealed result: {error:?}"))
}

/// Loads the client configuration named by `VERIFIER_CONFIG`. Schema is in the README.
fn load_config() -> Result<Config> {
    let path = env::var("VERIFIER_CONFIG")
        .context("VERIFIER_CONFIG must name a JSON client configuration file")?;
    let json = fs::read_to_string(&path)
        .with_context(|| format!("failed to read the client config at {path}"))?;

    Config::from_json(&json).with_context(|| format!("{path} is not a valid client config"))
}

struct ImagePaths {
    credential: PathBuf,
    live: PathBuf,
    challenge: PathBuf,
}

fn image_paths() -> Result<ImagePaths> {
    let mut args = env::args_os().skip(1);
    let usage = "usage: e2e <credential-image> <live-image> <challenge-image>";
    let credential = args.next().map(PathBuf::from).context(usage)?;
    let live = args.next().map(PathBuf::from).context(usage)?;
    let challenge = args.next().map(PathBuf::from).context(usage)?;
    ensure!(args.next().is_none(), "{usage}");

    Ok(ImagePaths {
        credential,
        live,
        challenge,
    })
}

fn read_image(path: &PathBuf, label: &str) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("failed to read {label} image at {}", path.display()))
}

fn hashes_json_for(image: &[u8]) -> Vec<u8> {
    let hash = hex::encode(Sha256::digest(image));
    format!(r#"{{"thumbnail.png":"{hash}"}}"#).into_bytes()
}

fn required_u32(name: &str) -> Result<u32> {
    env::var(name)
        .with_context(|| format!("{name} must be set"))
        .and_then(|value| {
            value
                .parse()
                .with_context(|| format!("{name} must be a valid u32"))
        })
}

fn optional_u32(name: &str, default: u32) -> Result<u32> {
    env::var(name).map_or(Ok(default), |value| {
        value
            .parse()
            .with_context(|| format!("{name} must be a valid u32"))
    })
}

fn optional_f32(name: &str, default: f32) -> Result<f32> {
    env::var(name).map_or(Ok(default), |value| {
        value
            .parse()
            .with_context(|| format!("{name} must be a valid f32"))
    })
}
