use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use flamingo_verifier_client::{
    Config, FlamingoVerifierClient, VerifiedAssignment, VerifiedMatch, VerifiedMatchResult,
};
use flamingo_verifier_enclave_types::MatchRequest;
use flamingo_verifier_protocol::match_token::{self, EdDSAPublicKey};
use flamingo_verifier_sealed_types::{
    DeepFaceInputs, GrayBadgeInputs, LiveCapture, MatchInputs, MatchResult,
};
use pontifex::client::ConnectionDetails;
use sha2::{Digest, Sha256};

const DEFAULT_ENCLAVE_PORT: u32 = 1000;
const DEFAULT_MATCH_THRESHOLD: f64 = 0.9;

#[tokio::main]
async fn main() -> Result<()> {
    let gray_badge = match env::var("MATCH_OPERATION").as_deref() {
        Err(env::VarError::NotPresent) | Ok("deep_face") => false,
        Ok("gray_badge") => true,
        _ => bail!("MATCH_OPERATION must be deep_face or gray_badge"),
    };
    let image_paths = image_paths(gray_badge)?;
    let credential_image = image_paths
        .credential
        .as_ref()
        .map(|path| read_image(path, "credential"))
        .transpose()?;
    let live_image = read_image(&image_paths.live, "live")?;
    let challenge_image = read_image(&image_paths.challenge, "challenge")?;

    let match_threshold = optional_f64("MATCH_THRESHOLD", DEFAULT_MATCH_THRESHOLD)?;

    let config = load_config()?;
    let verifier = config.verifier()?;

    let client = FlamingoVerifierClient::new(config).context("failed to build the client")?;
    let assignment = client
        .request_assignment()
        .await
        .context("enclave assignment did not verify")?;

    let inputs = if let Some(credential_image) = credential_image {
        let hashes_json = hashes_json_for(&credential_image);
        MatchInputs::DeepFace(DeepFaceInputs {
            live: LiveCapture::Vanilla(live_image.into()),
            orb_credential: credential_image.into(),
            hashes_json: hashes_json.into(),
            rtms_challenge: challenge_image.into(),
            match_threshold,
        })
    } else {
        MatchInputs::GrayBadge(GrayBadgeInputs {
            live: LiveCapture::Vanilla(live_image.into()),
            rtms_challenge: challenge_image.into(),
            match_threshold,
        })
    };
    let result = match env::var("VERIFIER_E2E_TRANSPORT").as_deref() {
        Err(env::VarError::NotPresent) | Ok("http") => {
            client.request_match(&assignment, &inputs).await?
        }
        Ok("vsock") => request_match_vsock(&assignment, &inputs, &verifier).await?,
        _ => bail!("VERIFIER_E2E_TRANSPORT must be http or vsock"),
    };

    let verified = match result {
        VerifiedMatchResult::Success(verified) => verified,
        VerifiedMatchResult::Failed(reason) => bail!("no statement was issued: {reason:?}"),
    };
    ensure!(
        inputs.matches_claims(&verified.claims),
        "statement did not bind the supplied inputs and threshold"
    );
    verified
        .claims
        .validate()
        .map_err(|error| anyhow!("invalid signed scores: {error:?}"))?;
    println!("attested match succeeded; input binding and all required comparisons verified");
    Ok(())
}

/// Exercises the internal host-to-enclave transport with the same verified assignment.
async fn request_match_vsock(
    assignment: &VerifiedAssignment,
    inputs: &MatchInputs,
    verifier: &pontifex::attestation::Verifier,
) -> Result<VerifiedMatchResult> {
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

    let response = pontifex::client::send(
        connection,
        &MatchRequest {
            body: sealed.into(),
        },
    )
    .await
    .context("failed to call the enclave matches route")?
    .map_err(|error| anyhow!("enclave rejected the match request: {error:?}"))?;

    let sealed_outcome = opener
        .open_from_enclave(&response.ciphertext)
        .map_err(|error| anyhow!("failed to open the sealed response: {error:?}"))?;
    let result = MatchResult::from_padded_cbor(&sealed_outcome)
        .map_err(|error| anyhow!("failed to decode the sealed result: {error:?}"))?;
    match result {
        MatchResult::Failed(reason) => Ok(VerifiedMatchResult::Failed(reason)),
        MatchResult::Success(statement) => {
            let document = verifier
                .verify_attestation_document(&statement.signing_key_attestation)?
                .into_document();
            let key: [u8; 32] = document
                .public_key
                .context("missing signing key")?
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("invalid signing key size"))?;
            let key = EdDSAPublicKey::from_compressed_bytes(key)
                .map_err(|_| anyhow!("invalid signing key"))?;
            let claims = match_token::verify(&statement.token, &key)
                .map_err(|e| anyhow!("invalid statement: {e:?}"))?;
            Ok(VerifiedMatchResult::Success(Box::new(VerifiedMatch {
                statement,
                claims,
            })))
        }
    }
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
    credential: Option<PathBuf>,
    live: PathBuf,
    challenge: PathBuf,
}

fn image_paths(gray_badge: bool) -> Result<ImagePaths> {
    let mut args = env::args_os().skip(1);
    let usage = if gray_badge {
        "usage: MATCH_OPERATION=gray_badge e2e <live-image> <challenge-image>"
    } else {
        "usage: e2e <credential-image> <live-image> <challenge-image>"
    };
    let credential = if gray_badge {
        None
    } else {
        Some(args.next().map(PathBuf::from).context(usage)?)
    };
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

fn optional_f64(name: &str, default: f64) -> Result<f64> {
    env::var(name).map_or(Ok(default), |value| {
        value
            .parse()
            .with_context(|| format!("{name} must be a valid f64"))
    })
}
