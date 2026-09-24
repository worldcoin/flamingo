use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use flamingo_verifier_client::{Config, FlamingoVerifierClient, VerifiedMatchResult};
use flamingo_verifier_sealed_types::{
    DeepFaceInputs, GrayBadgeInputs, LightGuardMatchingFrame, LiveCapture, MatchInputs,
};
use sha2::{Digest, Sha256};

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
    let live = match env::var("LIGHT_GUARD_UNILLUMINATED_IMAGE") {
        Ok(path) => {
            let matching_frame = match env::var("LIGHT_GUARD_MATCHING_FRAME").as_deref() {
                Err(env::VarError::NotPresent) | Ok("illuminated") => {
                    LightGuardMatchingFrame::Illuminated
                }

                Ok("unilluminated") => LightGuardMatchingFrame::Unilluminated,
                _ => bail!("LIGHT_GUARD_MATCHING_FRAME must be illuminated or unilluminated"),
            };
            LiveCapture::LightGuard {
                illuminated: read_image(&image_paths.live, "illuminated")?.into(),
                unilluminated: read_image(&PathBuf::from(path), "unilluminated")?.into(),
                matching_frame,
            }
        }
        Err(env::VarError::NotPresent) => {
            ensure!(
                env::var_os("LIGHT_GUARD_MATCHING_FRAME").is_none(),
                "LIGHT_GUARD_MATCHING_FRAME requires LIGHT_GUARD_UNILLUMINATED_IMAGE"
            );
            LiveCapture::Vanilla(read_image(&image_paths.live, "live")?.into())
        }
        Err(error) => return Err(error.into()),
    };
    let challenge_image = read_image(&image_paths.challenge, "challenge")?;

    let match_threshold = optional_f64("MATCH_THRESHOLD", DEFAULT_MATCH_THRESHOLD)?;

    let config = load_config()?;
    let client = FlamingoVerifierClient::new(config).context("failed to build the client")?;
    let session = client
        .connect_v2()
        .await
        .context("enclave assignment did not verify")?;

    let inputs = if let Some(credential_image) = credential_image {
        let hashes_json = hashes_json_for(&credential_image);
        MatchInputs::DeepFace(DeepFaceInputs {
            live,
            orb_credential: credential_image.into(),
            hashes_json: hashes_json.into(),
            rtms_challenge: challenge_image.into(),
            match_threshold,
        })
    } else {
        MatchInputs::GrayBadge(GrayBadgeInputs {
            live,
            rtms_challenge: challenge_image.into(),
            match_threshold,
        })
    };

    let result = session
        .request_match(&inputs)
        .await
        .context("match exchange did not verify")?;
    match result {
        VerifiedMatchResult::Success(_) => {
            println!("attested match succeeded; operation, capture commitments and score verified");
        }
        VerifiedMatchResult::Failed(reason) => bail!("no statement was issued: {reason:?}"),
    }
    Ok(())
}

/// Loads the client configuration named by `VERIFIER_CONFIG`; see `docs/api.md`.
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

fn optional_f64(name: &str, default: f64) -> Result<f64> {
    env::var(name).map_or(Ok(default), |value| {
        value
            .parse()
            .with_context(|| format!("{name} must be a valid f64"))
    })
}
