use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use flamingo_verifier_client::{
    Config, FlamingoVerifierClient, RequestContext, VerifiedMatchResult,
};
use flamingo_verifier_sealed_types::{ByteBuf, Entry, Payload};

/// The enclave's interim pipelines; see `verifier/enclave/src/pipeline.rs`.
const PIPELINE_DEEPFACE: u16 = 1;
const PIPELINE_GRAYBADGE: u16 = 2;
const DEFAULT_MATCH_STRICTNESS: u8 = 2;

#[tokio::main]
async fn main() -> Result<()> {
    let gray_badge = match env::var("MATCH_OPERATION").as_deref() {
        Err(env::VarError::NotPresent) | Ok("deep_face") => false,
        Ok("gray_badge") => true,
        _ => bail!("MATCH_OPERATION must be deep_face or gray_badge"),
    };
    let image_paths = image_paths(gray_badge)?;
    let entry = |data: Vec<u8>, meta: &[u8]| Entry {
        data: data.into(),
        meta: meta.to_vec().into(),
    };

    // Compared entries in role order, then the uncompared LightGuard partner frame, if any.
    let mut entries = Vec::new();
    if let Some(path) = &image_paths.credential {
        entries.push(entry(read_image(path, "credential")?, b""));
    }
    let live = read_image(&image_paths.live, "live")?;
    let partner = match env::var("LIGHT_GUARD_UNILLUMINATED_IMAGE") {
        Ok(path) => {
            let unilluminated = read_image(&PathBuf::from(path), "unilluminated")?;
            match env::var("LIGHT_GUARD_MATCHING_FRAME").as_deref() {
                Err(env::VarError::NotPresent) | Ok("illuminated") => {
                    entries.push(entry(live, b"illuminated"));
                    Some(entry(unilluminated, b"unilluminated"))
                }
                Ok("unilluminated") => {
                    entries.push(entry(unilluminated, b"unilluminated"));
                    Some(entry(live, b"illuminated"))
                }
                _ => bail!("LIGHT_GUARD_MATCHING_FRAME must be illuminated or unilluminated"),
            }
        }
        Err(env::VarError::NotPresent) => {
            ensure!(
                env::var_os("LIGHT_GUARD_MATCHING_FRAME").is_none(),
                "LIGHT_GUARD_MATCHING_FRAME requires LIGHT_GUARD_UNILLUMINATED_IMAGE"
            );
            entries.push(entry(live, b""));
            None
        }
        Err(error) => return Err(error.into()),
    };
    entries.push(entry(read_image(&image_paths.challenge, "challenge")?, b""));
    let compare = (0..u8::try_from(entries.len())?).collect();
    entries.extend(partner);

    let match_strictness = env::var("MATCH_STRICTNESS")
        .map_or(Ok(DEFAULT_MATCH_STRICTNESS), |value| {
            value.parse().context("MATCH_STRICTNESS must be a valid u8")
        })?;

    let config = load_config()?;
    let client = FlamingoVerifierClient::new(config).context("failed to build the client")?;
    let session = client
        .connect()
        .await
        .context("enclave assignment did not verify")?;
    let engine_hash = *session
        .assignment()
        .engine_hashes()
        .first()
        .context("the host serves no loaded Engine")?;

    let payload = Payload {
        hints: ByteBuf::new(),
        compare,
        entries,
        pipeline: if gray_badge {
            PIPELINE_GRAYBADGE
        } else {
            PIPELINE_DEEPFACE
        },
        engine_hash: engine_hash.into(),
        match_strictness,
    };
    // A fixed test binding; a real RP issues a fresh nonce per request.
    let mut nonce = [0; 32];
    nonce[31] = 1;
    let context = RequestContext {
        aud: [0; 32],
        nonce,
        aat_inputs: None,
    };

    let result = session
        .request_match(&payload, &context)
        .await
        .context("match exchange did not verify")?;
    match result {
        VerifiedMatchResult::Success { .. } => {
            println!("attested match succeeded; Flamingo Token and its claims verified");
        }
        VerifiedMatchResult::Failed { reason, .. } => bail!("no statement was issued: {reason:?}"),
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
