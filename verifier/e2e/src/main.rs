mod capture;
mod trust;

use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use capture::MatchingFrame;
use flamingo_verifier_client::{Config, FlamingoVerifierClient, VerifiedMatchResult};
use flamingo_verifier_sealed_types::{FailureReason, Request};

const DEFAULT_MATCH_STRICTNESS: u8 = 2;

#[tokio::main]
async fn main() -> Result<()> {
    let release = trust::load_release()?;
    let expected = ExpectedOutcome::from_env()?;
    let gray_badge = match env::var("MATCH_OPERATION").as_deref() {
        Err(env::VarError::NotPresent) | Ok("deep_face") => false,
        Ok("gray_badge") => true,
        _ => bail!("MATCH_OPERATION must be deep_face or gray_badge"),
    };
    let image_paths = image_paths(gray_badge)?;
    let credential = image_paths
        .credential
        .as_ref()
        .map(|path| read_image(path, "credential"))
        .transpose()?;
    let live = read_image(&image_paths.live, "live")?;
    let challenge = read_image(&image_paths.challenge, "challenge")?;
    let light_guard = match env::var("LIGHT_GUARD_UNILLUMINATED_IMAGE") {
        Ok(path) => {
            let frame = match env::var("LIGHT_GUARD_MATCHING_FRAME") {
                Ok(value) => MatchingFrame::parse(Some(&value))?,
                Err(env::VarError::NotPresent) => MatchingFrame::parse(None)?,
                Err(error) => return Err(error.into()),
            };
            Some((read_image(&PathBuf::from(path), "unilluminated")?, frame))
        }
        Err(env::VarError::NotPresent) => {
            ensure!(
                env::var_os("LIGHT_GUARD_MATCHING_FRAME").is_none(),
                "LIGHT_GUARD_MATCHING_FRAME requires LIGHT_GUARD_UNILLUMINATED_IMAGE"
            );
            None
        }
        Err(error) => return Err(error.into()),
    };

    let match_strictness = env::var("MATCH_STRICTNESS")
        .map_or(Ok(DEFAULT_MATCH_STRICTNESS), |value| {
            value.parse().context("MATCH_STRICTNESS must be a valid u8")
        })?;

    let release_hash = release.release_hash();
    let payload = capture::payload(
        credential,
        live,
        challenge,
        light_guard,
        match_strictness,
        release_hash,
    );
    release
        .pipeline(payload.pipeline)
        .context("selected release does not define this pipeline")?;
    ensure!(
        release.match_strictness_level(match_strictness).is_some(),
        "selected release does not define this match strictness"
    );
    let config = load_config()?;
    let client = FlamingoVerifierClient::new(config).context("failed to build the client")?;
    let session = client
        .connect()
        .await
        .context("enclave assignment did not verify")?;
    trust::require_offered(&release_hash, session.assignment().release_hashes())?;

    // A test RP: `aud` 0 and a random nonce, since the enclave rejects a repeated one.
    let nonce = rand::random::<u64>().max(1);
    let request = Request::new(0u64.into(), nonce.into(), &payload, None)
        .context("the request is out of bounds")?;

    let result = session
        .request_match(&request)
        .await
        .context("match exchange did not verify")?;
    expected.check(result)
}

/// Loads the client configuration named by `VERIFIER_CONFIG`; see `docs/api.md`.
fn load_config() -> Result<Config> {
    let path = env::var("VERIFIER_CONFIG")
        .context("VERIFIER_CONFIG must name a JSON client configuration file")?;
    let json = fs::read_to_string(&path)
        .with_context(|| format!("failed to read the client config at {path}"))?;

    trust::measured_config(&json)
        .with_context(|| format!("{path} is not a valid measured client config"))
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

#[derive(Debug, PartialEq, Eq)]
enum ExpectedOutcome {
    Pass,
    Reject(FailureReason),
}

impl ExpectedOutcome {
    fn from_env() -> Result<Self> {
        let optional = |name| match env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(anyhow::Error::new(error).context(format!("invalid {name}"))),
        };
        let outcome = optional("EXPECTED_OUTCOME")?;
        let failure = optional("EXPECTED_FAILURE")?;
        Self::parse(outcome.as_deref(), failure.as_deref())
    }

    fn parse(outcome: Option<&str>, failure: Option<&str>) -> Result<Self> {
        match (outcome.unwrap_or("pass"), failure) {
            ("pass", None) => Ok(Self::Pass),
            ("reject", Some(reason)) => {
                let reason: FailureReason = serde_json::from_str(reason)
                    .context("EXPECTED_FAILURE must be a FailureReason JSON value")?;
                ensure!(
                    !matches!(
                        reason,
                        FailureReason::Internal | FailureReason::EngineTimeout
                    ),
                    "infrastructure failures cannot qualify as an expected rejection"
                );
                Ok(Self::Reject(reason))
            }
            _ => bail!(
                "EXPECTED_OUTCOME must be pass, or reject with an exact EXPECTED_FAILURE JSON value"
            ),
        }
    }

    fn check(&self, result: VerifiedMatchResult) -> Result<()> {
        match (self, result) {
            (Self::Pass, VerifiedMatchResult::Success { .. }) => {
                println!(
                    "attested match succeeded; provider release, Flamingo Token and claims verified"
                );
                Ok(())
            }
            (Self::Reject(expected), VerifiedMatchResult::Failed { reason, .. })
                if *expected == reason =>
            {
                println!(
                    "expected sealed rejection verified: {}",
                    serde_json::to_string(&reason)?
                );
                Ok(())
            }
            (_, VerifiedMatchResult::Failed { reason, .. }) => bail!(
                "unexpected sealed rejection: {}",
                serde_json::to_string(&reason)?
            ),
            (Self::Reject(_), VerifiedMatchResult::Success { .. }) => {
                bail!("expected a sealed rejection, but received a successful match")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flamingo_verifier_sealed_types::DebugReport;

    #[test]
    fn rejection_requires_exact_reason_and_never_accepts_infrastructure_failure() {
        assert!(ExpectedOutcome::parse(Some("reject"), None).is_err());
        assert!(ExpectedOutcome::parse(Some("reject"), Some("\"internal\"")).is_err());
        assert!(ExpectedOutcome::parse(Some("reject"), Some("\"engine_timeout\"")).is_err());
        assert!(ExpectedOutcome::parse(Some("pass"), Some("\"malformed_inputs\"")).is_err());
        let expected =
            ExpectedOutcome::parse(Some("reject"), Some("\"malformed_inputs\"")).unwrap();
        let failure = |reason| VerifiedMatchResult::Failed {
            reason,
            debug_report: DebugReport::NotProduced,
        };
        assert!(
            expected
                .check(failure(FailureReason::MalformedInputs))
                .is_ok()
        );
        assert!(expected.check(failure(FailureReason::Internal)).is_err());
        assert!(
            expected
                .check(failure(FailureReason::EngineTimeout))
                .is_err()
        );
        assert!(
            expected
                .check(failure(FailureReason::UnsupportedRelease))
                .is_err()
        );
        assert!(
            ExpectedOutcome::Pass
                .check(failure(FailureReason::MalformedInputs))
                .is_err()
        );
    }
}
