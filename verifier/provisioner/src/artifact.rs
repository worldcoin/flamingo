use crate::{config::Config, process};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::AsyncReadExt;

pub async fn fetch(config: &Config, directory: &Path) -> Result<PathBuf> {
    let archive = directory.join("artifact.tar.gz");
    download(config, &archive).await?;
    verify(&archive, &config.artifact_sha256).await?;

    let executable = directory.join("executable");
    extract(&archive, &executable, &config.executable_name).await?;
    inspect(&executable).await?;

    Ok(executable)
}

async fn download(config: &Config, archive: &Path) -> Result<()> {
    process::output(
        "aws",
        &[
            "s3".as_ref(),
            "cp".as_ref(),
            config.artifact_uri.as_ref(),
            archive.as_os_str(),
            "--only-show-errors".as_ref(),
            "--no-progress".as_ref(),
        ],
        config.bootstrap_timeout,
    )
    .await
    .context("S3 download failed")?;

    Ok(())
}

async fn verify(archive: &Path, expected_sha256: &str) -> Result<String> {
    let mut file = tokio::fs::File::open(archive).await?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }

        hash.update(&buffer[..n]);
    }

    let digest = hex::encode(hash.finalize());
    ensure!(
        digest.eq_ignore_ascii_case(expected_sha256),
        "archive checksum mismatch"
    );

    Ok(digest)
}

async fn extract(archive: &Path, executable: &Path, name: &str) -> Result<()> {
    let listing = process::output(
        "tar",
        &["-tzf".as_ref(), archive.as_os_str()],
        Duration::from_secs(30),
    )
    .await?;
    let member = bundle_member(std::str::from_utf8(&listing)?, name)?;

    let types = process::output(
        "tar",
        &["-tvzf".as_ref(), archive.as_os_str()],
        Duration::from_secs(30),
    )
    .await?;
    ensure!(
        std::str::from_utf8(&types)?
            .lines()
            .all(|line| line.starts_with(['-', 'd'])),
        "archive contains links or special files"
    );

    process::to_file(
        "tar",
        &[
            "-xOzf".as_ref(),
            archive.as_os_str(),
            "--".as_ref(),
            member.as_ref(),
        ],
        Duration::from_secs(60),
        executable,
    )
    .await
}

async fn inspect(executable: &Path) -> Result<()> {
    let header = readelf("-h", executable).await?;
    ensure!(
        header.contains("Advanced Micro Devices X86-64"),
        "bundle executable must be an x86_64 ELF"
    );
    ensure!(
        !readelf("-l", executable).await?.contains("INTERP")
            && !readelf("-d", executable).await?.contains("(NEEDED)"),
        "bundle executable needs an external loader or shared library"
    );

    Ok(())
}

async fn readelf(option: &str, executable: &Path) -> Result<String> {
    Ok(String::from_utf8(
        process::output(
            "readelf",
            &[OsStr::new(option), executable.as_os_str()],
            Duration::from_secs(10),
        )
        .await?,
    )?)
}

fn bundle_member(listing: &str, name: &str) -> Result<String> {
    let mut root = None;
    let mut executable = None;

    for entry in listing.lines() {
        let (directory, filename) = entry
            .split_once('/')
            .context("archive member lacks root directory")?;
        ensure!(
            !directory.is_empty()
                && directory != "."
                && directory != ".."
                && directory
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)),
            "invalid archive directory"
        );
        ensure!(
            root.is_none_or(|value| value == directory),
            "multiple archive roots"
        );
        root = Some(directory);

        if filename == name {
            ensure!(executable.is_none(), "duplicate bundle executable");
            executable = Some(entry.to_owned());
        } else {
            ensure!(filename.is_empty(), "unexpected archive member");
        }
    }

    executable.context("archive has no bundle executable")
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKER: &str = "biometric-engines-worker";

    #[tokio::test]
    async fn verifies_downloaded_bytes_against_the_configured_checksum() {
        let file = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(file.path(), b"abc").await.unwrap();
        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(verify(file.path(), digest).await.unwrap(), digest);
        assert_eq!(
            verify(file.path(), &digest.to_uppercase()).await.unwrap(),
            digest
        );
        for invalid in ["", "placeholder", &"0".repeat(64)] {
            assert!(verify(file.path(), invalid).await.is_err());
        }
        tokio::fs::write(file.path(), b"changed").await.unwrap();
        assert!(verify(file.path(), digest).await.is_err());
    }

    #[test]
    fn accepts_only_one_executable_under_one_directory() {
        assert_eq!(
            bundle_member("release/\nrelease/biometric-engines-worker\n", WORKER).unwrap(),
            "release/biometric-engines-worker"
        );
        assert_eq!(
            bundle_member("release/biometric-engines-worker\n", WORKER).unwrap(),
            "release/biometric-engines-worker"
        );
        for listing in [
            "../biometric-engines-worker",
            "/biometric-engines-worker",
            "a/\nb/biometric-engines-worker",
            "a/biometric-engines-worker\na/biometric-engines-worker",
            "a/biometric-engines-worker\na/lib.so",
            "a/",
        ] {
            assert!(bundle_member(listing, WORKER).is_err(), "{listing}");
        }
    }
}
