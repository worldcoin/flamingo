use crate::{config::Config, process};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::AsyncReadExt;

pub async fn download_and_verify(config: &Config, directory: &Path) -> Result<PathBuf> {
    let archive = directory.join("worker.tar.gz");
    process::output(
        "aws",
        &[
            "s3".as_ref(),
            "cp".as_ref(),
            config.artifact_uri.as_ref(),
            archive.as_os_str(),
            "--region".as_ref(),
            "eu-central-1".as_ref(),
            "--only-show-errors".as_ref(),
            "--no-progress".as_ref(),
        ],
        config.bootstrap_timeout,
    )
    .await
    .context("S3 download failed")?;
    let mut file = tokio::fs::File::open(&archive).await?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    ensure!(
        hex::encode(hash.finalize()) == config.artifact_sha256,
        "archive checksum mismatch"
    );

    let listing = process::output(
        "tar",
        &["-tzf".as_ref(), archive.as_os_str()],
        Duration::from_secs(30),
    )
    .await?;
    let member = worker_member(std::str::from_utf8(&listing)?)?;
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
    let worker = directory.join("worker");
    process::to_file(
        "tar",
        &[
            "-xOzf".as_ref(),
            archive.as_os_str(),
            "--".as_ref(),
            member.as_ref(),
        ],
        Duration::from_secs(60),
        &worker,
    )
    .await?;
    let header = readelf("-h", &worker).await?;
    ensure!(
        header.contains("Advanced Micro Devices X86-64"),
        "worker must be an x86_64 ELF"
    );
    ensure!(
        !readelf("-l", &worker).await?.contains("INTERP")
            && !readelf("-d", &worker).await?.contains("(NEEDED)"),
        "worker needs an external loader or shared library"
    );

    let manifest = directory.join("manifest.json");
    process::to_file(
        &config.tool,
        &[
            "manifest".as_ref(),
            config.release_id.as_ref(),
            worker.as_os_str(),
        ],
        Duration::from_secs(30),
        &manifest,
    )
    .await?;
    let bundle = directory.join("worker.bundle");
    process::output(
        &config.tool,
        &[
            "pack".as_ref(),
            manifest.as_os_str(),
            worker.as_os_str(),
            bundle.as_os_str(),
        ],
        Duration::from_secs(60),
    )
    .await?;
    Ok(bundle)
}

async fn readelf(option: &str, worker: &Path) -> Result<String> {
    Ok(String::from_utf8(
        process::output(
            "readelf",
            &[OsStr::new(option), worker.as_os_str()],
            Duration::from_secs(10),
        )
        .await?,
    )?)
}

fn worker_member(listing: &str) -> Result<String> {
    let mut root = None;
    let mut worker = None;
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
        if filename == "biometric-engines-worker" {
            ensure!(worker.is_none(), "duplicate worker executable");
            worker = Some(entry.to_owned());
        } else {
            ensure!(filename.is_empty(), "unexpected archive member");
        }
    }
    worker.context("archive has no worker executable")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_one_worker_under_one_directory() {
        assert_eq!(
            worker_member("release/\nrelease/biometric-engines-worker\n").unwrap(),
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
            assert!(worker_member(listing).is_err(), "{listing}");
        }
    }
}
