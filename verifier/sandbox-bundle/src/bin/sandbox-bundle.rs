//! Manual commands backed by the same bundle library as enclave-provisioner.

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    time::Duration,
};

use flamingo_verifier_sandbox_bundle::{
    MAX_MANIFEST_BYTES,
    host::{self, Bundle},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("manifest") if args.len() == 4 => {
            let bundle = Bundle::prepare(&args[2], Path::new(&args[3])).await?;
            std::io::stdout().write_all(&bundle.manifest()?)?;
        }
        Some("pack") if args.len() == 5 => {
            let mut manifest = Vec::new();
            File::open(&args[2])?
                .take(MAX_MANIFEST_BYTES as u64 + 1)
                .read_to_end(&mut manifest)?;
            let output = Path::new(&args[4]);
            let parent = output
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            flamingo_verifier_sandbox_bundle::package(
                &mut temporary,
                &manifest,
                Path::new(&args[3]),
            )?;
            temporary.as_file().sync_all()?;
            temporary.persist_noclobber(output)?;
        }
        Some("health") if args.len() == 3 => host::health(args[2].parse()?).await?,
        Some("send") if args.len() == 5 => {
            host::send(
                args[2].parse()?,
                Path::new(&args[3]),
                Duration::from_secs(args[4].parse()?),
            )
            .await?;
        }
        _ => {
            return Err(concat!(
                "usage: sandbox-bundle manifest RELEASE_ID EXECUTABLE | ",
                "pack MANIFEST EXECUTABLE OUTPUT | ",
                "send CID BUNDLE IO_TIMEOUT_SECONDS | health CID"
            )
            .into());
        }
    }

    Ok(())
}
