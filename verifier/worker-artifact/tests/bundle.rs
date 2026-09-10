//! Signed byte fixtures only; these are not runnable workers or model substitutes.

use std::{fs, io::Cursor, os::unix::fs::PermissionsExt};

use flamingo_verifier_worker_artifact::{
    Artifact, Error, MAX_BUNDLE_BYTES, Manifest, Role, WORKER_PATH, package, receive,
};
use p384::ecdsa::{Signature, SigningKey, signature::Signer};
use sha2::{Digest, Sha384};

/// Small signed inventory for verification tests, never executed.
struct Fixture {
    /// Mutated and re-signed by structural validation tests.
    manifest: Manifest,
    /// Bytes in manifest order.
    files: Vec<Vec<u8>>,
    /// Test-only publisher, never included in measured image configuration.
    key: SigningKey,
}

impl Fixture {
    /// Builds a minimal architecture header and one library data file.
    fn new() -> Self {
        let mut elf = vec![0; 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16] = 2;
        elf[18] = 62;
        let files = vec![elf, b"library-fixture".to_vec()];
        let artifacts = [WORKER_PATH, "lib/fixture.so"]
            .iter()
            .enumerate()
            .map(|(index, path)| Artifact {
                logical_path: (*path).to_owned(),
                role: if index == 0 {
                    Role::Worker
                } else {
                    Role::Library
                },
                sha384: hex::encode(Sha384::digest(&files[index])),
                size: files[index].len() as u64,
            })
            .collect();
        Self {
            manifest: Manifest {
                manifest_version: 1,
                release_id: "test-release".into(),
                artifacts,
            },
            files,
            key: SigningKey::from_slice(&[1; 48]).unwrap(),
        }
    }

    /// Signs exact JSON and appends raw file bytes without archive metadata.
    fn bundle(&self) -> Vec<u8> {
        let manifest = serde_json::to_vec(&self.manifest).unwrap();
        let signature: Signature = self.key.sign(&manifest);
        let signature = signature.to_der();
        let mut bytes = Vec::new();
        for field in [manifest.as_slice(), signature.as_bytes()] {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        for file in &self.files {
            bytes.extend_from_slice(file);
        }
        bytes
    }
}

/// Release tooling rejects exactly the policy encodings that measured startup rejects.
#[test]
fn config_cli_uses_the_startup_validator() {
    let key = Fixture::new().key;
    let config = serde_json::json!({
        "publisher_keys": [hex::encode(key.verifying_key().to_encoded_point(true).as_bytes())],
        "max_bundle_bytes": 1024,
        "address_space_bytes": 1024,
        "max_threads": 1,
        "bootstrap_timeout_seconds": 1
    });
    let valid = serde_json::to_string(&config).unwrap();
    let mut invalid_key = config.clone();
    invalid_key["publisher_keys"] = serde_json::json!([format!("02{}", "ff".repeat(48))]);
    let mut unknown = config;
    unknown["disable_sandbox"] = true.into();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");

    for (bytes, expected) in [
        (valid.clone(), true),
        (invalid_key.to_string(), false),
        (unknown.to_string(), false),
        (valid.replace("1024", "1.024e3"), false),
        (" ".repeat(64 * 1024 + 1), false),
    ] {
        fs::write(&path, bytes).unwrap();
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_worker-bundle"))
            .arg("validate-config")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(result.status.success(), expected);
        assert!(result.stdout.is_empty());
    }
}

/// Only verified regular files and a read-only worker descriptor survive a successful transfer.
#[test]
fn exact_signed_release_round_trips() {
    let fixture = Fixture::new();
    let parent = tempfile::tempdir().unwrap();
    let runtime = receive(
        &mut Cursor::new(fixture.bundle()),
        &[*fixture.key.verifying_key()],
        1024,
        parent.path(),
    )
    .unwrap();
    assert_eq!(runtime.release_id, "test-release");
    for (artifact, expected) in fixture.manifest.artifacts.iter().zip(&fixture.files) {
        let path = runtime.root.path().join(&artifact.logical_path);
        assert_eq!(fs::read(&path).unwrap(), *expected);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o555
        );
    }
    let mut read_only = &runtime.binary;
    assert!(std::io::Write::write_all(&mut read_only, b"overwrite").is_err());
    drop(runtime);
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

/// Signature verification precedes creating runtime files or trusting manifest metadata.
#[test]
fn untrusted_publishers_and_changed_metadata_are_rejected() {
    let fixture = Fixture::new();
    let other = SigningKey::from_slice(&[2; 48]).unwrap();
    let parent = tempfile::tempdir().unwrap();
    assert!(matches!(
        receive(
            &mut Cursor::new(fixture.bundle()),
            &[*other.verifying_key()],
            1024,
            parent.path()
        ),
        Err(Error::InvalidSignature)
    ));
    let mut changed = fixture.bundle();
    let position = changed
        .windows(12)
        .position(|bytes| bytes == b"test-release")
        .unwrap();
    changed[position] = b'b';
    assert!(matches!(
        receive(
            &mut Cursor::new(changed),
            &[*fixture.key.verifying_key()],
            1024,
            parent.path()
        ),
        Err(Error::InvalidSignature)
    ));
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    assert!(
        receive(
            &mut Cursor::new(fixture.bundle()),
            &[*other.verifying_key(), *fixture.key.verifying_key()],
            1024,
            parent.path()
        )
        .is_ok()
    );
}

/// Path traversal, alternate entry points, duplicate files and file/directory collisions fail closed.
#[test]
fn unsafe_signed_inventories_are_rejected() {
    let mut fixture = Fixture::new();
    for path in [
        "../escape",
        "/lib/escape",
        "lib//escape",
        "lib/../escape",
        "lib/./escape",
        "models/model.onnx",
        "lib/a\\b",
        "lib/a\0b",
    ] {
        fixture.manifest.artifacts[1].logical_path = path.into();
        assert!(fixture.manifest.validate(1024).is_err(), "{path:?}");
    }
    fixture.manifest.artifacts[1].logical_path = WORKER_PATH.into();
    assert!(fixture.manifest.validate(1024).is_err());
    fixture.manifest.artifacts[1].logical_path = "lib/file".into();
    let mut child = fixture.manifest.artifacts[1].clone();
    child.logical_path = "lib/file/nested".into();
    fixture.manifest.artifacts.push(child);
    assert!(fixture.manifest.validate(1024).is_err());
    fixture.manifest.artifacts.reverse();
    assert!(fixture.manifest.validate(1024).is_err());
}

/// Missing configuration, aggregate exhaustion and integer overflow never allocate artifact bodies.
#[test]
fn format_and_resource_limits_are_checked_before_copying() {
    let mut fixture = Fixture::new();
    assert!(fixture.manifest.validate(0).is_err());
    assert!(fixture.manifest.validate(MAX_BUNDLE_BYTES + 1).is_err());
    assert!(fixture.manifest.validate(64).is_err());
    fixture.manifest.artifacts[0].size = u64::MAX;
    assert!(fixture.manifest.validate(MAX_BUNDLE_BYTES).is_err());
    let parent = tempfile::tempdir().unwrap();
    for header in [0_u32, u32::MAX, 65537] {
        assert!(matches!(
            receive(
                &mut Cursor::new(header.to_be_bytes()),
                &[*fixture.key.verifying_key()],
                1024,
                parent.path()
            ),
            Err(Error::InvalidManifest)
        ));
    }
    assert!(matches!(
        receive(&mut Cursor::new([]), &[], 1024, parent.path()),
        Err(Error::InvalidConfig)
    ));
}

/// Interrupted transfers, corrupted bodies and trailing data leave no partially trusted runtime.
#[test]
fn incomplete_or_tampered_bundles_are_cleaned_up() {
    let fixture = Fixture::new();
    let bundle = fixture.bundle();
    let parent = tempfile::tempdir().unwrap();
    for length in [0, 3, 4, 25, bundle.len() - 25, bundle.len() - 1] {
        assert!(
            receive(
                &mut Cursor::new(&bundle[..length]),
                &[*fixture.key.verifying_key()],
                1024,
                parent.path()
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
    let mut corrupt = bundle.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(matches!(
        receive(
            &mut Cursor::new(corrupt),
            &[*fixture.key.verifying_key()],
            1024,
            parent.path()
        ),
        Err(Error::DigestMismatch)
    ));
    let mut trailing = bundle;
    trailing.push(0);
    assert!(matches!(
        receive(
            &mut Cursor::new(trailing),
            &[*fixture.key.verifying_key()],
            1024,
            parent.path()
        ),
        Err(Error::TrailingData)
    ));
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

/// Valid signatures do not authorize a different executable architecture or an unknown role.
#[test]
fn wrong_architecture_and_unknown_fields_are_rejected() {
    let mut fixture = Fixture::new();
    fixture.files[0][18] = 183; // AArch64, not the reviewed x86_64 seccomp target.
    fixture.manifest.artifacts[0].sha384 = hex::encode(Sha384::digest(&fixture.files[0]));
    let parent = tempfile::tempdir().unwrap();
    assert!(matches!(
        receive(
            &mut Cursor::new(fixture.bundle()),
            &[*fixture.key.verifying_key()],
            1024,
            parent.path()
        ),
        Err(Error::InvalidExecutable)
    ));
    let mut value = serde_json::to_value(&fixture.manifest).unwrap();
    value["disable_seccomp"] = true.into();
    assert!(serde_json::from_value::<Manifest>(value).is_err());
}

/// Offline packaging validates actual local bytes and never silently follows artifact symlinks.
#[test]
fn packaging_matches_the_receiver_and_rejects_changed_files() {
    let fixture = Fixture::new();
    let source = tempfile::tempdir().unwrap();
    for (artifact, data) in fixture.manifest.artifacts.iter().zip(&fixture.files) {
        let path = source.path().join(&artifact.logical_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }
    let manifest = serde_json::to_vec(&fixture.manifest).unwrap();
    let signature: Signature = fixture.key.sign(&manifest);
    let mut bytes = Vec::new();
    package(
        &mut bytes,
        &manifest,
        signature.to_der().as_bytes(),
        source.path(),
    )
    .unwrap();
    assert_eq!(bytes, fixture.bundle());
    fs::write(source.path().join("lib/fixture.so"), b"changed").unwrap();
    assert!(
        package(
            &mut Vec::new(),
            &manifest,
            signature.to_der().as_bytes(),
            source.path()
        )
        .is_err()
    );
    fs::remove_file(source.path().join("lib/fixture.so")).unwrap();
    std::os::unix::fs::symlink(
        source.path().join(WORKER_PATH),
        source.path().join("lib/fixture.so"),
    )
    .unwrap();
    assert!(matches!(
        package(
            &mut Vec::new(),
            &manifest,
            signature.to_der().as_bytes(),
            source.path()
        ),
        Err(Error::InvalidManifest)
    ));
}
