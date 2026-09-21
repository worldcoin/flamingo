//! Executable byte fixtures only; these are not runnable workers or model substitutes.

use std::{
    fs,
    io::{Cursor, ErrorKind, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    time::Duration,
};

use flamingo_verifier_sandbox_bundle::{
    Error, MAX_BUNDLE_BYTES, Manifest, WORKER_PATH, package, receive,
};
use sha2::{Digest, Sha384};

/// Small executable for verification tests, never executed.
struct Fixture {
    /// Mutated by structural validation tests.
    manifest: Manifest,
    /// Executable bytes covered by the manifest.
    binary: Vec<u8>,
}

impl Fixture {
    /// Builds a minimal executable architecture header.
    fn new() -> Self {
        let mut elf = vec![0; 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16] = 2;
        elf[18] = 62;
        Self {
            manifest: Manifest {
                manifest_version: 3,
                release_id: "test-release".into(),
                sha384: hex::encode(Sha384::digest(&elf)),
                size: elf.len() as u64,
            },
            binary: elf,
        }
    }

    /// Frames exact JSON and appends raw file bytes without archive metadata.
    fn bundle(&self) -> Vec<u8> {
        let manifest = serde_json::to_vec(&self.manifest).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&manifest);
        bytes.extend_from_slice(&self.binary);
        bytes
    }
}

/// Only verified regular files and a read-only worker descriptor survive a successful transfer.
#[test]
fn exact_release_round_trips() {
    let fixture = Fixture::new();
    let parent = tempfile::tempdir().unwrap();
    let runtime = receive(&mut Cursor::new(fixture.bundle()), 1024, parent.path()).unwrap();
    assert_eq!(runtime.release_id, "test-release");
    let path = runtime.root.path().join(WORKER_PATH);
    assert_eq!(fs::read(&path).unwrap(), fixture.binary);
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o555
    );
    assert_eq!(fs::read_dir(runtime.root.path()).unwrap().count(), 1);
    assert_eq!(
        fs::read_dir(runtime.root.path().join("bin"))
            .unwrap()
            .count(),
        1
    );
    let mut read_only = &runtime.binary;
    assert!(std::io::Write::write_all(&mut read_only, b"overwrite").is_err());
    drop(runtime);
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

/// Publishers cannot select filesystem paths or supply the old multi-file format.
#[test]
fn old_format_and_publisher_paths_are_rejected() {
    let fixture = Fixture::new();
    let mut old = fixture.manifest.clone();
    old.manifest_version = 1;
    assert!(old.validate(1024).is_err());
    for (field, value) in [
        ("logical_path", serde_json::json!("../escape")),
        ("role", serde_json::json!("library")),
        ("artifacts", serde_json::json!([])),
    ] {
        let mut value_with_field = serde_json::to_value(&fixture.manifest).unwrap();
        value_with_field[field] = value;
        assert!(serde_json::from_value::<Manifest>(value_with_field).is_err());
    }
    assert!(
        serde_json::from_str::<Manifest>(
            r#"{"manifest_version":1,"release_id":"old","artifacts":[]}"#
        )
        .is_err()
    );
}

/// Missing configuration and oversized executables never allocate artifact bodies.
#[test]
fn format_and_resource_limits_are_checked_before_copying() {
    let mut fixture = Fixture::new();
    assert!(fixture.manifest.validate(0).is_err());
    assert!(fixture.manifest.validate(MAX_BUNDLE_BYTES + 1).is_err());
    assert!(fixture.manifest.validate(63).is_err());
    fixture.manifest.size = u64::MAX;
    assert!(fixture.manifest.validate(MAX_BUNDLE_BYTES).is_err());
    let parent = tempfile::tempdir().unwrap();
    for header in [0_u32, u32::MAX, 65537] {
        assert!(matches!(
            receive(&mut Cursor::new(header.to_be_bytes()), 1024, parent.path()),
            Err(Error::InvalidManifest)
        ));
    }
    assert!(matches!(
        receive(&mut Cursor::new([]), 0, parent.path()),
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
        assert!(receive(&mut Cursor::new(&bundle[..length]), 1024, parent.path()).is_err());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    let mut corrupt = bundle.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(matches!(
        receive(&mut Cursor::new(corrupt), 1024, parent.path()),
        Err(Error::DigestMismatch)
    ));
    let mut trailing = bundle;
    trailing.push(0);
    assert!(matches!(
        receive(&mut Cursor::new(trailing), 1024, parent.path()),
        Err(Error::TrailingData)
    ));
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

/// Native socket timeouts abort silent peers, partial files and missing write-half EOF.
/// Unix sockets exercise the portable receiver; deployed vsock is qualified separately.
#[test]
fn stalled_socket_receives_are_abandoned_and_cleaned_up() {
    let fixture = Fixture::new();
    let bundle = fixture.bundle();
    let parent = tempfile::tempdir().unwrap();
    for length in [0, bundle.len() - 1, bundle.len()] {
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        sender.write_all(&bundle[..length]).unwrap();
        // Keep the peer open without sending more bytes or signalling EOF.
        let result = receive(&mut receiver, 1024, parent.path());
        assert!(matches!(
            result,
            Err(Error::Io(ref error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
        ));
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
        drop(sender);
    }
}

/// A blocked package upload propagates the socket timeout instead of retrying forever.
#[test]
fn blocked_socket_upload_is_abandoned() {
    let mut fixture = Fixture::new();
    fixture.binary.resize(8 * 1024 * 1024, 1);
    fixture.manifest.size = fixture.binary.len() as u64;
    fixture.manifest.sha384 = hex::encode(Sha384::digest(&fixture.binary));
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("worker");
    fs::write(&executable, &fixture.binary).unwrap();
    let manifest = serde_json::to_vec(&fixture.manifest).unwrap();
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    sender
        .set_write_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let result = package(&mut sender, &manifest, &executable);
    assert!(matches!(
        result,
        Err(Error::Io(ref error))
            if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
    ));
    drop(receiver);
}

/// Valid hashes do not allow a different executable architecture or unknown metadata.
#[test]
fn wrong_architecture_and_unknown_fields_are_rejected() {
    let mut fixture = Fixture::new();
    fixture.binary[18] = 183; // AArch64, not the reviewed x86_64 seccomp target.
    fixture.manifest.sha384 = hex::encode(Sha384::digest(&fixture.binary));
    let parent = tempfile::tempdir().unwrap();
    assert!(matches!(
        receive(&mut Cursor::new(fixture.bundle()), 1024, parent.path()),
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
    let executable = source.path().join("worker");
    fs::write(&executable, &fixture.binary).unwrap();
    let generated = std::process::Command::new(env!("CARGO_BIN_EXE_sandbox-bundle"))
        .args(["manifest", &fixture.manifest.release_id])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(generated.status.success(), "{:?}", generated.stderr);
    let manifest: Manifest = serde_json::from_slice(&generated.stdout).unwrap();
    assert_eq!(
        serde_json::to_value(manifest).unwrap(),
        serde_json::to_value(&fixture.manifest).unwrap()
    );
    let manifest = serde_json::to_vec(&fixture.manifest).unwrap();
    let mut bytes = Vec::new();
    package(&mut bytes, &manifest, &executable).unwrap();
    assert_eq!(bytes, fixture.bundle());

    let manifest_path = source.path().join("manifest.json");
    let bundle_path = source.path().join("worker.bundle");
    fs::write(&manifest_path, &manifest).unwrap();
    let packed = std::process::Command::new(env!("CARGO_BIN_EXE_sandbox-bundle"))
        .arg("pack")
        .args([&manifest_path, &executable, &bundle_path])
        .output()
        .unwrap();
    assert!(packed.status.success(), "{:?}", packed.stderr);
    assert_eq!(fs::read(&bundle_path).unwrap(), bytes);

    fs::write(&executable, b"changed").unwrap();
    assert!(package(&mut Vec::new(), &manifest, &executable).is_err());
    fs::remove_file(&executable).unwrap();
    std::os::unix::fs::symlink(source.path().join(WORKER_PATH), &executable).unwrap();
    assert!(matches!(
        package(&mut Vec::new(), &manifest, &executable),
        Err(Error::InvalidManifest)
    ));
}
