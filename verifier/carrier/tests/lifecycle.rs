#[cfg(target_os = "linux")]
#[test]
fn mocked_lifecycle() {
    let output = std::process::Command::new("bash")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/lifecycle.sh"))
        .env("CARRIER_BIN", env!("CARGO_BIN_EXE_flamingo-carrier"))
        .output()
        .expect("run lifecycle contract tests (requires bash, jq, tar, sha256sum)");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
