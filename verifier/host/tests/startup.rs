//! What the binary needs to boot, driven by running it.
//!
//! The rollback position is only a rollback if it boots with nothing but the enclave settings,
//! so this starts the real binary in a cleared environment rather than asserting about the code
//! that reads it.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Picks a port the operating system has just confirmed is free.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a local port should be available");

    listener
        .local_addr()
        .expect("the listener should be bound")
        .port()
}

/// Starts the host with exactly `env` and nothing inherited.
///
/// `env_clear` is the point of the test: a `FEE_*` variable leaking in from the developer's shell
/// would hide the very thing being checked.
fn start(env: &[(&str, String)]) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_flamingo-verifier-host"));
    command
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    for (name, value) in env {
        command.env(name, value);
    }

    command.spawn().expect("the host binary should start")
}

/// Waits for the host to answer its health probe, or gives up.
fn wait_for_health(port: u16, child: &mut Child) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);

    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the host exited during startup with {status}");
        }

        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    false
}

/// The rollback path: no `FEE_*` variable is set, and the host still boots and serves.
///
/// `ENCLAVE_CID` and `ENCLAVE_PORT` are dummies. The Pontifex client does not connect until a
/// request needs the enclave, and health does not.
#[test]
fn payments_off_boots_without_any_fee_configuration() {
    let port = free_port();
    let mut child = start(&[
        ("PAYMENTS", "off".to_owned()),
        ("ENCLAVE_CID", "0".to_owned()),
        ("ENCLAVE_PORT", "0".to_owned()),
        ("PORT", port.to_string()),
    ]);

    let healthy = wait_for_health(port, &mut child);
    let _ = child.kill();

    assert!(
        healthy,
        "payments off must boot with no FEE_ESCROW_RPC_URL and no other fee settings"
    );
}

/// The same run with metering on stops at the first missing fee setting, so the requirement is
/// the mode's and not something this test arranged.
#[test]
fn payments_required_refuses_to_boot_without_fee_configuration() {
    let port = free_port();
    let mut child = start(&[
        ("PAYMENTS", "required".to_owned()),
        ("ENCLAVE_CID", "0".to_owned()),
        ("ENCLAVE_PORT", "0".to_owned()),
        ("PORT", port.to_string()),
    ]);

    let status = loop {
        if let Some(status) = child.try_wait().expect("the child should be waitable") {
            break status;
        }

        assert!(
            std::net::TcpStream::connect(("127.0.0.1", port)).is_err(),
            "metering must not serve without its fee settings"
        );

        std::thread::sleep(Duration::from_millis(50));
    };

    assert!(
        !status.success(),
        "a missing fee setting must fail the boot"
    );
}

/// An unknown mode is rejected by the parser rather than falling back to a default.
#[test]
fn an_unknown_payment_mode_is_refused() {
    let output = Command::new(env!("CARGO_BIN_EXE_flamingo-verifier-host"))
        .env_clear()
        .env("PAYMENTS", "sometimes")
        .output()
        .expect("the host binary should run");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("sometimes"),
        "the error should name what was rejected"
    );
}
