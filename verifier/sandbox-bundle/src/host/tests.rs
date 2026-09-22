use super::*;

const DEADLINE: Duration = Duration::from_secs(2);

async fn fixture(size: usize) -> (tempfile::TempDir, Bundle) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("executable");
    let mut bytes = vec![1; size.max(64)];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    tokio::fs::write(&path, bytes).await.unwrap();

    let bundle = Bundle::prepare("test-release", &path).await.unwrap();
    (directory, bundle)
}

#[tokio::test]
async fn direct_stream_matches_packaged_bytes_and_existing_receiver() {
    let (_source, bundle) = fixture(128 * 1024).await;
    let mut packaged = Vec::new();
    crate::package(
        &mut packaged,
        &bundle.manifest().unwrap(),
        &bundle.executable,
    )
    .unwrap();

    let (sender, mut receiver) = tokio::io::duplex(1024);
    let receive = tokio::spawn(async move {
        let mut bytes = Vec::new();
        receiver.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, packaged);

        let destination = tempfile::tempdir().unwrap();
        let runtime = crate::receive(
            &mut std::io::Cursor::new(bytes),
            MAX_BUNDLE_BYTES,
            destination.path(),
        )
        .unwrap();
        assert_eq!(runtime.release_id, "test-release");

        receiver.write_all(&[0]).await.unwrap();
        receiver.shutdown().await.unwrap();
    });

    bundle.deliver(sender, DEADLINE).await.unwrap();
    receive.await.unwrap();
}

#[tokio::test]
async fn initialization_requires_one_zero_byte_and_eof() {
    for acknowledgement in [vec![], vec![1], vec![0, 0]] {
        let (_source, bundle) = fixture(64).await;
        let (sender, mut receiver) = tokio::io::duplex(1024);
        let receive = tokio::spawn(async move {
            receiver.read_to_end(&mut Vec::new()).await.unwrap();
            receiver.write_all(&acknowledgement).await.unwrap();
            receiver.shutdown().await.unwrap();
        });

        let result = bundle.deliver(sender, DEADLINE).await;
        assert!(matches!(
            result,
            Err(Error::Acknowledgement)
                | Err(Error::Io {
                    stage: "ack-read",
                    ..
                })
        ));
        receive.await.unwrap();
    }
}

#[tokio::test]
async fn missing_acknowledgement_times_out_at_the_correct_stage() {
    let (_source, bundle) = fixture(64).await;
    let (sender, mut receiver) = tokio::io::duplex(4096);
    let result = bundle.deliver(sender, Duration::from_millis(30)).await;

    assert!(matches!(result, Err(Error::Timeout("ack-read"))));
    receiver.read_to_end(&mut Vec::new()).await.unwrap();
    assert!(receiver.write_all(&[0]).await.is_err());
}

#[tokio::test]
async fn acknowledgement_without_eof_times_out() {
    let (_source, bundle) = fixture(64).await;
    let (sender, mut receiver) = tokio::io::duplex(1024);
    let sending =
        tokio::spawn(async move { bundle.deliver(sender, Duration::from_millis(100)).await });

    receiver.read_to_end(&mut Vec::new()).await.unwrap();
    receiver.write_all(&[0]).await.unwrap();

    assert!(matches!(
        sending.await.unwrap(),
        Err(Error::Timeout("ack-close"))
    ));
    assert!(receiver.write_all(&[0]).await.is_err());
}

#[tokio::test]
async fn bootstrap_deadline_cancels_a_longer_transfer_deadline() {
    let (_source, bundle) = fixture(64).await;
    let (sender, mut receiver) = tokio::io::duplex(1);

    assert!(
        timeout(Duration::from_millis(30), bundle.deliver(sender, DEADLINE),)
            .await
            .is_err()
    );
    timeout(DEADLINE, receiver.read_to_end(&mut Vec::new()))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn stalled_transfer_times_out_and_closes_the_socket() {
    let (_source, bundle) = fixture(64).await;
    let (sender, mut receiver) = tokio::io::duplex(1);
    let result = bundle.deliver(sender, Duration::from_millis(30)).await;

    assert!(matches!(result, Err(Error::Timeout("transfer"))));
    timeout(DEADLINE, receiver.read_to_end(&mut Vec::new()))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cancellation_during_transfer_closes_the_socket() {
    let (_source, bundle) = fixture(128 * 1024).await;
    let (sender, mut receiver) = tokio::io::duplex(64);
    let sending = tokio::spawn(async move { bundle.deliver(sender, DEADLINE).await });

    receiver.read_exact(&mut [0]).await.unwrap();
    sending.abort();
    assert!(sending.await.unwrap_err().is_cancelled());

    let mut remaining = Vec::new();
    timeout(DEADLINE, receiver.read_to_end(&mut remaining))
        .await
        .unwrap()
        .unwrap();
    assert!(remaining.len() < 128 * 1024);
}

#[tokio::test]
async fn cancellation_while_waiting_for_initialization_closes_the_socket() {
    let (_source, bundle) = fixture(64).await;
    let (sender, mut receiver) = tokio::io::duplex(1024);
    let sending = tokio::spawn(async move { bundle.deliver(sender, DEADLINE).await });

    receiver.read_to_end(&mut Vec::new()).await.unwrap();
    sending.abort();
    assert!(sending.await.unwrap_err().is_cancelled());
    assert!(receiver.write_all(&[0]).await.is_err());
}

#[tokio::test]
async fn changed_executable_cannot_complete_initialization() {
    let (_source, bundle) = fixture(64).await;
    tokio::fs::write(&bundle.executable, vec![2; 64])
        .await
        .unwrap();

    let (sender, _receiver) = tokio::io::duplex(4096);
    assert!(matches!(
        bundle.deliver(sender, DEADLINE).await,
        Err(Error::Changed)
    ));
}

#[tokio::test]
async fn symlinks_are_not_bundle_executables() {
    let (directory, bundle) = fixture(64).await;
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&bundle.executable, &link).unwrap();

    assert!(matches!(
        Bundle::prepare("test-release", &link).await,
        Err(Error::InvalidBundle)
    ));
}

#[test]
fn error_diagnostics_preserve_stage_without_raw_io_message() {
    let error = io_error(
        "connect",
        io::Error::new(io::ErrorKind::ConnectionReset, "secret payload"),
    );
    let message = format!("{error:?}: {error}");

    assert!(message.contains("connect"));
    assert!(message.contains("ConnectionReset"));
    assert!(!message.contains("secret"));
}
