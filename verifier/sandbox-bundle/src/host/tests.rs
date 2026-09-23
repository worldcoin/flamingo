use super::*;

const DEADLINE: Duration = Duration::from_secs(2);

#[tokio::test(start_paused = true)]
async fn bootstrap_reset_and_refusal_retry_until_connected() {
    let started = tokio::time::Instant::now();
    let mut attempts = 0;
    let connected = connect_with(DEADLINE, || {
        attempts += 1;
        std::future::ready(match attempts {
            1 => Err(io::ErrorKind::ConnectionReset.into()),
            2 => Err(io::ErrorKind::ConnectionRefused.into()),
            _ => Ok("connected"),
        })
    })
    .await
    .unwrap();

    assert_eq!(connected, "connected");
    assert_eq!(attempts, 3);
    assert_eq!(started.elapsed(), Duration::from_millis(400));
}

#[tokio::test(start_paused = true)]
async fn fatal_connect_errors_are_not_retried() {
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::InvalidInput,
        io::ErrorKind::AddrNotAvailable,
        io::ErrorKind::TimedOut,
    ] {
        let mut attempts = 0;
        let result = connect_with(DEADLINE, || {
            attempts += 1;
            std::future::ready(Err::<(), _>(io::Error::from(kind)))
        })
        .await;

        assert!(
            matches!(result, Err(Error::Io { stage: "connect", kind: actual, .. }) if actual == kind)
        );
        assert_eq!(attempts, 1);
    }
}

#[tokio::test(start_paused = true)]
async fn connect_retries_share_one_deadline() {
    let started = tokio::time::Instant::now();
    let mut attempts = 0;
    let deadline = Duration::from_millis(550);
    let result = connect_with(deadline, || {
        attempts += 1;
        std::future::ready(Err::<(), _>(io::ErrorKind::ConnectionReset.into()))
    })
    .await;

    assert!(matches!(result, Err(Error::Timeout("connect"))));
    assert_eq!(attempts, 3);
    assert_eq!(started.elapsed(), deadline);
}

#[tokio::test(start_paused = true)]
async fn stalled_connect_is_bounded_and_drops_its_operation() {
    let (sender, mut receiver) = tokio::io::duplex(1);
    let mut sender = Some(sender);
    let result = connect_with(DEADLINE, || {
        let stream = sender.take().unwrap();
        async move {
            std::future::pending::<()>().await;
            Ok(stream)
        }
    })
    .await;

    assert!(matches!(result, Err(Error::Timeout("connect"))));
    assert_eq!(receiver.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn bootstrap_deadline_cancels_connect_retries() {
    let mut attempts = 0;
    let result = timeout(
        Duration::from_millis(350),
        connect_with(DEADLINE, || {
            attempts += 1;
            std::future::ready(Err::<(), _>(io::ErrorKind::ConnectionReset.into()))
        }),
    )
    .await;

    assert!(result.is_err());
    assert_eq!(attempts, 2);
    tokio::time::sleep(DEADLINE).await;
    assert_eq!(attempts, 2);
}

#[tokio::test(start_paused = true)]
async fn cancelling_pending_connect_closes_its_owned_socket() {
    let (sender, mut receiver) = tokio::io::duplex(1);
    let (started, waiting) = tokio::sync::oneshot::channel();
    let connecting = tokio::spawn(async move {
        let mut resources = Some((sender, started));
        connect_with(DEADLINE, || {
            let (stream, started) = resources.take().unwrap();
            async move {
                started.send(()).unwrap();
                std::future::pending::<()>().await;
                Ok(stream)
            }
        })
        .await
    });

    waiting.await.unwrap();
    connecting.abort();
    assert!(connecting.await.unwrap_err().is_cancelled());
    assert_eq!(receiver.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn reset_after_connect_fails_transfer_or_ack_without_reconnecting() {
    struct ResetStream {
        during_write: bool,
    }

    impl AsyncWrite for ResetStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(if self.during_write {
                Err(io::ErrorKind::ConnectionReset.into())
            } else {
                Ok(bytes.len())
            })
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for ResetStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }
    }

    let (_source, bundle) = fixture(64).await;

    for (during_write, expected_stage) in [(true, "transfer"), (false, "ack-read")] {
        let mut attempts = 0;
        let stream = connect_with(DEADLINE, || {
            attempts += 1;
            std::future::ready(Ok(ResetStream { during_write }))
        })
        .await
        .unwrap();
        let result = bundle.deliver(stream, DEADLINE).await;

        assert!(matches!(result, Err(Error::Io {
            stage, kind: io::ErrorKind::ConnectionReset, ..
        }) if stage == expected_stage));
        assert_eq!(attempts, 1);
    }
}

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
