use flamingo_verifier_worker_protocol::{
    CompareRequest, WorkerProtocolError, WorkerReady, decode_message, encode_message,
};

const LIMIT: usize = 1024;

fn ready() -> WorkerReady {
    WorkerReady {
        protocol_version: 1,
        max_in_flight: 2,
    }
}

#[test]
fn startup_has_stable_cbor_bytes() {
    let bytes = b"\xa2pprotocol_version\x01mmax_in_flight\x02";
    assert_eq!(encode_message(&ready(), LIMIT).unwrap(), bytes);
    assert_eq!(
        decode_message::<WorkerReady>(bytes, LIMIT).unwrap(),
        ready()
    );
}

#[test]
fn every_truncated_payload_is_rejected() {
    let payload = encode_message(&ready(), LIMIT).unwrap();
    for end in 0..payload.len() {
        assert!(decode_message::<WorkerReady>(&payload[..end], LIMIT).is_err());
    }
}

#[test]
fn exact_limit_is_accepted_and_oversize_is_rejected() {
    let payload = encode_message(&ready(), LIMIT).unwrap();
    assert_eq!(encode_message(&ready(), payload.len()).unwrap(), payload);
    assert!(matches!(
        encode_message(&ready(), payload.len() - 1),
        Err(WorkerProtocolError::TooLarge)
    ));
    assert!(matches!(
        decode_message::<WorkerReady>(&payload, payload.len() - 1),
        Err(WorkerProtocolError::TooLarge)
    ));
}

#[test]
fn malformed_empty_trailing_unknown_and_duplicate_fields_are_rejected() {
    let mut trailing = encode_message(&ready(), LIMIT).unwrap();
    trailing.push(0);
    for payload in [
        Vec::new(),
        vec![0xff],
        trailing,
        b"\xa3pprotocol_version\x01mmax_in_flight\x02ax\x00".to_vec(),
        b"\xa3pprotocol_version\x01mmax_in_flight\x02mmax_in_flight\x02".to_vec(),
    ] {
        assert!(matches!(
            decode_message::<WorkerReady>(&payload, LIMIT),
            Err(WorkerProtocolError::Malformed)
        ));
    }
}

#[test]
fn images_round_trip_without_pixels_in_debug() {
    let request = CompareRequest {
        credential_image: b"private-image".to_vec(),
        live_image: vec![42; 10],
        challenge_image: vec![43; 10],
    };
    let payload = encode_message(&request, LIMIT).unwrap();
    assert_eq!(
        decode_message::<CompareRequest>(&payload, LIMIT).unwrap(),
        request
    );
    assert!(!format!("{request:?}").contains("private-image"));
    assert!(!format!("{request:?}").contains("112, 114"));
    assert!(request.valid_image_sizes(13));
    assert!(!request.valid_image_sizes(12));
}

#[test]
fn malicious_inner_lengths_do_not_control_allocation() {
    for encoded in [
        b"\xa3pcredential_image\x9b\xff\xff\xff\xff\xff\xff\xff\xff".as_slice(),
        b"\xa3pcredential_image\x5b\xff\xff\xff\xff\xff\xff\xff\xff".as_slice(),
    ] {
        assert!(decode_message::<CompareRequest>(encoded, LIMIT).is_err());
    }
}

#[test]
fn recursion_is_bounded() {
    let mut payload = vec![0x81; 100];
    payload.push(0);
    assert!(matches!(
        decode_message::<ciborium::Value>(&payload, LIMIT),
        Err(WorkerProtocolError::Malformed)
    ));
}

#[test]
fn zero_limits_are_explicit_errors() {
    assert!(matches!(
        encode_message(&ready(), 0),
        Err(WorkerProtocolError::InvalidLimit)
    ));
    assert!(matches!(
        decode_message::<WorkerReady>(&[], 0),
        Err(WorkerProtocolError::InvalidLimit)
    ));
}
