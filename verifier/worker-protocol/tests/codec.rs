use flamingo_verifier_worker_protocol::{
    CompareRequest, WorkerProtocolError, decode_message, encode_message,
};

const LIMIT: usize = 1024;

/// Builds the smallest nonempty three-image comparison.
fn request() -> CompareRequest {
    CompareRequest {
        credential_image: vec![1],
        live_image: vec![2],
        challenge_image: vec![3],
    }
}

#[test]
/// Pins the shared byte-string request encoding.
fn comparison_has_stable_cbor_bytes() {
    let bytes = b"\xa3pcredential_image\x41\x01jlive_image\x41\x02ochallenge_image\x41\x03";
    assert_eq!(encode_message(&request(), LIMIT).unwrap(), bytes);
    assert_eq!(
        decode_message::<CompareRequest>(bytes, LIMIT).unwrap(),
        request()
    );
}

#[test]
/// Rejects every incomplete CBOR body.
fn every_truncated_payload_is_rejected() {
    let payload = encode_message(&request(), LIMIT).unwrap();
    for end in 0..payload.len() {
        assert!(decode_message::<CompareRequest>(&payload[..end], LIMIT).is_err());
    }
}

#[test]
/// Applies the same byte budget when encoding and decoding.
fn exact_limit_is_accepted_and_oversize_is_rejected() {
    let payload = encode_message(&request(), LIMIT).unwrap();
    assert_eq!(encode_message(&request(), payload.len()).unwrap(), payload);
    assert!(matches!(
        encode_message(&request(), payload.len() - 1),
        Err(WorkerProtocolError::TooLarge)
    ));
    assert!(matches!(
        decode_message::<CompareRequest>(&payload, payload.len() - 1),
        Err(WorkerProtocolError::TooLarge)
    ));
}

#[test]
/// Rejects ambiguous or malformed request encodings.
fn malformed_empty_trailing_unknown_and_duplicate_fields_are_rejected() {
    let mut trailing = encode_message(&request(), LIMIT).unwrap();
    trailing.push(0);
    let mut unknown = encode_message(&request(), LIMIT).unwrap();
    unknown[0] = 0xa4;
    unknown.extend_from_slice(b"ax\x00");
    let mut duplicate = encode_message(&request(), LIMIT).unwrap();
    duplicate[0] = 0xa4;
    duplicate.extend_from_slice(b"jlive_image\x41\x02");

    for payload in [Vec::new(), vec![0xff], trailing, unknown, duplicate] {
        assert!(matches!(
            decode_message::<CompareRequest>(&payload, LIMIT),
            Err(WorkerProtocolError::Malformed)
        ));
    }
}

#[test]
/// Round-trips images while redacting their contents.
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
/// Rejects hostile nested length declarations.
fn malicious_inner_lengths_do_not_control_allocation() {
    for encoded in [
        b"\xa3pcredential_image\x9b\xff\xff\xff\xff\xff\xff\xff\xff".as_slice(),
        b"\xa3pcredential_image\x5b\xff\xff\xff\xff\xff\xff\xff\xff".as_slice(),
    ] {
        assert!(decode_message::<CompareRequest>(encoded, LIMIT).is_err());
    }
}

#[test]
/// Bounds decoding work for deeply nested CBOR.
fn recursion_is_bounded() {
    let mut payload = vec![0x81; 100];
    payload.push(0);
    assert!(matches!(
        decode_message::<ciborium::Value>(&payload, LIMIT),
        Err(WorkerProtocolError::Malformed)
    ));
}

#[test]
/// Rejects disabled byte limits explicitly.
fn zero_limits_are_explicit_errors() {
    assert!(matches!(
        encode_message(&request(), 0),
        Err(WorkerProtocolError::InvalidLimit)
    ));
    assert!(matches!(
        decode_message::<CompareRequest>(&[], 0),
        Err(WorkerProtocolError::InvalidLimit)
    ));
}
