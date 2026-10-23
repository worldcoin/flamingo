//! Protocol-owned payload bytes cross IPC without changing their canonical encoding.
use flamingo_engine_interface::{decode_request, encode_request, framing, MAX_REQUEST_BYTES};
use world_id_flamingo::{Entry, Payload};

#[test]
fn published_protocol_payload_survives_worker_framing_unchanged() {
    let payload = Payload {
        pipeline: 1,
        match_strictness: 2,
        hints: vec![0, 128, 255],
        entries: vec![
            Entry {
                data: vec![0, 1, 255],
                meta: b"illuminated".to_vec(),
            },
            Entry {
                data: vec![4, 5],
                meta: vec![128, 255],
            },
            Entry {
                data: vec![6, 7, 8],
                meta: Vec::new(),
            },
        ],
        compare: vec![2, 0, 1],
        release_hash: [42; 32],
    };
    let encoded = payload.encode().unwrap();
    let mut wire = Vec::new();
    framing::write_frame(
        &mut wire,
        &encode_request(7, &encoded).unwrap(),
        MAX_REQUEST_BYTES,
    )
    .unwrap();
    let frame = framing::read_frame(&mut wire.as_slice(), MAX_REQUEST_BYTES)
        .unwrap()
        .unwrap();
    let (request_id, received) = decode_request(&frame).unwrap();
    assert_eq!(request_id, 7);
    assert_eq!(received, encoded);
    assert_eq!(Payload::decode(received).unwrap(), payload);
    assert_eq!(
        flamingo_engine_interface::MAX_DEBUG_REPORT_BYTES,
        world_id_flamingo::MAX_DEBUG_REPORT,
    );
}
