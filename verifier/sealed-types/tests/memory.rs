//! Allocation regression for the maximum-size encoded-image request (not model/RGB memory).
use flamingo_verifier_sealed_types::{DeepFaceInputs, LiveCapture, MatchInputs};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
struct TrackingAllocator;
fn added(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            added(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            added(new_size);
        }
        new
    }
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;
#[test]
fn maximum_request_has_bounded_codec_allocations() {
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let mib = 1024 * 1024;
    let request = MatchInputs::DeepFace(DeepFaceInputs {
        orb_credential: vec![1; 3 * mib].into(),
        live: LiveCapture {
            profile: "vanilla".to_owned(),
            frames: vec![vec![2; 2 * mib].into()],
            matching_frame: 0,
        },
        rtms_challenge: vec![3; 2 * mib].into(),
        hashes_json: b"{}".to_vec().into(),
        match_threshold: 0.5,
    });
    let encoded = request.to_cbor().unwrap();
    // The sending and receiving processes do not share their input buffers.
    drop(request);
    let decoded = MatchInputs::from_cbor(&encoded).unwrap();
    drop(encoded);
    decoded.validate().unwrap();
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    println!("maximum CBOR request: 7 MiB image bytes; peak live Rust allocation: {peak} bytes");
    // Allows owned decoded bytes, encoded bytes and ciborium scratch, but catches full-buffer clones.
    assert!(
        peak < 3 * 7 * mib,
        "unexpected codec allocation peak: {peak}"
    );
}
