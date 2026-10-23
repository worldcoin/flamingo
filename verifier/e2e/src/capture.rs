//! Caller-side encoding for the pipeline IDs supplied by this biometric worker release.

use anyhow::{Result, bail};
use flamingo_verifier_sealed_types::{Entry, Payload};

const DEEPFACE_VANILLA: u16 = 1;
const GRAYBADGE_VANILLA: u16 = 2;
const DEEPFACE_LIGHTGUARD: u16 = 3;
const GRAYBADGE_LIGHTGUARD: u16 = 4;

#[derive(Clone, Copy)]
pub enum MatchingFrame {
    Illuminated,
    Unilluminated,
}

impl MatchingFrame {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None | Some("illuminated") => Ok(Self::Illuminated),
            Some("unilluminated") => Ok(Self::Unilluminated),
            _ => bail!("LIGHT_GUARD_MATCHING_FRAME must be illuminated or unilluminated"),
        }
    }
}

pub fn payload(
    credential: Option<Vec<u8>>,
    live: Vec<u8>,
    challenge: Vec<u8>,
    light_guard: Option<(Vec<u8>, MatchingFrame)>,
    match_strictness: u8,
    release_hash: [u8; 32],
) -> Payload {
    let pipeline = match (credential.is_some(), light_guard.is_some()) {
        (true, false) => DEEPFACE_VANILLA,
        (false, false) => GRAYBADGE_VANILLA,
        (true, true) => DEEPFACE_LIGHTGUARD,
        (false, true) => GRAYBADGE_LIGHTGUARD,
    };
    let entry = |data, meta: &[u8]| Entry {
        data,
        meta: meta.to_vec(),
    };
    let mut entries = Vec::new();
    if let Some(data) = credential {
        entries.push(entry(data, b""));
    }
    // The positional live image is always illuminated in LightGuard mode.
    let partner = match light_guard {
        Some((unilluminated, MatchingFrame::Illuminated)) => {
            entries.push(entry(live, b"illuminated"));
            Some(entry(unilluminated, b"unilluminated"))
        }
        Some((unilluminated, MatchingFrame::Unilluminated)) => {
            entries.push(entry(unilluminated, b"unilluminated"));
            Some(entry(live, b"illuminated"))
        }
        None => {
            entries.push(entry(live, b""));
            None
        }
    };
    entries.push(entry(challenge, b""));
    let compare = if pipeline == DEEPFACE_VANILLA || pipeline == DEEPFACE_LIGHTGUARD {
        vec![0, 1, 2]
    } else {
        vec![0, 1]
    };
    entries.extend(partner);
    Payload {
        pipeline,
        match_strictness,
        hints: Vec::new(),
        entries,
        compare,
        release_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vanilla_operations_preserve_role_order_and_have_no_partner() {
        for (credential, expected_pipeline, compared) in
            [(Some(vec![10]), 1, vec![0, 1, 2]), (None, 2, vec![0, 1])]
        {
            let payload = payload(credential, vec![20], vec![30], None, 2, [42; 32]);
            assert_eq!(payload.pipeline, expected_pipeline);
            assert_eq!(payload.compare, compared);
            let data: Vec<_> = payload.entries.iter().map(|entry| entry.data[0]).collect();
            assert_eq!(
                data,
                if expected_pipeline == 1 {
                    vec![10, 20, 30]
                } else {
                    vec![20, 30]
                }
            );
            assert!(payload.entries.iter().all(|entry| entry.meta.is_empty()));
            assert_eq!(payload.match_strictness, 2);
            assert_eq!(payload.release_hash, [42; 32]);
            assert!(payload.encode().is_ok());
        }
    }

    #[test]
    fn lightguard_operations_select_explicit_ids_and_preserve_both_frame_choices() {
        for (credential, expected_pipeline, live_index) in [(Some(vec![10]), 3, 1), (None, 4, 0)] {
            for (selection, compared_data, compared_meta, partner_data, partner_meta) in [
                (
                    "illuminated",
                    20,
                    b"illuminated".as_slice(),
                    40,
                    b"unilluminated".as_slice(),
                ),
                (
                    "unilluminated",
                    40,
                    b"unilluminated".as_slice(),
                    20,
                    b"illuminated".as_slice(),
                ),
            ] {
                let payload = payload(
                    credential.clone(),
                    vec![20],
                    vec![30],
                    Some((vec![40], MatchingFrame::parse(Some(selection)).unwrap())),
                    2,
                    [42; 32],
                );
                assert_eq!(payload.pipeline, expected_pipeline);
                assert_eq!(
                    payload.compare,
                    if expected_pipeline == 3 {
                        vec![0, 1, 2]
                    } else {
                        vec![0, 1]
                    }
                );
                assert_eq!(payload.entries[live_index].data, [compared_data]);
                assert_eq!(payload.entries[live_index].meta, compared_meta);
                let partner_index = payload.entries.len() - 1;
                assert!(!payload.compare.contains(&(partner_index as u8)));
                assert_eq!(payload.entries[partner_index].data, [partner_data]);
                assert_eq!(payload.entries[partner_index].meta, partner_meta);
                let challenge = &payload.entries[live_index + 1];
                assert_eq!(challenge.data, [30]);
                assert!(challenge.meta.is_empty());
                if expected_pipeline == 3 {
                    assert_eq!(payload.entries[0].data, [10]);
                    assert!(payload.entries[0].meta.is_empty());
                }
                assert_eq!(payload.entries.len(), payload.compare.len() + 1);
                assert_eq!(payload.release_hash, [42; 32]);
                assert!(payload.encode().is_ok());
            }
        }
    }

    #[test]
    fn matching_frame_is_explicit_and_defaults_to_illuminated() {
        assert!(matches!(
            MatchingFrame::parse(None).unwrap(),
            MatchingFrame::Illuminated
        ));
        assert!(MatchingFrame::parse(Some("automatic")).is_err());
    }
}
