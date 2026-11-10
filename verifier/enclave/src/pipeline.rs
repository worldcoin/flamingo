//! Interim adapter from the WIP-201 request onto the DeepFace-specific engine operations.
//!
//! The current engine returns similarity scores instead of a verdict, so this module maps
//! `compare` positions and `pipeline_inputs` to roles and `match_strictness` levels to
//! thresholds. Both move into the Engine once it implements the generic WIP-201 interface.

use flamingo_verifier_sealed_types::{ComparisonRole, Entry, FailureReason, Payload};

use crate::biometric_engine::{LightGuardMatchingFrame, LiveCapture};

/// Compares the Credential image, the live capture and the challenge, in `compare` order.
pub const PIPELINE_DEEPFACE: u16 = 1;
/// Compares the live capture and the challenge, in `compare` order.
pub const PIPELINE_GRAYBADGE: u16 = 2;

/// `match_strictness` levels and the minimum normalized similarity of every compared pair.
const MATCH_THRESHOLDS: [(u8, f64); 3] = [(1, 0.85), (2, 0.9), (3, 0.95)];

/// Entry `meta` of the compared live frame and its partner in a `LightGuard` capture.
const ILLUMINATED: &[u8] = b"illuminated";
const UNILLUMINATED: &[u8] = b"unilluminated";

/// One engine call with its inputs in role order.
pub enum Operation {
    /// [`PIPELINE_DEEPFACE`].
    DeepFace {
        /// The Credential image.
        credential: Vec<u8>,
        /// The live capture.
        live: LiveCapture,
        /// The challenge image.
        challenge: Vec<u8>,
    },
    /// [`PIPELINE_GRAYBADGE`].
    GrayBadge {
        /// The live capture.
        live: LiveCapture,
        /// The challenge image.
        challenge: Vec<u8>,
    },
}

/// The minimum similarity every compared pair must reach.
///
/// # Errors
/// Returns [`FailureReason::UnsupportedMatchStrictness`] for an undefined level.
pub fn threshold(match_strictness: u8) -> Result<f64, FailureReason> {
    MATCH_THRESHOLDS
        .iter()
        .find(|(level, _)| *level == match_strictness)
        .map(|(_, threshold)| *threshold)
        .ok_or(FailureReason::UnsupportedMatchStrictness)
}

/// Fails a comparison below `threshold`; a score outside `0..=1` is an engine fault.
///
/// # Errors
/// Returns [`FailureReason::MatchBelowThreshold`] or [`FailureReason::Internal`].
pub fn check_score(
    score: f64,
    threshold: f64,
    comparison: ComparisonRole,
) -> Result<(), FailureReason> {
    if !score.is_finite() || !(0.0..=1.0).contains(&score) {
        return Err(FailureReason::Internal);
    }
    if score < threshold {
        return Err(FailureReason::MatchBelowThreshold(comparison));
    }
    Ok(())
}

/// Maps a validated payload onto an engine operation.
///
/// The live entry, at a fixed `compare` position per pipeline, is a pipeline input. A `LightGuard`
/// capture's other frame is the one other pipeline input, and is not compared: the compared frame's
/// `meta` is `illuminated` or `unilluminated`, and the other frame carries the other. All other
/// entry `meta` and the request-level `hints` are empty.
///
/// # Errors
/// Returns [`FailureReason::UnsupportedPipeline`] for an unknown pipeline or another layout.
pub fn operation(payload: Payload) -> Result<Operation, FailureReason> {
    let live_position = match payload.pipeline_id {
        PIPELINE_DEEPFACE => 1,
        PIPELINE_GRAYBADGE => 0,
        _ => return Err(FailureReason::UnsupportedPipeline),
    };
    if payload.compare.len() != live_position + 2 || !payload.hints.is_empty() {
        return Err(FailureReason::UnsupportedPipeline);
    }
    let live_index = payload.compare[live_position];
    let partner_index = match *payload.pipeline_inputs.as_slice() {
        [only] if only == live_index => None,
        [first, second] if first == live_index => Some(second),
        [first, second] if second == live_index => Some(first),
        _ => return Err(FailureReason::UnsupportedPipeline),
    };
    if partner_index.is_some_and(|index| payload.compare.contains(&index)) {
        return Err(FailureReason::UnsupportedPipeline);
    }

    let mut entries: Vec<Option<Entry>> = payload.entries.into_iter().map(Some).collect();
    let mut take = |index: u8| {
        entries
            .get_mut(usize::from(index))
            .and_then(Option::take)
            .ok_or(FailureReason::UnsupportedPipeline)
    };
    let mut compared = Vec::with_capacity(payload.compare.len());
    for &index in &payload.compare {
        compared.push(take(index)?);
    }
    let partner = partner_index.map(&mut take).transpose()?;
    if entries.iter().any(Option::is_some) {
        return Err(FailureReason::UnsupportedPipeline);
    }

    let challenge = compared.pop().ok_or(FailureReason::UnsupportedPipeline)?;
    let live = compared.pop().ok_or(FailureReason::UnsupportedPipeline)?;
    let live = live_capture(live, partner)?;
    let plain = |entry: Entry| {
        entry
            .meta
            .is_empty()
            .then_some(entry.data)
            .ok_or(FailureReason::UnsupportedPipeline)
    };
    let challenge = plain(challenge)?;

    Ok(match compared.pop() {
        Some(credential) => Operation::DeepFace {
            credential: plain(credential)?,
            live,
            challenge,
        },
        None => Operation::GrayBadge { live, challenge },
    })
}

fn live_capture(live: Entry, partner: Option<Entry>) -> Result<LiveCapture, FailureReason> {
    let Some(partner) = partner else {
        return if live.meta.is_empty() {
            Ok(LiveCapture::Vanilla(live.data))
        } else {
            Err(FailureReason::UnsupportedPipeline)
        };
    };
    match (live.meta.as_slice(), partner.meta.as_slice()) {
        (ILLUMINATED, UNILLUMINATED) => Ok(LiveCapture::LightGuard {
            illuminated: live.data,
            unilluminated: partner.data,
            matching_frame: LightGuardMatchingFrame::Illuminated,
        }),
        (UNILLUMINATED, ILLUMINATED) => Ok(LiveCapture::LightGuard {
            illuminated: partner.data,
            unilluminated: live.data,
            matching_frame: LightGuardMatchingFrame::Unilluminated,
        }),
        _ => Err(FailureReason::UnsupportedPipeline),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(data: &[u8], meta: &[u8]) -> Entry {
        Entry {
            data: data.to_vec(),
            meta: meta.to_vec(),
        }
    }

    fn payload(
        pipeline_id: u16,
        entries: Vec<Entry>,
        pipeline_inputs: Vec<u8>,
        compare: Vec<u8>,
    ) -> Payload {
        Payload {
            pipeline_id,
            match_strictness: 2,
            hints: Vec::new(),
            entries,
            pipeline_inputs,
            compare,
        }
    }

    #[test]
    fn deep_face_reads_roles_from_compare_positions() {
        let Ok(Operation::DeepFace {
            credential,
            live: LiveCapture::Vanilla(live),
            challenge,
        }) = operation(payload(
            PIPELINE_DEEPFACE,
            vec![
                entry(b"challenge", b""),
                entry(b"credential", b""),
                entry(b"live", b""),
            ],
            vec![2],
            vec![1, 2, 0],
        ))
        else {
            panic!("expected a vanilla DeepFace operation")
        };
        assert_eq!(credential, b"credential");
        assert_eq!(&live[..], b"live");
        assert_eq!(challenge, b"challenge");
    }

    #[test]
    fn light_guard_takes_the_uncompared_partner_frame() {
        for (live_meta, partner_meta, expected) in [
            (
                ILLUMINATED,
                UNILLUMINATED,
                LightGuardMatchingFrame::Illuminated,
            ),
            (
                UNILLUMINATED,
                ILLUMINATED,
                LightGuardMatchingFrame::Unilluminated,
            ),
        ] {
            let Ok(Operation::GrayBadge {
                live:
                    LiveCapture::LightGuard {
                        illuminated,
                        unilluminated,
                        matching_frame,
                    },
                ..
            }) = operation(payload(
                PIPELINE_GRAYBADGE,
                vec![
                    entry(b"partner", partner_meta),
                    entry(b"live", live_meta),
                    entry(b"challenge", b""),
                ],
                vec![0, 1],
                vec![1, 2],
            ))
            else {
                panic!("expected a LightGuard GrayBadge operation")
            };
            assert_eq!(matching_frame, expected);
            let (lit, dark): (&[u8], &[u8]) = match expected {
                LightGuardMatchingFrame::Illuminated => (b"live", b"partner"),
                LightGuardMatchingFrame::Unilluminated => (b"partner", b"live"),
            };
            assert_eq!(&illuminated[..], lit);
            assert_eq!(&unilluminated[..], dark);
        }
    }

    #[test]
    fn other_layouts_are_unsupported() {
        let plain = || vec![entry(b"a", b""), entry(b"b", b""), entry(b"c", b"")];
        for payload in [
            payload(3, plain(), vec![1], vec![0, 1, 2]),
            payload(PIPELINE_DEEPFACE, plain(), vec![1], vec![0, 1, 3]),
            payload(PIPELINE_DEEPFACE, plain(), vec![1], vec![0, 1, 255]),
            payload(PIPELINE_DEEPFACE, plain(), vec![1], vec![0, 1]),
            // The live entry is not a pipeline input.
            payload(PIPELINE_DEEPFACE, plain(), vec![0], vec![0, 1, 2]),
            // The partner frame is compared.
            payload(PIPELINE_DEEPFACE, plain(), vec![1, 2], vec![0, 1, 2]),
            payload(PIPELINE_DEEPFACE, plain(), vec![0, 1, 2], vec![0, 1, 2]),
            payload(PIPELINE_GRAYBADGE, plain(), vec![0], vec![0, 1]),
            payload(
                PIPELINE_DEEPFACE,
                vec![entry(b"a", b"x"), entry(b"b", b""), entry(b"c", b"")],
                vec![1],
                vec![0, 1, 2],
            ),
            payload(
                PIPELINE_GRAYBADGE,
                vec![
                    entry(b"a", ILLUMINATED),
                    entry(b"b", b""),
                    entry(b"c", ILLUMINATED),
                ],
                vec![0, 2],
                vec![0, 1],
            ),
            payload(
                PIPELINE_GRAYBADGE,
                vec![
                    entry(b"a", b""),
                    entry(b"b", b""),
                    entry(b"c", UNILLUMINATED),
                ],
                vec![0, 2],
                vec![0, 1],
            ),
        ] {
            assert!(matches!(
                operation(payload),
                Err(FailureReason::UnsupportedPipeline)
            ));
        }
        let mut with_hints = payload(
            PIPELINE_GRAYBADGE,
            vec![entry(b"a", b""), entry(b"b", b"")],
            vec![0],
            vec![0, 1],
        );
        with_hints.hints = vec![1];
        assert!(operation(with_hints).is_err());
    }

    #[test]
    fn strictness_levels_map_to_increasing_thresholds() {
        assert_eq!(threshold(0), Err(FailureReason::UnsupportedMatchStrictness));
        assert_eq!(threshold(4), Err(FailureReason::UnsupportedMatchStrictness));
        assert!(threshold(1).unwrap() < threshold(2).unwrap());
        assert!(threshold(2).unwrap() < threshold(3).unwrap());
    }

    #[test]
    fn scores_must_be_valid_and_reach_the_threshold() {
        let role = ComparisonRole::SelfieChallenge;
        for score in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
            assert_eq!(check_score(score, 0.8, role), Err(FailureReason::Internal));
        }
        assert_eq!(
            check_score(0.7, 0.8, role),
            Err(FailureReason::MatchBelowThreshold(role))
        );
        assert_eq!(check_score(0.8, 0.8, role), Ok(()));
    }
}
