//! Interim adapter from the WIP-201 request onto the DeepFace-specific engine operations.
//!
//! The current engine returns similarity scores instead of a verdict, so this module maps
//! `compare` positions and `pipeline_inputs` to roles and `match_strictness` levels to
//! thresholds. Both move into the Engine once it implements the generic WIP-201 interface.

use flamingo_verifier_sealed_types::{ComparisonRole, Entry, FailureReason, Payload};

use crate::biometric_engine::{LightGuardMatchingFrame, LiveCapture};

/// Compares the Credential image, a single live frame and the challenge, in `compare` order.
pub const PIPELINE_DEEPFACE: u16 = 1;
/// Compares a single live frame and the challenge, in `compare` order.
pub const PIPELINE_GRAYBADGE: u16 = 2;
/// [`PIPELINE_DEEPFACE`] with a `LightGuard` capture: two live frames as pipeline inputs.
pub const PIPELINE_DEEPFACE_LIGHTGUARD: u16 = 3;
/// [`PIPELINE_GRAYBADGE`] with a `LightGuard` capture: two live frames as pipeline inputs.
pub const PIPELINE_GRAYBADGE_LIGHTGUARD: u16 = 4;

/// Minimum similarity of every compared pair, in the units of the selected level.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MatchThreshold {
    /// Mobile Vanilla compares the raw cosine returned by the worker.
    RawCosine(f64),
    /// Historical levels compare the f32 midpoint of one and the raw cosine.
    Normalized(f64),
}

/// Entry `meta` of the compared live frame and its partner in a `LightGuard` capture.
const ILLUMINATED: &[u8] = b"illuminated";
const UNILLUMINATED: &[u8] = b"unilluminated";

/// One engine call with its inputs in role order.
pub enum Operation {
    /// [`PIPELINE_DEEPFACE`] or [`PIPELINE_DEEPFACE_LIGHTGUARD`].
    DeepFace {
        /// The Credential image.
        credential: Vec<u8>,
        /// The live capture.
        live: LiveCapture,
        /// The challenge image.
        challenge: Vec<u8>,
    },
    /// [`PIPELINE_GRAYBADGE`] or [`PIPELINE_GRAYBADGE_LIGHTGUARD`].
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
pub fn threshold(match_strictness: u8) -> Result<MatchThreshold, FailureReason> {
    match match_strictness {
        0 => Ok(MatchThreshold::RawCosine(0.459)),
        1 => Ok(MatchThreshold::Normalized(0.85)),
        2 => Ok(MatchThreshold::Normalized(0.90)),
        3 => Ok(MatchThreshold::Normalized(0.95)),
        _ => Err(FailureReason::UnsupportedMatchStrictness),
    }
}

impl MatchThreshold {
    /// Checks the worker's raw cosine in the units of this threshold.
    ///
    /// # Errors
    /// An invalid cosine is an engine fault. A comparison below the cutoff is a non-match.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "preserve the existing f32 cosine normalization"
    )]
    pub fn check(self, raw: f64, comparison: ComparisonRole) -> Result<(), FailureReason> {
        if !(-1.0..=1.0).contains(&raw) {
            return Err(FailureReason::Internal);
        }
        let matched = match self {
            Self::RawCosine(min) => raw >= min,
            Self::Normalized(min) => f64::from(f32::midpoint(1.0, raw as f32)) >= min,
        };
        if matched {
            Ok(())
        } else {
            Err(FailureReason::MatchBelowThreshold(comparison))
        }
    }
}

/// Maps a validated payload onto an engine operation.
///
/// The live entry, at a fixed `compare` position per Engine operation, is a pipeline input. A
/// release fixes each pipeline's input count (WIP-201 §4.3.4), so a single live frame and a
/// `LightGuard` capture use separate pipelines. A `LightGuard` capture's other frame is the one
/// other pipeline input, and is not compared: the compared frame's `meta` is `illuminated` or
/// `unilluminated`, and the other frame carries the other. All other entry `meta` and the
/// request-level `hints` are empty.
///
/// # Errors
/// Returns [`FailureReason::UnsupportedPipeline`] for an unknown pipeline or another layout.
pub fn operation(payload: Payload) -> Result<Operation, FailureReason> {
    let (live_position, light_guard) = match payload.pipeline_id {
        PIPELINE_DEEPFACE => (1, false),
        PIPELINE_GRAYBADGE => (0, false),
        PIPELINE_DEEPFACE_LIGHTGUARD => (1, true),
        PIPELINE_GRAYBADGE_LIGHTGUARD => (0, true),
        _ => return Err(FailureReason::UnsupportedPipeline),
    };
    if payload.compare.len() != live_position + 2 || !payload.hints.is_empty() {
        return Err(FailureReason::UnsupportedPipeline);
    }
    let live_index = payload.compare[live_position];
    let partner_index = match (light_guard, payload.pipeline_inputs.as_slice()) {
        (false, &[only]) if only == live_index => None,
        (true, &[first, second]) if first == live_index => Some(second),
        (true, &[first, second]) if second == live_index => Some(first),
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
                PIPELINE_GRAYBADGE_LIGHTGUARD,
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
            // A single-frame pipeline gets two frames, and a LightGuard one gets one.
            payload(PIPELINE_DEEPFACE, plain(), vec![1, 2], vec![0, 1]),
            payload(
                PIPELINE_DEEPFACE_LIGHTGUARD,
                plain(),
                vec![1],
                vec![0, 1, 2],
            ),
            // The partner frame is compared.
            payload(
                PIPELINE_DEEPFACE_LIGHTGUARD,
                plain(),
                vec![1, 2],
                vec![0, 1, 2],
            ),
            payload(PIPELINE_DEEPFACE, plain(), vec![0, 1, 2], vec![0, 1, 2]),
            payload(PIPELINE_GRAYBADGE, plain(), vec![0], vec![0, 1]),
            payload(
                PIPELINE_DEEPFACE,
                vec![entry(b"a", b"x"), entry(b"b", b""), entry(b"c", b"")],
                vec![1],
                vec![0, 1, 2],
            ),
            payload(
                PIPELINE_GRAYBADGE_LIGHTGUARD,
                vec![
                    entry(b"a", ILLUMINATED),
                    entry(b"b", b""),
                    entry(b"c", ILLUMINATED),
                ],
                vec![0, 2],
                vec![0, 1],
            ),
            payload(
                PIPELINE_GRAYBADGE_LIGHTGUARD,
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
    fn strictness_levels_use_their_declared_score_units() {
        assert_eq!(threshold(0), Ok(MatchThreshold::RawCosine(0.459)));
        assert_eq!(threshold(1), Ok(MatchThreshold::Normalized(0.85)));
        assert_eq!(threshold(2), Ok(MatchThreshold::Normalized(0.90)));
        assert_eq!(threshold(3), Ok(MatchThreshold::Normalized(0.95)));
        assert_eq!(threshold(4), Err(FailureReason::UnsupportedMatchStrictness));
    }

    #[test]
    fn mobile_cutoff_matches_the_phone_at_adjacent_worker_scores() {
        let role = ComparisonRole::OrbSelfie;
        let threshold = threshold(0).unwrap();
        let below = 0.459_f32;
        let above = below.next_up();
        assert!(f64::from(below) < 0.459 && f64::from(above) > 0.459);
        assert_eq!(
            threshold.check(f64::from(below), role),
            Err(FailureReason::MatchBelowThreshold(role))
        );
        assert_eq!(threshold.check(f64::from(above), role), Ok(()));
    }

    #[test]
    fn existing_levels_keep_their_f32_rounding_and_all_levels_reject_invalid_scores() {
        let role = ComparisonRole::SelfieChallenge;
        // The f32 midpoint of 1 and 0.8 rounds just below the f64 cutoff at level 2.
        assert_eq!(
            threshold(2).unwrap().check(0.8, role),
            Err(FailureReason::MatchBelowThreshold(role))
        );
        assert_eq!(
            threshold(2)
                .unwrap()
                .check(f64::from(0.8_f32.next_up()), role),
            Ok(())
        );
        for level in 0..=3 {
            let threshold = threshold(level).unwrap();
            for raw in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.01, 1.01] {
                assert_eq!(threshold.check(raw, role), Err(FailureReason::Internal));
            }
        }
    }
}
