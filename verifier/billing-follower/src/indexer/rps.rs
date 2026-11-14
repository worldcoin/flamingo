use std::collections::{BTreeMap, HashMap};

use flamingo_verifier_billing_state::BillingOp;
use world_id_primitives::rp::RpId;

type Position = (u64, u64, u64);

pub(super) struct Projection {
    rps: BTreeMap<u64, Rp>,
    ids: HashMap<String, (u64, Position)>,
    highwater: u64,
    window: u64,
    max_events: usize,
    events: usize,
    billed: usize,
    snapshot: bool,
}

#[derive(Default)]
struct Rp {
    baseline: Option<(Position, Event)>,
    recent: BTreeMap<Position, Event>,
}

struct Event {
    id: String,
    billed: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(super) enum ProjectionError {
    #[error("billing RP undo history is unavailable; a new snapshot is required")]
    HistoryUnavailable,
    #[error("inconsistent billing RP event identity or position")]
    InvalidEvent,
    #[error("billing RP projection capacity exceeded")]
    Capacity,
}

impl Projection {
    pub(super) fn new(window: u64, max_events: usize) -> Self {
        Self {
            rps: BTreeMap::new(),
            ids: HashMap::new(),
            highwater: 0,
            window,
            max_events,
            events: 0,
            billed: 0,
            snapshot: true,
        }
    }

    pub(super) fn advance(&mut self, head: u64) {
        self.highwater = self.highwater.max(head);
        let cutoff = self.highwater.saturating_sub(self.window);
        for rp in self.rps.values_mut() {
            while rp
                .recent
                .first_key_value()
                .is_some_and(|(position, _)| position.0 < cutoff)
            {
                let (position, event) = rp.recent.pop_first().expect("first event exists");
                if let Some((_, previous)) = rp.baseline.replace((position, event)) {
                    self.ids.remove(&previous.id);
                    self.events -= 1;
                }
            }
        }
        self.drop_unbilled_baselines();
    }

    pub(super) fn add(
        &mut self,
        rp: u64,
        block: u64,
        transaction_index: u64,
        log_index: u64,
        id: &str,
        billed: bool,
    ) -> Result<Option<BillingOp>, ProjectionError> {
        let position = (block, transaction_index, log_index);
        self.validate_identity(rp, position, id)?;
        if let Some(event) = self.rps.get(&rp).and_then(|rp| rp.event(position)) {
            return if event.id == id && event.billed == billed {
                Ok(None)
            } else {
                Err(ProjectionError::InvalidEvent)
            };
        }
        let old = block < self.highwater.saturating_sub(self.window);
        // Dropping an old false baseline after bootstrap loses the information
        // needed to fold another old event safely.
        if old && !self.snapshot {
            return Err(ProjectionError::HistoryUnavailable);
        }
        let state = self.rps.get(&rp);
        if old && state.is_some_and(|s| s.baseline.as_ref().is_some_and(|(p, _)| *p > position)) {
            return Ok(None);
        }
        let replaces_baseline = old && state.is_some_and(|s| s.baseline.is_some());
        if !replaces_baseline && self.events >= self.max_events {
            return Err(ProjectionError::Capacity);
        }
        let state = self.rps.entry(rp).or_default();
        let previous = state.billed();
        let event = Event {
            id: id.into(),
            billed,
        };
        if old {
            if let Some((_, replaced)) = state.baseline.replace((position, event)) {
                self.ids.remove(&replaced.id);
                self.events -= 1;
            }
        } else {
            state.recent.insert(position, event);
        }
        self.ids.insert(id.into(), (rp, position));
        self.events += 1;
        let current = state.billed();
        Ok(self.change(rp, previous, current))
    }

    pub(super) fn remove(
        &mut self,
        rp: u64,
        block: u64,
        transaction_index: u64,
        log_index: u64,
        id: &str,
        billed: bool,
    ) -> Result<Option<BillingOp>, ProjectionError> {
        let position = (block, transaction_index, log_index);
        self.validate_identity(rp, position, id)?;
        let state = self
            .rps
            .get_mut(&rp)
            .ok_or(ProjectionError::HistoryUnavailable)?;
        let event = state
            .event(position)
            .ok_or(ProjectionError::HistoryUnavailable)?;
        if event.id != id || event.billed != billed {
            return Err(ProjectionError::InvalidEvent);
        }
        if !state.recent.contains_key(&position) {
            return Err(ProjectionError::HistoryUnavailable);
        }
        let previous = state.billed();
        state.recent.remove(&position);
        self.ids.remove(id);
        self.events -= 1;
        let current = state.billed();
        if !self.snapshot && state.recent.is_empty() && !current {
            let state = self.rps.remove(&rp).expect("RP exists");
            if let Some((_, baseline)) = state.baseline {
                self.ids.remove(&baseline.id);
                self.events -= 1;
            }
        }
        Ok(self.change(rp, previous, current))
    }

    pub(super) fn finish_snapshot(&mut self) {
        self.snapshot = false;
        self.drop_unbilled_baselines();
    }

    pub(super) fn snapshot_after(&self, after: Option<u64>, limit: usize) -> Vec<BillingOp> {
        use std::ops::Bound::{Excluded, Unbounded};
        self.rps
            .range((after.map_or(Unbounded, Excluded), Unbounded))
            .filter(|(_, state)| state.billed())
            .take(limit)
            .map(|(&rp, _)| BillingOp::SetBilledRp {
                rp_id: RpId::new(rp),
                billed: true,
            })
            .collect()
    }

    pub(super) fn len(&self) -> usize {
        self.events
    }

    pub(super) fn billed_len(&self) -> usize {
        self.billed
    }

    fn validate_identity(
        &self,
        rp: u64,
        position: Position,
        id: &str,
    ) -> Result<(), ProjectionError> {
        if id.is_empty()
            || id.len() > 256
            || self
                .ids
                .get(id)
                .is_some_and(|entry| *entry != (rp, position))
        {
            return Err(ProjectionError::InvalidEvent);
        }
        Ok(())
    }

    fn change(&mut self, rp: u64, previous: bool, billed: bool) -> Option<BillingOp> {
        if previous == billed {
            return None;
        }
        if billed {
            self.billed += 1;
        } else {
            self.billed -= 1;
        }
        Some(BillingOp::SetBilledRp {
            rp_id: RpId::new(rp),
            billed,
        })
    }

    fn drop_unbilled_baselines(&mut self) {
        if self.snapshot {
            return;
        }
        self.rps.retain(|_, rp| {
            if !rp.recent.is_empty() || rp.billed() {
                return true;
            }
            if let Some((_, event)) = &rp.baseline {
                self.ids.remove(&event.id);
                self.events -= 1;
            }
            false
        });
    }
}

impl Rp {
    fn billed(&self) -> bool {
        self.recent
            .last_key_value()
            .map(|(_, event)| event)
            .or_else(|| self.baseline.as_ref().map(|(_, event)| event))
            .is_some_and(|event| event.billed)
    }

    fn event(&self, position: Position) -> Option<&Event> {
        self.recent.get(&position).or_else(|| {
            self.baseline
                .as_ref()
                .filter(|(p, _)| *p == position)
                .map(|(_, event)| event)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(rp: u64, billed: bool) -> Option<BillingOp> {
        Some(BillingOp::SetBilledRp {
            rp_id: RpId::new(rp),
            billed,
        })
    }

    #[test]
    fn unordered_snapshot_preserves_false_baselines() {
        let mut projection = Projection::new(2, 4);
        projection.advance(10);
        assert_eq!(projection.add(7, 5, 0, 0, "new", false), Ok(None));
        assert_eq!(projection.add(7, 1, 0, 0, "old", true), Ok(None));
        assert_eq!(projection.add(7, 3, 0, 0, "middle", true), Ok(None));
        assert_eq!(projection.len(), 1);
        assert_eq!(projection.billed_len(), 0);
        assert!(projection.snapshot_after(None, 10).is_empty());
        projection.finish_snapshot();
        assert_eq!(projection.len(), 0);
        assert_eq!(
            projection.add(7, 1, 0, 0, "old", true),
            Err(ProjectionError::HistoryUnavailable)
        );
    }

    #[test]
    fn removing_recent_events_restores_prior_true_and_false_values() {
        let mut projection = Projection::new(2, 4);
        projection.advance(10);
        assert_eq!(projection.add(7, 1, 0, 0, "base", true), Ok(op(7, true)));
        assert_eq!(projection.add(7, 9, 0, 0, "off", false), Ok(op(7, false)));
        assert_eq!(projection.add(7, 10, 0, 0, "on", true), Ok(op(7, true)));
        projection.finish_snapshot();
        assert_eq!(projection.remove(7, 10, 0, 0, "on", true), Ok(op(7, false)));
        assert_eq!(projection.remove(7, 9, 0, 0, "off", false), Ok(op(7, true)));
        assert_eq!(projection.billed_len(), 1);

        let mut projection = Projection::new(2, 4);
        projection.advance(10);
        projection.add(7, 1, 0, 0, "base", false).unwrap();
        projection.add(7, 9, 0, 0, "on", true).unwrap();
        projection.finish_snapshot();
        assert_eq!(projection.remove(7, 9, 0, 0, "on", true), Ok(op(7, false)));
        assert_eq!(projection.len(), 0);
        assert_eq!(projection.billed_len(), 0);
    }

    #[test]
    fn repeated_flags_and_duplicate_events_are_idempotent() {
        let mut projection = Projection::new(10, 4);
        projection.add(7, 1, 0, 0, "first", true).unwrap();
        assert_eq!(projection.add(7, 2, 0, 0, "second", true), Ok(None));
        assert_eq!(projection.add(7, 2, 0, 0, "second", true), Ok(None));
        projection.finish_snapshot();
        assert_eq!(projection.remove(7, 2, 0, 0, "second", true), Ok(None));
        assert_eq!(
            projection.snapshot_after(None, 10),
            vec![op(7, true).unwrap()]
        );
        assert_eq!(projection.len(), 1);
    }

    #[test]
    fn snapshot_pages_are_sorted_bounded_and_skip_false_rps() {
        let mut projection = Projection::new(10, 10);
        for (rp, billed) in [(15, true), (4, false), (2, true), (7, true)] {
            projection
                .add(rp, rp, 0, 0, &rp.to_string(), billed)
                .unwrap();
        }
        projection.finish_snapshot();
        assert_eq!(
            projection.snapshot_after(None, 2),
            vec![op(2, true).unwrap(), op(7, true).unwrap()]
        );
        assert_eq!(
            projection.snapshot_after(Some(7), 2),
            vec![op(15, true).unwrap()]
        );
        assert!(projection.snapshot_after(Some(u64::MAX), 2).is_empty());
        assert!(projection.snapshot_after(None, 0).is_empty());
        assert_eq!(projection.billed_len(), 3);
    }

    #[test]
    fn advancing_prunes_history_without_moving_the_highwater_backwards() {
        let mut projection = Projection::new(2, 4);
        projection.advance(10);
        projection.add(7, 1, 0, 0, "base", true).unwrap();
        projection.add(7, 8, 0, 0, "off", false).unwrap();
        projection.add(7, 9, 0, 0, "on", true).unwrap();
        projection.finish_snapshot();
        projection.advance(12);
        assert_eq!(projection.len(), 1);
        assert_eq!(projection.billed_len(), 1);
        projection.advance(10);
        assert_eq!(
            projection.remove(7, 9, 0, 0, "on", true),
            Err(ProjectionError::HistoryUnavailable)
        );
        assert_eq!(
            projection.remove(7, 8, 0, 0, "off", false),
            Err(ProjectionError::HistoryUnavailable)
        );
        assert_eq!(
            projection.add(8, 9, 0, 0, "late", true),
            Err(ProjectionError::HistoryUnavailable)
        );
        assert_eq!(
            projection.snapshot_after(None, 10),
            vec![op(7, true).unwrap()]
        );
    }

    #[test]
    fn inconsistent_events_and_capacity_errors_do_not_change_state() {
        let mut projection = Projection::new(2, 2);
        projection.advance(10);
        projection.add(7, 1, 0, 0, "base", true).unwrap();
        projection.add(7, 9, 0, 0, "recent", false).unwrap();
        assert_eq!(
            projection.add(7, 9, 0, 0, "changed", false),
            Err(ProjectionError::InvalidEvent)
        );
        assert_eq!(
            projection.add(7, 9, 0, 0, "recent", true),
            Err(ProjectionError::InvalidEvent)
        );
        assert_eq!(
            projection.add(8, 9, 0, 0, "recent", false),
            Err(ProjectionError::InvalidEvent)
        );
        assert_eq!(
            projection.add(7, 10, 0, 0, "recent", false),
            Err(ProjectionError::InvalidEvent)
        );
        assert_eq!(
            projection.remove(7, 9, 0, 0, "recent", true),
            Err(ProjectionError::InvalidEvent)
        );
        assert_eq!(
            projection.add(8, 10, 0, 0, "extra", true),
            Err(ProjectionError::Capacity)
        );
        assert_eq!(projection.add(7, 5, 0, 0, "new-base", true), Ok(None));
        assert_eq!(projection.len(), 2);
        assert_eq!(projection.billed_len(), 0);
        assert!(projection.snapshot_after(None, 10).is_empty());
        assert_eq!(
            projection.remove(8, 10, 0, 0, "missing", true),
            Err(ProjectionError::HistoryUnavailable)
        );
        assert_eq!(
            projection.remove(7, 5, 0, 0, "new-base", true),
            Err(ProjectionError::HistoryUnavailable)
        );
        assert_eq!(
            projection.add(8, 10, 0, 0, "", true),
            Err(ProjectionError::InvalidEvent)
        );
        assert_eq!(
            projection.add(8, 10, 0, 0, &"x".repeat(257), true),
            Err(ProjectionError::InvalidEvent)
        );
        assert_eq!(projection.len(), 2);
    }
}
