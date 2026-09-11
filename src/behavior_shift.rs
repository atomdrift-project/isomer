//! Differential fingerprints for calibration, not an additional gate.
//!
//! One maximum weight per ID prevents archive inheritance and repeated matches
//! from inflating a capability. Profiles describe the analyzed pairs: directory
//! comparisons include touched files, whereas archive pairs include all members.
use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Debug, Default)]
pub(crate) struct Profile(BTreeMap<String, f32>);

impl Profile {
    pub(crate) fn observe(&mut self, id: &str, weight: f32) {
        if weight.is_finite() && weight > 0.0 {
            self.0
                .entry(id.to_owned())
                .and_modify(|value| *value = value.max(weight))
                .or_insert(weight);
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Profiles {
    pub old: Profile,
    pub new: Profile,
    pub incomplete: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct Shift {
    pub population: &'static str,
    pub complete: bool,
    pub behavior: Weights,
    pub other_traits: Weights,
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct Weights {
    pub old: f32,
    pub new: f32,
    pub gained: f32,
    pub lost: f32,
    /// Weighted symmetric change / larger fingerprint, capped like Cleave ROC.
    pub roc: f32,
}

fn behavioral(id: &str) -> bool {
    id.starts_with("micro-behaviors/") || id.starts_with("objectives/")
}

impl Profiles {
    pub(crate) fn shift(&self) -> Shift {
        let mut result = Shift {
            population: "analyzed_pairs_unique_trait_ids",
            complete: !self.incomplete,
            behavior: Weights::default(),
            other_traits: Weights::default(),
        };
        for id in self
            .old
            .0
            .keys()
            .chain(self.new.0.keys().filter(|id| !self.old.0.contains_key(*id)))
        {
            let old = self.old.0.get(id).copied().unwrap_or_default();
            let new = self.new.0.get(id).copied().unwrap_or_default();
            let weights = if behavioral(id) {
                &mut result.behavior
            } else {
                &mut result.other_traits
            };
            weights.old += old;
            weights.new += new;
            weights.gained += (new - old).max(0.0);
            weights.lost += (old - new).max(0.0);
        }
        for weights in [&mut result.behavior, &mut result.other_traits] {
            let denominator = weights.old.max(weights.new);
            if denominator > 0.0 {
                weights.roc = ((weights.gained + weights.lost) / denominator).min(1.0);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_behavior_is_denominator_not_metadata() {
        let mut profiles = Profiles::default();
        profiles.old.observe("micro-behaviors/fs/read", 4.0);
        profiles.new.observe("micro-behaviors/fs/read", 4.0);
        profiles.new.observe("objectives/exfiltration/send", 2.0);
        profiles.new.observe("metadata/version", 100.0);
        let shift = profiles.shift();
        assert_eq!(shift.behavior.old, 4.0);
        assert_eq!(shift.behavior.new, 6.0);
        assert_eq!(shift.behavior.roc, 1.0 / 3.0);
        assert_eq!(shift.other_traits.roc, 1.0);
    }

    #[test]
    fn duplicates_and_confidence_changes_are_directional() {
        let mut profiles = Profiles::default();
        for weight in [1.0, 3.0, 2.0] {
            profiles.old.observe("objectives/execution/run", weight);
        }
        profiles.new.observe("objectives/execution/run", 1.0);
        let shift = profiles.shift();
        assert_eq!(shift.behavior.old, 3.0);
        assert_eq!(shift.behavior.gained, 0.0);
        assert_eq!(shift.behavior.lost, 2.0);
    }

    #[test]
    fn empty_invalid_and_missing_analysis_are_not_positive_evidence() {
        let mut profiles = Profiles::default();
        for weight in [0.0, -1.0, f32::NAN, f32::INFINITY] {
            profiles.old.observe("objectives/execution/run", weight);
        }
        profiles.incomplete = true;
        let shift = profiles.shift();
        assert!(!shift.complete);
        assert_eq!(shift.behavior.roc, 0.0);
    }

    #[test]
    fn equal_weight_replacement_is_change_but_not_net_growth() {
        let mut profiles = Profiles::default();
        profiles.old.observe("micro-behaviors/fs/read", 3.0);
        profiles.new.observe("micro-behaviors/net/connect", 3.0);
        let shift = profiles.shift();
        assert_eq!(shift.behavior.roc, 1.0);
        assert_eq!(shift.behavior.gained, 3.0);
        assert_eq!(shift.behavior.lost, 3.0);
        assert_eq!(shift.behavior.old, shift.behavior.new);
    }
}
