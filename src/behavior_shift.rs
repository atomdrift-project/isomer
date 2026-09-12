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

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Shift {
    pub population: &'static str,
    pub complete: bool,
    pub behavior: Weights,
    pub other_traits: Weights,
}

impl Shift {
    /// Share of the artifact's behavioral mass that this change introduced.
    ///
    /// The denominator is the larger of the two sides, so a release that keeps
    /// everything it had and adds as much again reads as `0.5`, and one whose
    /// behavior is wholly new reads as `1.0`. Removal does not enter: a
    /// remediation that strips a backdoor moves [`Weights::lost`], not this.
    pub(crate) fn injected_share(&self) -> f32 {
        let denominator = self.behavior.old.max(self.behavior.new);
        if denominator > 0.0 {
            (self.behavior.gained / denominator).min(1.0)
        } else {
            0.0
        }
    }

    /// Criticality-weighted mass of behavior the new side gained.
    pub(crate) fn injected_mass(&self) -> f32 {
        self.behavior.gained
    }

    /// Share of the artifact's *distinct behaviors* that are new, counting
    /// each trait id once and grading none of them.
    ///
    /// This is the criticality-blind twin of [`Self::injected_share`], and the
    /// one that still reads true when the payload matches no rule worth a
    /// severity: a library that could do 40 things and now does 100 has been
    /// rebuilt around something, whatever any rule thinks of the parts.
    pub(crate) fn injected_id_share(&self) -> f32 {
        let denominator = self.behavior.ids_old.max(self.behavior.ids_new);
        if denominator > 0 {
            // Both counts are small enough that f32 represents them exactly;
            // the ratio is a display/threshold value, not an accumulator.
            self.behavior.ids_gained as f32 / denominator as f32
        } else {
            0.0
        }
    }

    /// Count of distinct behaviors the new side gained.
    pub(crate) fn injected_ids(&self) -> u32 {
        self.behavior.ids_gained
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct Weights {
    pub old: f32,
    pub new: f32,
    pub gained: f32,
    pub lost: f32,
    /// Weighted symmetric change / larger fingerprint, capped like Cleave ROC.
    pub roc: f32,
    /// The same three quantities counted in *distinct trait ids*, with no
    /// criticality weighting at all. Weight answers "how bad is the worst
    /// thing that arrived"; these answer "how much of what this artifact does
    /// is new" — the reading that survives when no rule grades the payload.
    pub ids_old: u32,
    pub ids_new: u32,
    pub ids_gained: u32,
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
            weights.ids_old += u32::from(old > 0.0);
            weights.ids_new += u32::from(new > 0.0);
            weights.ids_gained += u32::from(old == 0.0 && new > 0.0);
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

    /// Counting ids is the criticality-blind reading: one `notable` capability
    /// and one `hostile` objective each move the count by one, though their
    /// weights differ by two orders of magnitude. That is the point — it is
    /// the measure that still works when nothing grades the payload.
    #[test]
    fn ids_are_counted_without_regard_to_weight() {
        let mut profiles = Profiles::default();
        profiles.old.observe("micro-behaviors/fs/read", 1.0);
        profiles.new.observe("micro-behaviors/fs/read", 1.0);
        profiles.new.observe("micro-behaviors/net/connect", 1.0);
        profiles.new.observe("objectives/exfiltration/send", 120.0);
        // Not behavioral: neither weight nor count may enter the behavior row.
        profiles.new.observe("metadata/version", 100.0);
        let shift = profiles.shift();
        assert_eq!(shift.behavior.ids_old, 1);
        assert_eq!(shift.behavior.ids_new, 3);
        assert_eq!(shift.behavior.ids_gained, 2);
        assert_eq!(shift.injected_ids(), 2);
        assert!((shift.injected_id_share() - 2.0 / 3.0).abs() < 1e-6);
        assert_eq!(shift.other_traits.ids_gained, 1);
        // The weighed reading of the same change is dominated by the one
        // hostile id; the counted one is not.
        assert!(shift.injected_share() > 0.98);
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
