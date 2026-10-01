//! Risk scoring via the azoth ML model that scan uses.
//!
//! The rubric judges *what* capabilities changed; azoth answers *how malicious
//! does the model think each side is*. Probabilities are diagnostic context:
//! routes and calibrated cutoffs can differ, even for two releases of the same
//! artifact. Preserve the model's decision rather than inferring maliciousness
//! from a universal probability cutoff.
//!
//! Scoring degrades gracefully: if no model bundle is installed, risk is simply
//! absent from the report rather than an error. Installing one is a network
//! step and never happens here — the command line does it up front, unless
//! `--offline`.

use std::path::Path;
use std::sync::OnceLock;

/// Model malware-probabilities for the two sides of a diff, in `[0, 1]`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Risk {
    pub old: f32,
    pub new: f32,
    pub new_classification: scan::Classification,
}

impl Risk {
    /// Severity allowed by the model's calibrated decision, not a raw score band.
    pub(crate) fn model_severity(self) -> crate::Severity {
        use crate::Severity;
        match self.new_classification {
            scan::Classification::Suspicious => Severity::High,
            scan::Classification::Hostile => Severity::Critical,
            _ => Severity::None,
        }
    }

    /// Change in model risk from old to new. Positive means the new release
    /// looks more dangerous to the model.
    pub(crate) fn delta(self) -> f32 {
        self.new - self.old
    }

    /// This risk with its new score raised to at least `floor` — how an
    /// interpreter's call is shown against the measurement, which itself is
    /// never changed.
    pub(crate) fn floored(self, floor: f32) -> Self {
        Self {
            new: self.new.max(floor),
            ..self
        }
    }

    /// Which way the model's read moved. A change under half a point is
    /// jitter, not a direction.
    pub(crate) fn trend(self) -> Trend {
        const JITTER: f32 = 0.005;
        let d = self.delta();
        if d > JITTER {
            Trend::Up
        } else if d < -JITTER {
            Trend::Down
        } else {
            Trend::Flat
        }
    }

    /// Whether [`floored`](Self::floored) would raise the new score.
    pub(crate) fn raised_by(self, floor: f32) -> bool {
        self.new < floor
    }
}

/// Which way a risk score moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Trend {
    Up,
    Down,
    Flat,
}

impl Trend {
    /// The arrow every renderer draws for it.
    pub(crate) fn arrow(self) -> &'static str {
        match self {
            Self::Up => "▲",
            Self::Down => "▼",
            Self::Flat => "·",
        }
    }
}

/// The process-wide analyzer, loaded once from the installed model bundle.
///
/// `None` when no bundle is installed — scoring is then skipped, not fatal. A
/// bundle that is present but will not load is said once: a silently missing
/// risk line reads exactly like a model with nothing to say.
fn analyzer() -> Option<&'static scan::Analyzer> {
    static ANALYZER: OnceLock<Option<scan::Analyzer>> = OnceLock::new();
    ANALYZER
        .get_or_init(|| {
            // `install_target`, not `model_dir`: the latter downloads a missing
            // bundle, and the library must not touch the network on its own.
            let dir = scan::models_repo::install_target();
            if !dir.is_dir() {
                return None;
            }
            match scan::Analyzer::load(&dir) {
                Ok(analyzer) => Some(analyzer),
                Err(e) => {
                    log::warn!("ML risk scoring unavailable ({}): {e:#}", dir.display());
                    None
                }
            }
        })
        .as_ref()
}

/// Score every changed file and report the most dangerous one — the file whose
/// new side scores highest, alongside that same file's old score. A change is
/// as suspicious as its worst file, and averaging would let one backdoor hide
/// behind a hundred benign edits.
///
/// Returns `None` if the model is unavailable or nothing scored — risk is
/// optional context, never a hard dependency.
pub(crate) fn score(pairs: &[crate::analysis::Pair]) -> Option<Risk> {
    // Nothing to score is not a reason to load the model.
    if pairs.iter().all(|pair| pair.new.is_none()) {
        return None;
    }
    let analyzer = analyzer()?;
    let scan = |p: Option<&Path>| {
        let p = p?;
        analyzer.scan_file(p, &crate::analysis::basename(p)).ok()
    };
    // The worst new side first; only that file's base is then scored, rather
    // than running the model over every base for one number.
    let (pair, new) = pairs
        .iter()
        .filter_map(|pair| Some((pair, scan(pair.new.as_deref())?)))
        .max_by(|a, b| a.1.probability.total_cmp(&b.1.probability))?;
    // A file with no base side is new: it introduced whatever risk it
    // carries, so the old side reads as zero rather than unknown.
    Some(Risk {
        old: scan(pair.old.as_deref()).map_or(0.0, |s| s.probability),
        new: new.probability,
        new_classification: new.classification,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_floor_only_ever_raises_the_shown_score() {
        let risk = Risk {
            old: 0.1,
            new: 0.3,
            new_classification: scan::Classification::Benign,
        };
        assert!((risk.floored(0.9).new - 0.9).abs() < f32::EPSILON);
        assert!(risk.raised_by(0.9));
        // A floor below the measurement leaves it alone.
        assert!((risk.floored(0.2).new - 0.3).abs() < f32::EPSILON);
        assert!(!risk.raised_by(0.2));
        // The old side is never touched.
        assert!((risk.floored(0.9).old - 0.1).abs() < f32::EPSILON);
    }
}
