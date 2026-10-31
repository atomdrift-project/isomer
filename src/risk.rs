//! Risk scoring via the azoth ML model that scan uses.
//!
//! The rubric judges *what* capabilities changed; azoth answers *how malicious
//! does the model think each side is*. Probabilities are diagnostic context:
//! routes and calibrated cutoffs can differ, even for two releases of the same
//! artifact. Preserve the model's decision rather than inferring maliciousness
//! from a universal probability cutoff.
//!
//! A side with [changed lines](crate::changed_lines) is read twice: the whole
//! file, and the lines the change removed or added. The model judges a file as
//! a whole, so an implant prepended to a multi-megabyte bundle is a sliver of
//! the whole file's features — but all of its changed lines'. The graver of the
//! two readings stands for the side.
//!
//! Scoring degrades gracefully: if no model bundle is installed, risk is simply
//! absent from the report rather than an error. Installing one is a network
//! step and never happens here — the command line does it up front, unless
//! `--offline`.

use std::cmp::Ordering;
use std::path::Path;
use std::sync::OnceLock;

use scan::Classification;
use scan::model::Level;

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
            let dir = scan::models_repo::install_target().ok()?;
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
/// new side reads gravest, alongside that same file's old reading. A change is
/// as suspicious as its worst file, and averaging would let one backdoor hide
/// behind a hundred benign edits.
///
/// Returns `None` if the model is unavailable or nothing scored — risk is
/// optional context, never a hard dependency.
pub(crate) fn score(
    pairs: &[crate::analysis::Pair],
    changed: &crate::changed_lines::ChangedLines,
) -> Option<Risk> {
    // Nothing to score is not a reason to load the model.
    if pairs.iter().all(|pair| pair.new.is_none()) {
        return None;
    }
    let analyzer = analyzer()?;
    // The worst new side first; only that file's base is then scored, rather
    // than running the model over every base for one number.
    let (index, pair, new) = pairs
        .iter()
        .enumerate()
        .filter_map(|(index, pair)| {
            let added = changed.of(index).filter_map(|lines| lines.new.as_deref());
            Some((index, pair, side(analyzer, pair.new.as_deref()?, added)?))
        })
        .reduce(|worst, next| {
            if next.2.outranks(worst.2) {
                next
            } else {
                worst
            }
        })?;
    let removed = changed.of(index).filter_map(|lines| lines.old.as_deref());
    let old = pair
        .old
        .as_deref()
        .and_then(|path| side(analyzer, path, removed));
    // A file with no base side is new: it introduced whatever risk it
    // carries, so the old side reads as zero rather than unknown.
    Some(Risk {
        old: old.map_or(0.0, |r| r.probability),
        new: new.probability,
        new_classification: new.class,
    })
}

/// One side's reading: its whole file, or the gravest of its `changed` lines —
/// the file's own, or each changed member's when the side is an archive — when
/// those read graver.
fn side<'p>(
    analyzer: &scan::Analyzer,
    path: &Path,
    changed: impl Iterator<Item = &'p Path>,
) -> Option<Reading> {
    let read = |path: &Path, what: &str| match analyzer
        .scan_file(path, &crate::analysis::basename(path))
    {
        Ok(r) => {
            let reading = Reading {
                class: r.classification,
                level: r.level,
                probability: r.probability,
            };
            log::debug!(
                "risk: {} {what} reads {} at {} (p={:.4})",
                path.display(),
                reading.class,
                reading.level,
                reading.probability,
            );
            Some(reading)
        }
        Err(e) => {
            log::debug!("risk: {} {what} not scored: {e:#}", path.display());
            None
        }
    };
    let whole = read(path, "whole file");
    changed
        .filter_map(|lines| read(lines, "changed lines"))
        .fold(whole, |worst, next| match worst {
            Some(worst) if !next.outranks(worst) => Some(worst),
            _ => Some(next),
        })
}

/// One model verdict, reduced to what ranks it against another.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Reading {
    class: Classification,
    level: Level,
    probability: f32,
}

impl Reading {
    /// Whether this reading is graver than `other`, by the rule scan ranks its
    /// own decisions with: the graver class, then the tighter firing level,
    /// then the higher probability. Probabilities from different routes are
    /// not on one scale, so they only break what remains.
    fn outranks(self, other: Self) -> bool {
        match self.class.cmp(&other.class) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => match (self.level, other.level) {
                (Level::At(a), Level::At(b)) if a != b => a < b,
                (Level::At(_), Level::Clean) => true,
                (Level::Clean, Level::At(_)) => false,
                _ => self.probability > other.probability,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readings_rank_by_class_then_level_then_probability() {
        let reading = |class, level, probability| Reading {
            class,
            level,
            probability,
        };
        let hostile = reading(Classification::Hostile, Level::At(50), 0.6);
        let benign = reading(Classification::Benign, Level::Clean, 0.8);
        // A graver class outranks a higher probability from another route.
        assert!(hostile.outranks(benign));
        assert!(!benign.outranks(hostile));
        // Within a class, the tighter level wins over probability.
        let tight = reading(Classification::Hostile, Level::At(1), 0.5);
        assert!(tight.outranks(hostile));
        let clean = reading(Classification::Hostile, Level::Clean, 0.99);
        assert!(hostile.outranks(clean));
        assert!(!clean.outranks(hostile));
        // Probability breaks what remains, and a tie is not an outranking.
        let higher = reading(Classification::Benign, Level::Clean, 0.9);
        assert!(higher.outranks(benign));
        assert!(!benign.outranks(benign));
    }

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
