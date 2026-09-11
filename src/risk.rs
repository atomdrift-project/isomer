//! Risk scoring via the azoth ML model that scan uses.
//!
//! The rubric judges *what* capabilities changed; azoth answers *how malicious
//! does the model think each side is*. Probabilities are diagnostic context:
//! routes and calibrated cutoffs can differ, even for two releases of the same
//! artifact. Preserve the model's decision rather than inferring maliciousness
//! from a universal probability cutoff.
//!
//! Scoring degrades gracefully: if the model bundle can't be found or loaded,
//! risk is simply absent from the report rather than an error.

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
}

/// The process-wide analyzer, loaded once. `None` when no model bundle is
/// available — scoring is then skipped, not fatal.
fn analyzer() -> Option<&'static scan::Analyzer> {
    static ANALYZER: OnceLock<Option<scan::Analyzer>> = OnceLock::new();
    ANALYZER
        .get_or_init(|| {
            let dir = scan::models_repo::model_dir().ok()?;
            scan::Analyzer::load(dir).ok()
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
    let analyzer = analyzer()?;
    let scan = |p: Option<&Path>| {
        let p = p?;
        analyzer.scan_file(p, &crate::analysis::basename(p)).ok()
    };
    pairs
        .iter()
        .filter_map(|pair| {
            let new = scan(pair.new.as_deref())?;
            // A file with no base side is new: it introduced whatever risk it
            // carries, so the old side reads as zero rather than unknown.
            Some(Risk {
                old: scan(pair.old.as_deref()).map_or(0.0, |s| s.probability),
                new: new.probability,
                new_classification: new.classification,
            })
        })
        .max_by(|a, b| a.new.total_cmp(&b.new))
}
