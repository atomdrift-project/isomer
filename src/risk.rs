//! Risk scoring via the azoth ML model that scan uses.
//!
//! The rubric judges *what* capabilities changed; azoth answers *how malicious
//! does the model think each side is*. Because both sides are the same artifact
//! on the same classifier route (`liblzma.so` 5.4.5 vs 5.6.0), their scores are
//! directly comparable — the cross-file caveat that makes absolute scores
//! incomparable does not apply within a diff. So the delta is meaningful: it is
//! the model's opinion of how much more dangerous the new release is.
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
}

impl Risk {
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
    let probability = |p: Option<&Path>| -> Option<f32> {
        let p = p?;
        Some(analyzer.scan_file(p, &basename(p)).ok()?.probability)
    };
    pairs
        .iter()
        .filter_map(|pair| {
            let new = probability(pair.new.as_deref())?;
            // A file with no base side is new: it introduced whatever risk it
            // carries, so the old side reads as zero rather than unknown.
            Some(Risk {
                old: probability(pair.old.as_deref()).unwrap_or(0.0),
                new,
            })
        })
        .max_by(|a, b| a.new.total_cmp(&b.new))
}

fn basename(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}
