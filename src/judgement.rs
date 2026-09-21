//! Judging one comparison, for a caller that is not a command line.
//!
//! [`judge`] is what the `fs` verb does without the printing: it compares two
//! paths, applies the rubric, and hands back the verdict and the JSON envelope
//! together. A caller that wants the terminal, SARIF or Markdown renders goes
//! through [`crate::analysis::Analysis`] as the binary does.

use std::path::Path;

use anyhow::Result;
use serde_json::value::RawValue;

use crate::analysis::{self, Analysis};
use crate::llm::Interpretation;
use crate::options::Options;
use crate::{Format, Severity};

/// What isomer concluded about one comparison.
///
/// The verdict is reported at two stages, because they have different
/// authorities behind them. [`Judgement::deterministic`] is the rubric alone:
/// reproducible from the bytes, the traits and the model. [`Judgement::severity`]
/// is that after the interpreter has had its say, which it only ever does when
/// [`Options::llm`] asked for one. A caller that reports the two engines
/// separately reads both; a caller that just wants the answer reads the second.
#[derive(Debug, Clone)]
pub struct Judgement {
    /// The verdict for the change, after the interpreter.
    pub severity: Severity,
    /// The verdict before the interpreter — the rubric's own reading.
    pub deterministic: Severity,
    /// The verdict counting only newly-introduced risk.
    pub new_severity: Severity,
    /// The verdict the exit code gates on, per [`Options::gate`].
    pub gated: Severity,
    /// Whether the run is clean at [`Options::fail_on`].
    pub clean: bool,
    /// The interpreter's reading, when one ran.
    pub interpretation: Option<Interpretation>,
    /// The full JSON envelope, exactly as `--format json` emits it.
    ///
    /// Kept pre-serialized rather than parsed into a tree: every caller so far
    /// forwards it somewhere rather than reading inside it, and a `RawValue`
    /// embeds into a larger document without a parse or a re-encode.
    pub report: Box<RawValue>,
}

/// Compare two paths and judge the difference.
///
/// Argument order is old, then new, as everywhere else in isomer. The
/// comparison is the `fs` one — two trees or two archives already on disk —
/// and the envelope records it as such.
///
/// The interpreter runs when [`Options::llm`] names an endpoint, under the
/// same rules the command line applies: it can only raise the verdict, never
/// lower it, and never moves [`Judgement::deterministic`] or the gate.
///
/// # Errors
///
/// Returns the underlying failure when either side cannot be analyzed, or
/// when the envelope cannot be serialized.
pub fn judge(old: &Path, new: &Path, opts: &Options) -> Result<Judgement> {
    // Source archives are compared member-by-member; matching the `fs` verb
    // here keeps a library caller and the command line on one code path.
    let all_source_members = analysis::is_source_archive(old) && analysis::is_source_archive(new);
    let options = cleave::AnalysisOptions {
        all_files: all_source_members,
        ..cleave::AnalysisOptions::default()
    };
    let report = analysis::diff(old, new, &options)?;
    let mut analysis = Analysis::new("fs", old, new, &options, &report, opts)?;
    analysis.finish(opts);

    // `render` rather than `json` so the two stay one code path: a divergence
    // would give a library caller a different envelope than `--format json`.
    let json = analysis.render(Format::Json, opts)?;
    Ok(Judgement {
        severity: analysis.verdict,
        deterministic: analysis.deterministic_verdict,
        new_severity: analysis.new_verdict,
        gated: analysis.gated,
        clean: analysis.clean,
        interpretation: analysis.interp.clone(),
        report: RawValue::from_string(json.trim_end().to_owned())?,
    })
}
