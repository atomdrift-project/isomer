//! Judging one comparison, for a caller that is not a command line.
//!
//! [`judge`] is what the `fs` verb does, with the verdict broken out: it
//! compares two paths, applies the rubric, and hands back the verdict and the
//! JSON envelope together. A caller that wants the terminal, SARIF or Markdown
//! render calls [`crate::fs::run`] with [`Options::format`] set, as the binary
//! does.

use std::fmt;
use std::path::Path;

use serde_json::value::RawValue;

use crate::analysis::{Comparison, Framing, Verb};
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
///
/// Only [`judge`] makes one, so a field added later is not a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
/// [`ErrorKind::Options`] when `opts` cannot be applied, checked before any
/// analysis runs; [`ErrorKind::Analysis`] when either side cannot be read or
/// analyzed; [`ErrorKind::Report`] when the envelope cannot be serialized.
pub fn judge(old: &Path, new: &Path, opts: &Options) -> Result<Judgement, Error> {
    opts.validate().map_err(Error::of(ErrorKind::Options))?;
    // The same `Comparison` the `fs` verb runs, so a library caller and the
    // command line judge a pair identically.
    let comparison = Comparison::run(old, new).map_err(Error::of(ErrorKind::Analysis))?;
    let mut analysis = comparison
        .judge(Verb::Fs, old, new, opts, Framing::default())
        .map_err(Error::of(ErrorKind::Analysis))?;

    // `render` rather than `json` so the two stay one code path: a divergence
    // would give a library caller a different envelope than `--format json`.
    let mut json = analysis
        .render(Format::Json)
        .map_err(Error::of(ErrorKind::Report))?;
    json.truncate(json.trim_end().len());
    Ok(Judgement {
        severity: analysis.verdict,
        deterministic: analysis.deterministic_verdict,
        new_severity: analysis.new_verdict,
        gated: analysis.gated(),
        clean: analysis.clean(),
        interpretation: analysis.interp.take(),
        report: RawValue::from_string(json)
            .map_err(anyhow::Error::from)
            .map_err(Error::of(ErrorKind::Report))?,
    })
}

/// Why [`judge`] reached no verdict.
///
/// Displays as the outermost message; `{:#}` prints the whole cause chain, and
/// [`std::error::Error::source`] walks it.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    inner: anyhow::Error,
}

/// What kind of failure an [`Error`] is, for a caller deciding whether to fix
/// its input, skip the pair, or report a bug.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The [`Options`] could not be applied — a version override that does
    /// not parse. Nothing was analyzed.
    Options,
    /// A side could not be read or analyzed.
    Analysis,
    /// The verdict was reached but could not be serialized.
    Report,
}

impl Error {
    /// What kind of failure this is.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    fn of(kind: ErrorKind) -> impl Fn(anyhow::Error) -> Self {
        move |inner| Self { kind, inner }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bad override is the caller's input, reported as such before either
    /// path is opened — these two do not exist.
    #[test]
    fn a_bad_override_fails_before_any_analysis() {
        let opts = Options {
            base_version: Some("not a version".to_owned()),
            ..Options::default()
        };
        let err = judge(
            Path::new("/nonexistent/old"),
            Path::new("/nonexistent/new"),
            &opts,
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Options);
        assert!(err.to_string().contains("--base-version"), "{err}");
    }

    #[test]
    fn an_unreadable_side_is_an_analysis_failure() {
        let opts = Options {
            offline: true,
            ..Options::default()
        };
        let err = judge(
            Path::new("/nonexistent/old"),
            Path::new("/nonexistent/new"),
            &opts,
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Analysis);
        // The alternate form carries the whole chain, as `anyhow`'s does.
        assert!(format!("{err:#}").len() >= err.to_string().len());
    }
}
