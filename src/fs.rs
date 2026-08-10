//! `isomer fs` — differential analysis of two local trees.
//!
//! The verb is deliberately thin: [`crate::analysis`] does the judging and the
//! renderers do the talking. `fs` only names the two sides and prints one
//! format.

use std::path::Path;

use anyhow::Result;

use crate::Cli;
use crate::analysis::{self, Analysis};
use crate::policy::Policy;

/// Diff `old` against `new`, emit the report, and return whether the delta is
/// clean at `--fail-on`.
pub(crate) fn run(old: &Path, new: &Path, cli: &Cli, policy: &Policy) -> Result<bool> {
    let options = cleave::AnalysisOptions::default();
    let report = analysis::diff(old, new, &options)?;
    let a = Analysis::new("fs", old, new, &options, &report, cli, policy)?;
    crate::write_stdout(&a.render(cli.format, cli)?)?;
    Ok(a.clean)
}
