//! `isomer fs` — differential analysis of two local trees.
//!
//! The verb is deliberately thin: [`crate::analysis`] does the judging and the
//! renderers do the talking. `fs` only names the two sides and prints one
//! format.

use std::path::Path;

use anyhow::Result;

use crate::Cli;
use crate::analysis::{self, Analysis};

/// Diff `old` against `new`, emit the report, and return whether the delta is
/// clean at `--fail-on`.
pub(crate) fn run(old: &Path, new: &Path, cli: &Cli) -> Result<bool> {
    // Source archives often carry meaningful non-program members: build
    // macros, test fixtures, and opaque payloads. Keep them in the
    // differential so source-only attacks are not reduced to the subset of
    // members with a recognized executable/source file type. Directory
    // comparisons retain cleave's safer recognized-file policy; direct scans
    // of source trees can legitimately contain corrupt fixtures.
    let all_source_members = analysis::is_source_archive(old) && analysis::is_source_archive(new);
    let options = cleave::AnalysisOptions {
        all_files: all_source_members,
        ..cleave::AnalysisOptions::default()
    };
    let report = analysis::diff(old, new, &options)?;
    let mut a = Analysis::new("fs", old, new, &options, &report, cli)?;
    // `--deps` fetches each added dependency — a network step, and the only one
    // `fs` makes; skip it under --offline, and show the spinner for a human.
    if cli.deps && !cli.offline {
        let progress = cli.format == crate::Format::Terminal
            && std::io::IsTerminal::is_terminal(&std::io::stderr());
        a.deps = crate::deps::profiles(a.diff, &options, progress);
    }
    crate::write_stdout(&a.render(cli.format, cli)?)?;
    Ok(a.clean)
}
