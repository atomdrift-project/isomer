//! `isomer fs` — differential analysis of two local trees.
//!
//! The verb is deliberately thin: the analysis does the judging and the
//! renderers do the talking. `fs` only names the two sides and renders one
//! format.

use std::path::Path;

use anyhow::Result;

use crate::Outcome;
use crate::analysis::{Comparison, Framing, Verb};
use crate::options::Options;

/// Diff `old` against `new`: the report in `--format`, and whether the delta is
/// clean at `--fail-on`.
pub fn run(old: &Path, new: &Path, opts: &Options) -> Result<Outcome> {
    opts.validate()?;
    let comparison = Comparison::run(old, new)?;
    let a = comparison.judge(Verb::Fs, old, new, opts, Framing::default())?;
    Ok(Outcome {
        report: a.render(opts.format)?,
        clean: a.clean(),
    })
}
