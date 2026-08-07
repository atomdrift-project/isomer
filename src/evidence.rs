//! Evidence rendering — the proof behind the verdict.
//!
//! The diff report names *which* traits appeared but carries none of their
//! matched bytes. To show a security engineer the actual code or hex where a
//! gained capability lives — the same context windows cleave and scan render —
//! we re-analyze the new side (cached, so cheap) and reuse cleave's own
//! context renderer, filtered to just the traits the diff surfaced. The
//! evidence is the *delta*: only windows touching a gained trait render, so the
//! engineer sees what changed, not the whole file.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};

/// Render context windows (source lines or hex+ascii, per file type) for the
/// gained trait ids, using cleave's renderer. Returns an empty string when none
/// of the gained traits carry byte-located evidence (many structural ELF traits
/// do not).
///
/// `compact` caps the number of windows for the default view; `--explain`
/// passes `false` for the fuller set.
pub(crate) fn render(
    new_path: &Path,
    options: &cleave::AnalysisOptions,
    gained_ids: &HashSet<String>,
    compact: bool,
) -> Result<String> {
    if gained_ids.is_empty() {
        return Ok(String::new());
    }
    let report = cleave::analyze_file(new_path, options)
        .with_context(|| format!("failed to re-analyze {} for evidence", new_path.display()))?;

    // Candidate files: the root plus any archive members, each converted to the
    // FileAnalysis shape `format_context` consumes.
    let mut candidates: Vec<cleave::types::FileAnalysis> = Vec::with_capacity(1 + report.files.len());
    candidates.push(report.to_file_analysis(0));
    candidates.extend(report.files.iter().cloned());

    // Keep the gained traits plus the composite legs they reference, so a
    // gained composite still renders the component windows that justify it.
    let mut keep = gained_ids.clone();
    for fa in &candidates {
        for f in &fa.findings {
            if gained_ids.contains(&f.id) {
                keep.extend(f.trait_refs.iter().cloned());
            }
        }
    }

    // Filter each candidate to the kept traits and drop those left with nothing
    // to show. Renumber ids so `format_context`'s id→file map stays unique.
    let mut files: Vec<cleave::types::FileAnalysis> = Vec::new();
    for (idx, mut fa) in candidates.into_iter().enumerate() {
        fa.id = idx as u32;
        fa.findings.retain(|f| keep.contains(&f.id));
        fa.context
            .retain(|line| line.notes.iter().any(|n| keep.contains(&n.id)));
        if !fa.context.is_empty() {
            files.push(fa);
        }
    }
    if files.is_empty() {
        return Ok(String::new());
    }

    let mut evidence = cleave::AnalysisReport::new(report.target.clone());
    evidence.version = "3".to_string();
    evidence.files = files;

    let opts = cleave::output::TinyOpts {
        // We print our own verdict header; cleave renders only the body.
        card: true,
        // Compact (default) view: only the hit rows of the strongest gained
        // traits, no surrounding context. `--explain` widens the net.
        top_n: if compact { 4 } else { 24 },
        always_crit: None,
        min_crit: cleave::Criticality::Baseline,
        focus_crit: compact.then_some(cleave::Criticality::Notable),
        context_lines: Some(if compact { 0 } else { 2 }),
        full_context: !compact,
        color: true,
        ..cleave::output::TinyOpts::terminal()
    };
    Ok(cleave::output::format_context(&evidence, &opts))
}
