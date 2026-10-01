//! What every renderer reads off an analysis, before it is laid out.
//!
//! The terminal, the PR comment, and SARIF describe the same case in
//! different layouts. The facts they share — the verdict's word, the scale of
//! the change, the counts that moved, a file's metric movers — are computed
//! here once, so the formats cannot drift apart on what they say.

use cleave::types::DiffReportV1;

use crate::Severity;
use crate::evidence::{Hunk, LineMark};
use crate::member::MemberPath;

/// The verdict word for a severity: HOSTILE / SUSPICIOUS / NOTABLE / CLEAN.
/// Shared with every other renderer, so one vocabulary describes a verdict
/// whether it lands in a terminal, a PR comment, SARIF, or an exit annotation.
pub(crate) fn verdict_word(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "HOSTILE",
        Severity::High => "SUSPICIOUS",
        Severity::Medium | Severity::Low => "NOTABLE",
        Severity::None => "CLEAN",
    }
}

/// The masthead's scale phrases: how many files moved, and how much content.
/// Shared with the markdown report so both state the change at the same scale.
pub(crate) fn change_scale(diff: &DiffReportV1) -> Vec<String> {
    let mut parts = Vec::new();
    // For a container, the summary's root entry restates the container
    // itself — drop it so the count matches the `files` member list.
    // Widen before summing: three `u32` counts added in `u32` would abort on
    // overflow under the dev profile's `panic = "abort"` and wrap in release.
    let mut touched = diff.summary.files_changed as usize
        + diff.summary.files_added as usize
        + diff.summary.files_removed as usize;
    let mut total = touched + diff.summary.files_unchanged as usize;
    if diff
        .files
        .iter()
        .any(|f| MemberPath::new(&f.path).is_member())
    {
        touched = touched.saturating_sub(1);
        total = total.saturating_sub(1);
    }
    if total > 1 {
        parts.push(format!("{touched} of {total} files changed"));
    }
    // The content-change scale — one of the three legs (content, behavior,
    // metrics) the report separates; the other two get their own sections.
    let roc = diff.summary.overall_roc;
    if roc > 0.005 {
        parts.push(format!("{:.0}% changed", f64::from(roc) * 100.0));
    }
    parts
}

/// One aggregate count that moved: symbols, sections, or strings.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StatRow {
    pub old: i64,
    pub new: i64,
    /// What was counted: `symbols`, `sections`, `strings`.
    pub label: &'static str,
    /// The gained names, when there are any to show; empty otherwise.
    pub note: String,
}

impl StatRow {
    pub(crate) fn delta(&self) -> i64 {
        self.new - self.old
    }
}

/// Aggregate count deltas across the changed files — only the *count* scopes
/// (symbols, sections, strings), which sum honestly
/// regardless of file type; the scalar per-file metrics (sizes, entropy, ratios)
/// ride each evidence header, where they keep their meaning. Pure data, shared
/// by the terminal and the markdown report. Empty when nothing counted moved.
pub(crate) fn stats(diff: &DiffReportV1) -> Vec<StatRow> {
    // For an archive, the leaf members carry the counts; skip the container
    // root so nothing is counted twice. A single-file diff has no `!!` entries,
    // so every changed entry is a leaf.
    let archive = diff
        .files
        .iter()
        .any(|f| MemberPath::new(&f.path).is_member());
    let (mut sym_o, mut sym_n) = (0i64, 0i64);
    let (mut sec_o, mut sec_n) = (0i64, 0i64);
    let (mut str_o, mut str_n) = (0i64, 0i64);
    let mut added_syms: Vec<&str> = Vec::new();
    let mut added_secs: Vec<&str> = Vec::new();
    for f in &diff.files {
        if matches!(f.status, cleave::types::FileStatus::Unchanged)
            || (archive && !MemberPath::new(&f.path).is_member())
        {
            continue;
        }
        if let Some(s) = &f.scopes.symbols {
            sym_o += i64::from(s.old_count);
            sym_n += i64::from(s.new_count);
            added_syms.extend(s.added.iter().map(|a| a.symbol.as_str()));
        }
        if let Some(s) = &f.scopes.sections {
            sec_o += i64::from(s.old_count);
            sec_n += i64::from(s.new_count);
            added_secs.extend(s.added.iter().map(|a| a.name.as_str()));
        }
        if let Some(s) = &f.scopes.strings {
            str_o += i64::from(s.old_count);
            str_n += i64::from(s.new_count);
        }
    }
    let mut rows = Vec::new();
    let mut push = |old, new, label, note| {
        rows.push(StatRow {
            old,
            new,
            label,
            note,
        })
    };
    if sym_o != sym_n || !added_syms.is_empty() {
        push(sym_o, sym_n, "symbols", names_note(&added_syms));
    }
    if sec_o != sec_n || !added_secs.is_empty() {
        push(sec_o, sec_n, "sections", names_note(&added_secs));
    }
    if str_o != str_n {
        push(str_o, str_n, "strings", String::new());
    }
    rows
}

/// A short, `, `-joined list of gained names, capped so one big change can't run
/// off the row.
fn names_note(names: &[&str]) -> String {
    const MAX: usize = 5;
    if names.is_empty() {
        return String::new();
    }
    // Symbol and section names are lifted from the artifact.
    let shown = crate::printable(&names[..names.len().min(MAX)].join(", "));
    match names.len().checked_sub(MAX) {
        Some(more) if more > 0 => format!("{shown}, +{more} more"),
        _ => shown,
    }
}

/// The scalar metric deltas for one changed file — sizes, entropy, ratios,
/// per-file counts — as `label old→new (Δ%)` items, strongest first. These are
/// the metrics that don't aggregate across files, so they ride the file's own
/// evidence header. `None` when the file has no scalar movers.
pub(crate) fn file_metrics_summary(diff: &DiffReportV1, member: &str) -> Option<Vec<String>> {
    const CAP: usize = 6;
    // `member` arrives from a hunk, whose name was neutralized for display, so
    // the diff's raw path has to be neutralized the same way before comparing —
    // otherwise a member whose name carries a control character never matches,
    // and the file most worth annotating is the one that loses its metrics.
    let entry = diff
        .files
        .iter()
        .find(|f| crate::printable(MemberPath::new(&f.path).leaf()) == member)
        .or_else(|| {
            // A single-file (non-archive) diff has one changed entry, unmatched
            // by name — fall back to it, but only when it is unambiguously the
            // only one.
            let mut changed = diff
                .files
                .iter()
                .filter(|f| matches!(f.status, cleave::types::FileStatus::Changed));
            let only = changed.next()?;
            changed.next().is_none().then_some(only)
        })?;
    let m = entry.scopes.metrics.as_ref()?;
    let mut movers: Vec<crate::analysis::MetricMove> = m
        .changed
        .iter()
        .filter_map(|c| {
            // Name the metric by its leaf, with the few cryptic ones spelled out.
            let p = c.new.path.as_str();
            let label = match p.rsplit(['.', '/']).next().unwrap_or(p) {
                "code_size" => "code",
                "size" | "size_bytes" => "size",
                "init_array_count" => "init_array",
                "dynrela_count" | "relacount" => "relocs",
                other => other,
            };
            crate::analysis::metric_move(c, None, label)
        })
        .collect();
    // `total_cmp`, not `partial_cmp(…).unwrap_or(Equal)`: the latter is not a
    // total order when a metric ratio is NaN, and `sort_by` is permitted to
    // panic on an inconsistent comparator.
    movers.sort_by(|a, b| b.importance.total_cmp(&a.importance));
    // One row per label — `relacount` and `dynrela_count` both read `relocs`,
    // so keep the larger mover, not both.
    let mut seen = std::collections::HashSet::new();
    movers.retain(|m| seen.insert(m.label.clone()));
    movers.truncate(CAP);
    (!movers.is_empty()).then(|| {
        movers
            .iter()
            .map(crate::analysis::MetricMove::describe)
            .collect()
    })
}

/// Say what the evidence marks mean, once, up top, instead of implying it.
/// Shared with the markdown report.
pub(crate) fn evidence_note_text(hunks: &[&Hunk]) -> &'static str {
    if hunks.iter().all(|h| h.is_bytes()) {
        "binary · all matches are gained traits · old bytes not shown"
    } else if hunks
        .iter()
        .any(|h| !h.is_bytes() && h.lines.iter().any(|l| l.added != LineMark::Unknown))
    {
        "gained behavior · + marks lines absent from the old version"
    } else {
        "matched code for gained traits"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleave::types::{Changed, FileDiffEntry, FileStatus, MetricChange, ScopeDiff, ScopeDiffs};

    #[test]
    fn metric_summary_keeps_the_six_largest_relative_moves() {
        let change = |name: &str, new: f64| Changed {
            old: MetricChange {
                path: format!("metric.{name}"),
                value: serde_json::json!(100.0),
            },
            new: MetricChange {
                path: format!("metric.{name}"),
                value: serde_json::json!(new),
            },
        };
        let diff = DiffReportV1 {
            old_root: "old".to_string(),
            new_root: "new".to_string(),
            summary: Default::default(),
            scopes: Default::default(),
            files: vec![FileDiffEntry {
                scopes: ScopeDiffs {
                    metrics: Some(ScopeDiff {
                        changed: vec![
                            change("largest", 1000.0),
                            change("second", 800.0),
                            change("third", 600.0),
                            change("fourth", 500.0),
                            change("fifth", 400.0),
                            change("sixth", 300.0),
                            change("seventh", 200.0),
                            change("smallest", 110.0),
                        ],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..crate::testkit::entry("sample", "elf", FileStatus::Changed)
            }],
        };

        let summary = file_metrics_summary(&diff, "sample").unwrap();
        assert_eq!(summary.len(), 6);
        assert!(summary[0].starts_with("largest "));
        assert!(summary[5].starts_with("sixth "));
        assert!(!summary.iter().any(|s| s.starts_with("seventh ")));
        assert!(!summary.iter().any(|s| s.starts_with("smallest ")));
    }

    #[test]
    fn long_name_lists_are_capped_with_a_count() {
        assert_eq!(names_note(&[]), "");
        assert_eq!(names_note(&["a", "b"]), "a, b");
        assert_eq!(
            names_note(&["a", "b", "c", "d", "e", "f", "g"]),
            "a, b, c, d, e, +2 more"
        );
    }
}
