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

/// One evidence row for the table renderer: where it is, what the code/bytes
/// are, and the rule's description.
#[derive(Debug)]
pub(crate) struct Window {
    /// Archive member path, when the hit is inside one; `None` for the root.
    pub member: Option<String>,
    /// Source line number, or hex byte offset for binaries.
    pub locator: String,
    /// The matched source line (truncated) or a hex byte run.
    pub code: String,
    /// The matching rule's human description.
    pub desc: String,
    /// Whether the matching finding is hostile (for coloring).
    pub hostile: bool,
}

/// Structured evidence rows for the gained traits — the same delta-filtered
/// windows as [`render`], but as data so the caller can lay them out as an
/// aligned `locator · code · description` table.
pub(crate) fn windows(
    new_path: &Path,
    options: &cleave::AnalysisOptions,
    gained_ids: &HashSet<String>,
    limit: usize,
) -> Result<Vec<Window>> {
    use cleave::Criticality;
    if gained_ids.is_empty() {
        return Ok(Vec::new());
    }
    let report = cleave::analyze_file(new_path, options)
        .with_context(|| format!("failed to re-analyze {} for evidence", new_path.display()))?;

    let mut candidates: Vec<(Option<String>, cleave::types::FileAnalysis)> = Vec::new();
    candidates.push((None, report.to_file_analysis(0)));
    for fa in &report.files {
        candidates.push((Some(clean_member(&fa.path)), fa.clone()));
    }
    // cleave finding ids are interned (`Istr`); compare/collect at the `&str`
    // boundary so this holds whether the field is `String` or `Istr`.
    let mut keep = gained_ids.clone();
    for (_, fa) in &candidates {
        for f in &fa.findings {
            if gained_ids.contains(f.id.as_str()) {
                keep.extend(f.trait_refs.iter().map(|s| s.as_str().to_string()));
            }
        }
    }

    // Collect every hit line (bounded), then rank so the strongest evidence
    // leads: the note's criticality picks which finding a shared line is
    // attributed to, and hostile rows sort ahead of the rest.
    let mut rows: Vec<Window> = Vec::new();
    for (member, fa) in &candidates {
        for line in &fa.context {
            let Some(note) = line
                .notes
                .iter()
                .filter(|n| keep.contains(n.id.as_str()))
                .max_by_key(|n| crit_rank(n.crit))
            else {
                continue;
            };
            let (locator, code) = match line.line {
                Some(l) => {
                    let text = String::from_utf8_lossy(&line.data);
                    let first = text.lines().next().unwrap_or("").trim_end();
                    (l.to_string(), truncate(first, 54))
                }
                None => (format!("{:x}", line.loc), hex_run(&line.data, 11)),
            };
            rows.push(Window {
                member: member.clone(),
                locator,
                code,
                desc: if note.desc.is_empty() { "matched".into() } else { note.desc.as_str().to_string() },
                hostile: matches!(note.crit, Criticality::Hostile),
            });
            if rows.len() >= 120 {
                break;
            }
        }
    }
    // Hostile first (stable within a tier), then one row per distinct
    // description so the compact view shows variety, not the same rule repeated.
    rows.sort_by_key(|r| !r.hostile);
    let mut seen: HashSet<String> = HashSet::new();
    rows.retain(|r| seen.insert(r.desc.clone()));
    rows.truncate(limit);
    Ok(rows)
}

fn crit_rank(c: cleave::Criticality) -> u8 {
    use cleave::Criticality::*;
    match c {
        Hostile => 5,
        Suspicious => 4,
        Notable => 3,
        Baseline => 2,
        Component => 1,
        _ => 0,
    }
}

/// `<root>!!package/foo.js` → `package/foo.js`; a bare member name is kept.
fn clean_member(path: &str) -> String {
    path.rsplit("!!").next().unwrap_or(path).to_string()
}

/// First `n` bytes as `41 5c c3 …`.
fn hex_run(data: &[u8], n: usize) -> String {
    let mut s = data
        .iter()
        .take(n)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    if data.len() > n {
        s.push_str(" …");
    }
    s
}

/// Char-aware truncation with a trailing ellipsis.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// Render context windows (source lines or hex+ascii, per file type) for the
/// gained trait ids, using cleave's renderer. Returns an empty string when none
/// of the gained traits carry byte-located evidence (many structural ELF traits
/// do not).
///
/// `compact` caps the number of windows for the default view; `--explain`
/// passes `false` for the fuller set.
#[allow(dead_code)]
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
            if gained_ids.contains(f.id.as_str()) {
                keep.extend(f.trait_refs.iter().map(|s| s.as_str().to_string()));
            }
        }
    }

    // Filter each candidate to the kept traits and drop those left with nothing
    // to show. Renumber ids so `format_context`'s id→file map stays unique.
    let mut files: Vec<cleave::types::FileAnalysis> = Vec::new();
    for (idx, mut fa) in candidates.into_iter().enumerate() {
        fa.id = idx as u32;
        fa.findings.retain(|f| keep.contains(f.id.as_str()));
        fa.context
            .retain(|line| line.notes.iter().any(|n| keep.contains(n.id.as_str())));
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
        // Plain code in the evidence windows — no match highlighting; the rail
        // and the `// rule` trailer carry the emphasis instead.
        color: false,
        ..cleave::output::TinyOpts::terminal()
    };
    Ok(cleave::output::format_context(&evidence, &opts))
}

/// Concise note for the no-change case: when the diff surfaced nothing but the
/// new artifact still carries suspicious/hostile traits, say so in one or two
/// lines rather than staying fully silent. Returns `None` when the artifact is
/// genuinely clean (then isomer prints nothing, like `diff`). Does not affect
/// the exit code — this is context, not a new finding.
pub(crate) fn existing_risk(
    new_path: &Path,
    options: &cleave::AnalysisOptions,
    name: &str,
) -> anyhow::Result<Option<String>> {
    use cleave::Criticality;
    use std::collections::BTreeMap;

    let report = cleave::analyze_file(new_path, options)?;
    // Highest criticality per namespace across the whole artifact.
    let mut worst: BTreeMap<String, Criticality> = BTreeMap::new();
    let findings = report
        .findings
        .iter()
        .chain(report.files.iter().flat_map(|f| f.findings.iter()));
    for f in findings {
        if matches!(f.crit, Criticality::Suspicious | Criticality::Hostile) {
            let ns = namespace_of(&f.id);
            let slot = worst.entry(ns).or_insert(f.crit);
            if rank(f.crit) > rank(*slot) {
                *slot = f.crit;
            }
        }
    }
    if worst.is_empty() {
        return Ok(None);
    }

    let hostile = worst.values().any(|c| *c == Criticality::Hostile);
    let mut items: Vec<(String, Criticality)> = worst.into_iter().collect();
    items.sort_by(|a, b| rank(b.1).cmp(&rank(a.1)).then(a.0.cmp(&b.0)));
    items.truncate(6);

    let label = if hostile {
        cleave::theme::paint_hostile("hostile")
    } else {
        cleave::theme::paint_suspicious("suspicious")
    };
    let list = items
        .iter()
        .map(|(ns, c)| {
            let dot = match c {
                Criticality::Hostile => cleave::theme::paint_hostile("●●●"),
                _ => cleave::theme::paint_suspicious("●● "),
            };
            format!("{dot} {ns}")
        })
        .collect::<Vec<_>>()
        .join("\n   ");
    Ok(Some(format!(
        " {name} · no behavioral change · existing {label} traits:\n   {list}\n"
    )))
}

/// Capability classes present in the base version, so the rubric can tell a
/// wholly new class from one that merely gained a trait. Empty on analysis
/// failure (then everything reads as new, the safe default).
pub(crate) fn base_classes(
    old_path: &Path,
    options: &cleave::AnalysisOptions,
) -> std::collections::HashSet<String> {
    let Ok(report) = cleave::analyze_file(old_path, options) else {
        return std::collections::HashSet::new();
    };
    use cleave::Criticality;
    report
        .findings
        .iter()
        .chain(report.files.iter().flat_map(|f| f.findings.iter()))
        // Only count a class the base exhibited *meaningfully* (notable+). A
        // baseline-criticality substring match doesn't mean the base "did C2";
        // counting it would dismiss a genuinely new capability as "expanded".
        // Erring toward notable+ keeps new capabilities flagged as new.
        .filter(|f| matches!(f.crit, Criticality::Notable | Criticality::Suspicious | Criticality::Hostile))
        .filter_map(|f| crate::rubric::capability_class(&f.id))
        .map(str::to_string)
        .collect()
}

/// Trait namespace: taxonomy path before `::`, taxonomy root stripped. Kept in
/// step with `rubric`'s namespace grouping.
fn namespace_of(id: &str) -> String {
    const ROOTS: &[&str] = &[
        "metadata",
        "micro-behaviors",
        "objectives",
        "well-known",
        "third_party",
    ];
    let path = id.split("::").next().unwrap_or(id);
    match path.split_once('/') {
        Some((root, rest)) if ROOTS.contains(&root) => rest.to_string(),
        _ => path.to_string(),
    }
}

fn rank(c: cleave::Criticality) -> u8 {
    match c {
        cleave::Criticality::Hostile => 2,
        cleave::Criticality::Suspicious => 1,
        _ => 0,
    }
}
