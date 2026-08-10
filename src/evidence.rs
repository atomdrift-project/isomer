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

use crate::analysis::Pair;

/// Width (chars) of one displayed code row. Context lines truncate here; the
/// matched line may carry up to [`MATCH_W`] chars, which the renderer wraps
/// across continuation rows.
pub(crate) const CODE_W: usize = 88;

/// Window budget around the top match — three display rows' worth.
const MATCH_W: usize = 3 * CODE_W;

/// How many hunks the evidence section shows, and the excerpt height of each.
pub(crate) const MAX_HUNKS: usize = 5;
const MAX_HUNK_LINES: usize = 7;

/// One evidence hunk — a contiguous matched region attributed to its top rule
/// (criticality × confidence, cleave's own ranking), rendered as a small
/// diff-style excerpt: matched lines bright, context dim, `+` on lines absent
/// from the old version.
#[derive(Debug)]
pub(crate) struct Hunk {
    /// The changed file this hunk belongs to, named as the reader sees it
    /// (repo-relative under `ci`). SARIF locations are built from this.
    pub file: String,
    /// Archive member path, when the hit is inside one; `None` for the root.
    pub member: Option<String>,
    /// 1-based source line of the top match, when the file has line structure.
    pub line: Option<u64>,
    /// Absolute byte offset of the top match — the file-order sort key.
    pub loc: u64,
    /// `file:line` (text) or `file:0x<offset>` (binary) for the header.
    pub location: String,
    /// Full trait id of the top rule — what this hunk is evidence *of*, so a
    /// finding can be anchored to the bytes that prove it.
    pub id: String,
    /// The top rule's human description.
    pub desc: String,
    /// The top rule's tier, painted on the header.
    pub severity: crate::Severity,
    /// True for byte windows in binaries (no line structure).
    pub binary: bool,
    /// Ranking score of the top note (crit × confidence).
    pub score: f32,
    pub lines: Vec<HunkLine>,
    /// 1-based line range covered (text hunks), for contiguity merging.
    span: Option<(u64, u64)>,
    /// Index into `lines` of the top match, kept for trimming.
    top: usize,
}

/// One rendered line of a hunk.
#[derive(Debug)]
pub(crate) struct HunkLine {
    /// Source line number, or hex byte offset for binaries.
    pub locator: String,
    /// The code (windowed around the match) or a hex byte run.
    pub text: String,
    /// `Some(true)` when the line is absent from the old version (`+`),
    /// `Some(false)` when present in both (context), `None` when unknown
    /// (no old text available to diff against).
    pub added: Option<bool>,
    /// Whether a kept rule matched on this line (vs pure context).
    pub is_match: bool,
}

/// Total hunks collected before ranking — a work cap, not a display cap.
const HUNK_BUDGET: usize = 120;

/// Analyze one file for evidence. A file that cannot be analyzed costs its own
/// evidence and nothing else: the verdict already stands on the diff, so this
/// logs and moves on rather than failing the run.
fn analyze(path: &Path, options: &cleave::AnalysisOptions) -> Option<cleave::AnalysisReport> {
    match cleave::analyze_file(path, options) {
        Ok(r) => Some(r),
        Err(e) => {
            eprintln!("isomer: no evidence from {}: {e:#}", path.display());
            None
        }
    }
}

/// Diff-style evidence hunks for the gained traits: one hunk per matched
/// region, each attributed to its strongest rule, contiguous regions merged,
/// strongest `limit` kept, presented in file order.
pub(crate) fn hunks(
    pairs: &[Pair],
    options: &cleave::AnalysisOptions,
    gained_ids: &HashSet<String>,
    limit: usize,
) -> Vec<Hunk> {
    if gained_ids.is_empty() {
        return Vec::new();
    }
    let mut all: Vec<Hunk> = Vec::new();
    for pair in pairs {
        let Some(new_path) = pair.new.as_deref() else {
            continue;
        };
        let Some(report) = analyze(new_path, options) else {
            continue;
        };
        file_hunks(pair, &report, gained_ids, &mut all);
        if all.len() >= HUNK_BUDGET {
            break;
        }
    }

    // Contiguous hunks in the same member merge into one, owned by the
    // stronger rule; each is then trimmed to a short excerpt around its top
    // match. The strongest `limit` hunks survive — one per rule, so five
    // hunks show five behaviors, not one behavior five times — and display
    // returns to file order.
    merge_contiguous(&mut all);
    for h in &mut all {
        trim(h);
    }
    // Notable+ hunks own the slots; baseline-tier matches qualify only when
    // nothing stronger exists (they're context, not standalone proof).
    if all.iter().any(|h| h.severity >= crate::Severity::Medium) {
        all.retain(|h| h.severity >= crate::Severity::Medium);
    }
    all.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.score.total_cmp(&a.score))
            .then(a.loc.cmp(&b.loc))
    });
    let mut seen: HashSet<String> = HashSet::new();
    all.retain(|h| seen.insert(h.desc.clone()));
    all.truncate(limit);
    all.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.member.cmp(&b.member))
            .then(a.loc.cmp(&b.loc))
    });
    all
}

/// Collect one file's hunks (the file itself plus any archive members) into
/// `all`.
fn file_hunks(
    pair: &Pair,
    report: &cleave::AnalysisReport,
    gained_ids: &HashSet<String>,
    all: &mut Vec<Hunk>,
) {
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

    let container = !report.files.is_empty();
    let old_lines = pair.old.as_deref().and_then(|p| old_line_set(p, container));

    for (member, fa) in &candidates {
        let shown = member.clone().unwrap_or_else(|| pair.label.clone());
        for chunk in &fa.context {
            let kept: Vec<&cleave::types::Note> = chunk
                .notes
                .iter()
                .filter(|n| keep.contains(n.id.as_str()))
                .collect();
            let Some(top) = kept
                .iter()
                .copied()
                .max_by(|a, b| score(a).total_cmp(&score(b)))
            else {
                continue;
            };
            // Hex of an archive's raw bytes is compression garbage, and a
            // binary match at byte 0 shows the file magic — neither proves
            // anything the grid doesn't already say, and the member hunks
            // carry the real proof.
            if chunk.line.is_none() && ((container && member.is_none()) || top.off == 0) {
                continue;
            }
            let mut h = match chunk.line {
                Some(first) => text_hunk(chunk, first, &kept, top, &shown, old_lines.as_ref()),
                None => binary_hunk(chunk, top, &shown),
            };
            h.member = member.clone();
            h.file = pair.label.clone();
            all.push(h);
            if all.len() >= HUNK_BUDGET {
                return;
            }
        }
    }
}

/// cleave's note ranking: criticality × confidence (unknown confidence reads
/// as certain).
fn score(n: &cleave::types::Note) -> f32 {
    f32::from(crit_rank(n.crit)) * if n.conf > 0.0 { n.conf } else { 1.0 }
}

fn desc_of(n: &cleave::types::Note) -> String {
    if n.desc.is_empty() {
        "matched".into()
    } else {
        n.desc.as_str().to_string()
    }
}

/// Tier of a note's criticality, for header painting.
fn tier(c: cleave::Criticality) -> crate::Severity {
    use cleave::Criticality::{Hostile, Notable, Suspicious};
    match c {
        Hostile => crate::Severity::Critical,
        Suspicious => crate::Severity::High,
        Notable => crate::Severity::Medium,
        _ => crate::Severity::Low,
    }
}

/// A hunk's tier: the rule's own criticality or the severity of the
/// capability it proves, whichever is higher — so the SSH-protocol string
/// that evidences a High network capability ranks (and paints) as High.
fn hunk_severity(n: &cleave::types::Note) -> crate::Severity {
    tier(n.crit).max(crate::rubric::capability_severity(n.id.as_str()))
}

/// Trimmed lines of the old version, for the `+` gutter. Plain text files
/// only: archive members would need extraction, and a NUL in the head marks
/// binary — both degrade to `None` (gutter unknown, no marks rendered).
fn old_line_set(old_path: &Path, container: bool) -> Option<HashSet<String>> {
    if container {
        return None;
    }
    let bytes = std::fs::read(old_path).ok()?;
    if bytes.iter().take(8192).any(|b| *b == 0) {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes);
    Some(text.lines().map(|l| l.trim().to_string()).collect())
}

/// A text hunk: every line of the chunk, matches marked, the top match's line
/// windowed around its column. `member` is filled by the caller.
fn text_hunk(
    chunk: &cleave::types::ContextLine,
    first_line: u64,
    kept: &[&cleave::types::Note],
    top: &cleave::types::Note,
    file: &str,
    old: Option<&HashSet<String>>,
) -> Hunk {
    let spans = line_spans(&chunk.data);
    let delta_of = |off: u64| -> usize {
        usize::try_from(off.saturating_sub(chunk.loc))
            .unwrap_or(usize::MAX)
            .min(chunk.data.len())
    };
    let line_of = |off: u64| -> usize {
        let d = delta_of(off);
        spans
            .iter()
            .position(|&(s, e)| d >= s && d <= e)
            .unwrap_or(0)
    };
    let matched: HashSet<usize> = kept.iter().map(|n| line_of(n.off)).collect();
    let top_idx = line_of(top.off);
    let mut lines = Vec::with_capacity(spans.len());
    for (i, &(s, e)) in spans.iter().enumerate() {
        let raw = &chunk.data[s..e];
        let full = String::from_utf8_lossy(raw);
        // A chunk can open mid-line (`col` > 1); the first segment is then a
        // continuation and its display marks the clipped start.
        let clipped = i == 0 && chunk.col.unwrap_or(1) > 1;
        let text = if i == top_idx {
            excerpt(raw, delta_of(top.off) - s, clipped)
        } else if clipped {
            truncate(&format!("…{}", full.trim_end()), CODE_W)
        } else {
            truncate(full.trim_end(), CODE_W)
        };
        lines.push(HunkLine {
            locator: (first_line + i as u64).to_string(),
            text,
            added: old.map(|set| !set.contains(full.trim())),
            is_match: matched.contains(&i),
        });
    }
    Hunk {
        file: String::new(),
        member: None,
        line: Some(first_line + top_idx as u64),
        loc: top.off,
        location: format!("{file}:{}", first_line + top_idx as u64),
        id: top.id.as_str().to_string(),
        desc: desc_of(top),
        severity: hunk_severity(top),
        binary: false,
        score: score(top),
        lines,
        span: Some((first_line, first_line + spans.len() as u64 - 1)),
        top: top_idx,
    }
}

/// A binary hunk: hex|ascii dump rows at the match, cleave's presentation.
/// The `+` is semantic — the trait is an addition — since binary bytes have
/// no line diff. The header carries no offset; the rows do.
fn binary_hunk(chunk: &cleave::types::ContextLine, top: &cleave::types::Note, file: &str) -> Hunk {
    const STRIDE: usize = 16;
    const ROWS: usize = 2;
    let delta = usize::try_from(top.off.saturating_sub(chunk.loc))
        .unwrap_or(usize::MAX)
        .min(chunk.data.len());
    let lines = chunk.data[delta..]
        .chunks(STRIDE)
        .take(ROWS)
        .enumerate()
        .map(|(i, row)| HunkLine {
            locator: format!("{:x}", top.off + (i * STRIDE) as u64),
            text: hex_ascii(row, STRIDE),
            added: Some(true),
            is_match: true,
        })
        .collect();
    Hunk {
        file: String::new(),
        member: None,
        line: None,
        loc: top.off,
        location: file.to_string(),
        id: top.id.as_str().to_string(),
        desc: desc_of(top),
        severity: hunk_severity(top),
        binary: true,
        score: score(top),
        lines,
        span: None,
        top: 0,
    }
}

/// One hex|ascii dump row: `XX `-cells padded to `stride`, a separator, then
/// the printable-ASCII column with `.` for the rest — cleave's dump style.
fn hex_ascii(row: &[u8], stride: usize) -> String {
    let mut s = String::with_capacity(stride * 4 + 1);
    for b in row {
        s.push_str(&format!("{b:02x} "));
    }
    for _ in row.len()..stride {
        s.push_str("   ");
    }
    s.push(' ');
    for &b in row {
        s.push(if b.is_ascii_graphic() || b == b' ' {
            b as char
        } else {
            '.'
        });
    }
    s
}

/// Merge contiguous text hunks of the same member into one, owned by the
/// stronger rule. Adjacent line ranges concatenate; overlapping ranges (two
/// byte windows into the same source line — obfuscated one-liners produce
/// many) keep only the stronger hunk, so a packed line reads as one region
/// with one verdict, not five.
fn merge_contiguous(hunks: &mut Vec<Hunk>) {
    let mut out: Vec<Hunk> = Vec::with_capacity(hunks.len());
    for h in hunks.drain(..) {
        let Some(prev) = out
            .last_mut()
            .filter(|p| p.file == h.file && p.member == h.member)
        else {
            out.push(h);
            continue;
        };
        match (prev.span, h.span) {
            (Some((ps, pe)), Some((hs, he))) if hs == pe + 1 => {
                if h.score > prev.score {
                    prev.score = h.score;
                    prev.desc = h.desc;
                    prev.severity = h.severity;
                    prev.location = h.location;
                    prev.loc = h.loc;
                    prev.top = prev.lines.len() + h.top;
                }
                prev.span = Some((ps, he));
                prev.lines.extend(h.lines);
            }
            (Some((ps, pe)), Some((hs, he))) if hs <= pe => {
                if h.score > prev.score {
                    *prev = h;
                    prev.span = Some((ps.min(hs), pe.max(he)));
                }
            }
            _ => out.push(h),
        }
    }
    *hunks = out;
}

/// Cap a hunk at [`MAX_HUNK_LINES`] around its top match, then drop blank
/// edge lines — they pad the excerpt without informing it.
fn trim(h: &mut Hunk) {
    if h.lines.len() > MAX_HUNK_LINES {
        let start = h.top.saturating_sub(2).min(h.lines.len() - MAX_HUNK_LINES);
        h.lines.drain(..start);
        h.lines.truncate(MAX_HUNK_LINES);
    }
    while h.lines.first().is_some_and(|l| l.text.is_empty()) {
        h.lines.remove(0);
    }
    while h.lines.last().is_some_and(|l| l.text.is_empty()) {
        h.lines.pop();
    }
}

/// Byte ranges of the lines within `data`, split on `\n` (terminator excluded).
fn line_spans(data: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (i, b) in data.iter().enumerate() {
        if *b == b'\n' {
            spans.push((start, i));
            start = i + 1;
        }
    }
    spans.push((start, data.len()));
    spans
}

/// The top match's source line for display. Short lines show whole; a line
/// wider than [`MATCH_W`] (obfuscated payloads run to thousands of chars)
/// shows a window opening just before the match column, `…` marking clipped
/// ends. The renderer wraps the result across rows of [`CODE_W`].
fn excerpt(line: &[u8], col: usize, clipped: bool) -> String {
    let text = String::from_utf8_lossy(line);
    let trimmed = text.trim_end();
    let total = trimmed.chars().count();
    if total <= MATCH_W {
        return if clipped {
            format!("…{trimmed}")
        } else {
            trimmed.to_string()
        };
    }
    let at = String::from_utf8_lossy(&line[..col.min(line.len())])
        .chars()
        .count();
    let keep = MATCH_W - 2;
    let start = at.saturating_sub(24).min(total - keep);
    let kept: String = trimmed.chars().skip(start).take(keep).collect();
    let head = if start > 0 || clipped { "…" } else { "" };
    let tail = if start + keep < total { "…" } else { "" };
    format!("{head}{kept}{tail}")
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
pub(crate) fn render(
    pairs: &[Pair],
    options: &cleave::AnalysisOptions,
    gained_ids: &HashSet<String>,
    compact: bool,
) -> String {
    if gained_ids.is_empty() {
        return String::new();
    }

    // Candidate files across every changed file: each root plus any archive
    // members, converted to the FileAnalysis shape `format_context` consumes.
    let mut candidates: Vec<cleave::types::FileAnalysis> = Vec::new();
    let mut target = None;
    for pair in pairs {
        let Some(new_path) = pair.new.as_deref() else {
            continue;
        };
        let Some(report) = analyze(new_path, options) else {
            continue;
        };
        candidates.push(report.to_file_analysis(0));
        candidates.extend(report.files.iter().cloned());
        if target.is_none() {
            target = Some(report.target.clone());
        }
    }
    let Some(target) = target else {
        return String::new();
    };

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
    for (idx, mut fa) in (0u32..).zip(candidates) {
        fa.id = idx;
        fa.findings.retain(|f| keep.contains(f.id.as_str()));
        fa.context
            .retain(|line| line.notes.iter().any(|n| keep.contains(n.id.as_str())));
        if !fa.context.is_empty() {
            files.push(fa);
        }
    }
    if files.is_empty() {
        return String::new();
    }

    let mut evidence = cleave::AnalysisReport::new(target);
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
    cleave::output::format_context(&evidence, &opts)
}

/// Concise note for the no-change case: when the diff surfaced nothing but the
/// new artifact still carries suspicious/hostile traits, say so in one or two
/// lines rather than staying fully silent. Returns `None` when the artifact is
/// genuinely clean (then isomer prints nothing, like `diff`). Does not affect
/// the exit code — this is context, not a new finding.
pub(crate) fn existing_risk(
    pairs: &[Pair],
    options: &cleave::AnalysisOptions,
    name: &str,
) -> Option<String> {
    use cleave::Criticality;
    use std::collections::BTreeMap;

    // Highest criticality per namespace across every changed file.
    let mut worst: BTreeMap<String, Criticality> = BTreeMap::new();
    for pair in pairs {
        let Some(new_path) = pair.new.as_deref() else {
            continue;
        };
        let Some(report) = analyze(new_path, options) else {
            continue;
        };
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
    }
    if worst.is_empty() {
        return None;
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
    Some(format!(
        " {name} · no behavioral change · existing {label} traits:\n   {list}\n"
    ))
}

/// Capability classes present in the base version, so the rubric can tell a
/// wholly new class from one that merely gained a trait. Empty on analysis
/// failure (then everything reads as new, the safe default).
pub(crate) fn base_classes(
    pairs: &[Pair],
    options: &cleave::AnalysisOptions,
) -> std::collections::HashSet<String> {
    use cleave::Criticality;
    let mut classes = std::collections::HashSet::new();
    for pair in pairs {
        // A file the change *added* has no base side — every class it carries
        // is new by definition, which is what an empty contribution means.
        let Some(old_path) = pair.old.as_deref() else {
            continue;
        };
        let Ok(report) = cleave::analyze_file(old_path, options) else {
            continue;
        };
        classes.extend(
            report
                .findings
                .iter()
                .chain(report.files.iter().flat_map(|f| f.findings.iter()))
                // Only count a class the base exhibited *meaningfully*
                // (notable+). A baseline-criticality substring match doesn't
                // mean the base "did C2"; counting it would dismiss a
                // genuinely new capability as "expanded". Erring toward
                // notable+ keeps new capabilities flagged as new.
                .filter(|f| {
                    matches!(
                        f.crit,
                        Criticality::Notable | Criticality::Suspicious | Criticality::Hostile
                    )
                })
                .filter_map(|f| crate::rubric::capability_class(&f.id))
                .map(str::to_string),
        );
    }
    classes
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
