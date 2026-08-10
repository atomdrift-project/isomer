//! Evidence rendering — the proof behind the verdict.
//!
//! The diff report names *which* traits appeared but carries none of their
//! matched bytes. To show a security engineer the actual code or hex where a
//! gained capability lives — the same context windows cleave and scan render —
//! we re-analyze the new side (cached, so cheap) and reuse cleave's own
//! context renderer, filtered to just the traits the diff surfaced. The
//! evidence is the *delta*: only windows touching a gained trait render, so the
//! engineer sees what changed, not the whole file.

use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;
use std::path::Path;

use crate::Severity;
use crate::analysis::Pair;
use crate::rubric::{crit_rank, namespace_of};

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
    pub severity: Severity,
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

/// Analyze one file. A file that cannot be analyzed costs its own evidence and
/// nothing else: the verdict already stands on the diff, so this logs and moves
/// on rather than failing the run.
fn analyze(path: &Path, options: &cleave::AnalysisOptions) -> Option<cleave::AnalysisReport> {
    match cleave::analyze_file(path, options) {
        Ok(r) => Some(r),
        Err(e) => {
            eprintln!("isomer: could not analyze {}: {e:#}", path.display());
            None
        }
    }
}

/// Diff-style evidence hunks for the gained traits: one hunk per matched
/// region, each attributed to its strongest rule, contiguous regions merged,
/// one hunk per distinct rule, **strongest first**.
///
/// Ranked rather than display-ordered because the cap differs per sink (five in
/// a terminal, twenty-four in the JSON record); [`strongest`] applies a cap and
/// returns to file order. Re-analyzing per sink is the expensive part, so this
/// runs once per report — see [`crate::analysis::Analysis::hunks`].
pub(crate) fn hunks(
    pairs: &[Pair],
    options: &cleave::AnalysisOptions,
    gained_ids: &HashSet<&str>,
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
    // match.
    merge_contiguous(&mut all);
    for h in &mut all {
        trim(h);
    }
    // Notable+ hunks own the slots; baseline-tier matches qualify only when
    // nothing stronger exists (they're context, not standalone proof).
    if all.iter().any(|h| h.severity >= Severity::Medium) {
        all.retain(|h| h.severity >= Severity::Medium);
    }
    all.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.score.total_cmp(&a.score))
            .then(a.loc.cmp(&b.loc))
    });
    // One hunk per rule, so five hunks show five behaviors rather than one
    // behavior five times.
    let mut seen: HashSet<String> = HashSet::new();
    all.retain(|h| seen.insert(h.desc.clone()));
    all
}

/// The strongest `limit` hunks of a ranked set, presented in file order — the
/// order a reader scans a diff in.
pub(crate) fn strongest(all: &[Hunk], limit: usize) -> Vec<&Hunk> {
    let mut shown: Vec<&Hunk> = all.iter().take(limit).collect();
    shown.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.member.cmp(&b.member))
            .then(a.loc.cmp(&b.loc))
    });
    shown
}

/// Collect one file's hunks (the file itself plus any archive members) into
/// `all`.
fn file_hunks(
    pair: &Pair,
    report: &cleave::AnalysisReport,
    gained_ids: &HashSet<&str>,
    all: &mut Vec<Hunk>,
) {
    // The root analysis plus one entry per archive member, all borrowed: these
    // carry every matched byte window in the file, so copying them to iterate
    // twice would dwarf the work being done.
    let root = report.to_file_analysis(0);
    let candidates: Vec<(Option<String>, &cleave::types::FileAnalysis)> =
        std::iter::once((None, &root))
            .chain(
                report
                    .files
                    .iter()
                    .map(|fa| (Some(clean_member(&fa.path)), fa)),
            )
            .collect();
    // The composite legs a gained trait references, so a gained composite still
    // renders the component windows that justify it. cleave finding ids are
    // interned (`Istr`); compare at the `&str` boundary so this holds whether
    // the field is `String` or `Istr`.
    let legs: HashSet<&str> = candidates
        .iter()
        .flat_map(|(_, fa)| &fa.findings)
        .filter(|f| gained_ids.contains(f.id.as_str()))
        .flat_map(|f| f.trait_refs.iter().map(cleave::types::Istr::as_str))
        .collect();
    let keep = |id: &str| gained_ids.contains(id) || legs.contains(id);

    let container = !report.files.is_empty();
    let old_lines = pair.old.as_deref().and_then(|p| old_line_set(p, container));

    for (member, fa) in &candidates {
        let shown = member.clone().unwrap_or_else(|| pair.label.clone());
        for chunk in &fa.context {
            let kept: Vec<&cleave::types::Note> =
                chunk.notes.iter().filter(|n| keep(n.id.as_str())).collect();
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
        crate::printable(n.desc.as_str())
    }
}

/// A hunk's tier — the rule's own criticality, which is where trait severity is
/// maintained. Unlike the rubric's mapping, sub-notable tiers land on `Low`
/// rather than `None`: a baseline window is still evidence, just weaker.
fn tier(c: cleave::Criticality) -> Severity {
    use cleave::Criticality::{Hostile, Notable, Suspicious};
    match c {
        Hostile => Severity::Critical,
        Suspicious => Severity::High,
        Notable => Severity::Medium,
        _ => Severity::Low,
    }
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
            crate::clip(&format!("…{}", full.trim_end()), CODE_W)
        } else {
            crate::clip(full.trim_end(), CODE_W)
        };
        lines.push(HunkLine {
            locator: (first_line + i as u64).to_string(),
            // Neutralize control chars before display; the `added` diff below
            // still compares the raw line, so the `+` gutter stays exact.
            text: crate::printable(&text),
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
        severity: tier(top.crit),
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
        severity: tier(top.crit),
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
        let _ = write!(s, "{b:02x} ");
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

/// `<root>!!package/foo.js` → `package/foo.js`; a bare member name is kept.
///
/// A member name is chosen by whoever built the archive, so it is neutralized
/// here: it reaches the terminal, the SARIF logical location, and the PR
/// comment, and an archive is free to name a file `evil\x1b[2J`.
fn clean_member(path: &str) -> String {
    crate::printable(path.rsplit("!!").next().unwrap_or(path))
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
    gained_ids: &HashSet<&str>,
    compact: bool,
) -> String {
    if gained_ids.is_empty() {
        return String::new();
    }

    // Candidate files across every changed file: each root plus any archive
    // members, converted to the FileAnalysis shape `format_context` consumes.
    // Owned, because the filtering below rewrites them in place.
    let mut candidates: Vec<cleave::types::FileAnalysis> = Vec::new();
    let mut target = None;
    for pair in pairs {
        let Some(new_path) = pair.new.as_deref() else {
            continue;
        };
        let Some(mut report) = analyze(new_path, options) else {
            continue;
        };
        candidates.push(report.to_file_analysis(0));
        if target.is_none() {
            target = Some(report.target.clone());
        }
        candidates.append(&mut report.files);
    }
    let Some(target) = target else {
        return String::new();
    };

    // The composite legs the gained traits reference, so a gained composite
    // still renders the component windows that justify it. Owned, so the
    // borrow of `candidates` ends before they are rewritten below.
    let legs: HashSet<String> = candidates
        .iter()
        .flat_map(|fa| &fa.findings)
        .filter(|f| gained_ids.contains(f.id.as_str()))
        .flat_map(|f| f.trait_refs.iter().map(|s| s.as_str().to_string()))
        .collect();
    let keep = |id: &str| gained_ids.contains(id) || legs.contains(id);

    // Filter each candidate to the kept traits and drop those left with nothing
    // to show. Renumber ids so `format_context`'s id→file map stays unique.
    let mut files: Vec<cleave::types::FileAnalysis> = Vec::new();
    for (idx, mut fa) in (0u32..).zip(candidates) {
        fa.id = idx;
        fa.findings.retain(|f| keep(f.id.as_str()));
        fa.context
            .retain(|line| line.notes.iter().any(|n| keep(n.id.as_str())));
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
                let slot = worst.entry(namespace_of(&f.id)).or_insert(f.crit);
                if crit_rank(f.crit) > crit_rank(*slot) {
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
    items.sort_by(|a, b| crit_rank(b.1).cmp(&crit_rank(a.1)).then(a.0.cmp(&b.0)));
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

/// What each side of the change exhibits, gathered in one walk over both.
///
/// Both sides are analyzed anyway — the base for its capability classes, the
/// head for evidence — and cleave caches per content hash, so collecting the
/// framework annotations here costs nothing beyond the bookkeeping.
#[derive(Debug, Default)]
pub(crate) struct Survey {
    /// Capability classes present in the base version, so the rubric can tell
    /// a wholly new class from one that merely gained a trait.
    pub base_classes: HashSet<String>,
    /// MITRE ATT&CK technique ids seen on each side.
    pub attack: Sides,
    /// MBC behavior ids seen on each side.
    pub mbc: Sides,
}

/// One framework's ids on either side of the change.
#[derive(Debug, Default)]
pub(crate) struct Sides {
    pub old: BTreeSet<String>,
    pub new: BTreeSet<String>,
}

impl Sides {
    /// Ids the change introduced.
    pub(crate) fn gained(&self) -> Vec<&str> {
        self.new.difference(&self.old).map(String::as_str).collect()
    }

    /// Ids the change removed. Reported because a technique disappearing is
    /// how a reviewer sees a fix land, not only how a regression looks.
    pub(crate) fn lost(&self) -> Vec<&str> {
        self.old.difference(&self.new).map(String::as_str).collect()
    }

    /// Ids present before and after — context for how much is genuinely new.
    pub(crate) fn kept(&self) -> usize {
        self.old.intersection(&self.new).count()
    }

    pub(crate) fn changed(&self) -> bool {
        self.old != self.new
    }
}

/// Walk both sides, collecting capability classes and framework annotations.
/// A file that fails to analyze contributes nothing rather than failing the
/// run; on the base side that makes its capabilities read as new, which is the
/// safe direction to be wrong in.
pub(crate) fn survey(pairs: &[Pair], options: &cleave::AnalysisOptions) -> Survey {
    use cleave::Criticality;
    let mut survey = Survey::default();
    for pair in pairs {
        // A file the change *added* has no base side — every class it carries
        // is new by definition, which is what an empty contribution means.
        for (path, is_base) in [(pair.old.as_deref(), true), (pair.new.as_deref(), false)] {
            let Some(path) = path else {
                continue;
            };
            let Some(report) = analyze(path, options) else {
                continue;
            };
            let findings = report
                .findings
                .iter()
                .chain(report.files.iter().flat_map(|f| f.findings.iter()))
                // Only count what the artifact exhibits *meaningfully*
                // (notable+), matching the rubric's reporting floor. A
                // baseline match doesn't mean the base "did C2"; counting it
                // would dismiss a genuinely new capability as "expanded".
                .filter(|f| {
                    matches!(
                        f.crit,
                        Criticality::Notable | Criticality::Suspicious | Criticality::Hostile
                    )
                });
            for f in findings {
                if is_base && let Some(class) = crate::rubric::capability_class(&f.id) {
                    survey.base_classes.insert(class);
                }
                let attack = ids(f.attack.as_ref().map(cleave::types::Istr::as_str));
                let mbc = ids(f.mbc.as_ref().map(cleave::types::Istr::as_str));
                if is_base {
                    survey.attack.old.extend(attack);
                    survey.mbc.old.extend(mbc);
                } else {
                    survey.attack.new.extend(attack);
                    survey.mbc.new.extend(mbc);
                }
            }
        }
    }
    survey
}

/// Split a framework annotation into ids. Traits write these as a free-text
/// field — `T1003`, `"T1003, T1041"`, `T1027,T1140`, or empty — so the split
/// is on commas with the pieces trimmed, and anything that doesn't look like
/// an identifier is dropped rather than shown to a reader as one.
fn ids(field: Option<&str>) -> Vec<String> {
    field
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 16
                && s.starts_with(|c: char| c.is_ascii_alphabetic())
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.')
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Traits write ATT&CK and MBC annotations as free text, so the parser
    /// meets every shape the corpus actually contains — a bare id, a quoted
    /// comma list with spaces, a comma list without, an empty field — and
    /// refuses anything that would put non-identifier text in front of a
    /// reader as though it were a technique.
    #[test]
    fn framework_ids_parse_the_shapes_traits_use() {
        assert_eq!(ids(Some("T1003")), ["T1003"]);
        assert_eq!(ids(Some("T1003, T1041")), ["T1003", "T1041"]);
        assert_eq!(ids(Some("T1027,T1140")), ["T1027", "T1140"]);
        assert_eq!(ids(Some("T1003.008")), ["T1003.008"]);
        assert_eq!(ids(Some("B0001.009")), ["B0001.009"]);
        assert!(ids(Some("")).is_empty());
        assert!(ids(None).is_empty());
        // Junk is dropped rather than displayed as a technique.
        assert!(ids(Some("see the notes above")).is_empty());
        assert!(ids(Some("  ,  ")).is_empty());
        assert_eq!(ids(Some("T1003, oops!, T1041")), ["T1003", "T1041"]);
    }

    /// The delta is a set difference in both directions: a technique that
    /// disappears is how a fix reads, and must not be silently dropped.
    #[test]
    fn sides_report_both_directions() {
        let sides = Sides {
            old: ["T1", "T2"].iter().map(ToString::to_string).collect(),
            new: ["T2", "T3"].iter().map(ToString::to_string).collect(),
        };
        assert_eq!(sides.gained(), ["T3"]);
        assert_eq!(sides.lost(), ["T1"]);
        assert_eq!(sides.kept(), 1);
        assert!(sides.changed());

        let same = Sides {
            old: ["T1"].iter().map(ToString::to_string).collect(),
            new: ["T1"].iter().map(ToString::to_string).collect(),
        };
        assert!(!same.changed());
        assert!(same.gained().is_empty());
    }
}
