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

use cleave::types::{DiffReportV1, FileStatus};

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
/// The LLM gets a wider set than the terminal: it reads for reasoning, not at a
/// glance, so more distinct signals help — but still the ranked, one-per-rule
/// top, not every match (a `substr: SYSTEM` trait hitting 30 files must not
/// drown the one change that matters).
pub(crate) const LLM_HUNKS: usize = 10;
/// Hard ceiling on a hunk's rendered lines; the per-tier window in [`trim`]
/// picks the actual count (2·ctx+1), so a hostile hit fills this and a notable
/// one uses ~5.
const MAX_HUNK_LINES: usize = 9;

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
    /// True when this hunk is a run of *added* source lines (the differential
    /// view), rather than a match window. Additions carry the full change — the
    /// lines a release introduced, matched or not — so they skip the
    /// match-centric [`trim`]/[`merge_contiguous`] passes, survive the
    /// notable-floor retain that culls weak match windows, and render
    /// filename-grouped rather than one-header-per-window.
    pub(crate) additions: bool,
    pub lines: Vec<HunkLine>,
    /// 1-based line range covered (text hunks), for contiguity merging.
    span: Option<(u64, u64)>,
    /// Index into `lines` of the top match, kept for trimming.
    top: usize,
}

impl Hunk {
    /// The name a hunk is filed under: the archive member when it is one, else
    /// the pair's own label (a plain file's basename).
    pub(crate) fn display_name(&self) -> &str {
        self.member.as_deref().unwrap_or(self.file.as_str())
    }
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
    diff: &DiffReportV1,
) -> Vec<Hunk> {
    if gained_ids.is_empty() {
        return Vec::new();
    }
    // The members the diff reports as actually changed. isomer is differential:
    // a gained trait's proof lives in a file that *moved*, not in an unchanged
    // bundled library that happened to already carry the same construct
    // (unrealircd's backdoor `memcmp` in `s_bsd.c`, not the identical `memcmp`
    // in the untouched `c-ares` copy). Members outside this set are excluded so
    // the evidence tracks the change, not the whole artifact. A root-level pair
    // (a plain source file, no `!!`) is always its own changed file, so an empty
    // set never filters those — [`file_hunks`] only consults it for members.
    let changed: HashSet<String> = diff
        .files
        .iter()
        .filter(|f| !matches!(f.status, FileStatus::Unchanged))
        .map(|f| clean_member(&f.path))
        .collect();
    let mut all: Vec<Hunk> = Vec::new();
    for pair in pairs {
        let Some(new_path) = pair.new.as_deref() else {
            continue;
        };
        let Some(report) = analyze(new_path, options) else {
            continue;
        };
        file_hunks(pair, &report, gained_ids, &changed, &mut all);
        if all.len() >= HUNK_BUDGET {
            break;
        }
    }

    // Match windows merge and trim to a short excerpt around their hit;
    // addition runs already carry the whole change, contiguity-grouped and
    // per-run capped, so both passes leave them untouched.
    merge_contiguous(&mut all);
    for h in &mut all {
        if !h.additions {
            trim(h);
        }
    }
    // Notable+ owns the slots — a baseline *match window* is context, not proof,
    // and is culled when anything stronger exists. Addition runs are exempt:
    // they are the change itself, and a sub-notable added line (unrealircd's
    // `system()` macro) is exactly what must not be dropped.
    if all.iter().any(|h| h.severity >= Severity::Medium) {
        all.retain(|h| h.severity >= Severity::Medium || h.additions);
    }
    all.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.score.total_cmp(&a.score))
            .then(a.loc.cmp(&b.loc))
    });
    // One window per rule (five hunks show five behaviors, not one behavior five
    // times); addition runs dedup by location instead — each is a distinct
    // region of the change, and they share the generic "added code" headline.
    let mut seen: HashSet<String> = HashSet::new();
    all.retain(|h| {
        seen.insert(if h.additions {
            h.location.clone()
        } else {
            h.desc.clone()
        })
    });
    all
}

/// Every finding in a report — the artifact's own, then each archive member's.
/// A capability is a capability wherever it lives, and no caller here cares
/// which level of an archive produced it.
pub(crate) fn all_findings(
    report: &cleave::AnalysisReport,
) -> impl Iterator<Item = &cleave::types::Finding> {
    report
        .findings
        .iter()
        .chain(report.files.iter().flat_map(|f| f.findings.iter()))
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

/// The run of addition hunks starting at `start` that share one file.
///
/// Every renderer heads such a run with one filename, one severity, and one
/// caption, then prints its runs in source order — so the grouping rule lives
/// here once rather than three times over, and the terminal, the PR comment,
/// and the LLM payload cannot drift apart on what counts as one file's change.
pub(crate) struct Additions<'a> {
    /// The file the whole run belongs to; the header's name.
    pub name: &'a str,
    /// Index one past the run's last hunk — where the caller resumes.
    pub end: usize,
    /// Worst severity in the run; the header's bar or dots.
    pub severity: Severity,
    /// Strongest hunk that named a rule, if any; the header's caption.
    pub top: Option<&'a Hunk>,
}

/// Group the addition hunks at `start`. See [`Additions`]. `start` past the end
/// yields an empty, unnamed run rather than panicking — no caller relies on
/// that, but a grouping helper should not be the thing that panics.
pub(crate) fn additions_at<'a>(hunks: &[&'a Hunk], start: usize) -> Additions<'a> {
    let Some(first) = hunks.get(start) else {
        return Additions {
            name: "",
            end: start,
            severity: Severity::None,
            top: None,
        };
    };
    let name = first.display_name();
    let mut end = start;
    while end < hunks.len() && hunks[end].additions && hunks[end].display_name() == name {
        end += 1;
    }
    let group = &hunks[start..end];
    Additions {
        name,
        end,
        severity: group
            .iter()
            .map(|h| h.severity)
            .max()
            .unwrap_or(Severity::None),
        top: group
            .iter()
            .filter(|h| !h.desc.is_empty())
            .max_by(|a, b| {
                a.severity
                    .cmp(&b.severity)
                    .then(a.score.total_cmp(&b.score))
            })
            .copied(),
    }
}

/// The distilled hunks as plain text for the LLM payload — strongest rule
/// first, one per rule, each a small diff excerpt (`+` new, `>` matched, ` `
/// context). This replaces the dump-every-match [`render`] on the LLM path:
/// there, one broad trait matching dozens of benign files (unrealircd's
/// `substr: SYSTEM`) produced dozens of windows and buried the real change,
/// which then read to the model as a false positive.
pub(crate) fn render_hunks(hunks: &[&Hunk]) -> String {
    let mut s = String::new();
    let mut i = 0;
    while i < hunks.len() {
        if hunks[i].additions {
            // Filename once, captioned with its strongest rule, then the added
            // lines run by run (`⋯` at each gap, `>` on matched lines) — the
            // model sees the whole change with the detected lines marked, not
            // scattered windows.
            let run = additions_at(hunks, i);
            let name = run.name;
            let caption = match run.top {
                Some(t) => format!(" — {} [{}]", t.desc, t.severity.as_str()),
                None => String::new(),
            };
            let _ = writeln!(s, "\n{name}{caption}  (added lines):");
            for (k, h) in hunks[i..run.end].iter().enumerate() {
                if k > 0 {
                    let _ = writeln!(s, "  ⋯");
                }
                for l in &h.lines {
                    let mark = if l.is_match { ">+" } else { " +" };
                    let _ = writeln!(s, "  {mark} {}", l.text);
                }
            }
            i = run.end;
        } else {
            let member = hunks[i]
                .member
                .as_deref()
                .map(|m| format!(" ({m})"))
                .unwrap_or_default();
            let _ = writeln!(
                s,
                "\n{}{}  [{}]  {}",
                hunks[i].location,
                member,
                hunks[i].severity.as_str(),
                hunks[i].desc
            );
            for l in &hunks[i].lines {
                let mark = match l.added {
                    Some(true) => '+',
                    _ if l.is_match => '>',
                    _ => ' ',
                };
                let _ = writeln!(s, "  {mark} {}", l.text);
            }
            i += 1;
        }
    }
    s
}

/// Collect one file's hunks (the file itself plus any archive members) into
/// `all`.
fn file_hunks(
    pair: &Pair,
    report: &cleave::AnalysisReport,
    gained_ids: &HashSet<&str>,
    changed: &HashSet<String>,
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
        // A hunk inside an archive member is evidence only if that member is one
        // the diff flagged as changed; an unchanged member carrying the same
        // construct is not what moved. The container root (`member == None`) is
        // the pair itself — always a changed file — so it is never filtered.
        if let Some(m) = member
            && !changed.contains(m)
        {
            continue;
        }
        // Source-additions path: when both sides' text is in reach, the change
        // *is* the added lines — show them whole (matched or not), so an attack
        // whose payload sits a few lines from the trait hit (unrealircd's
        // `system()` macro) stays in view. Needs a text new side and the old
        // text as the line-diff baseline; archive members are pulled per side.
        if let (Some(new_src), Some(old_src)) = (
            member_source(pair.new.as_deref(), member.as_deref()),
            member_source(pair.old.as_deref(), member.as_deref()),
        ) && !new_src.is_empty()
            && !looks_binary(&new_src)
        {
            addition_hunks(
                &new_src,
                &old_src,
                fa,
                &keep,
                &pair.label,
                member.as_deref(),
                all,
            );
            if all.len() >= HUNK_BUDGET {
                return;
            }
            continue;
        }

        // Binary / added-file fallback: match windows, cleave's presentation.
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
            let label = pair.label.as_str();
            all.push(match chunk.line {
                Some(first) => text_hunk(
                    chunk,
                    first,
                    &kept,
                    top,
                    label,
                    member.as_deref(),
                    old_lines.as_ref(),
                ),
                None => binary_hunk(chunk, top, label, member.as_deref()),
            });
            if all.len() >= HUNK_BUDGET {
                return;
            }
        }
    }
}

/// The source text of one changed file, per side. A plain-file pair reads the
/// path directly; an archive member is pulled from the archive by cleave (which
/// owns the decoders). `None` when the bytes are out of reach — a deleted side,
/// a member inside a nested archive, an unsupported container — and the caller
/// falls back to match-window evidence.
fn member_source(archive_or_file: Option<&Path>, member: Option<&str>) -> Option<Vec<u8>> {
    let p = archive_or_file?;
    match member {
        None => std::fs::read(p).ok(),
        Some(m) => cleave::extract_member(p, m).ok().flatten(),
    }
}

/// A NUL byte in the head marks binary content — cleave's own sniff, named
/// here so the two places that need it cannot drift on the window size.
fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|b| *b == 0)
}

/// 1-based line of a byte offset, by counting newlines before it — maps a
/// cleave match offset (into this member's own bytes) onto a source line.
fn line_at(bytes: &[u8], off: u64) -> usize {
    let end = usize::try_from(off).unwrap_or(usize::MAX).min(bytes.len());
    1 + bytes[..end].iter().filter(|&&b| b == b'\n').count()
}

/// Runs of lines a release *added* to one source file, each rendered as a hunk.
/// A run carrying a gained-trait match takes that rule's tier and headline and
/// leads the ranking; the rest are shown as plain additions so the whole change
/// is visible — the point of the differential view.
fn addition_hunks(
    new: &[u8],
    old: &[u8],
    fa: &cleave::types::FileAnalysis,
    keep: &impl Fn(&str) -> bool,
    file: &str,
    member: Option<&str>,
    all: &mut Vec<Hunk>,
) {
    // Lines only on the new side (set-based, matching `analysis::line_diff` so
    // a moved line reads as context, not an addition).
    let old_text = String::from_utf8_lossy(old);
    let old_set: HashSet<&str> = old_text.lines().map(str::trim).collect();
    let new_text = String::from_utf8_lossy(new);
    let new_lines: Vec<&str> = new_text.lines().collect();

    // Strongest kept match per 1-based line, from cleave's analysis of the new
    // side. Offsets are into this member's own bytes, so a newline count places
    // each on its line.
    let mut hit: std::collections::HashMap<usize, &cleave::types::Note> =
        std::collections::HashMap::new();
    for note in fa.context.iter().flat_map(|c| &c.notes) {
        if !keep(note.id.as_str()) {
            continue;
        }
        let ln = line_at(new, note.off);
        hit.entry(ln)
            .and_modify(|cur| {
                if score(note) > score(cur) {
                    *cur = note;
                }
            })
            .or_insert(note);
    }

    let added = |k: usize| k < new_lines.len() && !old_set.contains(new_lines[k].trim());
    let mut i = 0;
    while i < new_lines.len() {
        if !added(i) {
            i += 1;
            continue;
        }
        let start = i;
        while added(i) {
            i += 1;
        }
        // A run of only blank additions is a reformat, not content.
        if (start..i).all(|k| new_lines[k].trim().is_empty()) {
            continue;
        }
        all.push(addition_run(&new_lines, start, i, &hit, file, member));
        if all.len() >= HUNK_BUDGET {
            return;
        }
    }
}

/// One contiguous added-line run (`[start, end)`, 0-based) as a hunk. Capped at
/// [`MAX_RUN_LINES`] with a `+N more added` tail so a large legitimate edit
/// cannot flood the evidence.
fn addition_run(
    new_lines: &[&str],
    start: usize,
    end: usize,
    hit: &std::collections::HashMap<usize, &cleave::types::Note>,
    file: &str,
    member: Option<&str>,
) -> Hunk {
    /// Lines shown before the run is summarized — a per-run twin of
    /// [`MAX_HUNKS`], generous enough for a whole small payload.
    const MAX_RUN_LINES: usize = 20;
    let first_line = start + 1;
    // Strongest match anywhere in the run drives the header and tier.
    let top = (start..end)
        .filter_map(|k| hit.get(&(k + 1)).copied())
        .max_by(|a, b| score(a).total_cmp(&score(b)));

    let mut lines: Vec<HunkLine> = (start..end.min(start + MAX_RUN_LINES))
        .map(|k| HunkLine {
            locator: (k + 1).to_string(),
            text: crate::printable(&crate::clip(new_lines[k].trim_end(), CODE_W)),
            added: Some(true),
            is_match: hit.contains_key(&(k + 1)),
        })
        .collect();
    let overflow = (end - start).saturating_sub(MAX_RUN_LINES);
    if overflow > 0 {
        lines.push(HunkLine {
            locator: String::new(),
            text: format!("… +{overflow} more added"),
            added: None,
            is_match: false,
        });
    }

    // A run with a match wears that rule's tier and headline and ranks with the
    // findings; a run without carries `None` and an empty headline — it renders
    // as a titleless block of added lines under the file, so the detected
    // behavior still stands out while the rest of the change stays visible.
    let (severity, score_v, id, desc) = match top {
        Some(n) => (
            tier(n.crit),
            score(n),
            n.id.as_str().to_string(),
            desc_of(n),
        ),
        None => (Severity::None, 0.0, String::new(), String::new()),
    };
    Hunk {
        file: file.to_string(),
        member: member.map(str::to_string),
        line: Some(first_line as u64),
        loc: first_line as u64,
        location: format!("{}:{first_line}", member.unwrap_or(file)),
        id,
        desc,
        severity,
        binary: false,
        score: score_v,
        additions: true,
        lines,
        span: Some((first_line as u64, end as u64)),
        top: 0,
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
    // An *empty* old side is not rejected here: it means every new line really
    // is an addition, which is exactly what an empty set renders.
    if looks_binary(&bytes) {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes);
    Some(text.lines().map(|l| l.trim().to_string()).collect())
}

/// A text hunk: every line of the chunk, matches marked, the top match's line
/// windowed around its column.
fn text_hunk(
    chunk: &cleave::types::ContextLine,
    first_line: u64,
    kept: &[&cleave::types::Note],
    top: &cleave::types::Note,
    file: &str,
    member: Option<&str>,
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
        file: file.to_string(),
        member: member.map(str::to_string),
        line: Some(first_line + top_idx as u64),
        loc: top.off,
        location: format!("{}:{}", member.unwrap_or(file), first_line + top_idx as u64),
        id: top.id.as_str().to_string(),
        desc: desc_of(top),
        severity: tier(top.crit),
        binary: false,
        score: score(top),
        additions: false,
        lines,
        span: Some((first_line, first_line + spans.len() as u64 - 1)),
        top: top_idx,
    }
}

/// A binary hunk: hex|ascii dump rows at the match, cleave's presentation.
/// The `+` is semantic — the trait is an addition — since binary bytes have
/// no line diff. The header carries no offset; the rows do.
fn binary_hunk(
    chunk: &cleave::types::ContextLine,
    top: &cleave::types::Note,
    file: &str,
    member: Option<&str>,
) -> Hunk {
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
        file: file.to_string(),
        member: member.map(str::to_string),
        line: None,
        loc: top.off,
        location: member.unwrap_or(file).to_string(),
        id: top.id.as_str().to_string(),
        desc: desc_of(top),
        severity: tier(top.crit),
        binary: true,
        score: score(top),
        additions: false,
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
        // Addition runs are self-contained (already maximal, per-run capped);
        // only match windows merge.
        let Some(prev) = out
            .last_mut()
            .filter(|p| p.file == h.file && p.member == h.member && !p.additions && !h.additions)
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
    // Context lines each side of the match, by the hunk's tier: a hostile hit
    // earns room to show intent (the legs a composite fired on read as ordinary
    // context lines here), a notable one just enough to read the matched line.
    let ctx = match h.severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        _ => 1,
    };
    let window = (2 * ctx + 1).min(MAX_HUNK_LINES);
    if h.lines.len() > window {
        let start = h.top.saturating_sub(ctx).min(h.lines.len() - window);
        h.lines.drain(..start);
        h.lines.truncate(window);
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
        for f in all_findings(&report) {
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
    /// Files declared as local runtime entrypoints by a structured package
    /// manifest. These are content-derived graph edges (for example,
    /// `package.json` `main` -> `index.js`), not trait matches. Paths are
    /// archive-root independent so they can be joined to the normalized diff.
    pub runtime_entrypoints: HashSet<String>,
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
            if !is_base {
                survey
                    .runtime_entrypoints
                    .extend(manifest_runtime_entrypoints(&report));
            }
            let findings = all_findings(&report)
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

/// Resolve local references emitted by structured package manifests to the
/// members they select. Cleave's compact projection already performs exact
/// sibling/extension resolution, so Isomer consumes that graph instead of
/// guessing from filenames. The archive root is discarded because the diff
/// deliberately normalizes version-bearing roots between releases.
fn manifest_runtime_entrypoints(report: &cleave::AnalysisReport) -> HashSet<String> {
    let paths: HashSet<&str> = report.files.iter().map(|file| file.path.as_str()).collect();
    let mut entrypoints: HashSet<String> = report
        .files
        .iter()
        .filter(|file| {
            filefacts::FileType::from_label(&file.file_type)
                .is_some_and(|file_type| file_type.is_structured_data())
        })
        .flat_map(|file| {
            file.filefacts
                .iter()
                .flat_map(|facts| facts.references.iter())
                .filter_map(|reference| match (&reference.kind, &reference.locator) {
                    (filefacts::RefKind::Local, filefacts::RefLocator::Path(path)) => {
                        resolve_report_local_target(&file.path, path, &paths)
                    }
                    _ => None,
                })
        })
        .map(|path| {
            path.split_once("!!")
                .map_or(path, |(_, member)| member)
                .to_string()
        })
        .collect();

    // Some ecosystems declare identity directly in the runtime file instead
    // of a separate manifest: WordPress plugin headers are the common case,
    // but this is deliberately format-neutral. A source member that carries
    // the package's own name/version is a package entrypoint candidate; helper
    // files normally carry no identity at all.
    entrypoints.extend(report.files.iter().filter_map(|file| {
        let source = filefacts::FileType::from_label(&file.file_type)
            .is_some_and(|file_type| file_type.is_source_code());
        (source && file.identity.is_some()).then(|| {
            file.path
                .split_once("!!")
                .map_or(file.path.as_str(), |(_, member)| member)
                .to_string()
        })
    }));
    entrypoints
}

/// Resolve one manifest-local path against the files Cleave actually emitted.
/// Package formats routinely omit an extension or name a directory, so mirror
/// the conservative resolution Filefacts/Cleave use for their reference graph.
fn resolve_report_local_target<'a>(
    referrer: &str,
    spec: &str,
    paths: &HashSet<&'a str>,
) -> Option<&'a str> {
    let mut parts: Vec<&str> = referrer.split('/').collect();
    parts.pop();
    for part in spec.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    let base = parts.join("/");
    let candidates = std::iter::once(base.clone())
        .chain(
            [".js", ".cjs", ".mjs", ".json", ".node"]
                .into_iter()
                .map(|extension| format!("{base}{extension}")),
        )
        .chain(
            ["/index.js", "/index.cjs", "/index.mjs", "/index.json"]
                .into_iter()
                .map(|index| format!("{base}{index}")),
        );
    candidates
        .filter_map(|candidate| paths.get(candidate.as_str()).copied())
        .next()
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
