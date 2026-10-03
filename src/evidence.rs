//! Evidence rendering — the proof behind the verdict.
//!
//! The diff report names *which* traits appeared but carries none of their
//! matched bytes. To show a security engineer the actual code or hex where a
//! gained capability lives — the same context windows cleave and scan render —
//! we re-analyze the new side (cached, so cheap) and reuse cleave's own
//! context renderer, filtered to just the traits the diff surfaced. The
//! evidence is the *delta*: only windows touching a gained trait render, so the
//! engineer sees what changed, not the whole file.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write;
use std::path::Path;

use cleave::types::{DiffReportV1, FileStatus};

use crate::Severity;
use crate::analysis::Pair;
use crate::member::MemberPath;

/// Width (chars) of one displayed code row. Context lines truncate here; the
/// matched line may carry up to [`MATCH_W`] chars, which the renderer wraps
/// across continuation rows.
pub(crate) const CODE_W: usize = 88;

/// Window budget around the top match — three display rows' worth.
const MATCH_W: usize = 3 * CODE_W;

/// How many hunks the terminal's evidence section shows.
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
    /// Ranking score of the top note (crit × confidence).
    pub score: f32,
    pub kind: HunkKind,
    pub lines: Vec<HunkLine>,
}

/// What a hunk shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HunkKind {
    /// A window of source lines around a match. `span` is the 1-based lines
    /// it covers, for contiguity merging; `top` indexes its strongest match
    /// within `lines`, for trimming.
    Window { span: (u64, u64), top: usize },
    /// Hex rows at a match in a binary, which has no line structure.
    Bytes,
    /// A run of *added* source lines — the differential view. Additions carry
    /// the full change, matched or not, so they skip the match-centric
    /// [`trim`]/[`merge_contiguous`] passes, survive the notable-floor retain
    /// that culls weak match windows, and render filename-grouped rather than
    /// one-header-per-window.
    Additions,
}

impl Hunk {
    pub(crate) fn is_additions(&self) -> bool {
        self.kind == HunkKind::Additions
    }

    pub(crate) fn is_bytes(&self) -> bool {
        self.kind == HunkKind::Bytes
    }

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
    /// Whether the old version had this line.
    pub added: LineMark,
    /// Whether a kept rule matched on this line (vs pure context).
    pub is_match: bool,
}

/// Whether a line is new in this release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineMark {
    /// Absent from the old version: the `+` gutter.
    Added,
    /// Present in both.
    Context,
    /// No old text to diff against.
    Unknown,
}

impl LineMark {
    /// The JSON envelope's `added`: `true`, `false`, or omitted when unknown.
    pub(crate) fn as_flag(self) -> Option<bool> {
        match self {
            Self::Added => Some(true),
            Self::Context => Some(false),
            Self::Unknown => None,
        }
    }
}

/// How a byte-level note should be presented. Composite rules do not own a
/// single byte range: cleave records their matched component ids in
/// `trait_refs`, while the context windows carry notes for those components.
/// When a gained composite depends on a note, its conclusion is the useful
/// attribution (and ranking strength) for that window.
#[derive(Clone, Debug)]
struct Attribution {
    id: String,
    desc: String,
    severity: Severity,
    score: f32,
    /// Break equal-score ties in favor of the more specific composition.
    legs: usize,
}

/// Analyze one file. A file that cannot be analyzed costs its own evidence and
/// nothing else: the verdict already stands on the diff, so this logs and moves
/// on rather than failing the run.
fn analyze(path: &Path, options: &cleave::AnalysisOptions) -> Option<cleave::AnalysisReport> {
    match cleave::analyze_file(path, options) {
        Ok(r) => Some(r),
        Err(e) => {
            log::warn!("could not analyze {}: {e:#}", path.display());
            None
        }
    }
}

/// Diff-style evidence hunks for the gained traits: one hunk per matched
/// region, each attributed to its strongest rule, contiguous regions merged,
/// one hunk per distinct rule, **strongest first**.
///
/// Ranked rather than display-ordered because the cap differs per sink (five in
/// a terminal, ten for the LLM, twenty-four in SARIF, every hunk in the JSON
/// record); [`strongest`] applies a cap and returns to file order. Re-analyzing per sink is the expensive part, so this
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
    // bundled library that happened to already carry the same construct.
    // Members outside this set are excluded so the evidence tracks the change,
    // not the whole artifact. A root-level pair
    // (a plain source file, no `!!`) is always its own changed file, so an empty
    // set never filters those — [`file_hunks`] only consults it for members.
    let changed: HashSet<&str> = diff
        .files
        .iter()
        .filter(|f| !matches!(f.status, FileStatus::Unchanged))
        .map(|f| member_of(&f.path))
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
    }
    distill(&mut all);
    all
}

/// Rank the collected hunks, strongest first, keeping what proves the change.
fn distill(all: &mut Vec<Hunk>) {
    // Match windows merge and trim to a short excerpt around their hit;
    // addition runs already carry the whole change, contiguity-grouped and
    // per-run capped, so both passes leave them untouched.
    merge_contiguous(all);
    for h in all.iter_mut() {
        if !h.is_additions() {
            trim(h);
        }
    }
    // Notable+ owns the slots — a baseline *match window* is context, not proof,
    // and is culled when anything stronger exists. Addition runs are exempt:
    // they are the change itself, and a sub-notable added line is exactly what
    // must not be dropped. See `unrealircd_sub_notable_added_line_survives_the_cull`.
    if all.iter().any(|h| h.severity >= Severity::Medium) {
        all.retain(|h| h.severity >= Severity::Medium || h.is_additions());
    }
    all.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.score.total_cmp(&a.score))
            .then(a.loc.cmp(&b.loc))
    });
    one_per_rule(all);
}

/// Keep the first (strongest) window per rule — five hunks show five
/// behaviors, not one behavior five times. Addition runs dedup by location
/// instead: each is a distinct region of the change, and they share the
/// generic "added code" headline. Keyed on the rule's id, not its description:
/// rules without one all read "matched", and keying on that text collapsed
/// them into a single window.
fn one_per_rule(all: &mut Vec<Hunk>) {
    let mut seen: HashSet<(bool, &str)> = HashSet::new();
    let keep: Vec<bool> = all
        .iter()
        .map(|h| {
            seen.insert(if h.is_additions() {
                (true, h.location.as_str())
            } else {
                (false, h.id.as_str())
            })
        })
        .collect();
    let mut keep = keep.into_iter();
    all.retain(|_| keep.next().unwrap_or(false));
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

/// One block of evidence as every renderer lays it out.
///
/// The grouping rule lives here once rather than three times over, so the
/// terminal, the PR comment, and the LLM payload cannot drift apart on what
/// counts as one file's change.
pub(crate) enum Group<'a> {
    /// One file's added lines, run by run in source order: headed once by the
    /// file's name, its worst severity, and the strongest rule among them.
    Additions {
        /// The file the runs belong to; the header's name.
        name: &'a str,
        /// Worst severity across the runs; the header's bar or dots.
        severity: Severity,
        /// The strongest hunk that named a rule, if any; the header's caption.
        top: Option<&'a Hunk>,
        runs: &'a [&'a Hunk],
    },
    /// A match window or binary hunk, headed by its own rule.
    Single(&'a Hunk),
}

/// The blocks `hunks` read as: each run of one file's added lines together,
/// every other hunk on its own.
pub(crate) fn groups<'a>(hunks: &'a [&'a Hunk]) -> impl Iterator<Item = Group<'a>> {
    hunks
        .chunk_by(|a, b| {
            a.is_additions() && b.is_additions() && a.display_name() == b.display_name()
        })
        .map(|chunk| match chunk {
            [single] if !single.is_additions() => Group::Single(single),
            runs => Group::Additions {
                name: runs.first().map_or("", |h| h.display_name()),
                severity: runs
                    .iter()
                    .map(|h| h.severity)
                    .max()
                    .unwrap_or(Severity::None),
                top: runs
                    .iter()
                    .filter(|h| !h.desc.is_empty())
                    .max_by(|a, b| {
                        a.severity
                            .cmp(&b.severity)
                            .then(a.score.total_cmp(&b.score))
                    })
                    .copied(),
                runs,
            },
        })
}

/// The distilled hunks as plain text for the LLM payload — strongest rule
/// first, one per rule, each a small diff excerpt (`+` new, `>` matched, ` `
/// context). This replaces the old dump-every-match window `render` on the
/// LLM path: there, one broad trait matching dozens of benign files produced
/// dozens of windows and buried the real change, which then read to the model
/// as a false positive.
pub(crate) fn render_hunks(out: &mut impl Write, hunks: &[&Hunk]) -> std::fmt::Result {
    for group in groups(hunks) {
        match group {
            Group::Additions {
                name, top, runs, ..
            } => {
                // Filename once, captioned with its strongest rule, then the
                // added lines run by run (`⋯` at each gap, `>` on matched
                // lines) — the model sees the whole change with the detected
                // lines marked, not scattered windows.
                write!(out, "\n{name}")?;
                if let Some(t) = top {
                    write!(out, " — {} [{}]", t.desc, t.severity)?;
                }
                writeln!(out, "  (added lines):")?;
                for (k, h) in runs.iter().enumerate() {
                    if k > 0 {
                        writeln!(out, "  ⋯")?;
                    }
                    for l in &h.lines {
                        let mark = if l.is_match { ">+" } else { " +" };
                        writeln!(out, "  {mark} {}", l.text)?;
                    }
                }
            }
            Group::Single(h) => {
                write!(out, "\n{}", h.location)?;
                if let Some(m) = &h.member {
                    write!(out, " ({m})")?;
                }
                writeln!(out, "  [{}]  {}", h.severity, h.desc)?;
                for l in &h.lines {
                    let mark = match l.added {
                        LineMark::Added => '+',
                        _ if l.is_match => '>',
                        _ => ' ',
                    };
                    writeln!(out, "  {mark} {}", l.text)?;
                }
            }
        }
    }
    Ok(())
}

/// Collect one file's hunks (the file itself plus any archive members) into
/// `all`.
fn file_hunks(
    pair: &Pair,
    report: &cleave::AnalysisReport,
    gained_ids: &HashSet<&str>,
    changed: &HashSet<&str>,
    all: &mut Vec<Hunk>,
) {
    // The root analysis plus one entry per archive member, all borrowed: these
    // carry every matched byte window in the file, so copying them to iterate
    // twice would dwarf the work being done.
    let root = Scanned {
        findings: &report.findings,
        context: &report.context,
    };
    let candidates = std::iter::once((None, false, root)).chain(report.files.iter().map(|fa| {
        (
            Some(member_of(&fa.path)),
            // A member of an archive inside this one: its bytes are not
            // reachable by name in the outer archive, and a same-named outer
            // file would be read in its place.
            MemberPath::new(&fa.path).is_nested(),
            Scanned {
                findings: &fa.findings,
                context: &fa.context,
            },
        )
    }));
    let container = !report.files.is_empty();
    // The base side's bytes, read once: the root's line-diff baseline and the
    // `+` gutter both come from them.
    let old_root = member_source(pair.old.as_deref(), None);
    let old_lines = old_root
        .as_deref()
        .filter(|_| !container)
        .and_then(old_line_set);

    for (member, nested, scanned) in candidates {
        // A hunk inside an archive member is evidence only if that member is one
        // the diff flagged as changed; an unchanged member carrying the same
        // construct is not what moved. The container root (`member == None`) is
        // the pair itself — always a changed file — so it is never filtered.
        // Keyed on the raw member name: sanitizing first could make two
        // distinct names collide.
        if let Some(m) = member
            && !changed.contains(m)
        {
            continue;
        }
        // Promote each component note to the strongest gained composite it
        // proves. Keep this member-local: a common atom in another changed
        // member is not evidence for a composite that fired here.
        let promotions = composite_promotions(scanned.findings, gained_ids);
        let keep = |id: &str| gained_ids.contains(id) || promotions.contains_key(id);
        // The member as a reader sees it. A member name is chosen by whoever
        // built the archive, so it is neutralized for display — and only for
        // display: extraction below needs the real name.
        let shown = member.map(crate::printable);
        let site = Site {
            file: pair.label.as_str(),
            member: shown.as_deref(),
        };
        // Source-additions path: when both sides' text is in reach, the change
        // *is* the added lines — show them whole (matched or not), so an attack
        // whose payload sits a few lines from the trait hit stays in view. Needs a text new side and the old
        // text as the line-diff baseline; archive members are pulled per side.
        let (new_src, old_src) = match member {
            _ if nested => (None, None),
            None => (member_source(pair.new.as_deref(), None), old_root.clone()),
            Some(_) => (
                member_source(pair.new.as_deref(), member),
                member_source(pair.old.as_deref(), member),
            ),
        };
        if let (Some(new_src), Some(old_src)) = (new_src, old_src)
            && !new_src.is_empty()
            && !looks_binary(&new_src)
        {
            addition_hunks(
                &new_src,
                &old_src,
                scanned.context,
                &keep,
                &promotions,
                site,
                all,
            );
            continue;
        }

        // Binary / added-file fallback: match windows, cleave's presentation.
        for chunk in scanned.context {
            let kept: Vec<&cleave::types::Note> =
                chunk.notes.iter().filter(|n| keep(n.id.as_str())).collect();
            // Rank on the cheap key; only the winner's full attribution (two
            // allocated strings) is built, by the hunk constructor below.
            let Some(top) = kept
                .iter()
                .copied()
                .max_by(|a, b| strength(a, &promotions).total_cmp(&strength(b, &promotions)))
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
            all.push(match chunk.line {
                Some(first) => text_hunk(
                    chunk,
                    first,
                    &kept,
                    top,
                    &promotions,
                    site,
                    old_lines.as_ref(),
                ),
                None => binary_hunk(chunk, top, &promotions, site),
            });
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
    // Unreadable falls back like out-of-reach, but says so: a security tool
    // must not let an I/O failure pass for an absent file.
    match member {
        None => std::fs::read(p)
            .inspect_err(|e| log::warn!("could not read {} for evidence: {e}", p.display()))
            .ok(),
        Some(m) => cleave::extract_member(p, m)
            .inspect_err(|e| {
                log::warn!(
                    "could not extract {m} from {} for evidence: {e:#}",
                    p.display()
                );
            })
            .ok()
            .flatten(),
    }
}

/// The parts of one analyzed file that evidence reads, borrowed from wherever
/// they live — the report's own root or one archive member.
#[derive(Clone, Copy)]
struct Scanned<'a> {
    findings: &'a [cleave::types::Finding],
    context: &'a [cleave::types::ContextLine],
}

/// Where a hunk was found: the compared file, and the member inside it when
/// that file is an archive. Every hunk builder needs both, and every one of
/// them names the hunk by the member when there is one.
#[derive(Debug, Clone, Copy)]
struct Site<'a> {
    file: &'a str,
    member: Option<&'a str>,
}

impl<'a> Site<'a> {
    fn name(self) -> &'a str {
        self.member.unwrap_or(self.file)
    }
}

/// A NUL byte in the head marks binary content — cleave's own sniff, named
/// here so the two places that need it cannot drift on the window size.
fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|b| *b == 0)
}

/// Byte offsets of every newline in `bytes`, so [`line_at`] can place an
/// offset with a binary search instead of rescanning from byte zero per note.
fn newline_offsets(bytes: &[u8]) -> Vec<usize> {
    bytes
        .iter()
        .enumerate()
        .filter_map(|(i, &b)| (b == b'\n').then_some(i))
        .collect()
}

/// 1-based line of a byte offset — the number of newlines before it, plus one.
/// Maps a cleave match offset (into this member's own bytes) onto a source
/// line, given that member's [`newline_offsets`].
fn line_at(newlines: &[usize], off: u64) -> usize {
    let end = usize::try_from(off).unwrap_or(usize::MAX);
    1 + newlines.partition_point(|&nl| nl < end)
}

/// The key two lines are compared by when deciding whether a line is new:
/// surrounding whitespace ignored, so re-indenting a line does not read as
/// adding it. One definition for the evidence gutter, the addition runs, and
/// the LLM's line diff, which must agree on what "added" means.
pub(crate) fn line_key(line: &str) -> &str {
    line.trim()
}

/// Runs of lines a release *added* to one source file, each rendered as a hunk.
/// A run carrying a gained-trait match takes that rule's tier and headline and
/// leads the ranking; the rest are shown as plain additions so the whole change
/// is visible — the point of the differential view.
fn addition_hunks(
    new: &[u8],
    old: &[u8],
    context: &[cleave::types::ContextLine],
    keep: &impl Fn(&str) -> bool,
    promotions: &HashMap<&str, Attribution>,
    site: Site<'_>,
    all: &mut Vec<Hunk>,
) {
    // Lines only on the new side (set-based, keyed like `analysis::line_diff`
    // so a moved line reads as context, not an addition).
    let old_text = String::from_utf8_lossy(old);
    let old_set: HashSet<&str> = old_text.lines().map(line_key).collect();
    let new_text = String::from_utf8_lossy(new);
    let new_lines: Vec<&str> = new_text.lines().collect();

    // Strongest kept match per 1-based line, from cleave's analysis of the new
    // side. Offsets are into this member's own bytes, so a newline count places
    // each on its line.
    let newlines = newline_offsets(new);
    let mut hit: HashMap<usize, &cleave::types::Note> = HashMap::new();
    for note in context.iter().flat_map(|c| &c.notes) {
        if !keep(note.id.as_str()) {
            continue;
        }
        hit.entry(line_at(&newlines, note.off))
            .and_modify(|cur| {
                if strength(note, promotions) > strength(cur, promotions) {
                    *cur = note;
                }
            })
            .or_insert(note);
    }

    let added = |k: usize| k < new_lines.len() && !old_set.contains(line_key(new_lines[k]));
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
        all.push(addition_run(&new_lines, start, i, &hit, promotions, site));
    }
}

/// One contiguous added-line run (`[start, end)`, 0-based) as a hunk. Capped at
/// `MAX_RUN_LINES` with a `+N more added` tail so a large legitimate edit
/// cannot flood the evidence.
fn addition_run(
    new_lines: &[&str],
    start: usize,
    end: usize,
    hit: &HashMap<usize, &cleave::types::Note>,
    promotions: &HashMap<&str, Attribution>,
    site: Site<'_>,
) -> Hunk {
    /// Lines shown before the run is summarized — a per-run twin of
    /// [`MAX_HUNKS`], generous enough for a whole small payload.
    const MAX_RUN_LINES: usize = 20;
    let first_line = start + 1;
    // Strongest match anywhere in the run drives the header and tier.
    let top = (start..end)
        .filter_map(|k| hit.get(&(k + 1)).copied())
        .max_by(|a, b| strength(a, promotions).total_cmp(&strength(b, promotions)));

    let mut lines: Vec<HunkLine> = (start..end.min(start + MAX_RUN_LINES))
        .map(|k| HunkLine {
            locator: (k + 1).to_string(),
            text: crate::printable(&crate::clip(new_lines[k].trim_end(), CODE_W)),
            added: LineMark::Added,
            is_match: hit.contains_key(&(k + 1)),
        })
        .collect();
    let overflow = (end - start).saturating_sub(MAX_RUN_LINES);
    if overflow > 0 {
        lines.push(HunkLine {
            locator: String::new(),
            text: format!("… +{overflow} more added"),
            added: LineMark::Unknown,
            is_match: false,
        });
    }

    // A run with a match wears that rule's tier and headline and ranks with the
    // findings; a run without carries `None` and an empty headline — it renders
    // as a titleless block of added lines under the file, so the detected
    // behavior still stands out while the rest of the change stays visible.
    let (severity, score_v, id, desc) = match top {
        Some(n) => {
            let a = attribution(n, promotions);
            (a.severity, a.score, a.id, a.desc)
        }
        None => (Severity::None, 0.0, String::new(), String::new()),
    };
    Hunk {
        file: site.file.to_string(),
        member: site.member.map(str::to_string),
        line: Some(first_line as u64),
        loc: first_line as u64,
        location: format!("{}:{first_line}", site.name()),
        id,
        desc,
        severity,
        score: score_v,
        kind: HunkKind::Additions,
        lines,
    }
}

/// cleave's presentation ranking: criticality rank × confidence. Ranks one
/// match against another for display; [`crate::rubric::importance`] is the
/// separate mass a trait contributes to a verdict.
fn score(crit: cleave::Criticality, conf: f32) -> f32 {
    f32::from(crit.rank()) * crate::rubric::effective_conf(conf)
}

/// Strongest gained composite that a component note supports, keyed by the
/// component id. Inherited archive findings are excluded: the originating
/// member will contribute its own promotion and context.
fn composite_promotions<'a>(
    findings: &'a [cleave::types::Finding],
    gained_ids: &HashSet<&str>,
) -> HashMap<&'a str, Attribution> {
    let mut out = HashMap::new();
    for f in findings {
        if f.src.is_some() || !gained_ids.contains(f.id.as_str()) || f.trait_refs.is_empty() {
            continue;
        }
        let candidate = Attribution {
            id: f.id.as_str().to_string(),
            desc: if f.desc.is_empty() {
                "matched composite behavior".to_string()
            } else {
                crate::printable(f.desc.as_str())
            },
            severity: tier(f.crit),
            score: score(f.crit, f.conf),
            legs: f.trait_refs.len(),
        };
        for leg in &f.trait_refs {
            let slot = out.entry(leg.as_str()).or_insert_with(|| candidate.clone());
            if (candidate.score, candidate.legs) > (slot.score, slot.legs) {
                *slot = candidate.clone();
            }
        }
    }
    out
}

/// The rule a note is evidence of: its own, or the gained composite it is a leg
/// of when that composite ranks higher.
fn attribution(note: &cleave::types::Note, promotions: &HashMap<&str, Attribution>) -> Attribution {
    match promotion(note, promotions) {
        Some(p) => p.clone(),
        None => Attribution {
            id: note.id.as_str().to_string(),
            desc: desc_of(note),
            severity: tier(note.crit),
            score: score(note.crit, note.conf),
            legs: 0,
        },
    }
}

/// The promotion [`attribution`] would choose for `note`, if any.
fn promotion<'p>(
    note: &cleave::types::Note,
    promotions: &'p HashMap<&str, Attribution>,
) -> Option<&'p Attribution> {
    let direct = (score(note.crit, note.conf), 0);
    promotions
        .get(note.id.as_str())
        .filter(|p| (p.score, p.legs) > direct)
}

/// The score [`attribution`] would assign, without building it — the ranking
/// key for choosing a top note.
fn strength(note: &cleave::types::Note, promotions: &HashMap<&str, Attribution>) -> f32 {
    promotion(note, promotions).map_or_else(|| score(note.crit, note.conf), |p| p.score)
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
/// rather than `None`: a baseline window is still evidence, just weaker. Built
/// on the rubric's exhaustive mapping, so a tier added upstream cannot slip
/// through a catch-all here either.
fn tier(c: cleave::Criticality) -> Severity {
    crate::rubric::severity_from_crit(c).max(Severity::Low)
}

/// Line keys of the old version, for the `+` gutter. Plain text only — the
/// caller passes nothing for an archive, whose members would need extraction —
/// and a NUL in the head marks binary; both degrade to `None` (gutter unknown,
/// no marks rendered).
fn old_line_set(bytes: &[u8]) -> Option<HashSet<String>> {
    // An *empty* old side is not rejected here: it means every new line really
    // is an addition, which is exactly what an empty set renders.
    if looks_binary(bytes) {
        return None;
    }
    let text = String::from_utf8_lossy(bytes);
    Some(text.lines().map(|l| line_key(l).to_owned()).collect())
}

/// A text hunk: every line of the chunk, matches marked, the top match's line
/// windowed around its column.
fn text_hunk(
    chunk: &cleave::types::ContextLine,
    first_line: u64,
    kept: &[&cleave::types::Note],
    top: &cleave::types::Note,
    promotions: &HashMap<&str, Attribution>,
    site: Site<'_>,
    old: Option<&HashSet<String>>,
) -> Hunk {
    let attribution = attribution(top, promotions);
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
            added: match old {
                Some(set) if set.contains(line_key(&full)) => LineMark::Context,
                Some(_) => LineMark::Added,
                None => LineMark::Unknown,
            },
            is_match: matched.contains(&i),
        });
    }
    Hunk {
        file: site.file.to_string(),
        member: site.member.map(str::to_string),
        line: Some(first_line + top_idx as u64),
        loc: top.off,
        location: format!("{}:{}", site.name(), first_line + top_idx as u64),
        id: attribution.id,
        desc: attribution.desc,
        severity: attribution.severity,
        score: attribution.score,
        kind: HunkKind::Window {
            span: (first_line, first_line + spans.len() as u64 - 1),
            top: top_idx,
        },
        lines,
    }
}

/// A binary hunk: hex|ascii dump rows at the match, cleave's presentation.
/// The `+` is semantic — the trait is an addition — since binary bytes have
/// no line diff. The header carries no offset; the rows do.
fn binary_hunk(
    chunk: &cleave::types::ContextLine,
    top: &cleave::types::Note,
    promotions: &HashMap<&str, Attribution>,
    site: Site<'_>,
) -> Hunk {
    let attribution = attribution(top, promotions);
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
            added: LineMark::Added,
            is_match: true,
        })
        .collect();
    Hunk {
        file: site.file.to_string(),
        member: site.member.map(str::to_string),
        line: None,
        loc: top.off,
        location: site.name().to_string(),
        id: attribution.id,
        desc: attribution.desc,
        severity: attribution.severity,
        score: attribution.score,
        kind: HunkKind::Bytes,
        lines,
    }
}

/// One hex|ascii dump row: `XX `-cells padded to `stride`, a separator, then
/// the printable-ASCII column with `.` for the rest — cleave's dump style.
fn hex_ascii(row: &[u8], stride: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(stride * 4 + 1);
    for &b in row {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
        s.push(' ');
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
        // Only text match windows merge: addition runs are self-contained
        // (already maximal, per-run capped), and bytes have no lines.
        let Some(prev) = out
            .last_mut()
            .filter(|p| p.file == h.file && p.member == h.member)
        else {
            out.push(h);
            continue;
        };
        let (
            HunkKind::Window {
                span: (ps, pe),
                top: prev_top,
            },
            HunkKind::Window {
                span: (hs, he),
                top: h_top,
            },
        ) = (prev.kind, h.kind)
        else {
            out.push(h);
            continue;
        };
        if hs == pe + 1 {
            let top = if h.score > prev.score {
                // The stronger hunk's header — rule, tier, and the line it
                // anchors on — moves as one unit. Copying it field by field
                // once left the weaker rule's id and line under the stronger
                // rule's text, and SARIF anchors a finding on exactly those.
                let head = std::mem::take(&mut prev.lines);
                let top = head.len() + h_top;
                *prev = h;
                let tail = std::mem::replace(&mut prev.lines, head);
                prev.lines.extend(tail);
                top
            } else {
                prev.lines.extend(h.lines);
                prev_top
            };
            prev.kind = HunkKind::Window {
                span: (ps, he),
                top,
            };
        } else if hs <= pe {
            if h.score > prev.score {
                *prev = h;
                prev.kind = HunkKind::Window {
                    span: (ps.min(hs), pe.max(he)),
                    top: h_top,
                };
            }
        } else {
            out.push(h);
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
    let top = match h.kind {
        HunkKind::Window { top, .. } => top,
        HunkKind::Bytes | HunkKind::Additions => 0,
    };
    if h.lines.len() > window {
        let start = top.saturating_sub(ctx).min(h.lines.len() - window);
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
/// The innermost layer, because it is the only part the two sources agree on:
/// the diff names the comparison's root `<root>` and can add the analyzed
/// file's own name as a layer (`<root>!!manager!!embedded:elf@…`), while the
/// analysis report names members from that file (`manager!!embedded:elf@…`).
/// A nested member is therefore never extracted by this name — see the depth
/// check in [`file_hunks`].
///
/// Raw, for lookups and extraction. A member name is chosen by whoever built
/// the archive, so anything displayed from it goes through
/// [`crate::printable`] first: it reaches the terminal, the SARIF logical
/// location, and the PR comment, and an archive is free to name a file
/// `evil\x1b[2J`.
fn member_of(path: &str) -> &str {
    MemberPath::new(path).leaf()
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
                let slot = worst
                    .entry(crate::taxonomy::TraitId::new(&f.id).path().to_owned())
                    .or_insert(f.crit);
                *slot = (*slot).max(f.crit);
            }
        }
    }
    if worst.is_empty() {
        return None;
    }

    let hostile = worst.values().any(|c| *c == Criticality::Hostile);
    let mut items: Vec<(String, Criticality)> = worst.into_iter().collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
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
    pub trait_profiles: crate::behavior_shift::Profiles,
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
                survey.trait_profiles.incomplete = true;
                continue;
            };
            let profile = if is_base {
                &mut survey.trait_profiles.old
            } else {
                &mut survey.trait_profiles.new
            };
            for finding in all_findings(&report) {
                profile.observe(
                    finding.id.as_str(),
                    crate::rubric::importance(finding.crit, finding.conf),
                );
            }
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
        .map(|path| MemberPath::new(path).display().to_owned())
        .collect();

    // Node resolves a package with no `main`/`exports` declaration to a
    // sibling `index.*`. Filefacts emits explicit manifest references, but
    // there is no literal path to emit for this default. Add it only for an
    // actual package.json with no declared local target and only when the
    // resolved member exists in the analyzed archive.
    entrypoints.extend(report.files.iter().filter_map(|file| {
        // The member's file name exactly: `ends_with` also took
        // `mypackage.json` for a manifest.
        if MemberPath::new(&file.path).file_name() != "package.json" {
            return None;
        }
        let has_declared_entrypoint = file.filefacts.iter().any(|facts| {
            facts.references.iter().any(|reference| {
                matches!(reference.kind, filefacts::RefKind::Local)
                    && reference.source.starts_with("package.json:")
            })
        });
        if has_declared_entrypoint {
            return None;
        }
        default_npm_runtime_entrypoint(&file.path, &paths)
            .map(|path| MemberPath::new(path).display().to_owned())
    }));

    // Some ecosystems declare identity directly in the runtime file instead
    // of a separate manifest: WordPress plugin headers are the common case,
    // but this is deliberately format-neutral. A source member that carries
    // the package's own name/version is a package entrypoint candidate; helper
    // files normally carry no identity at all.
    entrypoints.extend(report.files.iter().filter_map(|file| {
        let source = filefacts::FileType::from_label(&file.file_type)
            .is_some_and(|file_type| file_type.is_source_code());
        (source && file.identity.is_some())
            .then(|| MemberPath::new(&file.path).display().to_owned())
    }));
    entrypoints
}

fn default_npm_runtime_entrypoint<'a>(
    manifest_path: &str,
    paths: &HashSet<&'a str>,
) -> Option<&'a str> {
    resolve_report_local_target(manifest_path, "index", paths)
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
    let mut candidates = std::iter::once(base.clone())
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
    candidates.find_map(|candidate| paths.get(candidate.as_str()).copied())
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

    /// Composite conclusions have no single context note of their own. Their
    /// component windows must nevertheless rank and read as evidence for the
    /// gained conclusion, or a generic notable atom can hide a hostile result.
    #[test]
    fn composite_conclusion_promotes_its_component_evidence() {
        use cleave::Criticality;

        let component_id = "micro-behaviors/process/create/agent::unattended";
        let composite_id = "objectives/impact/destroy::agent-directed";
        let file = cleave::types::FileAnalysis {
            findings: vec![cleave::types::Finding {
                id: composite_id.into(),
                desc: "Unattended agent receives destructive goal".into(),
                conf: 0.99,
                crit: Criticality::Hostile,
                trait_refs: vec![
                    component_id.into(),
                    "objectives/impact/destroy::goal".into(),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let gained = HashSet::from([composite_id]);
        let promotions = composite_promotions(&file.findings, &gained);
        let note = cleave::types::Note {
            crit: Criticality::Component,
            id: component_id.into(),
            desc: "unattended flag".into(),
            off: 42,
            len: 12,
            conf: 0.98,
        };

        let promoted = attribution(&note, &promotions);
        assert_eq!(promoted.id, composite_id);
        assert_eq!(promoted.severity, Severity::Critical);
        assert_eq!(promoted.desc, "Unattended agent receives destructive goal");
        assert!(promoted.score > score(note.crit, note.conf));
    }

    /// Collection must inspect the whole change. Presentation applies its own
    /// ranked cap later; stopping after an arbitrary number of early additions
    /// can hide a stronger payload near the end of a generated source file.
    #[test]
    fn evidence_collection_reaches_late_matches() {
        use cleave::Criticality;

        let mut old = String::new();
        let mut new = String::new();
        for i in 0..130 {
            old.push_str(&format!("keep-{i}\n"));
            new.push_str(&format!("keep-{i}\nadded-{i}\n"));
        }
        let target = "added-129";
        let off = new.find(target).expect("late added line") as u64;
        let file = cleave::types::FileAnalysis {
            context: vec![cleave::types::ContextLine {
                loc: off,
                line: Some(260),
                col: Some(1),
                data: target.as_bytes().to_vec(),
                notes: vec![cleave::types::Note {
                    crit: Criticality::Hostile,
                    id: "objectives/impact/destroy::late".into(),
                    desc: "late destructive behavior".into(),
                    off,
                    len: u32::try_from(target.len()).unwrap(),
                    conf: 1.0,
                }],
            }],
            ..Default::default()
        };
        let mut hunks = Vec::new();
        addition_hunks(
            new.as_bytes(),
            old.as_bytes(),
            &file.context,
            &|_| true,
            &HashMap::new(),
            Site {
                file: "generated.js",
                member: None,
            },
            &mut hunks,
        );

        assert_eq!(hunks.len(), 130);
        assert_eq!(hunks.last().map(|h| h.severity), Some(Severity::Critical));
        assert_eq!(hunks.last().map(|h| h.line), Some(Some(260)));
    }

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

    #[test]
    fn npm_default_entrypoint_resolves_only_an_existing_sibling_index() {
        let paths = HashSet::from([
            "package/package.json",
            "package/index.js",
            "package/lib/index.js",
        ]);
        assert_eq!(
            default_npm_runtime_entrypoint("package/package.json", &paths),
            Some("package/index.js")
        );

        let no_index = HashSet::from(["package/package.json", "package/main.js"]);
        assert_eq!(
            default_npm_runtime_entrypoint("package/package.json", &no_index),
            None
        );
    }

    /// A match window over lines `[first, last]`, top match on `line`.
    fn window(id: &str, desc: &str, score: f32, first: u64, last: u64, line: u64) -> Hunk {
        Hunk {
            file: "f.js".into(),
            member: None,
            line: Some(line),
            loc: line * 10,
            location: format!("f.js:{line}"),
            id: id.into(),
            desc: desc.into(),
            severity: Severity::High,
            score,
            kind: HunkKind::Window {
                span: (first, last),
                top: usize::try_from(line - first).unwrap(),
            },
            lines: (first..=last)
                .map(|n| HunkLine {
                    locator: n.to_string(),
                    text: format!("line {n}"),
                    added: LineMark::Unknown,
                    is_match: n == line,
                })
                .collect(),
        }
    }

    /// A merged window's span and top, which only a window has.
    fn window_of(h: &Hunk) -> ((u64, u64), usize) {
        match h.kind {
            HunkKind::Window { span, top } => (span, top),
            other => panic!("not a window: {other:?}"),
        }
    }

    /// When the later window wins a merge, its whole header moves with it.
    /// SARIF anchors a finding on `id` and `line`; leaving the weaker rule's
    /// there put the stronger rule's text on the wrong rule and line.
    #[test]
    fn a_merge_keeps_the_stronger_rules_header_together() {
        let mut hunks = vec![
            window("weak/rule::a", "weak", 1.0, 1, 3, 2),
            window("strong/rule::b", "strong", 5.0, 4, 6, 5),
        ];
        merge_contiguous(&mut hunks);
        assert_eq!(hunks.len(), 1);
        let h = &hunks[0];
        assert_eq!(h.id, "strong/rule::b");
        assert_eq!(h.desc, "strong");
        assert_eq!(h.line, Some(5));
        let (span, top) = window_of(h);
        assert_eq!(span, (1, 6));
        assert_eq!(h.lines.len(), 6);
        assert_eq!(h.lines[top].locator, "5", "top must index the strong match");

        // The weaker later window leaves the header alone but still extends it.
        let mut hunks = vec![
            window("strong/rule::b", "strong", 5.0, 1, 3, 2),
            window("weak/rule::a", "weak", 1.0, 4, 6, 5),
        ];
        merge_contiguous(&mut hunks);
        assert_eq!(hunks[0].id, "strong/rule::b");
        assert_eq!(hunks[0].line, Some(2));
        let (span, top) = window_of(&hunks[0]);
        assert_eq!(hunks[0].lines[top].locator, "2");
        assert_eq!(span, (1, 6));
    }

    #[test]
    fn line_at_counts_the_newlines_before_an_offset() {
        let text = b"a\nbb\n\nccc";
        let nl = newline_offsets(text);
        assert_eq!(line_at(&nl, 0), 1);
        assert_eq!(line_at(&nl, 1), 1, "the newline itself ends line 1");
        assert_eq!(line_at(&nl, 2), 2);
        assert_eq!(line_at(&nl, 5), 3);
        assert_eq!(line_at(&nl, 6), 4);
        assert_eq!(line_at(&nl, 999), 4, "past the end clamps to the last line");
    }

    /// Rules without a description all read "matched"; deduplicating on that
    /// text would show one of them and hide the rest.
    /// unrealircd 3.2.8.1: one broad rule (`substr: SYSTEM`) matched dozens of
    /// benign files, and with every window dumped the model read the real
    /// backdoor as a false positive. One window per rule keeps five hunks
    /// showing five behaviors.
    #[test]
    fn evidence_keeps_one_window_per_rule_id_not_per_description() {
        let mut all = vec![
            window("a/rule::x", "matched", 2.0, 1, 1, 1),
            window("b/rule::y", "matched", 1.0, 9, 9, 9),
            window("a/rule::x", "matched", 1.5, 20, 20, 20),
        ];
        one_per_rule(&mut all);
        let kept: Vec<_> = all.iter().map(|h| (h.id.as_str(), h.line)).collect();
        assert_eq!(kept, [("a/rule::x", Some(1)), ("b/rule::y", Some(9))]);
    }

    /// unrealircd 3.2.8.1: the backdoor's `system()` call was a `#define`
    /// added a few lines from where any rule fired, and on its own it rated
    /// below notable. Ranked as just another weak hit it would have been culled
    /// in favor of the stronger windows — dropping the very line that was the
    /// attack. Added lines are the change itself, so they survive the floor
    /// that culls weak match windows.
    #[test]
    fn unrealircd_sub_notable_added_line_survives_the_cull() {
        let weak = |mut h: Hunk| {
            h.severity = Severity::Low;
            h
        };
        let added = Hunk {
            kind: HunkKind::Additions,
            id: String::new(),
            desc: "added code".into(),
            lines: vec![HunkLine {
                locator: "35".into(),
                text: "#define DEBUG3_DOLOG_SYSTEM(x) system(x)".into(),
                added: LineMark::Added,
                is_match: false,
            }],
            ..weak(window("", "", 0.1, 35, 35, 35))
        };
        let mut all = vec![
            window("strong/rule::exec", "matched", 2.0, 1, 3, 2),
            weak(window("weak/rule::compare", "matched", 0.5, 50, 52, 51)),
            added,
        ];
        distill(&mut all);
        let kept: Vec<_> = all
            .iter()
            .map(|h| (h.id.as_str(), h.is_additions()))
            .collect();
        assert_eq!(kept, [("strong/rule::exec", false), ("", true)]);
    }
}
