//! The terminal report — masthead + grid.
//!
//! Output follows the UNIX-diff principle: **silent when there is no
//! noticeable behavioral change**, and a concise, styled verdict only when
//! there is something to say. `--explain` adds the full trait ids and cleave's
//! ledger beneath.
//!
//! One grid language throughout — every section is a `pill · dots · body` row
//! — with a blank line between sections so each triage question (known
//! campaign? who shipped it? what can it newly do?) reads as its own block.

use std::fmt::Write as _;

use cleave::types::{DiffReportV1, FileDiffEntry};
use colored::Colorize;

use crate::analysis::{Analysis, Naming};
use crate::evidence::Hunk;
use crate::risk::Risk;
use crate::rubric::Assessment;
use crate::{Cli, Severity};

const BAR: usize = 20;
/// Visible width of the section-pill cell (longest pill + a trailing space).
const PILL_COL: usize = 12;
/// Width the capability-class name column pads to.
const NAME_W: usize = 20;

/// The complete terminal report for one analysis.
pub(crate) fn report(a: &Analysis<'_>, cli: &Cli) -> String {
    let mut out = String::new();
    let detailed = a.detailed(cli);
    if a.speaks(cli) {
        render(&mut out, a, detailed);
        // The proof: diff-style hunks for the gained traits, each owned by its
        // strongest rule. A change that passes the gate does not get an
        // evidence dump — it gets named, and `isomer fs --explain` is one
        // command away if the reviewer wants to look closer.
        if detailed {
            let ids = a.assessment.gained_ids();
            let rows = a.hunks(crate::evidence::MAX_HUNKS);
            if rows.is_empty() && !ids.is_empty() {
                // Say the absence out loud — an analyst reading a verdict with
                // no proof section should know the gained traits carry no
                // byte-located matches, not suspect a rendering gap.
                out.push_str(&evidence_note());
            } else {
                out.push_str(&evidence_hunks(&rows));
            }
        }
        // Behavior-bearing atoms a source change introduced below the finding
        // floor — the "$HOME read, base64 heredoc" that no single trait scored
        // high enough to name. Shown on every speaking verdict (not gated on
        // `detailed`): when they are the *only* reason the diff spoke, they are
        // the whole story.
        let obs = a.observations();
        if !obs.is_empty() {
            out.push_str(&observations_section(&obs));
        }
    } else if let Some(existing) =
        crate::evidence::existing_risk(&a.pairs, a.options, &a.naming.name)
    {
        // No noticeable change, but the artifact still carries elevated
        // traits. Say so concisely rather than staying fully silent —
        // "nothing changed, but heads up". Does not affect exit code.
        out.push_str(&existing);
    }
    // What the added dependencies can do (`--deps`) — the risk the manifest
    // diff only named. Rendered whenever the fetch ran, even on an otherwise
    // silent change: a benign-looking version bump pulling a malicious release
    // is exactly the case worth surfacing.
    if !a.deps.is_empty() {
        out.push_str(&dependencies_section(&a.deps));
    }
    if cli.explain {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&cleave::diff::format::format_terminal(a.report));
    }
    out
}

/// The masthead and the detail grid. Order: verdict, ML risk, attribution,
/// identity, capabilities, structure, metrics, touched files.
///
/// `detailed` is false for a change that passes the gate: the judgement, the
/// risk move, and the named findings stay, while metrics, the file list, and
/// the evidence are dropped. The reviewer learns what was noticed in a few
/// lines instead of a screenful.
fn render(out: &mut String, a: &Analysis<'_>, detailed: bool) {
    let (assessment, naming, prop) = (&a.assessment, &a.naming, &a.prop);
    let mut sections: Vec<String> = Vec::new();
    let mut head = badge_line(a.verdict, a.diff, naming);
    // The judgement leads: what isomer makes of the change, before any of the
    // detail behind it. Annotation lines are indented past the badge so they
    // align under the artifact name rather than the verdict word.
    let indent = " ".repeat(badge_parts(a.verdict).0.len() + 5);
    let judgement = a.judgement();
    let _ = writeln!(head, "{indent}{}", judgement.truecolor(150, 160, 168));
    // Then say *why* the change shape is wrong, not just that it is:
    // behavioral delta vs the version bump's promise, and behavior vs content
    // skew. Annotations align under the artifact name, not the badge — and are
    // skipped when the judgement above already *is* the note, so the report
    // never says the same sentence twice.
    let mut warn = |text: &str| {
        let _ = writeln!(
            head,
            "{indent}{} {}",
            "⚠".truecolor(255, 176, 46),
            text.truecolor(255, 176, 46)
        );
    };
    if prop.disproportionate
        && let Some(note) = prop.note.as_deref().filter(|n| *n != judgement)
    {
        warn(note);
    }
    if let Some(skew) = prop.skew.as_deref().filter(|s| *s != judgement) {
        warn(skew);
    }
    if let Some(i) = a.interp.as_ref().filter(|i| !i.nature.trim().is_empty()) {
        let _ = writeln!(
            head,
            "{indent}✨ {}",
            i.nature.trim().truecolor(62, 207, 214)
        );
    }
    sections.push(head);
    // The model's read is shown when it moved bands (the reviewer needs to
    // know either way) or whenever the full report is being drawn.
    if let Some(r) = a.risk.filter(|_| detailed || a.risk_band_moved()) {
        sections.push(risk_rows(r));
    }
    let mut section = String::new();
    signature_grid(&mut section, assessment);
    push_section(&mut sections, &mut section);
    identity_grid(&mut section, assessment);
    push_section(&mut sections, &mut section);
    let (fresh, expanded): (Vec<_>, Vec<_>) = assessment
        .behavioral
        .categories
        .iter()
        .partition(|c| assessment.behavioral.is_new_category(c));
    class_group(&mut section, &fresh, "new", PILL_PLUM, true);
    push_section(&mut sections, &mut section);
    class_group(&mut section, &expanded, "expanded", PILL_PLUM_DIM, false);
    push_section(&mut sections, &mut section);
    structure_grid(&mut section, &assessment.structure);
    push_section(&mut sections, &mut section);
    frameworks_grid(&mut section, a);
    push_section(&mut sections, &mut section);
    // Metrics and the touched-file list are triage aids for a change that
    // failed; they are noise on one that passed.
    if detailed {
        for (i, body) in metrics_rows(a.diff).into_iter().enumerate() {
            let cell = if i == 0 {
                pill_cell("metrics", PILL_TEAL)
            } else {
                blank_cell()
            };
            section.push_str(&grid_line(&cell, "   ", &body));
        }
        push_section(&mut sections, &mut section);
        files_grid(&mut section, a.diff);
        push_section(&mut sections, &mut section);
    }
    out.push_str(&sections.join("\n"));
}

/// The MITRE ATT&CK and MBC ids this change moved.
///
/// isomer carries no catalog mapping these to prose, so it does not pretend
/// to: the ids are shown as ids, which is what an analyst pastes into their
/// own reference anyway. `+` is a technique the change introduced, `−` one it
/// no longer exhibits — a fix landing looks different from a regression.
fn frameworks_grid(out: &mut String, a: &Analysis<'_>) {
    for (label, sides) in [("attack", &a.survey.attack), ("mbc", &a.survey.mbc)] {
        if !sides.changed() {
            continue;
        }
        let mut items: Vec<String> = Vec::new();
        items.extend(sides.gained().iter().map(|id| format!("+{id}")));
        items.extend(sides.lost().iter().map(|id| format!("−{id}")));
        let kept = sides.kept();
        for (i, line) in wrap_items(&items, 60).into_iter().enumerate() {
            let cell = if i == 0 {
                pill_cell(label, PILL_OCEAN)
            } else {
                blank_cell()
            };
            let mut body = line.truecolor(205, 214, 221).to_string();
            if i == 0 && kept > 0 {
                body.push_str(&format!(
                    "   {}",
                    format!("{kept} unchanged").truecolor(102, 117, 127)
                ));
            }
            out.push_str(&grid_line(&cell, "   ", &body));
        }
    }
}

/// Move a finished section into the list, skipping empty ones so blank
/// separators never double up.
fn push_section(sections: &mut Vec<String>, section: &mut String) {
    if !section.is_empty() {
        sections.push(std::mem::take(section));
    }
}

/// The touched archive members — `~` changed, `+` added, `−` removed — so
/// the file count in the masthead resolves to names without leaving the
/// pane. Only containers render this; a single-file diff already names its
/// file up top.
fn files_grid(out: &mut String, diff: &DiffReportV1) {
    const MAX: usize = 6;
    let mut items: Vec<String> = Vec::new();
    for f in &diff.files {
        let Some((_, member)) = f.path.split_once("!!") else {
            continue;
        };
        let marker = match f.status {
            cleave::types::FileStatus::Changed => "~",
            cleave::types::FileStatus::Added => "+",
            cleave::types::FileStatus::Removed => "−",
            cleave::types::FileStatus::Unchanged => continue,
        };
        items.push(format!("{marker} {member}"));
    }
    if items.is_empty() {
        return;
    }
    let overflow = items.len().saturating_sub(MAX);
    items.truncate(MAX);
    if overflow > 0 {
        items.push(format!("+{overflow} more"));
    }
    for (i, line) in wrap_items(&items, 76).into_iter().enumerate() {
        let cell = if i == 0 {
            pill_cell("files", PILL_SLATE)
        } else {
            blank_cell()
        };
        out.push_str(&grid_line(
            &cell,
            "   ",
            &line.truecolor(150, 160, 168).to_string(),
        ));
    }
}

/// The structural-anomaly section (computed by the rubric): a new linked
/// dependency, functions turned into ifunc resolvers, new imports — the
/// signature-less tell for an xz-class attack. Every fact carries a change
/// marker: `+` newly present, `~` existing structure altered in place.
fn structure_grid(out: &mut String, structure: &crate::rubric::Structure) {
    for (i, f) in structure.facts.iter().enumerate() {
        let cell = if i == 0 {
            pill_cell("structure", PILL_SLATE)
        } else {
            blank_cell()
        };
        let marker = match f.kind {
            crate::rubric::FactKind::Added => "+",
            crate::rubric::FactKind::Became => "~",
        };
        let plain = format!("{marker} {}", f.label);
        let painted = format!("{} {}", marker.truecolor(120, 134, 144), f.label.bold());
        let name = pad_visible(&painted, &plain, NAME_W);
        let body = format!("{name} {}", f.detail.truecolor(150, 160, 168));
        out.push_str(&grid_line(&cell, &dots(f.severity), &body));
    }
}

/// ` [ HOSTILE ]  liblzma.so   5.4.5 → 5.6.0 · 2 minor releases · 35% changed`.
fn badge_line(verdict: Severity, diff: &DiffReportV1, naming: &Naming) -> String {
    let mut meta = String::new();
    if let (Some(o), Some(n)) = (&naming.old, &naming.new) {
        meta.push_str(&format!("   {} → {}", o.raw, n.raw));
        if let Some(b) = naming.bump {
            meta.push_str(&format!(" · {}", b.describe()));
        }
    }
    for part in change_scale(diff) {
        meta.push_str(&format!(" · {part}"));
    }
    format!(
        " {}  {}{}\n",
        badge(verdict),
        naming.name.as_str().bold(),
        meta.truecolor(102, 117, 127),
    )
}

/// The masthead's scale phrases: how many files moved, and how much content.
/// Shared with the markdown report so both state the change at the same scale.
pub(crate) fn change_scale(diff: &DiffReportV1) -> Vec<String> {
    let mut parts = Vec::new();
    // For a container, the summary's root entry restates the container
    // itself — drop it so the count matches the `files` member list.
    let mut touched = (diff.summary.files_changed
        + diff.summary.files_added
        + diff.summary.files_removed) as usize;
    let mut total = touched + diff.summary.files_unchanged as usize;
    if diff.files.iter().any(|f| f.path.contains("!!")) {
        touched = touched.saturating_sub(1);
        total = total.saturating_sub(1);
    }
    if total > 1 {
        parts.push(format!("{touched} of {total} files"));
    }
    // The content-change scale — one of the three legs (content, behavior,
    // metrics) the report separates; the other two get their own sections.
    let roc = diff.summary.overall_roc;
    if roc > 0.005 {
        parts.push(format!("{:.0}% changed", f64::from(roc) * 100.0));
    }
    parts
}

/// The ML detector as a grid section: `was`/`now` each on a benign→malware
/// bar, the jump called out on the `now` row.
fn risk_rows(r: Risk) -> String {
    let d = r.delta();
    let (arrow, dsev) = if d > 0.005 {
        ("▲", crate::analysis::risk_band(r.new))
    } else if d < -0.005 {
        ("▼", Severity::None)
    } else {
        ("·", Severity::None)
    };
    let was = format!(
        "{}  {}  {}  {}",
        "was".truecolor(102, 117, 127),
        format!("{:.2}", r.old).truecolor(140, 150, 158),
        bar(r.old),
        risk_word(r.old),
    );
    let now = format!(
        "{}  {}  {}  {}   {}",
        "now".truecolor(102, 117, 127),
        paint(crate::analysis::risk_band(r.new), &format!("{:.2}", r.new)).bold(),
        bar(r.new),
        risk_word(r.new),
        paint(dsev, &format!("{arrow} {d:+.2}")),
    );
    let mut s = grid_line(&pill_cell("risk", PILL_OCEAN), "   ", &was);
    s.push_str(&grid_line(&blank_cell(), "   ", &now));
    s
}

fn bar(value: f32) -> String {
    // The clamp lands the value in 0..=BAR before the cast, and a float->int
    // `as` saturates rather than wrapping, so a NaN or infinite probability
    // yields an in-range cell count instead of a panic or a bogus repeat().
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped to 0..=BAR, and BAR is small enough to be exact in f32"
    )]
    let filled = (value * BAR as f32).round().clamp(0.0, BAR as f32) as usize;
    format!(
        "{}{}",
        paint(crate::analysis::risk_band(value), &"█".repeat(filled)),
        "░".repeat(BAR - filled).truecolor(70, 80, 89),
    )
}

/// The plain word for an ML probability: benign / elevated / suspicious /
/// malware. Shared with the markdown report.
pub(crate) fn risk_label(p: f32) -> &'static str {
    match crate::analysis::risk_band(p) {
        Severity::Critical => "malware",
        Severity::High => "suspicious",
        Severity::Medium | Severity::Low => "elevated",
        Severity::None => "benign",
    }
}

fn risk_word(p: f32) -> String {
    let sev = crate::analysis::risk_band(p);
    let word = risk_label(p);
    if sev == Severity::None {
        word.truecolor(102, 117, 127).to_string()
    } else {
        paint(sev, word)
    }
}

// ── the detail grid ──────────────────────────────────────────────────────

fn class_group(
    out: &mut String,
    cats: &[&crate::rubric::Category],
    label: &str,
    color: (u8, u8, u8),
    fresh: bool,
) {
    /// A namespace list short enough to sit inline after the class name.
    const INLINE: usize = 52;
    /// Wrap width for namespace continuation lines.
    const WRAP: usize = 58;
    for (i, c) in cats.iter().enumerate() {
        let cell = if i == 0 {
            pill_cell(label, color)
        } else {
            blank_cell()
        };
        let name = pad_visible(&c.label.as_str().bold().to_string(), &c.label, NAME_W);
        let refs: Vec<&str> = c.namespaces.iter().map(String::as_str).collect();
        let head = common_prefix(&refs);
        let tails: Vec<String> = c
            .namespaces
            .iter()
            .map(|p| strip_prefix_path(p, &head))
            .filter(|t| !t.is_empty())
            .collect();
        let vis = head.chars().count() + tails.iter().map(|t| t.chars().count() + 3).sum::<usize>();
        if vis <= INLINE {
            // Fits: `head/tail1 · tail2` inline, as one line.
            let mut loc = head.as_str().bold().to_string();
            if !tails.is_empty() {
                let sep = if head.is_empty() { "" } else { "/" };
                loc.push_str(
                    &format!("{sep}{}", tails.join(" · "))
                        .truecolor(120, 134, 144)
                        .to_string(),
                );
            }
            let body = format!("{name} {loc}{}", count_str(c, fresh));
            out.push_str(&grid_line(&cell, &dots(c.severity), &body));
        } else {
            // Too many namespaces for one line: the shared prefix and count
            // up top, every tail wrapped beneath — nothing hidden.
            let body = format!("{name} {}{}", head.as_str().bold(), count_str(c, fresh));
            out.push_str(&grid_line(&cell, &dots(c.severity), &body));
            let items = if tails.is_empty() {
                c.namespaces.clone()
            } else {
                tails
            };
            // Indent to two columns past the namespace column above.
            let indent = " ".repeat(PILL_COL + NAME_W + 8);
            for line in wrap_items(&items, WRAP) {
                out.push_str(&format!("{indent}{}\n", line.truecolor(120, 134, 144)));
            }
        }
    }
}

/// Pack items into lines of at most `width` visible chars, ` · `-joined.
fn wrap_items(items: &[String], width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for item in items {
        if !cur.is_empty() && cur.chars().count() + 3 + item.chars().count() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push_str(" · ");
        }
        cur.push_str(item);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// A count only when it carries information — a lone new trait is the default.
fn count_str(c: &crate::rubric::Category, fresh: bool) -> String {
    let n = c.new_ids.len();
    let base = match (fresh, n) {
        (_, 0) | (true, 1) => String::new(),
        (true, k) => format!("  {}", paint(c.severity, &format!("{k} new"))),
        (false, k) => format!("  {}", paint(c.severity, &format!("+{k}"))),
    };
    if c.escalated_ids.is_empty() {
        base
    } else {
        format!(
            "{base}  {}",
            format!("{}↑", c.escalated_ids.len()).truecolor(102, 117, 127)
        )
    }
}

fn signature_grid(out: &mut String, a: &Assessment) {
    if a.signature.severity == Severity::None {
        return;
    }
    const MAX: usize = 6;
    /// Width cap for the description column.
    const DESC_W: usize = 56;
    let n = a.signature.ids.len();
    let shown = &a.signature.ids[..n.min(MAX)];
    // Description leads — the campaign or intent an analyst triages on —
    // with the rule id as dim provenance after it. The marker says whether
    // the rule newly matched (`+`) or an existing match escalated (`↑`).
    let descs: Vec<String> = shown.iter().map(|m| crate::clip(&m.desc, DESC_W)).collect();
    let descw = descs.iter().map(|d| d.chars().count()).max().unwrap_or(0);
    for (i, m) in shown.iter().enumerate() {
        let cell = if i == 0 {
            pill_cell("signature", PILL_HOT)
        } else {
            blank_cell()
        };
        let marker = if m.is_new { "+" } else { "↑" };
        let name = crate::rubric::short_name(&m.id);
        let text = if descs[i].is_empty() {
            &name
        } else {
            &descs[i]
        };
        let mut body = format!(
            "{} {}",
            marker.truecolor(120, 134, 144),
            pad_visible(text, text, descw),
        );
        if !descs[i].is_empty() {
            body.push_str(&format!(" {}", name.truecolor(102, 117, 127)));
        }
        if i == 0
            && let Some(cve) = &a.signature.cve
        {
            body.push_str(&format!("   {}", paint(Severity::Critical, cve)));
        }
        out.push_str(&grid_line(&cell, &dots(m.severity), &body));
    }
    if n > MAX {
        out.push_str(&grid_line(
            &blank_cell(),
            &"·  ".truecolor(102, 117, 127).to_string(),
            &format!("+{} more", n - MAX)
                .truecolor(102, 117, 127)
                .to_string(),
        ));
    }
}

fn identity_grid(out: &mut String, a: &Assessment) {
    if a.identity.severity == Severity::None {
        return;
    }
    for (i, ch) in a.identity.changes.iter().enumerate() {
        let cell = if i == 0 {
            pill_cell("identity", PILL_SLATE)
        } else {
            blank_cell()
        };
        let old = if ch.old.is_empty() {
            "none".to_string()
        } else {
            ch.old.clone()
        };
        let new = if ch.new.is_empty() {
            "none".to_string()
        } else {
            ch.new.clone()
        };
        let body = format!(
            "{}: {} {} {}",
            ch.label,
            old,
            "→".truecolor(70, 80, 89),
            new.bold()
        );
        out.push_str(&grid_line(&cell, &dots(a.identity.severity), &body));
    }
}

/// The evidence section as diff-style hunks: each hunk is headed by its
/// top rule (criticality × confidence) and location, then a short excerpt
/// with matched lines bright, context dim, and `+` marking lines absent
/// from the old version.
fn evidence_hunks(hunks: &[&Hunk]) -> String {
    if hunks.is_empty() {
        return String::new();
    }
    let locw = hunks
        .iter()
        .flat_map(|h| h.lines.iter())
        .map(|l| l.locator.chars().count())
        .max()
        .unwrap_or(4);
    let descs: Vec<String> = hunks.iter().map(|h| crate::clip(&h.desc, 56)).collect();
    let descw = descs.iter().map(|d| d.chars().count()).max().unwrap_or(0);
    let mut out = format!(
        "\n {}  {}\n",
        pill_cell("evidence", PILL_OCEAN).trim_end(),
        evidence_note_text(hunks).truecolor(102, 117, 127),
    );
    for (h, desc) in hunks.iter().zip(&descs) {
        out.push('\n');
        out.push_str(&format!(
            "   {} {}   {}\n",
            dots(h.severity),
            pad_visible(&paint(h.severity, desc), desc, descw),
            h.location.truecolor(102, 117, 127),
        ));
        for l in &h.lines {
            let gutter = match l.added {
                Some(true) => "+".truecolor(95, 175, 95).to_string(),
                _ => " ".to_string(),
            };
            // Matched code in terminal foreground, context dimmed behind it.
            let paint_code = |s: &str| {
                if l.is_match {
                    s.truecolor(205, 214, 221).to_string()
                } else {
                    s.truecolor(102, 117, 127).to_string()
                }
            };
            // A long matched line wraps across continuation rows: bare
            // rail, no repeated locator or gutter, a two-space hanging
            // indent marking the continuation.
            for (i, row_text) in wrap_code(&l.text, crate::evidence::CODE_W)
                .into_iter()
                .enumerate()
            {
                let row = if i == 0 {
                    let loc = format!("{:>locw$}", l.locator, locw = locw);
                    format!(
                        "   {} {} {gutter} {}",
                        loc.truecolor(70, 80, 89),
                        "│".truecolor(70, 80, 89),
                        paint_code(&row_text),
                    )
                } else {
                    format!(
                        "   {} {}     {}",
                        " ".repeat(locw),
                        "│".truecolor(70, 80, 89),
                        paint_code(&row_text),
                    )
                };
                out.push_str(row.trim_end());
                out.push('\n');
            }
        }
    }
    out
}

/// Say what the evidence marks mean, once, up top, instead of implying it.
/// Shared with the markdown report.
pub(crate) fn evidence_note_text(hunks: &[&Hunk]) -> &'static str {
    if hunks.iter().all(|h| h.binary) {
        "binary · all matches are gained traits · old bytes not shown"
    } else if hunks
        .iter()
        .any(|h| !h.binary && h.lines.iter().any(|l| l.added.is_some()))
    {
        "gained behavior · + marks lines absent from the old version"
    } else {
        "matched code for gained traits"
    }
}

/// Split code into display rows of at most `width` chars.
fn wrap_code(s: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= width {
        return vec![s.to_string()];
    }
    chars.chunks(width).map(|c| c.iter().collect()).collect()
}

/// The evidence section's stand-in when none of the gained traits carry
/// byte-located matches (structural and metric rules often don't).
fn evidence_note() -> String {
    format!(
        "\n {}  {}\n",
        pill_cell("evidence", PILL_OCEAN).trim_end(),
        "none of the gained traits carry byte-located matches".truecolor(102, 117, 127),
    )
}

// ── grid + pill primitives ───────────────────────────────────────────────

/// The `dependencies` section: one row per added dependency — severity dots,
/// its coordinate, and what it does, drilled from the fetched dependency's own
/// analysis. A dependency that couldn't be fetched shows its reason, never a
/// blank clean line.
/// Sub-Notable behavioral atoms a source change introduced — the changes the
/// finding floor drops. Purely informational: severity is never raised, the
/// gate never fails, but a reviewer sees that a file gained a `$HOME` read or a
/// base64 heredoc. Deduplicated by description and capped, so a file that
/// gained many atoms lists a representative few rather than a screenful.
fn observations_section(atoms: &[&crate::analysis::Atom]) -> String {
    const CAP: usize = 6;
    let mut seen = std::collections::HashSet::new();
    let mut labels: Vec<String> = Vec::new();
    for at in atoms {
        let label = if at.desc.is_empty() {
            crate::rubric::short_name(&at.id)
        } else {
            at.desc.clone()
        };
        if seen.insert(label.clone()) {
            labels.push(label);
        }
    }
    let extra = labels.len().saturating_sub(CAP);
    let mut out = String::new();
    for (i, label) in labels.iter().take(CAP).enumerate() {
        let cell = if i == 0 {
            pill_cell("observed", PILL_SLATE)
        } else {
            blank_cell()
        };
        out.push_str(&grid_line(
            &cell,
            &dots(Severity::None),
            &crate::printable(label).truecolor(150, 160, 168).to_string(),
        ));
    }
    if extra > 0 {
        out.push_str(&grid_line(
            &blank_cell(),
            &dots(Severity::None),
            &format!("+{extra} more")
                .truecolor(102, 117, 127)
                .to_string(),
        ));
    }
    out
}

fn dependencies_section(deps: &[crate::deps::DepProfile]) -> String {
    let mut out = String::new();
    let indent = " ".repeat(PILL_COL + NAME_W + 4);
    for (i, d) in deps.iter().enumerate() {
        let cell = if i == 0 {
            pill_cell("dependencies", PILL_PLUM)
        } else {
            blank_cell()
        };
        let name = pad_visible(&d.coord.clone().bold().to_string(), &d.coord, NAME_W);
        let eco = d.ecosystem.truecolor(102, 117, 127);
        let tail = match (&d.note, d.severity) {
            (Some(note), _) => format!("{eco}  {}", note.truecolor(255, 176, 46)),
            (None, Severity::None) => {
                format!("{eco}  {}", "no notable behavior".truecolor(102, 117, 127))
            }
            (None, _) => eco.to_string(),
        };
        out.push_str(&grid_line(
            &cell,
            &dots(d.severity),
            &format!("{name} {tail}"),
        ));
        for h in &d.highlights {
            let _ = writeln!(out, "{indent}{}", paint(d.severity, h));
        }
    }
    out
}

fn grid_line(cell: &str, dots: &str, body: &str) -> String {
    format!(" {cell}{dots} {body}\n")
}

fn pill_cell(label: &str, (r, g, b): (u8, u8, u8)) -> String {
    let p = format!(" {label} ")
        .bold()
        .white()
        .on_truecolor(r, g, b)
        .to_string();
    let vis = label.chars().count() + 2;
    format!("{p}{}", " ".repeat(PILL_COL.saturating_sub(vis)))
}

fn blank_cell() -> String {
    " ".repeat(PILL_COL)
}

/// Right-pad `painted` (carrying ANSI) to `width` visible columns.
fn pad_visible(painted: &str, plain: &str, width: usize) -> String {
    let vis = plain.chars().count();
    format!("{painted}{}", " ".repeat(width.saturating_sub(vis)))
}

// ── metrics ──────────────────────────────────────────────────────────────

fn single_changed_file(diff: &DiffReportV1) -> Option<&FileDiffEntry> {
    let mut changed = diff
        .files
        .iter()
        .filter(|f| matches!(f.status, cleave::types::FileStatus::Changed));
    let only = changed.next()?;
    changed.next().is_none().then_some(only)
}

/// The metric movers as `(label, value, severity)`, largest relative change
/// first. Shared with the markdown report: the terminal paints them by
/// severity, markdown renders the same words plain.
pub(crate) fn metrics(diff: &DiffReportV1) -> Vec<(String, String, Severity)> {
    const FLOOR: f64 = 0.12;
    const KEEP: usize = 5;
    let Some(file) = single_changed_file(diff) else {
        return Vec::new();
    };
    let Some(m) = file.scopes.metrics.as_ref() else {
        return Vec::new();
    };
    let mut movers: Vec<(f64, String, String, Severity)> = Vec::new();
    for c in &m.changed {
        // `load_segment_*`/`size_bytes` restate other movers; `dependencies`
        // and the loader flag are named in the structure section.
        let p = &c.new.path;
        if p.contains("load_segment")
            || p.ends_with("size_bytes")
            || p.contains("dependencies")
            || p.contains("has_direct_loader_dep")
        {
            continue;
        }
        let (Some(o), Some(n)) = (c.old.value.as_f64(), c.new.value.as_f64()) else {
            continue;
        };
        if o == n {
            continue;
        }
        let rel = if o != 0.0 {
            (n - o).abs() / o.abs()
        } else {
            f64::INFINITY
        };
        if rel < FLOOR {
            continue;
        }
        let (label, value) = describe(&c.new.path, o, n);
        movers.push((rel, label, value, intensity_severity(rel)));
    }
    movers.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    // One row per label, keeping the largest mover — so `relacount` and
    // `dynrela_count` collapse to a single `relocs`.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    movers.retain(|(_, label, _, _)| seen.insert(label.clone()));
    movers.truncate(KEEP);
    movers
        .into_iter()
        .map(|(_, label, value, sev)| (label, value, sev))
        .collect()
}

/// Grid bodies for the metric movers, one per row: `label  value`, the value
/// tinted by how far the metric moved.
fn metrics_rows(diff: &DiffReportV1) -> Vec<String> {
    metrics(diff)
        .into_iter()
        .map(|(label, value, sev)| {
            let painted = label.as_str().truecolor(150, 160, 168).to_string();
            format!(
                "{} {}",
                pad_visible(&painted, &label, NAME_W),
                paint(sev, &value)
            )
        })
        .collect()
}

/// `(label, value)` for one metric change.
fn describe(path: &str, old: f64, new: f64) -> (String, String) {
    let leaf = path.rsplit(['.', '/']).next().unwrap_or(path);
    let label = match leaf {
        "code_size" => "code",
        "size" | "size_bytes" => "size",
        "init_array_count" => "init_array",
        "dynrela_count" | "relacount" => "relocs",
        other => other,
    };
    let value = if old > 0.0 && old.max(new) >= 8.0 {
        let arrow = if new >= old { "↑" } else { "↓" };
        format!("{arrow}{:.0}%", (new - old).abs() / old * 100.0)
    } else {
        format!("{}→{}", fmt_num(old), fmt_num(new))
    };
    (label.to_string(), value)
}

/// Whole numbers plain, fractional ones with two decimals — so a ratio like
/// `0.28 → 0.05` never rounds to the meaningless `0→0`.
fn fmt_num(v: f64) -> String {
    if v == v.trunc() {
        format!("{v:.0}")
    } else {
        format!("{v:.2}")
    }
}

fn intensity_severity(rel: f64) -> Severity {
    if rel >= 0.50 {
        Severity::Critical
    } else if rel >= 0.20 {
        Severity::High
    } else if rel >= 0.05 {
        Severity::Medium
    } else {
        Severity::None
    }
}

fn common_prefix(paths: &[&str]) -> String {
    let Some(first) = paths.first() else {
        return String::new();
    };
    let mut prefix: Vec<&str> = first.split('/').collect();
    for p in &paths[1..] {
        let segs: Vec<&str> = p.split('/').collect();
        let keep = prefix
            .iter()
            .zip(segs.iter())
            .take_while(|(a, b)| a == b)
            .count();
        prefix.truncate(keep);
    }
    prefix.join("/")
}

fn strip_prefix_path(path: &str, prefix: &str) -> String {
    if prefix.is_empty() {
        return path.to_string();
    }
    path.strip_prefix(prefix)
        .map(|r| r.trim_start_matches('/').to_string())
        .unwrap_or_else(|| path.to_string())
}

// ── painters ─────────────────────────────────────────────────────────────

const PILL_PLUM: (u8, u8, u8) = (60, 30, 75);
const PILL_PLUM_DIM: (u8, u8, u8) = (44, 30, 52);
const PILL_HOT: (u8, u8, u8) = (127, 43, 43);
const PILL_TEAL: (u8, u8, u8) = (0, 60, 55);
const PILL_OCEAN: (u8, u8, u8) = (12, 58, 75);
const PILL_SLATE: (u8, u8, u8) = (55, 55, 58);

/// The verdict word for a severity: HOSTILE / SUSPICIOUS / NOTABLE / CLEAN.
/// Shared with every other renderer, so one vocabulary describes a verdict
/// whether it lands in a terminal, a PR comment, SARIF, or an exit annotation.
pub(crate) fn verdict_word(sev: Severity) -> &'static str {
    badge_parts(sev).0
}

fn badge_parts(sev: Severity) -> (&'static str, (u8, u8, u8)) {
    match sev {
        Severity::Critical => ("HOSTILE", (176, 46, 46)),
        Severity::High => ("SUSPICIOUS", (150, 105, 0)),
        Severity::Medium | Severity::Low => ("NOTABLE", (0, 90, 140)),
        Severity::None => ("CLEAN", (40, 110, 40)),
    }
}

fn badge(sev: Severity) -> String {
    let (word, (r, g, b)) = badge_parts(sev);
    format!(" {word} ")
        .bold()
        .white()
        .on_truecolor(r, g, b)
        .to_string()
}

fn dots(sev: Severity) -> String {
    let d = match sev {
        Severity::Critical => "●●●",
        Severity::High => "●● ",
        Severity::Medium | Severity::Low => "●  ",
        Severity::None => "·  ",
    };
    paint(sev, d)
}

fn paint(sev: Severity, text: &str) -> String {
    match sev {
        Severity::Critical => cleave::theme::paint_hostile(text).to_string(),
        Severity::High => cleave::theme::paint_suspicious(text).to_string(),
        Severity::Medium | Severity::Low => cleave::theme::paint_notable(text).to_string(),
        Severity::None => cleave::theme::paint_baseline(text).to_string(),
    }
}
