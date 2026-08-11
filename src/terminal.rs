//! The terminal report — masthead + grid.
//!
//! Output follows the UNIX-diff principle: **silent when there is no
//! noticeable behavioral change**, and a single styled verdict — masthead,
//! grid, and the differential evidence behind it — when there is something to
//! say.
//!
//! One grid language throughout — every section is a `label  body` row, its
//! marker (a severity dot or a change sign) landing in the content column — with
//! a blank line between sections so each triage question (known campaign? who
//! shipped it? what can it newly do?) reads as its own block.

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
const PILL_COL: usize = 10;
/// Width the capability-class name column pads to.
const NAME_W: usize = 20;

/// The complete terminal report for one analysis.
pub(crate) fn report(a: &Analysis<'_>, cli: &Cli) -> String {
    let mut out = String::new();
    if a.speaks(cli) {
        render(&mut out, a);
        // The proof: diff-style hunks for the gained traits, each owned by its
        // strongest rule and drawn from the files the diff actually changed.
        // Shown on every speaking verdict — the code behind a behavior change
        // is the root cause a reviewer has to assess, not a detail to gate
        // behind a flag.
        let ids = a.assessment.gained_ids();
        let rows = a.hunks(crate::evidence::MAX_HUNKS);
        if !rows.is_empty() {
            out.push_str(&evidence_hunks(&rows, a.diff));
        } else if !ids.is_empty() {
            // Say the absence out loud — an analyst reading a verdict with no
            // proof section should know the gained traits carry no byte-located
            // matches, not suspect a rendering gap.
            out.push_str(&evidence_note());
        }
        // Behavior-bearing atoms a source change introduced below the finding
        // floor — the "$HOME read, base64 heredoc" that no single trait scored
        // high enough to name. When they are the *only* reason the diff spoke,
        // they are the whole story.
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
    out
}

/// The masthead and the detail grid. Order: verdict, ML risk, attribution,
/// identity, capabilities, structure, metrics, touched files.
///
/// One view: a speaking verdict draws the whole grid. isomer stays silent when
/// there is no noticeable change (see [`Analysis::speaks`]); once it speaks, it
/// shows the reviewer everything behind the call rather than making them ask.
fn render(out: &mut String, a: &Analysis<'_>) {
    let (assessment, naming) = (&a.assessment, &a.naming);
    let mut sections: Vec<String> = Vec::new();
    sections.push(badge_line(a.verdict, a.diff, naming));

    // Verdict summary block: why (the deterministic reason), model (the read,
    // when one was computed), and the ML risk move on one line each.
    let mut summary = String::new();
    summary.push_str(&grid_line(
        &pill_cell("why", PILL_HOT),
        "",
        &a.reason().truecolor(255, 176, 46).to_string(),
    ));
    if let Some(i) = a.interp.as_ref().filter(|i| !i.nature.trim().is_empty()) {
        summary.push_str(&grid_line(
            &pill_cell("model", PILL_OCEAN),
            "",
            &i.nature.trim().truecolor(62, 207, 214).to_string(),
        ));
    }
    if let Some(r) = a.risk {
        summary.push_str(&risk_row(r));
    }
    push_section(&mut sections, &mut summary);

    let mut section = String::new();
    signature_grid(&mut section, assessment);
    push_section(&mut sections, &mut section);
    identity_grid(&mut section, assessment);
    push_section(&mut sections, &mut section);
    gained_grid(&mut section, assessment);
    push_section(&mut sections, &mut section);
    structure_grid(&mut section, &assessment.structure);
    push_section(&mut sections, &mut section);
    frameworks_grid(&mut section, a);
    push_section(&mut sections, &mut section);
    // Aggregate counts that sum honestly across file types (symbols, sections,
    // strings); scalar per-file metrics ride each evidence header instead.
    for (i, body) in stats_rows(a.diff).into_iter().enumerate() {
        let cell = if i == 0 {
            pill_cell("stats", PILL_TEAL)
        } else {
            blank_cell()
        };
        section.push_str(&grid_line(&cell, "", &body));
    }
    push_section(&mut sections, &mut section);
    files_grid(&mut section, a.diff);
    push_section(&mut sections, &mut section);
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
            out.push_str(&grid_line(&cell, "", &body));
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
    const MAX: usize = 8;
    let mut names: Vec<String> = Vec::new();
    for f in &diff.files {
        let Some((_, member)) = f.path.split_once("!!") else {
            continue;
        };
        if matches!(f.status, cleave::types::FileStatus::Unchanged) {
            continue;
        }
        names.push(split_path(member).1.to_string());
    }
    if names.is_empty() {
        return;
    }
    let overflow = names.len().saturating_sub(MAX);
    names.truncate(MAX);
    if overflow > 0 {
        names.push(format!("+{overflow} more"));
    }
    // A plain, space-delimited list; each file's full path and severity live on
    // its evidence header below.
    let body = names.join("   ").truecolor(232, 237, 242).to_string();
    out.push_str(&grid_line(&pill_cell("files", PILL_SLATE), "", &body));
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

/// The ML detector on one line: `old → new` on a benign→malware bar, the band
/// word, and the jump.
fn risk_row(r: Risk) -> String {
    let d = r.delta();
    let (arrow, dsev) = if d > 0.005 {
        ("▲", crate::analysis::risk_band(r.new))
    } else if d < -0.005 {
        ("▼", Severity::None)
    } else {
        ("·", Severity::None)
    };
    let body = format!(
        "{} {} {}  {}  {}   {}",
        format!("{:.2}", r.old).truecolor(140, 150, 158),
        "→".truecolor(102, 117, 127),
        paint(crate::analysis::risk_band(r.new), &format!("{:.2}", r.new)).bold(),
        bar(r.new),
        risk_word(r.new),
        paint(dsev, &format!("{arrow} {d:+.2}")),
    );
    grid_line(&pill_cell("risk", PILL_OCEAN), "", &body)
}

/// The gained capability classes as a tree: a marker per class — green `+` for
/// one the old version lacked, amber `↑` for an existing class that grew — then
/// its newly-gained traits as `└─` leaves. Replaces the old new/expanded split
/// so both directions read in one section, hierarchy explicit.
fn gained_grid(out: &mut String, a: &Assessment) {
    let cats = &a.behavioral.categories;
    // Align the leaf's `└─` just under its class name (past the label + the
    // 3-wide marker column).
    let leaf_indent = " ".repeat(PILL_COL + 4);
    for (i, c) in cats.iter().enumerate() {
        let cell = if i == 0 {
            pill_cell("gained", PILL_PLUM)
        } else {
            blank_cell()
        };
        let marker = if a.behavioral.is_new_category(c) {
            "+".truecolor(95, 175, 95)
        } else {
            "↑".truecolor(255, 176, 46)
        };
        let ns = if c.namespaces.is_empty() {
            c.label.clone()
        } else {
            c.namespaces.join(" · ")
        };
        out.push_str(&grid_line(
            &cell,
            &format!("{marker}  "),
            &ns.bold().to_string(),
        ));
        for id in &c.new_ids {
            let leaf = id.split("::").last().unwrap_or(id);
            out.push_str(&format!(
                "{leaf_indent}{} {}\n",
                "└─".truecolor(70, 80, 89),
                leaf.truecolor(76, 178, 255),
            ));
        }
    }
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
fn evidence_hunks(hunks: &[&Hunk], diff: &DiffReportV1) -> String {
    if hunks.is_empty() {
        return String::new();
    }
    let locw = hunks
        .iter()
        .flat_map(|h| h.lines.iter())
        .map(|l| l.locator.chars().count())
        .max()
        .unwrap_or(4);
    // Width of the desc column, over the *window* hunks only (additions render
    // filename-headed, not desc-padded).
    let descw = hunks
        .iter()
        .filter(|h| !h.additions)
        .map(|h| crate::clip(&h.desc, 56).chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    let mut i = 0;
    while i < hunks.len() {
        if hunks[i].additions {
            // One header per changed file — a severity bar, the path (directory
            // dim, basename bright), and the file's strongest rule as caption.
            // Its runs follow in source order as plain added-line blocks, a
            // single ellipsis marking each gap; matched lines stay bright so the
            // detected behavior reads at a glance without per-run headings.
            let name = file_label(hunks[i]);
            let mut j = i;
            while j < hunks.len() && hunks[j].additions && file_label(hunks[j]) == name {
                j += 1;
            }
            let group = &hunks[i..j];
            let sev = group
                .iter()
                .map(|h| h.severity)
                .max()
                .unwrap_or(Severity::None);
            let cap = group
                .iter()
                .filter(|h| !h.desc.is_empty())
                .max_by(|a, b| {
                    a.severity
                        .cmp(&b.severity)
                        .then(a.score.total_cmp(&b.score))
                })
                .map(|h| format!("   {}", paint(sev, &crate::clip(&h.desc, 56))))
                .unwrap_or_default();
            let (dir, base) = split_path(name);
            let _ = write!(
                out,
                "\n  {} {}{}{cap}\n",
                paint(sev, "▌"),
                dir.truecolor(70, 80, 89),
                base.truecolor(232, 237, 242).bold(),
            );
            // Per-file scalar metrics (sizes, entropy, ratios) — the ones that
            // don't sum across files — live here, next to their file.
            if let Some(ms) = file_metrics_summary(diff, name) {
                let _ = writeln!(out, "   {}", ms.truecolor(102, 117, 127));
            }
            for (k, h) in group.iter().enumerate() {
                if k > 0 {
                    // The gap marker sits in the locator lane, no rail.
                    let _ = writeln!(
                        out,
                        "  {}",
                        format!("{:>locw$}", "⋯", locw = locw).truecolor(70, 80, 89),
                    );
                }
                push_hunk_lines(&mut out, h, locw);
            }
            i = j;
        } else {
            let name = file_label(hunks[i]);
            let desc = crate::clip(&hunks[i].desc, 56);
            let _ = write!(
                out,
                "\n   {} {}   {}\n",
                dots(hunks[i].severity),
                pad_visible(&paint(hunks[i].severity, &desc), &desc, descw),
                hunks[i].location.truecolor(102, 117, 127),
            );
            // The first hunk of a (binary) file carries its scalar metrics.
            if (i == 0 || file_label(hunks[i - 1]) != name)
                && let Some(ms) = file_metrics_summary(diff, name)
            {
                let _ = writeln!(out, "   {}", ms.truecolor(102, 117, 127));
            }
            push_hunk_lines(&mut out, hunks[i], locw);
            i += 1;
        }
    }
    out
}

/// The name a hunk is filed under: the archive member when it is one, else the
/// pair's own label (a plain file's basename).
fn file_label(h: &Hunk) -> &str {
    h.member.as_deref().unwrap_or(h.file.as_str())
}

/// `Unreal3.2/include/struct.h` → (`Unreal3.2/include/`, `struct.h`); a bare
/// name → (``, name). The directory is rendered dim, the basename bright.
fn split_path(p: &str) -> (&str, &str) {
    // `+ 1` keeps the trailing `/` on the directory; it is one ASCII byte, so
    // the split lands on a char boundary.
    match p.rfind('/') {
        Some(i) => p.split_at(i + 1),
        None => ("", p),
    }
}

/// Push a hunk's code rows: `locator + code`, the `+` gutter doubling as the
/// rail. Matched lines bright, dim context behind them, long lines wrapped
/// across bare continuation rows.
fn push_hunk_lines(out: &mut String, h: &Hunk, locw: usize) {
    for l in &h.lines {
        let gutter = match l.added {
            Some(true) => "+".truecolor(95, 175, 95).to_string(),
            _ => " ".to_string(),
        };
        let paint_code = |s: &str| {
            if l.is_match {
                s.truecolor(205, 214, 221).to_string()
            } else {
                s.truecolor(102, 117, 127).to_string()
            }
        };
        for (i, row_text) in wrap_code(&l.text, crate::evidence::CODE_W)
            .into_iter()
            .enumerate()
        {
            let row = if i == 0 {
                let loc = format!("{:>locw$}", l.locator, locw = locw);
                format!(
                    "  {} {gutter} {}",
                    loc.truecolor(70, 80, 89),
                    paint_code(&row_text)
                )
            } else {
                format!("  {}   {}", " ".repeat(locw), paint_code(&row_text))
            };
            out.push_str(row.trim_end());
            out.push('\n');
        }
    }
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
            pill_cell("deps", PILL_PLUM)
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

/// One grid row: ` {label}{marker}{body}`. `marker` is a 3-wide severity glyph
/// (`●  `) or a tree/change sign for the rows that carry one, and empty for the
/// plain label rows — so a marker, when present, lands in the content column and
/// its body sits just past it.
fn grid_line(cell: &str, marker: &str, body: &str) -> String {
    format!(" {cell}{marker}{body}\n")
}

/// A section label: colored text, left-aligned in the label column — no
/// background. The color is the section's accent; the width lines every row's
/// content up at the same column.
fn pill_cell(label: &str, (r, g, b): (u8, u8, u8)) -> String {
    format!(
        "{}",
        format!("{label:<w$}", w = PILL_COL)
            .truecolor(r, g, b)
            .bold()
    )
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

/// Aggregate count deltas across the changed files, as `old → new  label  (+Δ)`
/// with the gained names listed. Only the *count* scopes — symbols, sections,
/// strings — which sum honestly regardless of file type; the scalar per-file
/// metrics (sizes, entropy, ratios) ride each evidence header, where they keep
/// their meaning. Empty when nothing counted moved.
fn stats_rows(diff: &DiffReportV1) -> Vec<String> {
    // For an archive, the leaf members carry the counts; skip the container
    // root so nothing is counted twice. A single-file diff has no `!!` entries,
    // so every changed entry is a leaf.
    let archive = diff.files.iter().any(|f| f.path.contains("!!"));
    let (mut sym_o, mut sym_n) = (0i64, 0i64);
    let (mut sec_o, mut sec_n) = (0i64, 0i64);
    let (mut str_o, mut str_n) = (0i64, 0i64);
    let mut added_syms: Vec<String> = Vec::new();
    let mut added_secs: Vec<String> = Vec::new();
    for f in &diff.files {
        if matches!(f.status, cleave::types::FileStatus::Unchanged)
            || (archive && !f.path.contains("!!"))
        {
            continue;
        }
        if let Some(s) = &f.scopes.symbols {
            sym_o += i64::from(s.old_count);
            sym_n += i64::from(s.new_count);
            added_syms.extend(s.added.iter().map(|a| a.symbol.clone()));
        }
        if let Some(s) = &f.scopes.sections {
            sec_o += i64::from(s.old_count);
            sec_n += i64::from(s.new_count);
            added_secs.extend(s.added.iter().map(|a| a.name.clone()));
        }
        if let Some(s) = &f.scopes.strings {
            str_o += i64::from(s.old_count);
            str_n += i64::from(s.new_count);
        }
    }
    let mut raw: Vec<(i64, i64, &str, String)> = Vec::new();
    if sym_o != sym_n || !added_syms.is_empty() {
        raw.push((sym_o, sym_n, "symbols", names_note(&added_syms)));
    }
    if sec_o != sec_n || !added_secs.is_empty() {
        raw.push((sec_o, sec_n, "sections", names_note(&added_secs)));
    }
    if str_o != str_n {
        raw.push((str_o, str_n, "strings", String::new()));
    }
    if raw.is_empty() {
        return Vec::new();
    }
    // Right-align old/new in one field so every `→` stacks.
    let w = raw
        .iter()
        .map(|(o, n, ..)| o.to_string().len().max(n.to_string().len()))
        .max()
        .unwrap_or(1);
    raw.into_iter()
        .map(|(o, n, label, note)| {
            let d = n - o;
            let delta = if d > 0 {
                format!("(+{d})").truecolor(95, 175, 95).to_string()
            } else {
                format!("({d:+})").truecolor(102, 117, 127).to_string()
            };
            let mut body = format!(
                "{} {} {}  {}  {delta}",
                format!("{o:>w$}").truecolor(140, 150, 158),
                "→".truecolor(102, 117, 127),
                format!("{n:>w$}").truecolor(140, 150, 158),
                format!("{label:<8}").truecolor(150, 160, 168),
            );
            if !note.is_empty() {
                let _ = write!(body, "  {}", note.truecolor(120, 134, 144));
            }
            body
        })
        .collect()
}

/// A short, `, `-joined list of gained names, capped so one big change can't run
/// off the row.
fn names_note(names: &[String]) -> String {
    const MAX: usize = 5;
    if names.is_empty() {
        return String::new();
    }
    let mut s = names
        .iter()
        .take(MAX)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > MAX {
        let _ = write!(s, ", +{} more", names.len() - MAX);
    }
    s
}

/// The scalar metric deltas for one changed file — sizes, entropy, ratios,
/// per-file counts — as `label old→new (Δ%)`, joined with ` · `. These are the
/// metrics that don't aggregate across files, so they ride the file's own
/// evidence header. `None` when the file has no scalar movers.
fn file_metrics_summary(diff: &DiffReportV1, member: &str) -> Option<String> {
    const CAP: usize = 6;
    let entry = diff
        .files
        .iter()
        .find(|f| f.path.rsplit_once("!!").map_or(f.path.as_str(), |(_, m)| m) == member)
        // A single-file (non-archive) diff has one changed entry, unmatched by
        // name — fall back to it.
        .or_else(|| single_changed_file(diff))?;
    let m = entry.scopes.metrics.as_ref()?;
    let mut movers: Vec<(f64, String, String)> = Vec::new();
    for c in &m.changed {
        let p = c.new.path.as_str();
        // `size_bytes` restates other movers; the rest are archive noise or are
        // named in the structure section.
        if p.contains("mtime")
            || p.contains("timing")
            || p.contains("dependencies")
            || p.contains("has_direct_loader_dep")
            || p.contains("load_segment")
            || p.ends_with("size_bytes")
        {
            continue;
        }
        let (Some(o), Some(n)) = (c.old.value.as_f64(), c.new.value.as_f64()) else {
            continue;
        };
        if o == n {
            continue;
        }
        let (label, _) = describe(p, o, n);
        let (rel, delta) = if o != 0.0 {
            (
                (n - o).abs() / o.abs(),
                format!("{:+.0}%", (n - o) / o * 100.0),
            )
        } else {
            (f64::INFINITY, "new".to_string())
        };
        movers.push((
            rel,
            label,
            format!("{}→{} ({delta})", fmt_num(o), fmt_num(n)),
        ));
    }
    movers.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    // One row per label — `relacount` and `dynrela_count` both read `relocs`,
    // so keep the larger mover, not both.
    let mut seen = std::collections::HashSet::new();
    movers.retain(|(_, label, _)| seen.insert(label.clone()));
    movers.truncate(CAP);
    (!movers.is_empty()).then(|| {
        movers
            .into_iter()
            .map(|(_, label, v)| format!("{label} {v}"))
            .collect::<Vec<_>>()
            .join(" · ")
    })
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

const PILL_PLUM: (u8, u8, u8) = (60, 30, 75);
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
