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
//! shipped it? what can it newly do?) reads as its own block. Anything that
//! belongs to a row — a fact's detail, a hunk's bytes, a class's traits — sits
//! indented beneath it, so every line has a visible parent and no row runs
//! past a 100-column pane.

use std::fmt::Write as _;

use cleave::types::DiffReportV1;
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
/// Width cap for the rule-description column, in the signature grid and over
/// the evidence headers, so both lanes clip at the same place.
const DESC_W: usize = 56;
/// Indent of the rows that belong to a grid row — leaves, details, code —
/// just past the label cell, the 2-wide change sign, and the 4-wide severity
/// column.
const INDENT: usize = PILL_COL + 7;
/// Visible width the wrapped prose beneath a row stops at, from [`INDENT`].
const PROSE_W: usize = 74;
/// Display width of one code row in an evidence hunk. Narrower than
/// [`crate::evidence::CODE_W`], the *windowing* budget, so a row plus its
/// locator gutter still fits beside the label column.
const CODE_COLS: usize = 74;

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
        let rows = a.hunks(crate::evidence::MAX_HUNKS);
        if !rows.is_empty() {
            out.push_str(&evidence_hunks(&rows, a.diff));
        } else if !a.assessment.gained_ids().is_empty() {
            // Say the absence out loud — an analyst reading a verdict with no
            // proof section should know the gained traits carry no byte-located
            // matches (structural and metric rules often carry none), not
            // suspect a rendering gap.
            out.push('\n');
            out.push_str(&grid_line(
                &pill_cell("evidence", PILL_OCEAN),
                "",
                &"none of the gained traits carry byte-located matches"
                    .truecolor(102, 117, 127)
                    .to_string(),
            ));
        }
        // Behavior-bearing atoms a source change introduced below the finding
        // floor — the "$HOME read, base64 heredoc" that no single trait scored
        // high enough to name. When they are the *only* reason the diff spoke,
        // they are the whole story.
        let obs = a.observations();
        if !obs.is_empty() {
            out.push('\n');
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
        out.push('\n');
        out.push_str(&dependencies_section(&a.deps));
    }
    if !a.registry.is_empty() {
        out.push_str("\nregistry (current lookup; not historical resolution):\n");
        for row in &a.registry {
            let _ = writeln!(
                out,
                "  {}: {} (new: {})",
                crate::printable(&row.subject),
                row.severity().as_str(),
                row.new_severity.as_str()
            );
            if let Some(reason) = &row.policy_reason {
                let _ = writeln!(out, "    {reason}");
            }
            for (side, observation) in [("before", &row.old), ("after", &row.new)] {
                if let Some(observation) = observation {
                    for finding in &observation.findings {
                        let _ = writeln!(
                            out,
                            "    {side} {}: {}",
                            crate::printable(&observation.coordinate),
                            finding.description
                        );
                    }
                }
                if let Some(error) = observation.as_ref().and_then(|o| o.error.as_ref()) {
                    let _ = writeln!(out, "    {side}: {}", crate::printable(error));
                }
            }
        }
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
    sections.push(badge_line(a.verdict, a.display_diff(), naming));

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
    // The shape of the change — its own block, so the verdict lines above
    // stand alone.
    differential_grid(&mut summary, a);
    push_section(&mut sections, &mut summary);

    let mut section = String::new();
    signature_grid(&mut section, assessment);
    push_section(&mut sections, &mut section);
    identity_grid(&mut section, assessment);
    push_section(&mut sections, &mut section);
    identity_claims_grid(&mut section, a);
    push_section(&mut sections, &mut section);
    removed_grid(&mut section, a);
    push_section(&mut sections, &mut section);
    gained_grid(&mut section, assessment);
    push_section(&mut sections, &mut section);
    structure_grid(&mut section, &assessment.structure);
    push_section(&mut sections, &mut section);
    frameworks_grid(&mut section, a);
    push_section(&mut sections, &mut section);
    // The numbers behind the call — the metrics that moved most, then the
    // aggregate counts that sum honestly across file types (symbols, sections,
    // strings). In a container diff, each file's own movers ride its evidence
    // header too.
    metrics_grid(&mut section, a);
    push_section(&mut sections, &mut section);
    for (i, body) in stats_rows(a.display_diff()).into_iter().enumerate() {
        let cell = section_cell(i, "stats", PILL_TEAL);
        section.push_str(&grid_line(&cell, "", &body));
    }
    push_section(&mut sections, &mut section);
    files_grid(&mut section, a.display_diff());
    push_section(&mut sections, &mut section);
    out.push_str(&sections.join("\n"));
}

/// Parsed claims about what the changed artifact or member says it is. These
/// are context only; the trust marker distinguishes cryptographic provenance
/// from unsigned manifest/version metadata.
fn identity_claims_grid(out: &mut String, a: &Analysis<'_>) {
    for (i, line) in a.identity_change_summary().into_iter().enumerate() {
        let cell = section_cell(i, "claims", PILL_SLATE);
        out.push_str(&grid_line(
            &cell,
            "",
            &line.truecolor(190, 201, 209).to_string(),
        ));
    }
}

/// The compact facts that make a large package diff legible: member topology,
/// scope rates, delivery anomalies, and executable replacement. This is the
/// same distilled view supplied to the local model, so a human can audit the
/// facts behind its conclusion without opening the raw JSON.
fn differential_grid(out: &mut String, a: &Analysis<'_>) {
    let summary = a.differential_summary();
    let mut rows: Vec<(&str, &str)> = Vec::new();
    for line in &summary {
        let (label, body) = line.split_once(": ").unwrap_or(("diff", line.as_str()));
        // The metric movers get a table of their own, the headline already
        // opens the report, and the gate is the exit code — the LLM reads
        // them here, the grid does not.
        if matches!(
            label,
            "largest metric changes" | "deterministic assessment" | "primary deterministic signal"
        ) || label.starts_with("current registry")
            || label.starts_with("registry coverage gap")
        {
            continue;
        }
        // The LLM's scope name is jargon on a screen.
        let label = if label == "scope ROC" {
            "changed"
        } else {
            label
        };
        // Payload indicators arrive as one ` · `-joined line but read as a list,
        // so they get a row each under a single heading.
        if label == "payload indicators" {
            rows.extend(body.split(" · ").map(|item| (label, item)));
        } else {
            rows.push((label, body));
        }
    }
    // A label names its run once and stays blank for the rest of it — keyed on
    // the previous row, not on the row index, since a split-out run never
    // starts at the top of the section.
    let mut previous = "";
    let mut row = 0;
    for (label, body) in rows {
        let name = if label == previous {
            " ".repeat(label.chars().count())
        } else {
            label.bold().to_string()
        };
        previous = label;
        // A long shape sentence wraps under its own first word, so the label
        // column stays a column.
        let lead = label.chars().count() + 2;
        for (k, line) in wrap_words(body, PROSE_W.saturating_sub(lead))
            .into_iter()
            .enumerate()
        {
            let cell = section_cell(row, "diff", PILL_TEAL);
            row += 1;
            let body = if k == 0 {
                format!("{name}  {}", line.truecolor(190, 201, 209))
            } else {
                format!("{:lead$}{}", "", line.truecolor(190, 201, 209))
            };
            out.push_str(&grid_line(&cell, "", &body));
        }
    }
}

/// The MITRE ATT&CK and MBC ids this change moved.
///
/// isomer carries no catalog mapping these to prose, so it does not pretend
/// to: the ids are shown as ids, which is what an analyst pastes into their
/// own reference anyway. `+` is a technique the change introduced, `−` one it
/// no longer exhibits — a fix landing looks different from a regression.
fn frameworks_grid(out: &mut String, a: &Analysis<'_>) {
    const MAX: usize = 10;
    for (label, sides) in [("attack", &a.survey.attack), ("mbc", &a.survey.mbc)] {
        if !sides.changed() {
            continue;
        }
        // One id per row, its official name beside it: `+` introduced, `−` no
        // longer exhibited, the introduced ones bright.
        let mut rows: Vec<(String, bool)> = Vec::new();
        rows.extend(sides.gained().into_iter().map(|id| (id.to_string(), true)));
        rows.extend(sides.lost().into_iter().map(|id| (id.to_string(), false)));
        let overflow = rows.len().saturating_sub(MAX);
        rows.truncate(MAX);
        let idw = rows
            .iter()
            .map(|(id, _)| id.chars().count())
            .max()
            .unwrap_or(0);
        for (i, (id, gained)) in rows.iter().enumerate() {
            let cell = section_cell(i, label, PILL_OCEAN);
            let painted = if *gained {
                id.truecolor(205, 214, 221)
            } else {
                id.truecolor(102, 117, 127)
            };
            let name = crate::frameworks::name(id).unwrap_or_default();
            let body = format!(
                "{}  {}",
                pad_visible(&painted.to_string(), id, idw),
                name.truecolor(190, 201, 209)
            );
            let marker = sign(Some(if *gained { '+' } else { '−' }));
            out.push_str(&grid_line(&cell, &marker, &body));
        }
        let mut tail: Vec<String> = Vec::new();
        if overflow > 0 {
            tail.push(format!("+{overflow} more"));
        }
        if sides.kept() > 0 {
            tail.push(format!("{} unchanged", sides.kept()));
        }
        if !tail.is_empty() {
            out.push_str(&grid_line(
                &blank_cell(),
                &sign(None),
                &tail.join(" · ").truecolor(102, 117, 127).to_string(),
            ));
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
///
/// Worst first, two rows per fact at most: the marker and label, with the
/// image it was read from dim at the end (named once per run); then the
/// observations on one line, ` · `-joined. A rubric fact's names ride the
/// label row itself. The caveat is left to the prose renderers: on screen it
/// is clutter.
fn structure_grid(out: &mut String, structure: &crate::rubric::Structure) {
    let mut facts: Vec<&crate::rubric::StructFact> = structure.facts.iter().collect();
    facts.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let sep = " · ".truecolor(102, 117, 127).to_string();
    let mut previous: Option<&String> = None;
    for (i, f) in facts.iter().enumerate() {
        let cell = section_cell(i, "structure", PILL_SLATE);
        let marker = match f.kind {
            crate::rubric::FactKind::Added => '+',
            crate::rubric::FactKind::Became => '~',
        };
        let mut head = f.label.bold().to_string();
        // The values speak for themselves under the label; their names stay
        // in the prose renderers. A rubric fact's one unnamed value — the
        // names it found — rides the label row.
        let mut items: Vec<(&str, String)> = Vec::new();
        for (name, value) in &f.facts {
            if name.is_empty() {
                let _ = write!(head, " {}", value.truecolor(150, 160, 168));
            } else {
                items.push((value, value.truecolor(190, 201, 209).to_string()));
            }
        }
        // A subject names its run once: three facts read from the same image
        // carry it on the first, not three times over.
        if let Some(subject) = f.subject.as_ref().filter(|s| Some(*s) != previous) {
            let _ = write!(head, "   {}", subject.truecolor(102, 117, 127));
        }
        previous = f.subject.as_ref();
        out.push_str(&grid_line(
            &cell,
            &format!("{}{}", sign(Some(marker)), dots(f.severity)),
            &head,
        ));
        // Greedy over the plain widths, painted output: a fact with many
        // observations takes a second row rather than running off the pane.
        // This row may run to the pane edge; it is terse by construction.
        const ROW_W: usize = PROSE_W + 8;
        let (mut row, mut width): (Vec<String>, usize) = (Vec::new(), 0);
        for (plain, painted) in items {
            let w = plain.chars().count();
            if !row.is_empty() && width + 3 + w > ROW_W {
                let _ = writeln!(out, "{:INDENT$}{}", "", row.join(sep.as_str()));
                row.clear();
                width = 0;
            }
            width += if row.is_empty() { w } else { 3 + w };
            row.push(painted);
        }
        if !row.is_empty() {
            let _ = writeln!(out, "{:INDENT$}{}", "", row.join(sep.as_str()));
        }
    }
}

/// The scalar metrics that moved most, one per row with the columns aligned —
/// name, `old → new`, relative change — so the eye ranks them without reading.
/// The rows arrive ranked by [`crate::analysis::metric_change_importance`].
fn metrics_grid(out: &mut String, a: &Analysis<'_>) {
    const MEMBER_W: usize = 24;
    const LABEL_W: usize = 36;
    let moves = a.metric_moves();
    // In a container diff a member column leads, named once per run — the
    // metric names stay whole, since the leaf is what distinguishes them.
    let members: Vec<String> = moves
        .iter()
        .map(|m| {
            m.member
                .as_deref()
                .map(|s| crate::clip(s, MEMBER_W))
                .unwrap_or_default()
        })
        .collect();
    let labels: Vec<String> = moves
        .iter()
        .map(|m| crate::clip(&m.label, LABEL_W))
        .collect();
    let widest = |items: &[String]| items.iter().map(|s| s.chars().count()).max().unwrap_or(0);
    let (mw, lw) = (widest(&members), widest(&labels));
    let (ow, nw, dw) = (
        moves
            .iter()
            .map(|m| m.old.chars().count())
            .max()
            .unwrap_or(0),
        moves
            .iter()
            .map(|m| m.new.chars().count())
            .max()
            .unwrap_or(0),
        moves
            .iter()
            .map(|m| m.delta.chars().count())
            .max()
            .unwrap_or(0),
    );
    let mut previous = "";
    for (i, m) in moves.iter().enumerate() {
        let cell = section_cell(i, "metrics", PILL_TEAL);
        let member = if members[i] == previous {
            ""
        } else {
            &members[i]
        };
        previous = &members[i];
        let delta = if m.delta.starts_with('-') {
            format!("{:>dw$}", m.delta).truecolor(102, 117, 127)
        } else {
            format!("{:>dw$}", m.delta).truecolor(95, 175, 95)
        };
        let mut body = String::new();
        if mw > 0 {
            let _ = write!(
                body,
                "{}  ",
                pad_visible(&member.truecolor(102, 117, 127).to_string(), member, mw)
            );
        }
        let _ = write!(
            body,
            "{}  {} {} {}  {delta}",
            pad_visible(
                &labels[i].truecolor(190, 201, 209).to_string(),
                &labels[i],
                lw
            ),
            format!("{:>ow$}", m.old).truecolor(140, 150, 158),
            "→".truecolor(102, 117, 127),
            pad_visible(&m.new.truecolor(232, 237, 242).to_string(), &m.new, nw),
        );
        out.push_str(&grid_line(&cell, "", &body));
    }
}

/// Greedy word wrap to `width` visible chars; a word longer than the width
/// stands on its own row rather than being split.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
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
    // Widen before summing: three `u32` counts added in `u32` would abort on
    // overflow under the dev profile's `panic = "abort"` and wrap in release.
    let mut touched = diff.summary.files_changed as usize
        + diff.summary.files_added as usize
        + diff.summary.files_removed as usize;
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

/// The ML detector on one line: scores, a probability bar, the calibrated
/// classification, and the jump. Color follows the decision, not a raw cutoff.
fn risk_row(r: Risk) -> String {
    let d = r.delta();
    let band = r.model_severity();
    let (arrow, dsev) = if d > 0.005 {
        ("▲", band)
    } else if d < -0.005 {
        ("▼", Severity::None)
    } else {
        ("·", Severity::None)
    };
    // The band word carries its own severity color, except a benign read, which
    // stays dim rather than claiming the green a clean verdict owns.
    let label = r.new_classification.to_string();
    let word = if band == Severity::None {
        label.truecolor(102, 117, 127).to_string()
    } else {
        paint(band, &label)
    };
    let body = format!(
        "{} {} {}  {}  {}   {}",
        format!("{:.2}", r.old).truecolor(140, 150, 158),
        "→".truecolor(102, 117, 127),
        paint(band, &format!("{:.2}", r.new)).bold(),
        bar(r.new, band),
        word,
        paint(dsev, &format!("{arrow} {d:+.2}")),
    );
    grid_line(&pill_cell("risk", PILL_OCEAN), "", &body)
}

/// The gained traits, one row per namespace: a marker — green `+` for a
/// capability class the old version lacked, amber `↑` for an existing class
/// that grew — the tier of the strongest trait under it, the taxonomy path,
/// and how many traits it covers. The path is the finding; the individual
/// traits and their evidence are in the JSON and the evidence section.
/// Worst tier first, alphabetical within a tier so siblings sit together.
fn gained_grid(out: &mut String, a: &Assessment) {
    const MAX_ROWS: usize = 12;
    // namespace → (all classes new, worst tier, trait count)
    let mut groups: Vec<(String, bool, Severity, usize)> = Vec::new();
    for c in &a.behavioral.categories {
        for id in c.new_ids.iter().chain(&c.escalated_ids) {
            let ns = crate::rubric::namespace_of(id);
            let sev = c.traits.get(id).map_or(c.severity, |n| n.severity);
            match groups.iter_mut().find(|g| g.0 == ns) {
                Some(g) => {
                    g.1 = g.1 && a.behavioral.is_new_category(c);
                    g.2 = g.2.max(sev);
                    g.3 += 1;
                }
                None => groups.push((ns, a.behavioral.is_new_category(c), sev, 1)),
            }
        }
    }
    groups.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    let overflow = groups.len().saturating_sub(MAX_ROWS);
    groups.truncate(MAX_ROWS);
    let nsw = groups
        .iter()
        .map(|g| g.0.chars().count())
        .max()
        .unwrap_or(0);
    for (i, (ns, all_new, sev, count)) in groups.iter().enumerate() {
        let cell = section_cell(i, "gained", PILL_PLUM);
        let marker = if *all_new { '+' } else { '↑' };
        let mut body = ns.bold().to_string();
        if *count > 1 {
            let _ = write!(
                body,
                "{}   {}",
                " ".repeat(nsw - ns.chars().count()),
                format!("{count} traits").truecolor(102, 117, 127)
            );
        }
        out.push_str(&grid_line(
            &cell,
            &format!("{}{}", sign(Some(marker)), dots(*sev)),
            &body,
        ));
    }
    if overflow > 0 {
        out.push_str(&grid_line(
            &blank_cell(),
            &format!("{}{}", sign(None), dots(Severity::None)),
            &format!("+{overflow} more namespaces")
                .truecolor(102, 117, 127)
                .to_string(),
        ));
    }
}

/// A `└─` leaf under the section row it belongs to, aligned just under the
/// class name — past the label cell and the 3-wide marker column. The caller
/// paints the text; the stem is the same in every section.
fn leaf_line(out: &mut String, painted: &str) {
    let _ = writeln!(
        out,
        "{:indent$}{} {painted}",
        "",
        "└─".truecolor(70, 80, 89),
        indent = INDENT
    );
}

/// High-risk behavior that disappeared. It is remediation evidence, not a
/// newly gained finding, so keep it visually and semantically separate.
fn removed_grid(out: &mut String, a: &Analysis<'_>) {
    for (i, group) in a.removed_high_risk_behaviors().iter().enumerate() {
        let cell = section_cell(i, "removed", PILL_TEAL);
        out.push_str(&grid_line(
            &cell,
            &format!("{}    ", sign(Some('−'))),
            &group.namespace.as_str().bold().to_string(),
        ));
        for leaf in &group.traits {
            leaf_line(out, &leaf.truecolor(95, 175, 95).to_string());
        }
    }
}

fn bar(value: f32, severity: Severity) -> String {
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
        paint(severity, &"█".repeat(filled)),
        "░".repeat(BAR - filled).truecolor(70, 80, 89),
    )
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
    let n = a.signature.ids.len();
    let shown = &a.signature.ids[..n.min(MAX)];
    // Description leads — the campaign or intent an analyst triages on —
    // with the rule id as dim provenance after it. The marker says whether
    // the rule newly matched (`+`) or an existing match escalated (`↑`).
    let descs: Vec<String> = shown.iter().map(|m| crate::clip(&m.desc, DESC_W)).collect();
    let descw = descs.iter().map(|d| d.chars().count()).max().unwrap_or(0);
    for (i, m) in shown.iter().enumerate() {
        let cell = section_cell(i, "signature", PILL_HOT);
        let marker = if m.is_new { '+' } else { '↑' };
        let name = crate::rubric::short_name(&m.id);
        let text = if descs[i].is_empty() {
            &name
        } else {
            &descs[i]
        };
        let mut body = pad_visible(text, text, descw);
        if !descs[i].is_empty() {
            body.push_str(&format!(" {}", name.truecolor(102, 117, 127)));
        }
        if i == 0
            && let Some(cve) = &a.signature.cve
        {
            body.push_str(&format!("   {}", paint(Severity::Critical, cve)));
        }
        out.push_str(&grid_line(
            &cell,
            &format!("{}{}", sign(Some(marker)), dots(m.severity)),
            &body,
        ));
    }
    if n > MAX {
        out.push_str(&grid_line(
            &blank_cell(),
            &format!("{}{}", sign(None), dots(Severity::None)),
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
        let cell = section_cell(i, "identity", PILL_SLATE);
        let (old, new) = ch.shown();
        let body = format!(
            "{}: {} {} {}",
            ch.label,
            old,
            "→".truecolor(70, 80, 89),
            new.bold()
        );
        out.push_str(&grid_line(
            &cell,
            &format!("{}{}", sign(Some('~')), dots(a.identity.severity)),
            &body,
        ));
    }
}

/// The evidence section as diff-style hunks under one `evidence` label: each
/// hunk is headed by its top rule (criticality × confidence) and `file:where`,
/// then a short excerpt indented beneath — matched lines bright, context dim,
/// `+` marking lines absent from the old version. A blank line separates
/// hunks so each excerpt reads with its own header.
fn evidence_hunks(hunks: &[&Hunk], diff: &DiffReportV1) -> String {
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
        .map(|h| crate::clip(&h.desc, DESC_W).chars().count())
        .max()
        .unwrap_or(0);
    // A file's own metric movers caption its evidence only in a container
    // diff; for a single file they would restate the metrics section.
    let archive = diff.files.iter().any(|f| f.path.contains("!!"));
    let mut out = String::new();
    let mut i = 0;
    let mut row = 0;
    while i < hunks.len() {
        out.push('\n');
        let cell = section_cell(row, "evidence", PILL_OCEAN);
        row += 1;
        if hunks[i].additions {
            // One header per changed file — a severity bar, the path (directory
            // dim, basename bright), and the file's strongest rule as caption.
            // Its runs follow in source order as plain added-line blocks, a
            // single ellipsis marking each gap; matched lines stay bright so the
            // detected behavior reads at a glance without per-run headings.
            let run = crate::evidence::additions_at(hunks, i);
            let name = run.name;
            let sev = run.severity;
            let cap = run
                .top
                .map(|h| format!("   {}", paint(sev, &crate::clip(&h.desc, DESC_W))))
                .unwrap_or_default();
            let (dir, base) = split_path(name);
            let head = format!(
                "{}{}{cap}",
                dir.truecolor(70, 80, 89),
                base.truecolor(232, 237, 242).bold(),
            );
            out.push_str(&grid_line(
                &cell,
                &format!("{}{}", sign(Some('+')), dots(sev)),
                &head,
            ));
            if archive {
                metrics_caption(&mut out, diff, name);
            }
            for (k, h) in hunks[i..run.end].iter().enumerate() {
                if k > 0 {
                    // The gap marker sits in the locator lane, no rail.
                    let _ = writeln!(
                        out,
                        "{:INDENT$}{}",
                        "",
                        format!("{:>locw$}", "⋯", locw = locw).truecolor(70, 80, 89),
                    );
                }
                push_hunk_lines(&mut out, h, locw);
            }
            i = run.end;
        } else {
            let h = hunks[i];
            let name = h.display_name();
            let desc = crate::clip(&h.desc, DESC_W);
            // A binary hunk's location is its file alone; the byte offset of
            // the top match says where in it.
            let location = if h.binary {
                format!("{name}:{:#x}", h.loc)
            } else {
                h.location.clone()
            };
            let head = format!(
                "{}   {}",
                pad_visible(&paint(h.severity, &desc), &desc, descw),
                location.truecolor(102, 117, 127),
            );
            out.push_str(&grid_line(
                &cell,
                &format!("{}{}", sign(Some('+')), dots(h.severity)),
                &head,
            ));
            if archive && (i == 0 || hunks[i - 1].display_name() != name) {
                metrics_caption(&mut out, diff, name);
            }
            push_hunk_lines(&mut out, h, locw);
            i += 1;
        }
    }
    out
}

/// A file's scalar metric movers (sizes, entropy, ratios — the ones that don't
/// sum across files), captioned under its evidence header and wrapped so the
/// list never runs off the pane.
fn metrics_caption(out: &mut String, diff: &DiffReportV1, name: &str) {
    const LEAD: &str = "metrics  ";
    let Some(items) = file_metrics_summary(diff, name) else {
        return;
    };
    for (k, line) in wrap_items(&items, PROSE_W - LEAD.len())
        .into_iter()
        .enumerate()
    {
        let lead = if k == 0 { LEAD } else { "         " };
        let _ = writeln!(
            out,
            "{:INDENT$}{}{}",
            "",
            lead.truecolor(102, 117, 127),
            line.truecolor(102, 117, 127)
        );
    }
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

/// Push a hunk's code rows: `locator + code`, the `+` gutter marking the
/// lines absent from the old version against dim context. A binary hunk has
/// no context — every byte shown is new, which its header's sign already
/// says — so its rows carry no gutter. Matched lines bright, long lines
/// wrapped across bare continuation rows.
fn push_hunk_lines(out: &mut String, h: &Hunk, locw: usize) {
    for l in &h.lines {
        let gutter = match l.added {
            _ if h.binary => " ".to_string(),
            Some(true) => " +".truecolor(95, 175, 95).to_string(),
            _ => "  ".to_string(),
        };
        let gutter_w = if h.binary { 1 } else { 2 };
        let paint_code = |s: &str| {
            if l.is_match {
                s.truecolor(205, 214, 221).to_string()
            } else {
                s.truecolor(102, 117, 127).to_string()
            }
        };
        for (i, row_text) in wrap_code(&l.text).into_iter().enumerate() {
            let row = if i == 0 {
                let loc = format!("{:>locw$}", l.locator, locw = locw);
                format!(
                    "{:INDENT$}{}{gutter} {}",
                    "",
                    loc.truecolor(70, 80, 89),
                    paint_code(&row_text)
                )
            } else {
                format!(
                    "{:INDENT$}{} {}",
                    "",
                    " ".repeat(locw + gutter_w),
                    paint_code(&row_text)
                )
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

/// Split code into display rows of at most [`CODE_COLS`] chars.
fn wrap_code(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= CODE_COLS {
        return vec![s.to_string()];
    }
    chars
        .chunks(CODE_COLS)
        .map(|c| c.iter().collect())
        .collect()
}

// ── grid + pill primitives ───────────────────────────────────────────────

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
        let cell = section_cell(i, "observed", PILL_SLATE);
        out.push_str(&grid_line(
            &cell,
            &format!("{}{}", sign(None), dots(Severity::None)),
            &crate::printable(label).truecolor(150, 160, 168).to_string(),
        ));
    }
    if extra > 0 {
        out.push_str(&grid_line(
            &blank_cell(),
            &format!("{}{}", sign(None), dots(Severity::None)),
            &format!("+{extra} more")
                .truecolor(102, 117, 127)
                .to_string(),
        ));
    }
    out
}

/// The `dependencies` section: one row per added dependency — severity dots,
/// its coordinate, and what it does, drilled from the fetched dependency's own
/// analysis. A dependency that couldn't be fetched shows its reason, never a
/// blank clean line.
fn dependencies_section(deps: &[crate::deps::DepProfile]) -> String {
    let mut out = String::new();
    let indent = " ".repeat(PILL_COL + NAME_W + 4);
    for (i, d) in deps.iter().enumerate() {
        let cell = section_cell(i, "deps", PILL_PLUM);
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
            &format!("{}{}", sign(None), dots(d.severity)),
            &format!("{name} {tail}"),
        ));
        let _ = writeln!(
            out,
            "{indent}{} (new: {})",
            d.comparison,
            d.new_severity.as_str()
        );
        if let Some(baseline) = &d.baseline {
            let _ = writeln!(out, "{indent}baseline: {}", crate::printable(baseline));
        }
        for h in &d.highlights {
            let _ = writeln!(out, "{indent}{}", paint(d.severity, h));
        }
    }
    out
}

/// One grid row: ` {label}{marker}{body}`. `marker` is the change sign
/// ([`sign`]) followed by a 4-wide severity glyph (`●●● `) for the rows that
/// carry them, and empty for the plain label rows — so a marker, when present,
/// lands in the content column and its body sits just past it.
fn grid_line(cell: &str, marker: &str, body: &str) -> String {
    format!(" {cell}{marker}{body}\n")
}

/// The 2-wide change-sign cell that opens a finding row, so what *happened*
/// reads before how bad it is: green `+` for something newly present, `−` for
/// something gone (green: it is remediation), grey `~` for existing structure
/// altered in place, amber `↑` for something that was there and grew. `None`
/// keeps the column for rows that carry no change.
fn sign(s: Option<char>) -> String {
    match s {
        Some('+') | Some('−') => format!(
            "{} ",
            s.unwrap_or_default().to_string().truecolor(95, 175, 95)
        ),
        Some('↑') => format!("{} ", "↑".truecolor(255, 176, 46)),
        Some(c) => format!("{} ", c.to_string().truecolor(120, 134, 144)),
        None => "  ".to_string(),
    }
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

/// The label cell for row `i` of a section: the pill on the first row, blank on
/// every row after it, so a multi-row section reads as one block under one
/// heading rather than as a heading repeated down the page.
fn section_cell(i: usize, label: &str, color: (u8, u8, u8)) -> String {
    if i == 0 {
        pill_cell(label, color)
    } else {
        blank_cell()
    }
}

/// Right-pad `painted` (carrying ANSI) to `width` visible columns.
fn pad_visible(painted: &str, plain: &str, width: usize) -> String {
    let vis = plain.chars().count();
    format!("{painted}{}", " ".repeat(width.saturating_sub(vis)))
}

// ── metrics ──────────────────────────────────────────────────────────────

/// Aggregate count deltas across the changed files as `(old, new, label, note)`
/// — only the *count* scopes (symbols, sections, strings), which sum honestly
/// regardless of file type; the scalar per-file metrics (sizes, entropy, ratios)
/// ride each evidence header, where they keep their meaning. Pure data, shared
/// by the terminal and the markdown report. Empty when nothing counted moved.
pub(crate) fn stats_data(diff: &DiffReportV1) -> Vec<(i64, i64, &'static str, String)> {
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
    let mut raw: Vec<(i64, i64, &'static str, String)> = Vec::new();
    if sym_o != sym_n || !added_syms.is_empty() {
        raw.push((sym_o, sym_n, "symbols", names_note(&added_syms)));
    }
    if sec_o != sec_n || !added_secs.is_empty() {
        raw.push((sec_o, sec_n, "sections", names_note(&added_secs)));
    }
    if str_o != str_n {
        raw.push((str_o, str_n, "strings", String::new()));
    }
    raw
}

/// The stats section rows for the terminal — [`stats_data`] formatted with old
/// and new right-aligned so every `→` stacks.
fn stats_rows(diff: &DiffReportV1) -> Vec<String> {
    let raw = stats_data(diff);
    if raw.is_empty() {
        return Vec::new();
    }
    let w = raw
        .iter()
        .map(|(o, n, ..)| o.to_string().len().max(n.to_string().len()))
        .max()
        .unwrap_or(1);
    raw.into_iter()
        .flat_map(|(o, n, label, note)| {
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
            // The gained names ride the row when short; a long list, wrapped,
            // sits beneath it so the count column stays aligned.
            let counted = 2 * w + 20 + 2 + note.chars().count();
            if !note.is_empty() && counted <= PROSE_W {
                let _ = write!(body, "  {}", note.truecolor(120, 134, 144));
                vec![body]
            } else {
                std::iter::once(body)
                    .chain(
                        wrap_words(&note, PROSE_W)
                            .into_iter()
                            .map(|line| format!("   {}", line.truecolor(120, 134, 144))),
                    )
                    .collect()
            }
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
        .find(|f| {
            let raw = f.path.rsplit_once("!!").map_or(f.path.as_str(), |(_, m)| m);
            crate::printable(raw) == member
        })
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
            crate::analysis::metric_move(c, None, label.to_string())
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

// Section-label accents. These are drawn as *text*, so they must read on a
// black terminal as well as a white one: mid-brightness tints, each distinct
// from the severity palette (coral, gold, azure, green) so a label never
// reads as a verdict.
const PILL_PLUM: (u8, u8, u8) = (177, 137, 224);
const PILL_HOT: (u8, u8, u8) = (224, 108, 117);
const PILL_TEAL: (u8, u8, u8) = (78, 201, 176);
const PILL_OCEAN: (u8, u8, u8) = (86, 182, 194);
const PILL_SLATE: (u8, u8, u8) = (160, 170, 180);

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
        Severity::Critical => "●●● ",
        Severity::High => "●●  ",
        Severity::Medium | Severity::Low => "●   ",
        Severity::None => "·   ",
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

#[cfg(test)]
mod tests {
    use super::file_metrics_summary;
    use cleave::types::{
        Changed, DiffReportV1, FileDiffEntry, FileStatus, MetricChange, ScopeDiff, ScopeDiffs,
    };

    #[test]
    fn risk_row_uses_calibrated_classification_not_probability_label() {
        for classification in [
            scan::Classification::Benign,
            scan::Classification::Suspicious,
            scan::Classification::Hostile,
        ] {
            let row = super::risk_row(crate::risk::Risk {
                old: 0.8005945,
                new: 0.90685314,
                new_classification: classification,
            });
            assert!(row.contains(&classification.to_string()));
            assert!(!row.contains("malware"));
        }
    }

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
                path: "sample".to_string(),
                file_type: Some("elf".to_string()),
                status: FileStatus::Changed,
                identity: None,
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
                old_formula: None,
                new_formula: None,
            }],
        };

        let summary = file_metrics_summary(&diff, "sample").unwrap();
        assert_eq!(summary.len(), 6);
        assert!(summary[0].starts_with("largest "));
        assert!(summary[5].starts_with("sixth "));
        assert!(!summary.iter().any(|s| s.starts_with("seventh ")));
        assert!(!summary.iter().any(|s| s.starts_with("smallest ")));
    }
}
