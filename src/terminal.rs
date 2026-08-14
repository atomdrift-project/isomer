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
    // Aggregate counts that sum honestly across file types (symbols, sections,
    // strings); scalar per-file metrics ride each evidence header instead.
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
    for (i, (label, body)) in rows.into_iter().enumerate() {
        let name = if label == previous {
            String::new()
        } else {
            label.bold().to_string()
        };
        previous = label;
        out.push_str(&grid_line(
            &section_cell(i, "diff", PILL_TEAL),
            "",
            &format!("{name}  {}", body.truecolor(190, 201, 209)),
        ));
    }
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
            let cell = section_cell(i, label, PILL_OCEAN);
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
        let cell = section_cell(i, "structure", PILL_SLATE);
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

/// The ML detector on one line: `old → new` on a benign→malware bar, the band
/// word, and the jump.
fn risk_row(r: Risk) -> String {
    let d = r.delta();
    let band = crate::analysis::risk_band(r.new);
    let (arrow, dsev) = if d > 0.005 {
        ("▲", band)
    } else if d < -0.005 {
        ("▼", Severity::None)
    } else {
        ("·", Severity::None)
    };
    // The band word carries its own severity color, except a benign read, which
    // stays dim rather than claiming the green a clean verdict owns.
    let word = if band == Severity::None {
        risk_label(r.new).truecolor(102, 117, 127).to_string()
    } else {
        paint(band, risk_label(r.new))
    };
    let body = format!(
        "{} {} {}  {}  {}   {}",
        format!("{:.2}", r.old).truecolor(140, 150, 158),
        "→".truecolor(102, 117, 127),
        paint(band, &format!("{:.2}", r.new)).bold(),
        bar(r.new),
        word,
        paint(dsev, &format!("{arrow} {d:+.2}")),
    );
    grid_line(&pill_cell("risk", PILL_OCEAN), "", &body)
}

/// The gained capability classes as a tree: a marker per class — green `+` for
/// one the old version lacked, amber `↑` for an existing class that grew — then
/// its newly-gained traits as `└─` leaves. Replaces the old new/expanded split
/// so both directions read in one section, hierarchy explicit.
fn gained_grid(out: &mut String, a: &Assessment) {
    const MAX_TRAITS: usize = 24;
    // Group categories by namespace so a namespace shows once with all its
    // gained traits beneath it — xz's three `binary/linking/runtime` traits are
    // one class, not three. A group is `new` (green `+`) only when every trait
    // in it is; a mix means the class already existed and grew (amber `↑`).
    let mut ranked: Vec<(f32, String, bool, String, String)> = Vec::new();
    for c in &a.behavioral.categories {
        let ns = if c.namespaces.is_empty() {
            c.label.clone()
        } else {
            c.namespaces.join(" · ")
        };
        ranked.extend(c.new_ids.iter().map(|id| {
            (
                c.trait_scores.get(id).copied().unwrap_or_default(),
                ns.clone(),
                a.behavioral.is_new_category(c),
                id.rsplit("::").next().unwrap_or(id).to_string(),
                id.clone(),
            )
        }));
        ranked.extend(c.escalated_ids.iter().map(|id| {
            (
                c.trait_scores.get(id).copied().unwrap_or_default(),
                ns.clone(),
                false,
                id.rsplit("::").next().unwrap_or(id).to_string(),
                id.clone(),
            )
        }));
    }
    ranked.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.4.cmp(&b.4)));
    let overflow = ranked.len().saturating_sub(MAX_TRAITS);
    ranked.truncate(MAX_TRAITS);

    let mut groups: Vec<(String, bool, Vec<String>)> = Vec::new();
    for (_, ns, new, leaf, _) in ranked {
        if let Some(g) = groups.iter_mut().find(|(n, ..)| *n == ns) {
            g.1 = g.1 && new;
            g.2.push(leaf);
        } else {
            groups.push((ns, new, vec![leaf]));
        }
    }
    for (i, (ns, all_new, leaves)) in groups.iter().enumerate() {
        let cell = section_cell(i, "gained", PILL_PLUM);
        let marker = if *all_new {
            "+".truecolor(95, 175, 95)
        } else {
            "↑".truecolor(255, 176, 46)
        };
        out.push_str(&grid_line(
            &cell,
            &format!("{marker}  "),
            &ns.as_str().bold().to_string(),
        ));
        for leaf in leaves {
            leaf_line(out, &leaf.truecolor(76, 178, 255).to_string());
        }
    }
    if overflow > 0 {
        leaf_line(
            out,
            &format!("+{overflow} more lower-scoring traits")
                .truecolor(102, 117, 127)
                .to_string(),
        );
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
        indent = PILL_COL + 4
    );
}

/// High-risk behavior that disappeared. It is remediation evidence, not a
/// newly gained finding, so keep it visually and semantically separate.
fn removed_grid(out: &mut String, a: &Analysis<'_>) {
    for (i, group) in a.removed_high_risk_behaviors().iter().enumerate() {
        let cell = section_cell(i, "removed", PILL_TEAL);
        out.push_str(&grid_line(
            &cell,
            &format!("{}  ", "−".truecolor(95, 175, 95)),
            &group.namespace.as_str().bold().to_string(),
        ));
        for leaf in &group.traits {
            leaf_line(out, &leaf.truecolor(95, 175, 95).to_string());
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
        let cell = section_cell(i, "identity", PILL_SLATE);
        let (old, new) = ch.shown();
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
    let mut out = String::new();
    let mut i = 0;
    while i < hunks.len() {
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
            for (k, h) in hunks[i..run.end].iter().enumerate() {
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
            i = run.end;
        } else {
            let name = hunks[i].display_name();
            let desc = crate::clip(&hunks[i].desc, DESC_W);
            let _ = write!(
                out,
                "\n   {} {}   {}\n",
                dots(hunks[i].severity),
                pad_visible(&paint(hunks[i].severity, &desc), &desc, descw),
                hunks[i].location.truecolor(102, 117, 127),
            );
            // The first hunk of a (binary) file carries its scalar metrics.
            if (i == 0 || hunks[i - 1].display_name() != name)
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
        for (i, row_text) in wrap_code(&l.text).into_iter().enumerate() {
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

/// Split code into display rows of at most [`crate::evidence::CODE_W`] chars.
fn wrap_code(s: &str) -> Vec<String> {
    const W: usize = crate::evidence::CODE_W;
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= W {
        return vec![s.to_string()];
    }
    chars.chunks(W).map(|c| c.iter().collect()).collect()
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
pub(crate) fn file_metrics_summary(diff: &DiffReportV1, member: &str) -> Option<String> {
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
        // Name the metric by its leaf, with the few cryptic ones spelled out.
        let label = match p.rsplit(['.', '/']).next().unwrap_or(p) {
            "code_size" => "code",
            "size" | "size_bytes" => "size",
            "init_array_count" => "init_array",
            "dynrela_count" | "relacount" => "relocs",
            other => other,
        };
        let importance = crate::analysis::metric_change_importance(o, n);
        let delta = if o != 0.0 {
            format!("{:+.0}%", (n - o) / o * 100.0)
        } else {
            "new".to_string()
        };
        movers.push((
            importance,
            label.to_string(),
            format!(
                "{}→{} ({delta})",
                crate::analysis::compact_metric_number(o),
                crate::analysis::compact_metric_number(n)
            ),
        ));
    }
    // `total_cmp`, not `partial_cmp(…).unwrap_or(Equal)`: the latter is not a
    // total order when a metric ratio is NaN, and `sort_by` is permitted to
    // panic on an inconsistent comparator.
    movers.sort_by(|a, b| b.0.total_cmp(&a.0));
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

#[cfg(test)]
mod tests {
    use super::file_metrics_summary;
    use cleave::types::{
        Changed, DiffReportV1, FileDiffEntry, FileStatus, MetricChange, ScopeDiff, ScopeDiffs,
    };

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
        assert!(summary.starts_with("largest "));
        assert!(summary.contains("sixth "));
        assert!(!summary.contains("seventh "));
        assert!(!summary.contains("smallest "));
        assert_eq!(summary.matches(" · ").count(), 5);
    }
}
