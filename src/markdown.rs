//! `--format markdown` — the pull-request comment body.
//!
//! The reader is a reviewer looking at a diff, not an analyst at a terminal, so
//! the body answers their questions in the order they ask them: is this bad,
//! why, what can the code now do that it couldn't, show me, and how do I make
//! this go away if it's wrong.
//!
//! The body carries a hidden [`MARKER`] so the action can find its own comment
//! and edit it in place; every push updates one comment instead of spamming the
//! thread.

use std::fmt::Write as _;

use crate::analysis::Analysis;
use crate::{Cli, Severity};

/// Hidden HTML comment identifying an isomer report, so the posting step can
/// find the comment it wrote last time. Part of the action's contract — do not
/// change it without a matching action release.
pub(crate) const MARKER: &str = "<!-- isomer-report -->";

/// GitHub rejects comment bodies over 65536 characters. Stay clear of the
/// ceiling and say so when the evidence is trimmed to fit.
const MAX_BODY: usize = 60_000;

/// Evidence hunks in the comment. Fewer than the JSON record: a reviewer wants
/// the smoking gun, not the archive.
const MAX_HUNKS: usize = 6;

/// Render the report body.
pub(crate) fn report(a: &Analysis<'_>, cli: &Cli) -> String {
    let mut s = String::with_capacity(4096);
    let _ = writeln!(s, "{MARKER}");
    let _ = writeln!(s, "### {}", heading(a));
    let _ = writeln!(s);

    if !a.speaks(cli) {
        // Nothing to say — but the comment may already exist from an earlier,
        // worse push, so it has to say *that* rather than going blank.
        let _ = writeln!(s, "{}", clean_body(a, cli));
        return s;
    }

    // The judgement first, always: what isomer makes of the change, before any
    // of the detail behind it. Escaped like any other untrusted line — it may
    // carry a rule description, or the LLM's phrasing of a diff that tried to
    // talk to it.
    let _ = writeln!(s, "> {}", cell(&a.judgement()));
    let _ = writeln!(s);
    risk(&mut s, a);
    behavioral(&mut s, a);
    signatures(&mut s, a);
    identity(&mut s, a);
    structure(&mut s, a);
    frameworks(&mut s, a);
    // A change that passes the gate is named, not dissected: metrics and
    // evidence are for a reviewer who has to act.
    if a.detailed(cli) {
        metrics(&mut s, a);
        evidence(&mut s, a);
    }
    let _ = write!(s, "\n---\n{}\n", footer(a, cli));

    if s.len() > MAX_BODY {
        s.truncate(floor_char_boundary(&s, MAX_BODY));
        let _ = write!(
            s,
            "\n\n_Report truncated to fit GitHub's comment limit. \
             The full record is in the job's SARIF upload and step summary._\n"
        );
    }
    s
}

/// `🔴 HOSTILE · node-ipc · 12.0.0 → 12.0.1 · patch release · 3 of 14 files`.
fn heading(a: &Analysis<'_>) -> String {
    let mut parts = vec![format!(
        "{} {}",
        emoji(a.verdict),
        crate::terminal::verdict_word(a.verdict)
    )];
    if !a.naming.name.is_empty() {
        parts.push(code(&a.naming.name));
    }
    if let (Some(o), Some(n)) = (&a.naming.old, &a.naming.new) {
        parts.push(format!("{} → {}", cell(&o.raw), cell(&n.raw)));
        if let Some(b) = a.naming.bump {
            parts.push(b.describe());
        }
    }
    if let Some(scope) = a.scope {
        parts.push(scope.label().to_string());
    }
    parts.extend(crate::terminal::change_scale(a.diff));
    parts.join(" · ")
}

/// The whole report for a run with nothing to say, in one line.
///
/// The step summary is a page a reviewer opens on purpose, and most of the time
/// the honest content is "nothing changed behaviourally". Spending a screen on
/// that teaches people to stop opening it, and the day it matters they will not
/// look. So: the heading, which already carries the verdict, what was covered,
/// and how big the change was — and nothing else.
pub(crate) fn one_line(a: &Analysis<'_>) -> String {
    format!("### {}\n", heading(a))
}

/// The body for a change isomer has nothing to say about. Kept short and
/// affirmative: this is the state a reviewer should see most of the time.
fn clean_body(a: &Analysis<'_>, cli: &Cli) -> String {
    let scale = crate::terminal::change_scale(a.diff);
    let scope = if scale.is_empty() {
        String::new()
    } else {
        format!(" across {}", scale.join(", "))
    };
    format!(
        "No newly-introduced capabilities, known-bad signatures, or publisher drift{scope}.\n{}",
        footer(a, cli)
    )
}

fn footer(a: &Analysis<'_>, cli: &Cli) -> String {
    let gate = if a.clean {
        format!("passes `--fail-on {}`", cli.fail_on.as_str())
    } else {
        format!(
            "**fails `--fail-on {}`** — gated severity `{}`",
            cli.fail_on.as_str(),
            a.gated.as_str()
        )
    };
    format!(
        "<sub>isomer {} · gate `{}` · {gate}</sub>",
        env!("CARGO_PKG_VERSION"),
        match cli.gate {
            crate::Gate::New => "new",
            crate::Gate::Any => "any",
        },
    )
}

fn risk(s: &mut String, a: &Analysis<'_>) {
    // Shown when the model changed its mind, or whenever the full report is
    // being written. An unchanged band on a passing change is not news.
    let Some(r) = a.risk.filter(|_| a.risk_band_moved() || !a.clean) else {
        return;
    };
    let d = r.delta();
    let arrow = if d > 0.005 {
        format!(" ▲ {d:+.2}")
    } else if d < -0.005 {
        format!(" ▼ {d:+.2}")
    } else {
        String::new()
    };
    let _ = writeln!(
        s,
        "**ML malware risk** `{:.2}` {} → `{:.2}` {}{arrow}\n",
        r.old,
        crate::terminal::risk_label(r.old),
        r.new,
        crate::terminal::risk_label(r.new),
    );
}

fn behavioral(s: &mut String, a: &Analysis<'_>) {
    let cats = &a.assessment.behavioral.categories;
    if cats.is_empty() {
        return;
    }
    let _ = writeln!(s, "#### Capabilities\n");
    let _ = writeln!(s, "| | capability | namespace | traits |");
    let _ = writeln!(s, "|---|---|---|---|");
    for c in cats {
        let fresh = a.assessment.behavioral.is_new_category(c);
        let count = match (fresh, c.new_ids.len(), c.escalated_ids.len()) {
            (_, 0, e) => format!("{e} escalated"),
            (true, n, _) => format!("{n} new"),
            (false, n, _) => format!("+{n}"),
        };
        let _ = writeln!(
            s,
            "| {} **{}** | {} | {} | {count} |",
            dots(c.severity),
            if fresh { "new" } else { "expanded" },
            cell(&c.label),
            code_list(&c.namespaces),
        );
    }
    let _ = writeln!(s);
}

fn signatures(s: &mut String, a: &Analysis<'_>) {
    let sig = &a.assessment.signature;
    if sig.ids.is_empty() {
        return;
    }
    let cve = sig
        .cve
        .as_ref()
        .map(|c| format!(" · {c}"))
        .unwrap_or_default();
    let _ = writeln!(s, "#### Known-bad signatures{cve}\n");
    let _ = writeln!(s, "| | rule | detects |");
    let _ = writeln!(s, "|---|---|---|");
    for m in sig.ids.iter().take(10) {
        let _ = writeln!(
            s,
            "| {} | {} | {} |",
            dots(m.severity),
            code(&crate::rubric::short_name(&m.id)),
            cell(&m.desc),
        );
    }
    if sig.ids.len() > 10 {
        let _ = writeln!(s, "| | _+{} more_ | |", sig.ids.len() - 10);
    }
    let _ = writeln!(s);
}

fn identity(s: &mut String, a: &Analysis<'_>) {
    let changes = &a.assessment.identity.changes;
    if changes.is_empty() {
        return;
    }
    let _ = writeln!(s, "#### Publisher\n");
    for ch in changes {
        let old = if ch.old.is_empty() { "none" } else { &ch.old };
        let new = if ch.new.is_empty() { "none" } else { &ch.new };
        let _ = writeln!(s, "- **{}**: {} → {}", ch.label, cell(old), cell(new));
    }
    let _ = writeln!(s);
}

fn structure(s: &mut String, a: &Analysis<'_>) {
    let facts = &a.assessment.structure.facts;
    if facts.is_empty() {
        return;
    }
    let _ = writeln!(s, "#### Structure\n");
    for f in facts {
        let kind = match f.kind {
            crate::rubric::FactKind::Added => "new",
            crate::rubric::FactKind::Became => "became",
        };
        let _ = writeln!(
            s,
            "- {} {kind} **{}** — {}",
            dots(f.severity),
            f.label,
            cell(&f.detail)
        );
    }
    let _ = writeln!(s);
}

/// ATT&CK and MBC ids the change moved. Shown as ids: isomer has no catalog
/// mapping them to prose and will not invent one.
fn frameworks(s: &mut String, a: &Analysis<'_>) {
    let rows: Vec<(&str, &crate::evidence::Sides)> =
        [("ATT&CK", &a.survey.attack), ("MBC", &a.survey.mbc)]
            .into_iter()
            .filter(|(_, sides)| sides.changed())
            .collect();
    if rows.is_empty() {
        return;
    }
    let _ = writeln!(s, "#### Technique coverage\n");
    let _ = writeln!(s, "| | introduced | no longer present | unchanged |");
    let _ = writeln!(s, "|---|---|---|---|");
    for (label, sides) in rows {
        let list = |ids: Vec<&str>| {
            if ids.is_empty() {
                "—".to_string()
            } else {
                ids.iter()
                    .map(|i| format!("`{}`", cell(i)))
                    .collect::<Vec<_>>()
                    .join(" ")
            }
        };
        let _ = writeln!(
            s,
            "| **{label}** | {} | {} | {} |",
            list(sides.gained()),
            list(sides.lost()),
            sides.kept(),
        );
    }
    let _ = writeln!(s);
}

fn metrics(s: &mut String, a: &Analysis<'_>) {
    let m = crate::terminal::metrics(a.diff);
    if m.is_empty() {
        return;
    }
    let joined = m
        .iter()
        .map(|(label, value, _)| format!("{label} {value}"))
        .collect::<Vec<_>>()
        .join(" · ");
    let _ = writeln!(s, "**Metrics** {joined}\n");
}

fn evidence(s: &mut String, a: &Analysis<'_>) {
    let hunks = a.hunks(MAX_HUNKS);
    if hunks.is_empty() {
        return;
    }
    let _ = writeln!(s, "#### Evidence\n");
    let _ = writeln!(
        s,
        "<sub>{}</sub>\n",
        crate::terminal::evidence_note_text(&hunks)
    );
    for h in &hunks {
        let where_ = match &h.member {
            Some(m) => format!("{} → {}", code(&h.file), code(m)),
            None => code(&h.location),
        };
        let _ = writeln!(s, "{} {} — {}\n", dots(h.severity), where_, cell(&h.desc));
        let body: String = h
            .lines
            .iter()
            .map(|l| {
                let gutter = if l.added == Some(true) { "+" } else { " " };
                format!("{gutter} {:>6}  {}\n", l.locator, l.text)
            })
            .collect();
        let _ = writeln!(s, "{}", fence(&body));
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn emoji(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium | Severity::Low => "🔵",
        Severity::None => "✅",
    }
}

fn dots(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "●●●",
        Severity::High => "●●",
        Severity::Medium | Severity::Low => "●",
        Severity::None => "·",
    }
}

/// Make a value safe as markdown *prose* — a table cell, a list item, or text
/// sitting beside the raw HTML this report emits.
///
/// Pipes would end a column and newlines a row. `<` and `&` matter just as
/// much: GitHub renders a comment body as rich text, so an artifact whose
/// author field or suppression reason carries `<img>`/`<details>` can forge a
/// banner, hide the real verdict behind a collapsed block, or beacon the
/// reviewer's IP. Everything reaching a comment is attacker-controlled — a
/// fork's pull request supplies both the artifact *and* `.isomer.toml`.
fn cell(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

/// An inline code span whose delimiter outgrows any backtick run inside it, so
/// attacker-controlled text — an archive member name, a rule id, a path from a
/// fork's pull request — cannot close the span and inject markup after it. The
/// inline twin of [`fence_lang`], and the reason nothing here interpolates into
/// a bare `` `…` ``.
///
/// A span's content is literal, so only the table-breaking characters need
/// escaping; GFM honors `\|` inside a code span.
fn code(s: &str) -> String {
    let text = s.replace('|', "\\|").replace(['\n', '\r'], " ");
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let ticks = "`".repeat(longest + 1);
    // CommonMark strips one leading and trailing space inside a span, so pad
    // content that itself starts or ends with a backtick.
    let pad = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{ticks}{pad}{text}{pad}{ticks}")
}

fn code_list(items: &[String]) -> String {
    items
        .iter()
        .map(|i| code(i))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// A fenced block whose fence is longer than any backtick run inside it, so
/// attacker-controlled evidence cannot break out of the fence and inject
/// markup into the comment.
fn fence(body: &str) -> String {
    fence_lang(body, "")
}

fn fence_lang(body: &str, lang: &str) -> String {
    let longest = body.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let ticks = "`".repeat(longest.max(2) + 1);
    format!("{ticks}{lang}\n{}\n{ticks}\n", body.trim_end())
}

/// Largest index ≤ `max` that lands on a `char` boundary, so truncation never
/// splits a multi-byte character.
fn floor_char_boundary(s: &str, max: usize) -> usize {
    let mut i = max.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Evidence is attacker-controlled: a payload containing a fence must not
    /// be able to close ours and inject markup into the PR comment.
    #[test]
    fn fence_outgrows_backticks_in_body() {
        let hostile = "before\n```\n### injected heading\n```\nafter";
        let block = fence(hostile);
        assert!(
            block.starts_with("````\n"),
            "fence must outgrow the body: {block}"
        );
        assert!(block.trim_end().ends_with("\n````"));
    }

    #[test]
    fn table_cells_escape_pipes_and_newlines() {
        assert_eq!(cell("a|b"), "a\\|b");
        assert_eq!(cell("a\nb"), "a b");
    }

    /// The inline half of the fence problem: a member name or path out of a
    /// hostile archive must not close the span and inject markup after it.
    #[test]
    fn code_span_outgrows_backticks() {
        assert_eq!(code("plain"), "`plain`");
        let span = code("a`b</code><img src=x onerror=alert(1)>");
        assert!(span.starts_with("``") && span.ends_with("``"), "{span}");
        // No backtick run inside can reach the delimiter's length.
        assert!(!span.contains("```"), "{span}");
        // Content that itself begins and ends with a backtick survives intact.
        assert!(code("`x`").contains("`x`"));
    }

    /// A comment body is rich text, and a fork's pull request supplies both the
    /// artifact and `.isomer.toml` — raw HTML must not survive into it.
    #[test]
    fn cells_neutralize_html() {
        assert_eq!(
            cell("<img src=x onerror=alert(1)>"),
            "&lt;img src=x onerror=alert(1)>"
        );
        assert_eq!(cell("a & b"), "a &amp; b");
        // Ampersand first, so an escaped entity is not re-encoded into a live one.
        assert_eq!(cell("&lt;script>"), "&amp;lt;script>");
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let s = "aé";
        // Byte 2 splits the 'é'; the floor must step back to 1.
        assert_eq!(floor_char_boundary(s, 2), 1);
        assert!(s.is_char_boundary(floor_char_boundary(s, 2)));
    }
}
