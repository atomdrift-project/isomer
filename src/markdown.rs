//! `--format markdown` — the pull-request comment body.
//!
//! The reader is a reviewer looking at a diff, not an analyst at a terminal, so
//! the body answers their questions in the order they ask them: is this bad,
//! why, what can the code now do that it couldn't, show me, and how do I make
//! this go away if it's wrong. The last one matters most — a security tool with
//! no cheap suppression path gets switched off — so the report writes the
//! `.isomer.toml` stanza for the reader to paste.
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
    // of the detail behind it.
    let _ = writeln!(s, "> {}", a.judgement());
    let _ = writeln!(s);
    risk(&mut s, a);
    behavioral(&mut s, a);
    signatures(&mut s, a);
    identity(&mut s, a);
    structure(&mut s, a);
    // A change that passes the gate is named, not dissected: metrics, evidence,
    // and a paste-ready suppression are for a reviewer who has to act.
    if a.detailed(cli) {
        metrics(&mut s, a);
        evidence(&mut s, a);
        suppression(&mut s, a);
    }
    let _ = write!(s, "{}", suppressed(a));
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
        parts.push(format!("`{}`", a.naming.name));
    }
    if let (Some(o), Some(n)) = (&a.naming.old, &a.naming.new) {
        parts.push(format!("{} → {}", o.raw, n.raw));
        if let Some(b) = a.naming.bump {
            parts.push(b.describe());
        }
    }
    parts.extend(crate::terminal::change_scale(a.diff));
    parts.join(" · ")
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
        "No newly-introduced capabilities, known-bad signatures, or publisher drift{scope}.\n{}\n{}",
        suppressed(a),
        footer(a, cli)
    )
}

/// What policy withheld, named. A reviewer must be able to tell a clean run
/// from a silenced one without opening `.isomer.toml`.
fn suppressed(a: &Analysis<'_>) -> String {
    let items = &a.assessment.suppressed;
    if items.is_empty() {
        return String::new();
    }
    let list: String = items
        .iter()
        .map(|s| {
            format!(
                "<li><code>{}</code> — {}</li>",
                cell(&s.id),
                cell(&s.describe())
            )
        })
        .collect();
    format!(
        "\n<details>\n<summary>{} finding{} suppressed by <code>{}</code></summary>\n<ul>{list}</ul>\n</details>\n",
        items.len(),
        if items.len() == 1 { "" } else { "s" },
        cell(a.policy_source()),
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
            "| {} | `{}` | {} |",
            dots(m.severity),
            cell(&crate::rubric::short_name(&m.id)),
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
            Some(m) => format!("`{}` → `{m}`", h.file),
            None => format!("`{}`", h.location),
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

/// The paste-ready suppression stanza. A false positive must cost one
/// reviewable line of config, so the report writes the line.
fn suppression(s: &mut String, a: &Analysis<'_>) {
    let mut ids: Vec<&str> = Vec::new();
    for c in &a.assessment.behavioral.categories {
        ids.extend(c.new_ids.iter().map(String::as_str));
    }
    ids.extend(a.assessment.signature.ids.iter().map(|m| m.id.as_str()));
    ids.truncate(3);
    if ids.is_empty() {
        return;
    }
    let stanzas: String = ids
        .iter()
        .map(|id| format!("[[allow]]\nid = \"{id}\"\nreason = \"\"   # required\n"))
        .collect::<Vec<_>>()
        .join("\n");
    let _ = writeln!(
        s,
        "<details>\n<summary>False positive? Suppress it in <code>.isomer.toml</code></summary>\n\n\
         {}\n\
         An `expires = \"YYYY-MM-DD\"` field is optional; an empty `reason` is rejected, \
         so the next reader learns why.\n</details>",
        fence_lang(&stanzas, "toml"),
    );
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

/// Make a value safe inside a table cell: pipes would end the column, and
/// newlines would end the row.
fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

fn code_list(items: &[String]) -> String {
    items
        .iter()
        .map(|i| format!("`{}`", cell(i)))
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

    #[test]
    fn truncation_respects_char_boundaries() {
        let s = "aé";
        // Byte 2 splits the 'é'; the floor must step back to 1.
        assert_eq!(floor_char_boundary(s, 2), 1);
        assert!(s.is_char_boundary(floor_char_boundary(s, 2)));
    }
}
