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

use crate::Severity;
use crate::analysis::Analysis;
use crate::evidence::{Group, LineMark};

/// Hidden HTML comment identifying an isomer report, so the posting step can
/// find the comment it wrote last time. Part of the action's contract — do not
/// change it without a matching action release.
pub(crate) const MARKER: &str = "<!-- isomer-report -->";

/// GitHub rejects comment bodies over 65536 characters. Stay clear of the
/// ceiling and say so when the evidence is trimmed to fit.
const MAX_BODY: usize = 60_000;

/// Evidence hunks in the comment. Fewer than the JSON record: a reviewer wants
/// the smoking gun, not the archive.
const COMMENT_HUNKS: usize = 6;

/// Known-bad rules listed before the rest are summarized as a count.
const MAX_SIGNATURES: usize = 10;

/// The note appended where the body was cut to fit [`MAX_BODY`].
const TRUNCATED: &str = "\n_Report truncated to fit GitHub's comment limit. \
                         The full record is in the job's SARIF upload and step summary._\n";

/// Render the report body.
pub(crate) fn report(a: &Analysis<'_>) -> Result<String, std::fmt::Error> {
    let mut s = String::with_capacity(4096);
    writeln!(s, "{MARKER}")?;
    writeln!(s, "### {}", heading(a))?;
    writeln!(s)?;

    if !a.speaks() {
        // Nothing to say — but the comment may already exist from an earlier,
        // worse push, so it has to say *that* rather than going blank.
        writeln!(s, "{}", clean_body(a))?;
        return Ok(s);
    }

    // The judgement first, always: what isomer makes of the change, before any
    // of the detail behind it. Escaped like any other untrusted line — it may
    // carry a rule description, or the LLM's phrasing of a diff that tried to
    // talk to it.
    writeln!(s, "> {}", cell(&a.judgement()))?;
    writeln!(s)?;
    risk(&mut s, a)?;
    behavioral(&mut s, a)?;
    signatures(&mut s, a)?;
    identity(&mut s, a)?;
    structure(&mut s, a)?;
    frameworks(&mut s, a)?;
    // One view: a speaking verdict carries its metrics and the evidence behind
    // it — the differential hunks are the root cause a reviewer acts on.
    stats(&mut s, a)?;
    evidence(&mut s, a)?;
    Ok(fit(s, &format!("\n---\n{}\n", footer(a))))
}

/// Join a body and its footer within [`MAX_BODY`].
///
/// The footer carries the gate verdict, so it is reserved first and the body
/// is what gets cut — on a line boundary, so no fence marker or table row is
/// split, and with any evidence fence the cut left open closed again, so the
/// truncation note does not render as code.
fn fit(mut body: String, footer: &str) -> String {
    let budget = MAX_BODY.saturating_sub(footer.len());
    if body.len() <= budget {
        body.push_str(footer);
        return body;
    }
    // Room for the note and a closing fence; a fence is never wider than the
    // longest backtick run in the evidence plus one, so 64 is generous.
    let cut = body.floor_char_boundary(budget.saturating_sub(TRUNCATED.len() + 64));
    body.truncate(cut);
    if let Some(line_end) = body.rfind('\n') {
        body.truncate(line_end + 1);
    }
    if let Some(open) = open_fence(&body).map(str::len) {
        body.push_str(&"`".repeat(open));
        body.push('\n');
    }
    body.push_str(TRUNCATED);
    body.push_str(footer);
    body
}

/// The fence left open at the end of `body`, if any. A fence line is a run of
/// three or more backticks alone on a line, closed by a run at least as long —
/// the only fences [`fence`] writes.
fn open_fence(body: &str) -> Option<&str> {
    let mut open: Option<&str> = None;
    for line in body.lines() {
        let line = line.trim_end();
        if line.len() < 3 || !line.bytes().all(|b| b == b'`') {
            continue;
        }
        open = match open {
            Some(fence) if line.len() >= fence.len() => None,
            Some(fence) => Some(fence),
            None => Some(line),
        };
    }
    open
}

/// `🔴 HOSTILE · node-ipc · 12.0.0 → 12.0.1 · patch release · 3 of 14 files`.
fn heading(a: &Analysis<'_>) -> String {
    let mut parts = vec![format!(
        "{} {}",
        emoji(a.verdict),
        crate::view::verdict_word(a.verdict)
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
    parts.extend(crate::view::change_scale(a.display_diff()));
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
fn clean_body(a: &Analysis<'_>) -> String {
    let scale = crate::view::change_scale(a.display_diff());
    let scope = if scale.is_empty() {
        String::new()
    } else {
        format!(" across {}", scale.join(", "))
    };
    format!(
        "No newly-introduced capabilities, known-bad signatures, or publisher drift{scope}.\n{}",
        footer(a)
    )
}

fn footer(a: &Analysis<'_>) -> String {
    let gate = if a.clean() {
        format!("passes `--fail-on {}`", a.fail_on().as_str())
    } else {
        format!(
            "**fails `--fail-on {}`** — gated severity `{}`",
            a.fail_on().as_str(),
            a.gated().as_str()
        )
    };
    format!(
        "<sub>isomer {} · gate `{}` · {gate}</sub>",
        crate::VERSION,
        a.gate().as_str(),
    )
}

fn risk(s: &mut String, a: &Analysis<'_>) -> std::fmt::Result {
    // Shown when the model changed its mind, or whenever the full report is
    // being written. An unchanged band on a passing change is not news.
    let Some(r) = a.shown_risk().filter(|_| a.risk_band_moved() || !a.clean()) else {
        return Ok(());
    };
    let arrow = match r.trend() {
        crate::risk::Trend::Flat => String::new(),
        trend => format!(" {} {:+.2}", trend.arrow(), r.delta()),
    };
    writeln!(
        s,
        "**ML risk score** `{:.2}` → `{:.2}` (new decision: {}){arrow}\n",
        r.old, r.new, r.new_classification,
    )?;

    Ok(())
}

fn behavioral(s: &mut String, a: &Analysis<'_>) -> std::fmt::Result {
    let cats = &a.assessment.behavioral.categories;
    if cats.is_empty() {
        return Ok(());
    }
    writeln!(s, "#### Capabilities\n")?;
    writeln!(s, "| | capability | namespace | traits |")?;
    writeln!(s, "|---|---|---|---|")?;
    for c in cats {
        let fresh = a.assessment.behavioral.is_new_category(c);
        // Both halves, when both moved: a category with new *and* escalated
        // traits used to report only the new ones, hiding the escalations the
        // terminal's tree shows.
        let count = match (c.new_ids.len(), c.escalated_ids.len()) {
            (0, e) => format!("{e} escalated"),
            (n, 0) if fresh => format!("{n} new"),
            (n, 0) => format!("+{n}"),
            (n, e) if fresh => format!("{n} new · {e} escalated"),
            (n, e) => format!("+{n} · {e} escalated"),
        };
        let namespaces: Vec<String> = c.namespaces.iter().map(|n| code(n)).collect();
        writeln!(
            s,
            "| {} **{}** | {} | {} | {count} |",
            dots(c.severity),
            if fresh { "new" } else { "expanded" },
            cell(&c.label),
            namespaces.join(" · "),
        )?;
    }
    writeln!(s)?;

    Ok(())
}

fn signatures(s: &mut String, a: &Analysis<'_>) -> std::fmt::Result {
    let sig = &a.assessment.signature;
    if sig.ids.is_empty() {
        return Ok(());
    }
    let cve = sig
        .cve
        .as_ref()
        .map(|c| format!(" · {c}"))
        .unwrap_or_default();
    writeln!(s, "#### Known-bad signatures{cve}\n")?;
    writeln!(s, "| | rule | detects |")?;
    writeln!(s, "|---|---|---|")?;
    for m in sig.ids.iter().take(MAX_SIGNATURES) {
        writeln!(
            s,
            "| {} | {} | {} |",
            dots(m.severity),
            code(&crate::rubric::short_name(&m.id)),
            cell(&m.desc),
        )?;
    }
    if sig.ids.len() > MAX_SIGNATURES {
        writeln!(s, "| | _+{} more_ | |", sig.ids.len() - MAX_SIGNATURES)?;
    }
    writeln!(s)?;

    Ok(())
}

fn identity(s: &mut String, a: &Analysis<'_>) -> std::fmt::Result {
    let changes = &a.assessment.identity.changes;
    if changes.is_empty() {
        return Ok(());
    }
    writeln!(s, "#### Publisher\n")?;
    for ch in changes {
        let (old, new) = ch.shown();
        writeln!(s, "- **{}**: {} → {}", ch.label, cell(old), cell(new))?;
    }
    writeln!(s)?;

    Ok(())
}

fn structure(s: &mut String, a: &Analysis<'_>) -> std::fmt::Result {
    let facts = &a.assessment.structure.facts;
    if facts.is_empty() {
        return Ok(());
    }
    writeln!(s, "#### Structure\n")?;
    for f in facts {
        let kind = f.kind.as_str();
        writeln!(
            s,
            "- {} {kind} **{}** — {}",
            dots(f.severity),
            f.label,
            cell(&f.sentence())
        )?;
    }
    writeln!(s)?;

    Ok(())
}

/// ATT&CK and MBC ids the change moved. Shown as ids: isomer has no catalog
/// mapping them to prose and will not invent one.
fn frameworks(s: &mut String, a: &Analysis<'_>) -> std::fmt::Result {
    let rows: Vec<(&str, &crate::evidence::Sides)> =
        [("ATT&CK", &a.survey.attack), ("MBC", &a.survey.mbc)]
            .into_iter()
            .filter(|(_, sides)| sides.changed())
            .collect();
    if rows.is_empty() {
        return Ok(());
    }
    writeln!(s, "#### Technique coverage\n")?;
    writeln!(s, "| | introduced | no longer present | unchanged |")?;
    writeln!(s, "|---|---|---|---|")?;
    for (label, sides) in rows {
        // Each id with its official name, one per line in the cell.
        let list = |ids: Vec<&str>| {
            if ids.is_empty() {
                "—".to_string()
            } else {
                ids.iter()
                    .map(|i| match crate::frameworks::name(i) {
                        Some(name) => format!("{} {}", code(i), cell(&name)),
                        None => code(i),
                    })
                    .collect::<Vec<_>>()
                    .join("<br>")
            }
        };
        writeln!(
            s,
            "| **{label}** | {} | {} | {} |",
            list(sides.gained()),
            list(sides.lost()),
            sides.kept(),
        )?;
    }
    writeln!(s)?;
    Ok(())
}

fn stats(s: &mut String, a: &Analysis<'_>) -> std::fmt::Result {
    let rows = crate::view::stats(a.display_diff());
    if rows.is_empty() {
        return Ok(());
    }
    let joined = rows
        .iter()
        .map(|row| {
            let mut r = format!(
                "{} → {} {} ({:+})",
                row.old,
                row.new,
                row.label,
                row.delta()
            );
            if !row.note.is_empty() {
                r.push_str(" — ");
                r.push_str(&code(&row.note));
            }
            r
        })
        .collect::<Vec<_>>()
        .join(" · ");
    writeln!(s, "**Stats** {joined}\n")?;

    Ok(())
}

fn evidence(s: &mut String, a: &Analysis<'_>) -> std::fmt::Result {
    let hunks = a.hunks(COMMENT_HUNKS);
    if hunks.is_empty() {
        return Ok(());
    }
    writeln!(s, "#### Evidence\n")?;
    writeln!(
        s,
        "<sub>{}</sub>\n",
        crate::view::evidence_note_text(&hunks)
    )?;
    for group in crate::evidence::groups(&hunks) {
        match group {
            Group::Additions {
                name,
                severity,
                top,
                runs,
            } => {
                // One heading per changed file — captioned with its strongest
                // rule — then a single fenced diff of its added lines, an
                // ellipsis at each gap, mirroring the terminal's grouped view.
                let title = top
                    .map(|h| format!(" — {}", cell(&h.desc)))
                    .unwrap_or_default();
                writeln!(
                    s,
                    "{} {}{title} — added lines\n",
                    dots(severity),
                    code(name)
                )?;
                if let Some(ms) = crate::view::file_metrics_summary(a.display_diff(), name) {
                    writeln!(s, "<sub>{}</sub>\n", cell(&ms.join(" · ")))?;
                }
                let mut body = String::new();
                for (k, h) in runs.iter().enumerate() {
                    if k > 0 {
                        body.push_str("  ⋯\n");
                    }
                    for l in &h.lines {
                        writeln!(body, "+ {:>6}  {}", l.locator, l.text)?;
                    }
                }
                writeln!(s, "{}", fence(&body))?;
            }
            Group::Single(h) => {
                let where_ = match &h.member {
                    Some(m) => format!("{} → {}", code(&h.file), code(m)),
                    None => code(&h.location),
                };
                writeln!(s, "{} {where_} — {}\n", dots(h.severity), cell(&h.desc))?;
                let mut body = String::new();
                for l in &h.lines {
                    let gutter = if l.added == LineMark::Added { "+" } else { " " };
                    writeln!(body, "{gutter} {:>6}  {}", l.locator, l.text)?;
                }
                writeln!(s, "{}", fence(&body))?;
            }
        }
    }

    Ok(())
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
/// Everything reaching a comment is attacker-controlled — a fork's pull
/// request supplies both the artifact *and* `.isomer.toml` — and GitHub
/// renders a comment as rich text. So every ASCII punctuation character is
/// backslash-escaped, which CommonMark defines for exactly this purpose: `<`
/// cannot open `<img>`/`<details>` (forge a banner, hide the verdict, beacon
/// the reviewer's IP), `[`/`](`/`![` cannot forge a "✅ CLEAN" link or image,
/// `*`/`_`/`#`/`>` cannot restyle the line, and `|` cannot end a column.
/// Newlines would end a row and become spaces. Two GitHub conveniences are not
/// markdown and survive escaping, so they are broken with an invisible word
/// joiner: an `@team` mention would ping people, and a `#123` reference would
/// link an unrelated issue.
fn cell(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\n' | '\r' => out.push(' '),
            '@' | '#' => {
                out.push('\\');
                out.push(c);
                out.push('\u{2060}');
            }
            c if c.is_ascii_punctuation() => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

/// An inline code span whose delimiter outgrows any backtick run inside it, so
/// attacker-controlled text — an archive member name, a rule id, a path from a
/// fork's pull request — cannot close the span and inject markup after it. The
/// inline twin of [`fence`], and the reason nothing here interpolates into
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

/// A fenced block whose fence is longer than any backtick run inside it, so
/// attacker-controlled evidence cannot break out of the fence and inject
/// markup into the comment.
fn fence(body: &str) -> String {
    let longest = body.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let ticks = "`".repeat(longest.max(2) + 1);
    format!("{ticks}\n{}\n{ticks}\n", body.trim_end())
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

    /// Link, image, and emphasis syntax from an artifact must render as the
    /// literal text it is, or a signer name can forge a passing banner.
    #[test]
    fn cells_cannot_forge_links_images_or_mentions() {
        let forged = cell("![✅ CLEAN](https://x/b.svg) [ok](https://x) **bold** _i_");
        assert!(!forged.contains("]("), "{forged}");
        assert!(!forged.contains("**"), "{forged}");
        assert!(forged.contains("\\!\\[✅ CLEAN\\]"), "{forged}");
        // A mention or issue reference is split by an invisible joiner.
        assert_eq!(cell("@team"), "\\@\u{2060}team");
        assert_eq!(cell("#123"), "\\#\u{2060}123");
        // Ordinary words and non-ASCII text pass through.
        assert_eq!(cell("Jörg Müller"), "Jörg Müller");
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
            "\\<img src\\=x onerror\\=alert\\(1\\)\\>"
        );
        assert_eq!(cell("a & b"), "a \\& b");
        // An entity spelled out in the input stays literal text.
        assert_eq!(cell("&lt;script>"), "\\&lt\\;script\\>");
    }

    /// An oversized report keeps its footer — the gate verdict — and never
    /// leaves an evidence fence open over the truncation note.
    #[test]
    fn truncation_keeps_the_footer_and_closes_an_open_fence() {
        let mut body = String::from("intro\n");
        body.push_str("````\n");
        while body.len() < MAX_BODY * 2 {
            body.push_str("+ 1  é line of evidence\n");
        }
        let footer = "\n---\n<sub>gate verdict</sub>\n";
        let out = fit(body, footer);
        assert!(out.len() <= MAX_BODY, "{} > {MAX_BODY}", out.len());
        assert!(out.ends_with(footer));
        assert!(out.contains("Report truncated"));
        assert_eq!(open_fence(&out), None, "the cut must close its fence");

        let short = fit("small\n".to_owned(), footer);
        assert_eq!(short, format!("small\n{footer}"));
    }

    #[test]
    fn open_fence_tracks_nesting_by_length() {
        assert_eq!(open_fence("```\ncode\n```\n"), None);
        assert_eq!(open_fence("````\n```\n"), Some("````"));
        assert_eq!(open_fence("text\n````\nx\n"), Some("````"));
    }
}
