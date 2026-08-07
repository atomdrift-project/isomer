//! `isomer fs` — differential analysis of two local trees.
//!
//! cleave's `diff_paths` measures everything (six scopes); [`crate::rubric`]
//! judges the delta; [`crate::version`] supplies proportionality. Output
//! follows the UNIX-diff principle: **silent when there is no noticeable
//! behavioral change**, and a concise, styled verdict only when there is
//! something to say. `--explain` adds the full trait ids and cleave's ledger.

use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use cleave::types::{DiffReportV1, FileDiffEntry};

use crate::rubric::{self, Assessment};
use crate::version::{Bump, Version};
use crate::{Cli, Format, Severity};

/// Diff `old` against `new`, emit the report, and return whether the delta is
/// clean at `--fail-on`.
pub(crate) fn run(old: &Path, new: &Path, cli: &Cli) -> Result<bool> {
    let options = cleave::AnalysisOptions::default();
    let report = cleave::diff::diff_paths(
        old,
        new,
        &options,
        cleave::diff::ScopeMask::all(),
        cleave::diff::DEFAULT_LIMIT_CHANGES,
    )?;
    let diff = report
        .diff
        .as_ref()
        .context("diff_paths returned a report without a diff")?;

    let assessment = rubric::assess(diff);
    let naming = Naming::resolve(old, new, cli);
    let prop = Proportionality::eval(&assessment, &naming);
    let clean = !assessment.severity.fails(cli.fail_on);

    match cli.format {
        Format::Terminal => {
            let mut out = String::new();
            if should_speak(&assessment, &prop, cli) {
                // Azoth ML risk for each side (optional; skipped if no model).
                let risk = crate::risk::score_pair(old, new);
                header::render(&mut out, &assessment, diff, &naming, &prop, risk);
                // The proof: context windows for the gained traits, rendered by
                // cleave so they match what scan shows byte for byte.
                let ids = assessment.gained_ids();
                let ev = crate::evidence::render(new, &options, &ids, !cli.explain)?;
                if !ev.trim().is_empty() {
                    out.push_str(&format!(
                        "   {}\n\n",
                        cleave::theme::paint_component("evidence — where the change lives")
                    ));
                    out.push_str(&ev);
                }
            }
            if cli.explain {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&cleave::diff::format::format_terminal(&report));
            }
            write_stdout(&out)?;
        }
        Format::Json => {
            let risk = crate::risk::score_pair(old, new);
            write_stdout(&format!(
                "{}\n",
                json(&assessment, &naming, &prop, risk, &report)?
            ))?;
        }
        Format::Sarif | Format::Markdown => bail!("--format {:?} is not implemented yet", cli.format),
    }

    Ok(clean)
}

/// The diff-like speech gate: stay silent unless there is a real signal. We
/// speak when the verdict fails the threshold, when anything reaches High, or
/// when behavioral drift is disproportionate for the version bump. `--explain`
/// always speaks.
fn should_speak(a: &Assessment, prop: &Proportionality, cli: &Cli) -> bool {
    cli.explain
        || a.severity.fails(cli.fail_on)
        || a.severity >= Severity::High
        || (prop.disproportionate && a.behavioral.severity >= Severity::Medium)
}

/// Broken-pipe-safe write: a closed downstream pipe (e.g. `| head`) is a normal
/// exit, not a panic. `println!` would panic here.
fn write_stdout(s: &str) -> Result<()> {
    let mut out = io::stdout().lock();
    match out.write_all(s.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e.into()),
    }
}

// ── version + naming ────────────────────────────────────────────────────────

/// Detected versions and the artifact name for the header, from the input
/// paths (or explicit `--base-version` / `--head-version`).
struct Naming {
    name: String,
    old: Option<Version>,
    new: Option<Version>,
    bump: Option<Bump>,
}

impl Naming {
    fn resolve(old: &Path, new: &Path, cli: &Cli) -> Self {
        let ob = basename(old);
        let nb = basename(new);
        let ov = cli
            .base_version
            .as_deref()
            .and_then(Version::parse)
            .or_else(|| Version::detect(&ob));
        let nv = cli
            .head_version
            .as_deref()
            .and_then(Version::parse)
            .or_else(|| Version::detect(&nb));
        let bump = match (&ov, &nv) {
            (Some(o), Some(n)) => Some(Bump::classify(o, n)),
            _ => None,
        };
        Self {
            name: artifact_name(&nb, &ob, nv.as_ref().or(ov.as_ref())),
            old: ov,
            new: nv,
            bump,
        }
    }
}

fn basename(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// A display name: the new file's basename with the detected version token and
/// any archive extension stripped, separators tidied. Falls back to the old
/// basename when the new one empties out.
fn artifact_name(new_base: &str, old_base: &str, ver: Option<&Version>) -> String {
    let cleaned = clean_name(new_base, ver);
    if cleaned.is_empty() {
        clean_name(old_base, ver)
    } else {
        cleaned
    }
}

fn clean_name(base: &str, ver: Option<&Version>) -> String {
    let mut s = base.to_string();
    if let Some(v) = ver {
        s = s.replace(&v.raw, "");
    }
    for ext in [".tar.gz", ".tgz", ".tar", ".zip", ".gz"] {
        if let Some(stripped) = s.strip_suffix(ext) {
            s = stripped.to_string();
            break;
        }
    }
    // Collapse separators left behind by removing the version token.
    while s.contains("..") {
        s = s.replace("..", ".");
    }
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    s.trim_matches(['-', '.', '_', ' ']).to_string()
}

// ── proportionality ─────────────────────────────────────────────────────────

/// Whether the behavioral drift exceeds the tolerance for the detected bump.
struct Proportionality {
    disproportionate: bool,
    note: Option<String>,
}

impl Proportionality {
    fn eval(a: &Assessment, naming: &Naming) -> Self {
        let Some(bump) = naming.bump else {
            return Self {
                disproportionate: false,
                note: None,
            };
        };
        if a.behavioral.severity == Severity::None {
            return Self {
                disproportionate: false,
                note: None,
            };
        }
        if a.behavioral.severity > bump.tolerance() {
            Self {
                disproportionate: true,
                note: Some(format!(
                    "disproportionate — a {} bump gained a {}-severity capability",
                    bump.label(),
                    a.behavioral.severity.as_str()
                )),
            }
        } else {
            Self {
                disproportionate: false,
                note: Some(format!("within tolerance for a {} bump", bump.label())),
            }
        }
    }
}

// ── JSON ────────────────────────────────────────────────────────────────────

fn json(
    a: &Assessment,
    naming: &Naming,
    prop: &Proportionality,
    risk: Option<crate::risk::Risk>,
    report: &cleave::types::AnalysisReport,
) -> Result<String> {
    let categories: Vec<_> = a
        .behavioral
        .categories
        .iter()
        .map(|c| {
            serde_json::json!({
                "class": c.class,
                "severity": c.severity.as_str(),
                "trait_ids": c.ids,
            })
        })
        .collect();
    let envelope = serde_json::json!({
        "schema_version": 1,
        "artifact": naming.name,
        "version": {
            "old": naming.old.as_ref().map(|v| &v.raw),
            "new": naming.new.as_ref().map(|v| &v.raw),
            "bump": naming.bump.map(Bump::label),
        },
        "verdict": {
            "severity": a.severity.as_str(),
            "behavioral": { "severity": a.behavioral.severity.as_str(), "categories": categories },
            "signature": {
                "severity": a.signature.severity.as_str(),
                "count": a.signature.ids.len(),
                "cve": a.signature.cve,
                "trait_ids": a.signature.ids.iter().map(|(_, id)| id).collect::<Vec<_>>(),
            },
            "identity": { "severity": a.identity.severity.as_str(), "files": a.identity.files },
            "proportionality": { "disproportionate": prop.disproportionate, "note": prop.note },
            "risk": risk.map(|r| serde_json::json!({
                "old": r.old, "new": r.new, "delta": r.delta(), "model": "azoth",
            })),
        },
        "report": report,
    });
    Ok(serde_json::to_string(&envelope)?)
}

// ── terminal header — "Incident Brief" ───────────────────────────────────────

mod header {
    use super::{DiffReportV1, FileDiffEntry, Naming, Proportionality, Severity};
    use crate::risk::Risk;
    use crate::rubric::Assessment;

    /// Width of the left label column in the brief body.
    const LABEL: usize = 13;

    pub(super) fn render(
        out: &mut String,
        a: &Assessment,
        diff: &DiffReportV1,
        naming: &Naming,
        prop: &Proportionality,
        risk: Option<Risk>,
    ) {
        // Eyebrow.
        out.push_str(&format!(
            " {}\n\n",
            cleave::theme::paint_component("isomer · supply-chain differential")
        ));

        // Subject: what, which versions, the verdict stamp.
        out.push_str(&subject_line(a, diff, naming));
        // Risk: the model's opinion of each side, and the change between them.
        if let Some(r) = risk {
            out.push_str(&risk_line(r));
        }
        out.push('\n');

        // Narrative: one sentence a human reads first.
        for line in wrap(&narrative(a, naming, prop), 66) {
            out.push_str(&format!("   {} {}\n", paint(a.severity, "┃"), line));
        }
        out.push('\n');

        // Labeled evidence rows.
        for (label, body) in body_rows(a) {
            out.push_str(&format!("   {}{}\n", pad(&label), body));
        }
        if let Some(m) = single_changed_file(diff).and_then(metrics_line) {
            out.push_str(&format!("   {}{}\n", pad("metrics"), m));
        }
        out.push('\n');
    }

    /// `   liblzma.so   5.4.5 ──▶ 5.6.0   · minor release        [ HOSTILE ]`.
    fn subject_line(a: &Assessment, diff: &DiffReportV1, naming: &Naming) -> String {
        let mut s = format!("   {}", bold(&naming.name));
        if let (Some(o), Some(n)) = (&naming.old, &naming.new) {
            s.push_str(&format!(
                "   {} {} {}",
                o.raw,
                cleave::theme::paint_component("──▶"),
                bold(&n.raw)
            ));
            if let Some(b) = naming.bump {
                s.push_str(&cleave::theme::paint_component(format!("   · {} release", b.label())).to_string());
            }
        }
        let total = diff.summary.files_changed
            + diff.summary.files_added
            + diff.summary.files_removed
            + diff.summary.files_unchanged;
        if total > 1 {
            s.push_str(
                &cleave::theme::paint_component(format!(" · {} of {} files", diff.summary.files_changed, total))
                    .to_string(),
            );
        }
        s.push_str(&format!("   {}\n", stamp(a.severity)));
        s
    }

    /// `   risk    0.02 ──▶ 0.98    ▲ +0.96    azoth malware probability`.
    fn risk_line(r: Risk) -> String {
        let new_sev = risk_severity(r.new);
        let d = r.delta();
        let arrow = if d > 0.005 {
            "▲"
        } else if d < -0.005 {
            "▼"
        } else {
            "·"
        };
        let delta_sev = if d > 0.005 { new_sev } else { Severity::None };
        format!(
            "   {}{:.2} {} {}    {}   {}\n",
            pad("risk"),
            r.old,
            cleave::theme::paint_component("──▶"),
            paint(new_sev, &format!("{:.2}", r.new)),
            paint(delta_sev, &format!("{arrow} {d:+.2}")),
            cleave::theme::paint_component("azoth malware probability"),
        )
    }

    /// The labeled body rows, in reading order. Behavioral leads with the
    /// single worst finding named in full (the "smoking gun"); the rest are
    /// summarized.
    fn body_rows(a: &Assessment) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = Vec::new();

        if let Some(worst) = a.behavioral.categories.first() {
            let phrase = strip_gained(worst.phrase);
            rows.push((
                "smoking gun".into(),
                format!("{} — {}", paint(worst.severity, worst.class), phrase),
            ));
            if let Some(id) = worst.ids.first() {
                rows.push((
                    String::new(),
                    format!(
                        "{}   {} {}",
                        cleave::theme::paint_component(id),
                        dots(worst.severity),
                        paint(worst.severity, sev_word(worst.severity)),
                    ),
                ));
            }
            let rest: Vec<&str> = a.behavioral.categories[1..].iter().map(|c| c.class).collect();
            if !rest.is_empty() {
                let body = format!("{} ({} capabilities total)", rest.join(" · "), a.behavioral.total());
                rows.push(("also new".into(), cleave::theme::paint_component(body).to_string()));
            }
        }

        if a.signature.severity != Severity::None {
            let n = a.signature.ids.len();
            let rules = if n == 1 { "rule" } else { "rules" };
            let mut body = format!("{n} known-bad {rules}");
            if let Some(cve) = &a.signature.cve {
                body.push_str(&format!(" · {}", bold(cve)));
            }
            body.push_str(&format!(
                "   {} {}",
                dots(a.signature.severity),
                paint(a.signature.severity, sev_word(a.signature.severity))
            ));
            rows.push(("confirmed".into(), body));
        }

        if a.identity.severity != Severity::None {
            let mut body = "signer / publisher changed".to_string();
            if a.identity.files > 1 {
                body.push_str(&format!(" ({} files)", a.identity.files));
            }
            body.push_str(&format!(
                "   {} {}",
                dots(a.identity.severity),
                paint(a.identity.severity, sev_word(a.identity.severity))
            ));
            rows.push(("identity".into(), body));
        }

        rows
    }

    /// One sentence stating the finding, written for a human.
    fn narrative(a: &Assessment, naming: &Naming, prop: &Proportionality) -> String {
        let name = &naming.name;
        if let Some(worst) = a.behavioral.categories.first() {
            let what = strip_gained(worst.phrase);
            if prop.disproportionate {
                let bump = naming.bump.map(|b| b.label()).unwrap_or("minor");
                return format!(
                    "{name} gained {what} — disproportionate for a {bump} release."
                );
            }
            return format!("{name} gained {what}.");
        }
        if a.signature.severity != Severity::None {
            let n = a.signature.ids.len();
            return format!("{name} matches {n} known-bad signature(s).");
        }
        if a.identity.severity != Severity::None {
            return format!("{name} changed its signer or publisher.");
        }
        format!("{name} changed.")
    }

    /// `"gained an ifunc resolver"` → `"an ifunc resolver"`.
    fn strip_gained(phrase: &str) -> &str {
        phrase.strip_prefix("gained ").unwrap_or(phrase)
    }

    /// Map a model probability to a severity band for coloring.
    fn risk_severity(p: f32) -> Severity {
        if p >= 0.90 {
            Severity::Critical
        } else if p >= 0.50 {
            Severity::High
        } else if p >= 0.15 {
            Severity::Medium
        } else {
            Severity::None
        }
    }

    /// Left-pad a label to the body column, dimmed. Empty labels align
    /// continuation rows under their parent.
    fn pad(label: &str) -> String {
        if label.is_empty() {
            " ".repeat(LABEL)
        } else {
            format!("{}{}", cleave::theme::paint_component(label), " ".repeat(LABEL.saturating_sub(label.len())))
        }
    }

    /// Word-wrap to `width` columns (plain text; spans are added by the caller).
    fn wrap(text: &str, width: usize) -> Vec<String> {
        let mut lines = Vec::new();
        let mut cur = String::new();
        for word in text.split(' ') {
            if !cur.is_empty() && cur.len() + 1 + word.len() > width {
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

    fn bold(text: &str) -> String {
        use colored::Colorize;
        text.bold().to_string()
    }

    fn stamp(sev: Severity) -> String {
        let word = match sev {
            Severity::Critical => "HOSTILE",
            Severity::High => "SUSPICIOUS",
            Severity::Medium | Severity::Low => "NOTABLE",
            Severity::None => "CLEAN",
        };
        paint(sev, &format!("[ {word} ]"))
    }

    fn single_changed_file(diff: &DiffReportV1) -> Option<&FileDiffEntry> {
        let changed: Vec<&FileDiffEntry> = diff
            .files
            .iter()
            .filter(|f| matches!(f.status, cleave::types::FileStatus::Changed))
            .collect();
        (changed.len() == 1).then(|| changed[0])
    }

    /// The most substantial metric movements, as `code +37% · init_array 2→1`.
    /// Ranks changed numeric metrics by relative magnitude and keeps the top
    /// few above a noise floor, so only genuinely large shifts surface.
    fn metrics_line(file: &FileDiffEntry) -> Option<String> {
        const FLOOR: f64 = 0.15; // 15% — below this is version-churn noise.
        const KEEP: usize = 3;
        let m = file.scopes.metrics.as_ref()?;
        let mut movers: Vec<(f64, String)> = Vec::new();
        for c in &m.changed {
            let (Some(o), Some(n)) = (num(&c.old.value), num(&c.new.value)) else {
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
            movers.push((rel, describe(&c.new.path, o, n)));
        }
        movers.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        movers.truncate(KEEP);
        if movers.is_empty() {
            return None;
        }
        Some(
            movers
                .into_iter()
                .map(|(_, d)| d)
                .collect::<Vec<_>>()
                .join(" · "),
        )
    }

    /// Human phrasing for one metric delta. Percent for sizes/counts that grew
    /// a lot; explicit `a→b` for small integer counts where the ratio reads
    /// oddly (e.g. `init_array 2→1`).
    fn describe(path: &str, old: f64, new: f64) -> String {
        let leaf = path.rsplit(['.', '/']).next().unwrap_or(path);
        let label = if path.contains("dependencies") {
            "deps"
        } else {
            match leaf {
                "code_size" | "size" | "size_bytes" => "code",
                "init_array_count" => "init_array",
                "dynrela_count" | "relacount" => "relocs",
                other => other,
            }
        };
        if old > 0.0 && old.max(new) >= 8.0 {
            let pct = (new - old) / old * 100.0;
            let sign = if pct >= 0.0 { "+" } else { "" };
            format!("{label} {sign}{pct:.0}%")
        } else {
            format!("{label} {old:.0}→{new:.0}")
        }
    }

    fn num(v: &serde_json::Value) -> Option<f64> {
        v.as_f64()
    }

    // ── shared painters ─────────────────────────────────────────────────────

    fn sev_word(sev: Severity) -> &'static str {
        match sev {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::None => "clean",
        }
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
}
