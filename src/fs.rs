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
use crate::{Cli, Format, Gate, Severity};

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

    // Capability classes present in the base, so we can tell a wholly new
    // class from one that merely gained a trait (a cached analyze of old).
    let base_classes = crate::evidence::base_classes(old, &options);
    let assessment = rubric::assess(diff, &base_classes);
    let naming = Naming::resolve(old, new, cli);
    let prop = Proportionality::eval(&assessment, &naming);

    // Azoth ML risk is the *primary* detector: a jump into a worse band drives
    // the verdict on its own, even when no trait or signature fired. Computed
    // once up front (a diff needs it to decide whether to speak). `None` when no
    // model is available — then the hand-coded rubric stands alone.
    let risk = crate::risk::score_pair(old, new);
    let risk_now = risk.map_or(Severity::None, |r| risk_band(r.new));
    let risk_jump = risk.map_or(Severity::None, |r| {
        if risk_band(r.new) > risk_band(r.old) { risk_band(r.new) } else { Severity::None }
    });

    // The verdict folds the rubric axes with the ML risk. The gate then decides
    // exit: `new` counts only newly-introduced risk (rubric-new ∪ a risk jump);
    // `any` includes escalations of pre-existing findings.
    let verdict = assessment.severity.max(risk_now);
    let verdict_new = assessment.new_severity().max(risk_jump);
    let gated = match cli.gate {
        Gate::New => verdict_new,
        Gate::Any => verdict,
    };
    let clean = !gated.fails(cli.fail_on);

    match cli.format {
        Format::Terminal => {
            let mut out = String::new();
            if should_speak(&assessment, &prop, gated, cli) {
                // Optional LLM read of the change — computed first so it can sit
                // in the masthead. Failures log to stderr and don't block.
                let interp = crate::llm::config(cli).and_then(|cfg| {
                    let ctx = llm_context(&assessment, &naming, risk, new, &options).ok()?;
                    match crate::llm::interpret(&cfg, &ctx) {
                        Ok(i) => Some(i),
                        Err(e) => {
                            eprintln!("isomer: llm interpretation failed: {e:#}");
                            None
                        }
                    }
                });
                header::render(&mut out, verdict, &assessment, diff, &naming, &prop, risk, interp.as_ref());
                // The proof: context windows for the gained traits as an aligned
                // table (locator · code · description).
                let ids = assessment.gained_ids();
                let limit = if cli.explain { 24 } else { 6 };
                let rows = crate::evidence::windows(new, &options, &ids, limit)?;
                out.push_str(&header::evidence_table(&rows));
            } else if let Some(existing) =
                crate::evidence::existing_risk(new, &options, &naming.name)?
            {
                // No noticeable change, but the artifact still carries elevated
                // traits. Say so concisely rather than staying fully silent —
                // "nothing changed, but heads up". Does not affect exit code.
                out.push_str(&existing);
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
            // Include the LLM read when asked, exactly as the terminal path does.
            let interp = crate::llm::config(cli).and_then(|cfg| {
                let ctx = llm_context(&assessment, &naming, risk, new, &options).ok()?;
                match crate::llm::interpret(&cfg, &ctx) {
                    Ok(i) => Some(i),
                    Err(e) => {
                        eprintln!("isomer: llm interpretation failed: {e:#}");
                        None
                    }
                }
            });
            let gate = GateDecision {
                on: match cli.gate {
                    Gate::New => "new",
                    Gate::Any => "any",
                },
                fail_on: cli.fail_on.as_str(),
                severity: gated.as_str(),
                fail: !clean,
            };
            // The proof windows and the full identity claims — everything the UI
            // and the CLI cache need to redraw without re-reading the artifact.
            let evidence =
                crate::evidence::windows(new, &options, &assessment.gained_ids(), EVIDENCE_JSON_CAP)?;
            let provenance = diff
                .files
                .iter()
                .find_map(|f| f.identity.as_ref())
                .map_or((None, None), |idd| (idd.old.as_ref(), idd.new.as_ref()));
            write_stdout(&format!(
                "{}\n",
                json(
                    &assessment, &naming, &prop, risk, &gate, interp.as_ref(), &evidence, provenance,
                    &report,
                )?
            ))?;
        }
        Format::Interpret => {
            // Exactly what `--llm` would send (minus the system prompt).
            let ctx = llm_context(&assessment, &naming, risk, new, &options)?;
            write_stdout(&format!("{ctx}\n"))?;
        }
        Format::Sarif | Format::Markdown => bail!("--format {:?} is not implemented yet", cli.format),
    }

    Ok(clean)
}

/// Build the plain-text payload describing the diff, sent to the LLM (and shown
/// verbatim by `--format interpret`). No color, no rail — just the structured
/// behavioral delta plus the matched code/bytes.
fn llm_context(
    a: &Assessment,
    naming: &Naming,
    risk: Option<crate::risk::Risk>,
    new: &Path,
    options: &cleave::AnalysisOptions,
) -> Result<String> {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "artifact: {}", naming.name);
    if let (Some(o), Some(n)) = (&naming.old, &naming.new) {
        let bump = naming.bump.map(|b| format!(" ({})", b.describe())).unwrap_or_default();
        let _ = writeln!(s, "version: {} -> {}{bump}", o.raw, n.raw);
    }
    if let Some(r) = risk {
        let _ = writeln!(s, "ml_malware_probability: {:.2} -> {:.2}", r.old, r.new);
    }

    let (fresh, expanded): (Vec<_>, Vec<_>) = a
        .behavioral
        .categories
        .iter()
        .partition(|c| a.behavioral.is_new_category(c));
    if !fresh.is_empty() {
        let _ = writeln!(s, "\nNEW capability classes (absent in old version):");
        for c in &fresh {
            let _ = writeln!(s, "- {} [{}]: {} ({} new traits)", c.label, c.severity.as_str(), c.namespaces.join(", "), c.new_ids.len());
        }
    }
    if !expanded.is_empty() {
        let _ = writeln!(s, "\nEXPANDED capability classes (already present in old version):");
        for c in &expanded {
            let _ = writeln!(s, "- {} [{}]: {} (+{} traits)", c.label, c.severity.as_str(), c.namespaces.join(", "), c.new_ids.len());
        }
    }
    if a.signature.severity != Severity::None {
        let _ = writeln!(s, "\nknown-bad signatures matched:");
        for (sev, id, _) in &a.signature.ids {
            let _ = writeln!(s, "- [{}] {}", sev.as_str(), header::sig_name(id));
        }
        if let Some(cve) = &a.signature.cve {
            let _ = writeln!(s, "  referenced CVE: {cve}");
        }
    }
    if !a.identity.changes.is_empty() {
        let _ = writeln!(s, "\nidentity changes (publisher/signer):");
        for ch in &a.identity.changes {
            let old = if ch.old.is_empty() { "none" } else { &ch.old };
            let new = if ch.new.is_empty() { "none" } else { &ch.new };
            let _ = writeln!(s, "- {}: {} -> {}", ch.label, old, new);
        }
    }

    // Compact evidence — the matched rows and their descriptions, not the full
    // surrounding dump; keeps the payload focused and the token cost bounded.
    let ev = crate::evidence::render(new, options, &a.gained_ids(), true)?;
    if !ev.trim().is_empty() {
        let _ = writeln!(s, "\nchanged code / bytes (matched by rules):");
        s.push_str(ev.trim_end());
        s.push('\n');
    }
    Ok(s)
}

/// The diff-like speech gate: stay silent unless there is a real signal. We
/// speak when the gated verdict fails the threshold, when the change reaches
/// High, or when behavioral drift is disproportionate for the version bump.
/// `--explain` always speaks. `gated` is the severity under the active
/// `--gate` policy, so a `new`-gated run stays quiet about pre-existing risk
/// here (it's surfaced concisely instead).
/// Map an ML malware probability to a severity band (mirrors the risk words:
/// benign / elevated / suspicious / malware).
fn risk_band(p: f32) -> Severity {
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

fn should_speak(a: &Assessment, prop: &Proportionality, gated: Severity, cli: &Cli) -> bool {
    cli.explain
        || gated.fails(cli.fail_on)
        || gated >= Severity::High
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

/// Evidence windows to embed in `--format json`. Higher than the terminal's
/// display cap: the JSON is a complete, cacheable record, not a screenful.
const EVIDENCE_JSON_CAP: usize = 64;

/// The CI exit decision, ready to place in the envelope's `gate` field.
struct GateDecision {
    on: &'static str,
    fail_on: &'static str,
    severity: &'static str,
    fail: bool,
}

/// Build the `--format json` envelope. Compact and typed, mirroring `../scan`:
/// a curated `verdict` and its evidence beside the full `raw` cleave diff. See
/// [`crate::json`].
#[allow(clippy::too_many_arguments)]
fn json<R: serde::Serialize>(
    a: &Assessment,
    naming: &Naming,
    prop: &Proportionality,
    risk: Option<crate::risk::Risk>,
    gate: &GateDecision,
    interp: Option<&crate::llm::Interpretation>,
    evidence: &[crate::evidence::Window],
    provenance: (Option<&filefacts::Identity>, Option<&filefacts::Identity>),
    report: &R,
) -> Result<String> {
    use crate::json as j;
    let categories = a
        .behavioral
        .categories
        .iter()
        .map(|c| j::Category {
            class: &c.class,
            label: &c.label,
            severity: c.severity.as_str(),
            new_category: a.behavioral.is_new_category(c),
            namespaces: &c.namespaces,
            new_ids: &c.new_ids,
            escalated_ids: &c.escalated_ids,
        })
        .collect();
    let sig_ids = a
        .signature
        .ids
        .iter()
        .map(|(sev, id, new)| j::SigId { id, crit: sev.as_str(), new: *new })
        .collect();
    let facts = a
        .structure
        .facts
        .iter()
        .map(|f| j::Fact { severity: f.severity.as_str(), label: f.label, detail: &f.detail })
        .collect();
    let changes = a
        .identity
        .changes
        .iter()
        .map(|c| j::IdChange { field: c.label, old: &c.old, new: &c.new })
        .collect();
    let evidence = evidence
        .iter()
        .map(|w| j::Ev {
            member: w.member.as_deref(),
            locator: &w.locator,
            code: &w.code,
            desc: &w.desc,
            hostile: w.hostile,
        })
        .collect();

    let envelope = j::Envelope {
        v: "1",
        eng: concat!("isomer/", env!("CARGO_PKG_VERSION")),
        verb: "fs",
        artifact: (!naming.name.is_empty()).then_some(naming.name.as_str()),
        version: j::Version {
            old: naming.old.as_ref().map(|v| v.raw.as_str()),
            new: naming.new.as_ref().map(|v| v.raw.as_str()),
            bump: naming.bump.map(Bump::label),
        },
        provenance: j::Provenance { old: provenance.0, new: provenance.1 },
        verdict: j::Verdict {
            severity: a.severity.as_str(),
            new_severity: a.new_severity().as_str(),
            gate: j::Gate {
                on: gate.on,
                fail_on: gate.fail_on,
                severity: gate.severity,
                fail: gate.fail,
            },
            risk: risk.map(|r| j::Risk { old: r.old, new: r.new, delta: r.delta(), model: "azoth" }),
            proportionality: j::Prop {
                disproportionate: prop.disproportionate,
                note: prop.note.as_deref(),
            },
            behavioral: j::Behavioral { severity: a.behavioral.severity.as_str(), categories },
            signature: j::Signature {
                severity: a.signature.severity.as_str(),
                cve: a.signature.cve.as_deref(),
                count: a.signature.ids.len(),
                ids: sig_ids,
            },
            identity: j::Identity { severity: a.identity.severity.as_str(), changes },
            structure: j::Structure { severity: a.structure.severity.as_str(), facts },
        },
        evidence,
        llm: interp.map(|i| j::Llm { nature: &i.nature, verdict: &i.verdict, model: &i.model }),
        raw: report,
    };
    Ok(serde_json::to_string(&envelope)?)
}

// ── terminal header — "Command Rail" ─────────────────────────────────────────
// ── terminal header — masthead + grid ────────────────────────────────────────

mod header {
    use colored::Colorize;

    use super::{DiffReportV1, FileDiffEntry, Naming, Proportionality, Severity};
    use crate::evidence::Window;
    use crate::llm::Interpretation;
    use crate::risk::Risk;
    use crate::rubric::Assessment;

    const BAR: usize = 20;
    /// Visible width of the section-pill cell (longest pill + a trailing space).
    const PILL_COL: usize = 12;
    /// Width the capability-class name column pads to.
    const NAME_W: usize = 20;

    #[allow(clippy::too_many_arguments)]
    pub(super) fn render(
        out: &mut String,
        verdict: Severity,
        a: &Assessment,
        diff: &DiffReportV1,
        naming: &Naming,
        prop: &Proportionality,
        risk: Option<Risk>,
        interp: Option<&Interpretation>,
    ) {
        // ── masthead: verdict, the one-line read, the risk move ──
        out.push_str(&badge_line(verdict, diff, naming, prop));
        if let Some(i) = interp.filter(|i| !i.nature.trim().is_empty()) {
            out.push_str(&format!(" {} {}\n", "✨", i.nature.trim().truecolor(62, 207, 214)));
        }
        if let Some(r) = risk {
            out.push_str(&risk_twin(r));
        }
        out.push('\n');

        // ── detail: one grid, pill · dots · name · locator ──
        behavioral_grid(out, a);
        structure_grid(out, &a.structure);
        signature_grid(out, a);
        identity_grid(out, a);
        if let Some(m) = single_changed_file(diff).and_then(metrics_body) {
            out.push_str(&grid_line(&pill_cell("metrics", PILL_TEAL), "   ", &m));
        }
    }

    /// The structural-anomaly section (computed by the rubric): a new linked
    /// dependency, functions turned into ifunc resolvers, new imports — the
    /// signature-less tell for an xz-class attack.
    fn structure_grid(out: &mut String, structure: &crate::rubric::Structure) {
        for (i, f) in structure.facts.iter().enumerate() {
            let cell = if i == 0 { pill_cell("structure", PILL_SLATE) } else { blank_cell() };
            let name = pad_visible(&f.label.bold().to_string(), f.label, NAME_W);
            let body = format!("{name} {}", f.detail.truecolor(150, 160, 168));
            out.push_str(&grid_line(&cell, &dots(f.severity), &body));
        }
    }

    /// ` [ HOSTILE ]  liblzma.so   5.4.5 → 5.6.0 · 2 minor releases`.
    fn badge_line(verdict: Severity, diff: &DiffReportV1, naming: &Naming, prop: &Proportionality) -> String {
        let mut meta = String::new();
        if let (Some(o), Some(n)) = (&naming.old, &naming.new) {
            meta.push_str(&format!("   {} → {}", o.raw, n.raw));
            if let Some(b) = naming.bump {
                meta.push_str(&format!(" · {}", b.describe()));
            }
        }
        let total = diff.summary.files_changed
            + diff.summary.files_added
            + diff.summary.files_removed
            + diff.summary.files_unchanged;
        if total > 1 {
            meta.push_str(&format!(" · {} of {} files", diff.summary.files_changed, total));
        }
        let mut s = format!(
            " {}  {}{}",
            badge(verdict),
            naming.name.clone().bold(),
            meta.truecolor(102, 117, 127),
        );
        if prop.disproportionate {
            s.push_str(&format!(" {}", "· disproportionate".truecolor(255, 176, 46)));
        }
        s.push('\n');
        s
    }

    /// Twin-bar risk: `was`/`now` each on a benign→malware bar, jump called out.
    fn risk_twin(r: Risk) -> String {
        let d = r.delta();
        let (arrow, dsev) = if d > 0.005 {
            ("▲", risk_severity(r.new))
        } else if d < -0.005 {
            ("▼", Severity::None)
        } else {
            ("·", Severity::None)
        };
        format!(
            " {} {}\n    {}  {}  {}  {}\n    {}  {}  {}  {}   {}\n",
            "📊",
            "malware risk".truecolor(102, 117, 127),
            "was".truecolor(102, 117, 127),
            format!("{:.2}", r.old).truecolor(140, 150, 158),
            bar(r.old),
            risk_word(r.old),
            "now".truecolor(102, 117, 127),
            paint(risk_severity(r.new), &format!("{:.2}", r.new)).bold(),
            bar(r.new),
            risk_word(r.new),
            paint(dsev, &format!("{arrow} {d:+.2}")),
        )
    }

    fn bar(value: f32) -> String {
        let filled = (value * BAR as f32).round().clamp(0.0, BAR as f32) as usize;
        let sev = risk_severity(value);
        format!(
            "{}{}",
            paint(sev, &"█".repeat(filled)),
            "░".repeat(BAR - filled).truecolor(70, 80, 89),
        )
    }

    fn risk_word(p: f32) -> String {
        let (word, sev) = if p >= 0.90 {
            ("malware", Severity::Critical)
        } else if p >= 0.50 {
            ("suspicious", Severity::High)
        } else if p >= 0.15 {
            ("elevated", Severity::Medium)
        } else {
            ("benign", Severity::None)
        };
        if sev == Severity::None {
            word.truecolor(102, 117, 127).to_string()
        } else {
            paint(sev, word)
        }
    }

    // ── the detail grid ──────────────────────────────────────────────────────

    fn behavioral_grid(out: &mut String, a: &Assessment) {
        let (fresh, expanded): (Vec<_>, Vec<_>) = a
            .behavioral
            .categories
            .iter()
            .partition(|c| a.behavioral.is_new_category(c));
        class_group(out, &fresh, "new", PILL_PLUM, true);
        class_group(out, &expanded, "expanded", PILL_PLUM_DIM, false);
    }

    fn class_group(out: &mut String, cats: &[&crate::rubric::Category], label: &str, color: (u8, u8, u8), fresh: bool) {
        for (i, c) in cats.iter().enumerate() {
            let cell = if i == 0 { pill_cell(label, color) } else { blank_cell() };
            let name = pad_visible(&c.label.clone().bold().to_string(), &c.label, NAME_W);
            let body = format!("{name} {}{}", locator(c), count_str(c, fresh));
            out.push_str(&grid_line(&cell, &dots(c.severity), &body));
        }
    }

    /// The namespace locator: common prefix shown once, divergent tails listed.
    fn locator(c: &crate::rubric::Category) -> String {
        const MAX_TAILS: usize = 3;
        let refs: Vec<&str> = c.namespaces.iter().map(String::as_str).collect();
        let head = common_prefix(&refs);
        let mut tails: Vec<String> = c
            .namespaces
            .iter()
            .map(|p| strip_prefix_path(p, &head))
            .filter(|t| !t.is_empty())
            .collect();
        let overflow = tails.len().saturating_sub(MAX_TAILS);
        tails.truncate(MAX_TAILS);
        let mut s = head.clone().bold().to_string();
        if !tails.is_empty() {
            let joined = tails.join(&" · ".truecolor(70, 80, 89).to_string());
            s.push_str(&format!("/{joined}").truecolor(120, 134, 144).to_string());
        }
        if overflow > 0 {
            s.push_str(&format!(" +{overflow}").truecolor(102, 117, 127).to_string());
        }
        s
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
            format!("{base}  {}", format!("{}↑", c.escalated_ids.len()).truecolor(102, 117, 127))
        }
    }

    fn signature_grid(out: &mut String, a: &Assessment) {
        if a.signature.severity == Severity::None {
            return;
        }
        const MAX: usize = 4;
        let n = a.signature.ids.len();
        for (i, (sev, id, _)) in a.signature.ids.iter().take(MAX).enumerate() {
            let cell = if i == 0 { pill_cell("signature", PILL_HOT) } else { blank_cell() };
            let mut body = sig_name(id);
            if i == 0 && let Some(cve) = &a.signature.cve {
                body.push_str(&format!("   {}", paint(Severity::Critical, cve)));
            }
            out.push_str(&grid_line(&cell, &dots(*sev), &body));
        }
        if n > MAX {
            out.push_str(&grid_line(
                &blank_cell(),
                &"·  ".truecolor(102, 117, 127).to_string(),
                &format!("+{} more", n - MAX).truecolor(102, 117, 127).to_string(),
            ));
        }
    }

    fn identity_grid(out: &mut String, a: &Assessment) {
        if a.identity.severity == Severity::None {
            return;
        }
        for (i, ch) in a.identity.changes.iter().enumerate() {
            let cell = if i == 0 { pill_cell("identity", PILL_SLATE) } else { blank_cell() };
            let old = if ch.old.is_empty() { "none".to_string() } else { ch.old.clone() };
            let new = if ch.new.is_empty() { "none".to_string() } else { ch.new.clone() };
            let body = format!("{}: {} {} {}", ch.label, old, "→".truecolor(70, 80, 89), new.bold());
            out.push_str(&grid_line(&cell, &dots(a.identity.severity), &body));
        }
    }

    /// The evidence table — its own `member / locator / code / description`
    /// columns, kept separate from the capability grid above.
    pub(super) fn evidence_table(rows: &[Window]) -> String {
        if rows.is_empty() {
            return String::new();
        }
        let locw = rows.iter().map(|r| r.locator.chars().count()).max().unwrap_or(4);
        let codew = rows.iter().map(|r| r.code.chars().count()).max().unwrap_or(0).min(54);
        let mut out = format!("\n {}\n", pill_cell("evidence", PILL_OCEAN).trim_end());
        let mut last: Option<&str> = None;
        for r in rows {
            let member = r.member.as_deref();
            if member != last {
                if let Some(m) = member {
                    out.push_str(&format!("   {}\n", format!("📄 {m}").truecolor(120, 134, 144)));
                }
                last = member;
            }
            let loc = format!("{:>locw$}", r.locator, locw = locw);
            let code = format!("{:codew$}", r.code, codew = codew);
            let desc = if r.hostile {
                paint(Severity::Critical, &r.desc)
            } else {
                r.desc.truecolor(120, 134, 144).to_string()
            };
            out.push_str(&format!(
                "   {}  {}  {}\n",
                loc.truecolor(70, 80, 89),
                code.ink(),
                desc,
            ));
        }
        out
    }

    // ── grid + pill primitives ───────────────────────────────────────────────

    fn grid_line(cell: &str, dots: &str, body: &str) -> String {
        format!(" {cell}{dots} {body}\n")
    }

    fn pill_cell(label: &str, (r, g, b): (u8, u8, u8)) -> String {
        let p = format!(" {label} ").bold().white().on_truecolor(r, g, b).to_string();
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
        let changed: Vec<&FileDiffEntry> = diff
            .files
            .iter()
            .filter(|f| matches!(f.status, cleave::types::FileStatus::Changed))
            .collect();
        (changed.len() == 1).then(|| changed[0])
    }

    fn metrics_body(file: &FileDiffEntry) -> Option<String> {
        const FLOOR: f64 = 0.12;
        const KEEP: usize = 5;
        let m = file.scopes.metrics.as_ref()?;
        let mut movers: Vec<(f64, String)> = Vec::new();
        for c in &m.changed {
            // `load_segment_*` restate code size; `dependencies` and the loader
            // flag are named in the structure section — don't repeat them here.
            let p = &c.new.path;
            // `load_segment_*`/`size_bytes` restate other movers; `dependencies`
            // and the loader flag are named in the structure section.
            if p.contains("load_segment")
                || p.ends_with("size_bytes")
                || p.contains("dependencies")
                || p.contains("has_direct_loader_dep")
            {
                continue;
            }
            let (Some(o), Some(n)) = (num(&c.old.value), num(&c.new.value)) else {
                continue;
            };
            if o == n {
                continue;
            }
            let rel = if o != 0.0 { (n - o).abs() / o.abs() } else { f64::INFINITY };
            if rel < FLOOR {
                continue;
            }
            movers.push((rel, describe(&c.new.path, o, n)));
        }
        movers.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        // One row per label (the plain leading word), keeping the largest mover
        // — so `relacount` and `dynrela_count` collapse to a single `relocs`.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        movers.retain(|(_, s)| seen.insert(s.split(' ').next().unwrap_or("").to_string()));
        movers.truncate(KEEP);
        if movers.is_empty() {
            return None;
        }
        Some(
            movers
                .into_iter()
                .map(|(_, d)| d)
                .collect::<Vec<_>>()
                .join(&" · ".truecolor(102, 117, 127).to_string()),
        )
    }

    fn describe(path: &str, old: f64, new: f64) -> String {
        let leaf = path.rsplit(['.', '/']).next().unwrap_or(path);
        let label = if path.contains("dependencies") {
            "deps"
        } else {
            match leaf {
                "code_size" => "code",
                "size" | "size_bytes" => "size",
                "init_array_count" => "init_array",
                "dynrela_count" | "relacount" => "relocs",
                other => other,
            }
        };
        let rel = if old != 0.0 { (new - old).abs() / old.abs() } else { 1.0 };
        let sev = intensity_severity(rel);
        let value = if old > 0.0 && old.max(new) >= 8.0 {
            let arrow = if new >= old { "↑" } else { "↓" };
            format!("{arrow}{:.0}%", (new - old).abs() / old * 100.0)
        } else {
            format!("{old:.0}→{new:.0}")
        };
        format!("{label} {}", paint(sev, &value))
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

    fn num(v: &serde_json::Value) -> Option<f64> {
        v.as_f64()
    }

    fn common_prefix(paths: &[&str]) -> String {
        let Some(first) = paths.first() else {
            return String::new();
        };
        let mut prefix: Vec<&str> = first.split('/').collect();
        for p in &paths[1..] {
            let segs: Vec<&str> = p.split('/').collect();
            let keep = prefix.iter().zip(segs.iter()).take_while(|(a, b)| a == b).count();
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

    pub(super) fn sig_name(id: &str) -> String {
        if let Some((_, leaf)) = id.rsplit_once("::") {
            return leaf.to_string();
        }
        if let Some(rest) = id.strip_prefix("third_party/") {
            let segs: Vec<&str> = rest.split('/').collect();
            return match (segs.first(), segs.last()) {
                (Some(v), Some(l)) if segs.len() > 1 => format!("{v}/{l}"),
                (Some(v), _) => v.to_string(),
                _ => rest.to_string(),
            };
        }
        id.rsplit('/').next().unwrap_or(id).to_string()
    }

    // ── painters ─────────────────────────────────────────────────────────────

    const PILL_PLUM: (u8, u8, u8) = (60, 30, 75);
    const PILL_PLUM_DIM: (u8, u8, u8) = (44, 30, 52);
    const PILL_HOT: (u8, u8, u8) = (127, 43, 43);
    const PILL_TEAL: (u8, u8, u8) = (0, 60, 55);
    const PILL_OCEAN: (u8, u8, u8) = (12, 58, 75);
    const PILL_SLATE: (u8, u8, u8) = (55, 55, 58);

    fn badge(sev: Severity) -> String {
        let (word, (r, g, b)) = match sev {
            Severity::Critical => ("HOSTILE", (176, 46, 46)),
            Severity::High => ("SUSPICIOUS", (150, 105, 0)),
            Severity::Medium | Severity::Low => ("NOTABLE", (0, 90, 140)),
            Severity::None => ("CLEAN", (40, 110, 40)),
        };
        format!(" {word} ").bold().white().on_truecolor(r, g, b).to_string()
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

    fn paint(sev: Severity, text: &str) -> String {
        match sev {
            Severity::Critical => cleave::theme::paint_hostile(text).to_string(),
            Severity::High => cleave::theme::paint_suspicious(text).to_string(),
            Severity::Medium | Severity::Low => cleave::theme::paint_notable(text).to_string(),
            Severity::None => cleave::theme::paint_baseline(text).to_string(),
        }
    }

    /// Regular terminal-foreground text (evidence code, left plain).
    trait Ink {
        fn ink(&self) -> String;
    }
    impl Ink for String {
        fn ink(&self) -> String {
            self.truecolor(205, 214, 221).to_string()
        }
    }
}
