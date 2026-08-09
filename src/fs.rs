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
    let prop = Proportionality::eval(&assessment, &naming, diff);

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
                    let ctx = llm_context(&assessment, &naming, &prop, risk, new, &options).ok()?;
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
                let ctx = llm_context(&assessment, &naming, &prop, risk, new, &options).ok()?;
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
            let ctx = llm_context(&assessment, &naming, &prop, risk, new, &options)?;
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
    prop: &Proportionality,
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
    if let Some(n) = &prop.note {
        let _ = writeln!(s, "proportionality: {n}");
    }
    if let Some(n) = &prop.skew {
        let _ = writeln!(s, "change shape: {n}");
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
        for m in &a.signature.ids {
            let name = header::sig_name(&m.id);
            if m.desc.is_empty() {
                let _ = writeln!(s, "- [{}] {}", m.severity.as_str(), name);
            } else {
                let _ = writeln!(s, "- [{}] {} — {}", m.severity.as_str(), name, m.desc);
            }
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
        // An implant-shaped change (already gated on Medium+ behavior) always
        // deserves words.
        || prop.skew.is_some()
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

/// The two change-shape reads: behavioral drift vs the version bump's promise
/// (`disproportionate`/`note`), and behavioral drift vs content drift (`skew`).
struct Proportionality {
    disproportionate: bool,
    note: Option<String>,
    /// Behavioral change far outpacing content change — the implant tell. A
    /// rewrite moves both together; a surgical backdoor moves behavior on a
    /// small edit (xz: 99% of behavior on a ~20% content change).
    skew: Option<String>,
}

impl Proportionality {
    fn eval(a: &Assessment, naming: &Naming, diff: &DiffReportV1) -> Self {
        let skew = skew_note(a, diff);
        let (disproportionate, note) = match naming.bump {
            Some(bump) if a.behavioral.severity != Severity::None => {
                if a.behavioral.severity > bump.tolerance() {
                    (
                        true,
                        Some(format!(
                            "disproportionate — a {} bump gained a {}-severity capability",
                            bump.label(),
                            a.behavioral.severity.as_str()
                        )),
                    )
                } else {
                    (false, Some(format!("within tolerance for a {} bump", bump.label())))
                }
            }
            _ => (false, None),
        };
        Self { disproportionate, note, skew }
    }
}

/// Skew read over the per-scope rates of change: fires when the traits scope
/// (behavior) moved at least [`SKEW_RATIO`]× the mean of the content scopes and
/// a judged capability actually appeared. Calibrated on the bundled cases: the
/// xz backdoor sits at 4.5×; full rewrites (behavior and content moving
/// together) sit below 2.5×.
fn skew_note(a: &Assessment, diff: &DiffReportV1) -> Option<String> {
    const SKEW_RATIO: f32 = 3.0;
    let s = &diff.summary.scope_roc;
    let content: Vec<f32> = [s.metrics, s.kv, s.symbols, s.strings, s.sections]
        .into_iter()
        .filter(|r| *r > 0.0)
        .collect();
    if content.is_empty() || a.behavioral.severity < Severity::Medium {
        return None;
    }
    let mean = content.iter().sum::<f32>() / content.len() as f32;
    (s.traits >= 0.5 && s.traits >= mean * SKEW_RATIO).then(|| {
        format!(
            "surgical — {:.0}% of behavior changed on a {:.0}% content change",
            s.traits * 100.0,
            mean * 100.0,
        )
    })
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
        .map(|m| j::SigId { id: &m.id, desc: &m.desc, crit: m.severity.as_str(), new: m.is_new })
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
            before: w.before.as_deref(),
            after: w.after.as_deref(),
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
                skew: prop.skew.as_deref(),
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
        // One grid language throughout — every section is `pill · dots · body`
        // rows — and a blank line between sections so each triage question
        // (known campaign? who shipped it? what can it newly do?) reads as its
        // own block. Order: verdict, ML risk, attribution, identity,
        // capabilities, structure, metrics, touched files.
        let mut sections: Vec<String> = Vec::new();
        let mut head = badge_line(verdict, diff, naming);
        // Say *why* the change shape is wrong, not just that it is: behavioral
        // delta vs the version bump's promise, and behavior vs content skew.
        if prop.disproportionate && let Some(note) = &prop.note {
            head.push_str(&format!(" {} {}\n", "⚖", note.clone().truecolor(255, 176, 46)));
        }
        if let Some(skew) = &prop.skew {
            head.push_str(&format!(" {} {}\n", "⚖", skew.clone().truecolor(255, 176, 46)));
        }
        if let Some(i) = interp.filter(|i| !i.nature.trim().is_empty()) {
            head.push_str(&format!(" {} {}\n", "✨", i.nature.trim().truecolor(62, 207, 214)));
        }
        sections.push(head);
        if let Some(r) = risk {
            sections.push(risk_rows(r));
        }
        let mut section = String::new();
        signature_grid(&mut section, a);
        push_section(&mut sections, &mut section);
        identity_grid(&mut section, a);
        push_section(&mut sections, &mut section);
        behavioral_grid(&mut section, a);
        push_section(&mut sections, &mut section);
        structure_grid(&mut section, &a.structure);
        push_section(&mut sections, &mut section);
        if let Some(file) = single_changed_file(diff) {
            for (i, body) in metrics_rows(file).into_iter().enumerate() {
                let cell = if i == 0 { pill_cell("metrics", PILL_TEAL) } else { blank_cell() };
                section.push_str(&grid_line(&cell, "   ", &body));
            }
        }
        push_section(&mut sections, &mut section);
        files_grid(&mut section, diff);
        push_section(&mut sections, &mut section);
        out.push_str(&sections.join("\n"));
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
            let cell = if i == 0 { pill_cell("files", PILL_SLATE) } else { blank_cell() };
            out.push_str(&grid_line(&cell, "   ", &line.truecolor(150, 160, 168).to_string()));
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

    /// ` [ HOSTILE ]  liblzma.so   5.4.5 → 5.6.0 · 2 minor releases · 35% changed`.
    fn badge_line(verdict: Severity, diff: &DiffReportV1, naming: &Naming) -> String {
        let mut meta = String::new();
        if let (Some(o), Some(n)) = (&naming.old, &naming.new) {
            meta.push_str(&format!("   {} → {}", o.raw, n.raw));
            if let Some(b) = naming.bump {
                meta.push_str(&format!(" · {}", b.describe()));
            }
        }
        // For a container, the summary's root entry restates the container
        // itself — drop it so the count matches the `files` member list.
        let mut touched =
            (diff.summary.files_changed + diff.summary.files_added + diff.summary.files_removed) as usize;
        let mut total = touched + diff.summary.files_unchanged as usize;
        if diff.files.iter().any(|f| f.path.contains("!!")) {
            touched = touched.saturating_sub(1);
            total = total.saturating_sub(1);
        }
        if total > 1 {
            meta.push_str(&format!(" · {touched} of {total} files"));
        }
        // The content-change scale — one of the three legs (content, behavior,
        // metrics) the report separates; the other two get their own sections.
        let roc = diff.summary.overall_roc;
        if roc > 0.005 {
            meta.push_str(&format!(" · {:.0}% changed", f64::from(roc) * 100.0));
        }
        format!(
            " {}  {}{}\n",
            badge(verdict),
            naming.name.clone().bold(),
            meta.truecolor(102, 117, 127),
        )
    }

    /// The ML detector as a grid section: `was`/`now` each on a benign→malware
    /// bar, the jump called out on the `now` row.
    fn risk_rows(r: Risk) -> String {
        let d = r.delta();
        let (arrow, dsev) = if d > 0.005 {
            ("▲", risk_severity(r.new))
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
            paint(risk_severity(r.new), &format!("{:.2}", r.new)).bold(),
            bar(r.new),
            risk_word(r.new),
            paint(dsev, &format!("{arrow} {d:+.2}")),
        );
        let mut s = grid_line(&pill_cell("risk", PILL_OCEAN), "   ", &was);
        s.push_str(&grid_line(&blank_cell(), "   ", &now));
        s
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
        /// A namespace list short enough to sit inline after the class name.
        const INLINE: usize = 52;
        /// Wrap width for namespace continuation lines.
        const WRAP: usize = 58;
        for (i, c) in cats.iter().enumerate() {
            let cell = if i == 0 { pill_cell(label, color) } else { blank_cell() };
            let name = pad_visible(&c.label.clone().bold().to_string(), &c.label, NAME_W);
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
                let mut loc = head.clone().bold().to_string();
                if !tails.is_empty() {
                    let sep = if head.is_empty() { "" } else { "/" };
                    loc.push_str(&format!("{sep}{}", tails.join(" · ")).truecolor(120, 134, 144).to_string());
                }
                let body = format!("{name} {loc}{}", count_str(c, fresh));
                out.push_str(&grid_line(&cell, &dots(c.severity), &body));
            } else {
                // Too many namespaces for one line: the shared prefix and count
                // up top, every tail wrapped beneath — nothing hidden.
                let body = format!("{name} {}{}", head.clone().bold(), count_str(c, fresh));
                out.push_str(&grid_line(&cell, &dots(c.severity), &body));
                let items = if tails.is_empty() { c.namespaces.clone() } else { tails };
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
            format!("{base}  {}", format!("{}↑", c.escalated_ids.len()).truecolor(102, 117, 127))
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
        // with the rule id as dim provenance after it.
        let descs: Vec<String> = shown.iter().map(|m| clip(&m.desc, DESC_W)).collect();
        let descw = descs.iter().map(|d| d.chars().count()).max().unwrap_or(0);
        for (i, m) in shown.iter().enumerate() {
            let cell = if i == 0 { pill_cell("signature", PILL_HOT) } else { blank_cell() };
            let name = sig_name(&m.id);
            let mut body = if descs[i].is_empty() {
                name
            } else {
                format!(
                    "{} {}",
                    pad_visible(&descs[i], &descs[i], descw),
                    name.truecolor(102, 117, 127),
                )
            };
            if i == 0 && let Some(cve) = &a.signature.cve {
                body.push_str(&format!("   {}", paint(Severity::Critical, cve)));
            }
            out.push_str(&grid_line(&cell, &dots(m.severity), &body));
        }
        if n > MAX {
            out.push_str(&grid_line(
                &blank_cell(),
                &"·  ".truecolor(102, 117, 127).to_string(),
                &format!("+{} more", n - MAX).truecolor(102, 117, 127).to_string(),
            ));
        }
    }

    /// Char-aware clip with a trailing ellipsis.
    fn clip(s: &str, max: usize) -> String {
        if s.chars().count() <= max {
            return s.to_string();
        }
        let kept: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
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

    /// The evidence table — `locator / code / description` in file order, with
    /// the neighboring source lines dimmed around hostile matches and `⋯`
    /// marking the gaps between non-contiguous runs.
    pub(super) fn evidence_table(rows: &[Window]) -> String {
        if rows.is_empty() {
            return String::new();
        }
        // The locator column must also fit the context rows' line ± 1.
        let locw = rows
            .iter()
            .map(|r| match r.line {
                Some(l) => (l + 1).to_string().chars().count(),
                None => r.locator.chars().count(),
            })
            .max()
            .unwrap_or(4);
        let codew = rows
            .iter()
            .map(|r| r.code.chars().count())
            .max()
            .unwrap_or(0)
            .min(crate::evidence::CODE_W + 2);
        let mut out = format!("\n {}\n", pill_cell("evidence", PILL_OCEAN).trim_end());
        let mut last_member: Option<&str> = None;
        // Last printed source line, for gap markers and overlap suppression.
        let mut printed: Option<u64> = None;
        let mut any = false;
        for r in rows {
            let member = r.member.as_deref();
            if member != last_member {
                if let Some(m) = member {
                    if any {
                        out.push('\n');
                    }
                    out.push_str(&format!("   {}\n", format!("📄 {m}").truecolor(120, 134, 144)));
                }
                last_member = member;
                printed = None;
            }
            any = true;
            let Some(line) = r.line else {
                // Binary window: a single hex row, no line bookkeeping.
                match_row(&mut out, &r.locator, r, locw, codew);
                printed = None;
                continue;
            };
            let first_shown = line - u64::from(r.before.is_some());
            if printed.is_some_and(|p| first_shown > p + 1) {
                let gap = format!("{:>locw$}", "⋯", locw = locw);
                out.push_str(&format!("   {}\n", gap.truecolor(70, 80, 89)));
            }
            if let Some(b) = &r.before
                && printed.is_none_or(|p| line - 1 > p)
            {
                context_row(&mut out, line - 1, b, locw);
            }
            match_row(&mut out, &line.to_string(), r, locw, codew);
            printed = Some(line);
            if let Some(a) = &r.after {
                context_row(&mut out, line + 1, a, locw);
                printed = Some(line + 1);
            }
        }
        out
    }

    /// One matched evidence line: locator, code, rule description.
    fn match_row(out: &mut String, locator: &str, r: &Window, locw: usize, codew: usize) {
        let loc = format!("{:>locw$}", locator, locw = locw);
        let code = format!("{:codew$}", r.code, codew = codew);
        let desc = if r.hostile {
            paint(Severity::Critical, &r.desc)
        } else {
            r.desc.truecolor(120, 134, 144).to_string()
        };
        out.push_str(&format!("   {}  {}  {}\n", loc.truecolor(70, 80, 89), code.ink(), desc));
    }

    /// One dimmed context line around a hostile match.
    fn context_row(out: &mut String, line: u64, text: &str, locw: usize) {
        let loc = format!("{:>locw$}", line, locw = locw);
        out.push_str(&format!(
            "   {}  {}\n",
            loc.truecolor(70, 80, 89),
            text.truecolor(102, 117, 127),
        ));
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

    /// Grid bodies for the metric movers, one per row: `label  value`, largest
    /// relative change first.
    fn metrics_rows(file: &FileDiffEntry) -> Vec<String> {
        const FLOOR: f64 = 0.12;
        const KEEP: usize = 5;
        let Some(m) = file.scopes.metrics.as_ref() else {
            return Vec::new();
        };
        let mut movers: Vec<(f64, String, String)> = Vec::new();
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
            let (label, value) = describe(&c.new.path, o, n);
            movers.push((rel, label, value));
        }
        movers.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        // One row per label, keeping the largest mover — so `relacount` and
        // `dynrela_count` collapse to a single `relocs`.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        movers.retain(|(_, label, _)| seen.insert(label.clone()));
        movers.truncate(KEEP);
        movers
            .into_iter()
            .map(|(_, label, value)| {
                let painted = label.clone().truecolor(150, 160, 168).to_string();
                format!("{} {value}", pad_visible(&painted, &label, NAME_W))
            })
            .collect()
    }

    /// `(label, painted value)` for one metric change.
    fn describe(path: &str, old: f64, new: f64) -> (String, String) {
        let leaf = path.rsplit(['.', '/']).next().unwrap_or(path);
        let label = match leaf {
            "code_size" => "code",
            "size" | "size_bytes" => "size",
            "init_array_count" => "init_array",
            "dynrela_count" | "relacount" => "relocs",
            other => other,
        };
        let rel = if old != 0.0 { (new - old).abs() / old.abs() } else { 1.0 };
        let sev = intensity_severity(rel);
        let value = if old > 0.0 && old.max(new) >= 8.0 {
            let arrow = if new >= old { "↑" } else { "↓" };
            format!("{arrow}{:.0}%", (new - old).abs() / old * 100.0)
        } else {
            format!("{}→{}", fmt_num(old), fmt_num(new))
        };
        (label.to_string(), paint(sev, &value))
    }

    /// Whole numbers plain, fractional ones with two decimals — so a ratio like
    /// `0.28 → 0.05` never rounds to the meaningless `0→0`.
    fn fmt_num(v: f64) -> String {
        if v == v.trunc() { format!("{v:.0}") } else { format!("{v:.2}") }
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
