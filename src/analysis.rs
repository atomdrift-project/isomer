//! One differential analysis, shared by every output format.
//!
//! cleave's `diff_paths` measures the change (six scopes); [`crate::rubric`]
//! judges it; [`crate::version`] supplies proportionality; [`crate::risk`]
//! scores both sides with the ML model. This module runs that pipeline exactly
//! once and hands the result to a renderer — the terminal grid, the JSON
//! envelope, the SARIF file, or the PR-comment markdown.
//!
//! Running it once is the whole point: `isomer ci` emits four sinks from a
//! single scan, and analysis is the expensive part.

use std::cell::OnceCell;
use std::path::Path;

use anyhow::{Context, Result};
use cleave::types::{AnalysisReport, DiffReportV1};

use crate::evidence::Hunk;
use crate::rubric::Assessment;
use crate::version::{Bump, Version};
use crate::{Cli, Format, Gate, Severity};

/// Run cleave's differential analysis over a pair of paths.
pub(crate) fn diff(
    old: &Path,
    new: &Path,
    options: &cleave::AnalysisOptions,
) -> Result<AnalysisReport> {
    cleave::diff::diff_paths(
        old,
        new,
        options,
        cleave::diff::ScopeMask::all(),
        cleave::diff::DEFAULT_LIMIT_CHANGES,
    )
}

/// How much of a change a run actually looked at.
///
/// Reported so a reader never has to assume. A pull request whose base build
/// failed still produces a verdict — but only over the source, and a report
/// that did not say so would read exactly like one that compared both builds
/// and found nothing wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The committed change, and nothing built from it.
    Source,
    /// The committed change plus the build outputs of both sides.
    SourceAndBuild,
}

impl Scope {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Source => "source only",
            Self::SourceAndBuild => "source + build output",
        }
    }
}

/// One file's two sides, named the way a reader should see it.
///
/// A comparison is a *set* of these: `fs` on two files has one, `ci` on a pull
/// request has one per changed file. Deep analysis (evidence, ML risk, base
/// capabilities) is per file, so it needs the pairing that the two root paths
/// alone don't carry. Either side may be absent — a file added by the change
/// has no old side, a deleted one has no new side.
#[derive(Debug)]
pub(crate) struct Pair {
    /// How the file is named in output: repo-relative under `ci`, the
    /// basename under `fs`.
    pub label: String,
    pub old: Option<std::path::PathBuf>,
    pub new: Option<std::path::PathBuf>,
}

impl Pair {
    /// Pairs for a two-root comparison: the roots themselves when both sides
    /// are single files (cleave pairs them by canonical root, whatever they
    /// are named), otherwise one pair per file the diff reports as touched.
    fn from_roots(old: &Path, new: &Path, diff: &DiffReportV1) -> Vec<Self> {
        if old.is_file() && new.is_file() {
            return vec![Self {
                label: basename(new),
                old: Some(old.to_path_buf()),
                new: Some(new.to_path_buf()),
            }];
        }
        diff.files
            .iter()
            .filter(|f| !matches!(f.status, cleave::types::FileStatus::Unchanged))
            // Archive members are decomposed by the analysis of their
            // container, which has its own pair; pairing them again would
            // double-count and point at paths that don't exist on disk.
            .filter(|f| !f.path.contains("!!"))
            .map(|f| Self {
                label: f.path.clone(),
                old: existing(old.join(&f.path)),
                new: existing(new.join(&f.path)),
            })
            .collect()
    }
}

fn existing(p: std::path::PathBuf) -> Option<std::path::PathBuf> {
    p.is_file().then_some(p)
}

/// Trait atoms that moved on one file, worst criticality first. Added and
/// removed together — a reviewer wants both directions of a source change.
fn trait_atoms(entry: &cleave::types::FileDiffEntry) -> Vec<Atom> {
    let Some(traits) = entry.scopes.traits.as_ref() else {
        return Vec::new();
    };
    let mut atoms: Vec<Atom> = traits
        .added
        .iter()
        .map(|t| (true, t))
        .chain(traits.removed.iter().map(|t| (false, t)))
        .map(|(gained, t)| Atom {
            id: t.id.clone(),
            desc: t.desc.clone(),
            crit: t.crit,
            gained,
        })
        .collect();
    atoms.sort_by(|a, b| {
        crate::rubric::crit_rank(b.crit)
            .cmp(&crate::rubric::crit_rank(a.crit))
            .then(a.id.cmp(&b.id))
    });
    atoms
}

/// A full line diff of two text files: `+` for a line only on the new side,
/// `-` for one only on the old, a space for context. Set-based (not
/// positional), so a moved line reads as context and the output is
/// order-independent — enough for an LLM to see exactly what text entered or
/// left. Control chars are neutralized; the total is line-capped so one large
/// file can't blow the context budget.
fn line_diff(old: &[u8], new: &[u8]) -> String {
    use std::collections::HashSet;
    use std::fmt::Write as _;
    const MAX_LINES: usize = 400;

    let old_text = String::from_utf8_lossy(old);
    let new_text = String::from_utf8_lossy(new);
    let old_set: HashSet<&str> = old_text.lines().map(str::trim_end).collect();
    let new_set: HashSet<&str> = new_text.lines().map(str::trim_end).collect();

    let mut s = String::new();
    let new_lines: Vec<&str> = new_text.lines().collect();
    for line in new_lines.iter().take(MAX_LINES) {
        let mark = if old_set.contains(line.trim_end()) {
            ' '
        } else {
            '+'
        };
        let _ = writeln!(s, "{mark} {}", crate::printable(line));
    }
    if new_lines.len() > MAX_LINES {
        let _ = writeln!(s, "  … (diff truncated)");
    }
    for line in old_text
        .lines()
        .filter(|l| !new_set.contains(l.trim_end()))
        .take(MAX_LINES)
    {
        let _ = writeln!(s, "- {}", crate::printable(line));
    }
    s
}

/// The cleave diff plus everything isomer derived from it.
///
/// Borrows the (large) cleave report rather than owning it, so the caller
/// produces it once and every renderer reads the same copy.
pub(crate) struct Analysis<'a> {
    /// The surface that produced this analysis, e.g. `fs` or `ci`.
    pub verb: &'static str,
    pub options: &'a cleave::AnalysisOptions,
    pub report: &'a AnalysisReport,
    pub diff: &'a DiffReportV1,
    /// The changed files, each with both sides — what deep analysis runs over.
    pub pairs: Vec<Pair>,
    /// What each side exhibits: base capability classes, and the ATT&CK / MBC
    /// ids present before and after.
    pub survey: crate::evidence::Survey,
    pub assessment: Assessment,
    pub naming: Naming,
    pub prop: Proportionality,
    pub risk: Option<crate::risk::Risk>,
    /// Worst of the rubric axes and the *current* ML risk band — "how bad is
    /// it now".
    pub verdict: Severity,
    /// Newly-introduced risk only (rubric-new ∪ an ML band jump) — the axis
    /// `--gate new` acts on.
    pub new_verdict: Severity,
    /// The severity the active `--gate` compares against `--fail-on`.
    pub gated: Severity,
    /// Whether the run passes at `--fail-on`.
    pub clean: bool,
    /// Optional `--llm` read of the change.
    pub interp: Option<crate::llm::Interpretation>,
    /// What the comparison actually covered. A verb fills this in when it
    /// knows; `None` means the surface has nothing useful to say about scope
    /// (`fs` compares two paths the caller named, so "source" would be a lie).
    pub scope: Option<Scope>,
    /// Profiles of the dependencies this change added — what each can do,
    /// attributed to the dependency. Empty unless `--deps` was requested; a
    /// verb fills it after construction, since it is a separate network step.
    pub deps: Vec<crate::deps::DepProfile>,
    /// Evidence hunks, ranked strongest-first, computed on first use.
    ///
    /// Collecting them re-analyzes every changed file, and `ci` renders four
    /// formats from one analysis — so this is computed at most once per run,
    /// and not at all for a run with nothing to show.
    hunks: OnceCell<Vec<Hunk>>,
    /// Source files whose traits moved, with the atoms and a full line diff —
    /// the signal the Notable finding floor drops. Reads both sides from disk,
    /// so it is computed at most once per run.
    source_changes: OnceCell<Vec<SourceChange>>,
}

/// A source-language file whose behavior-bearing traits changed between the two
/// sides. Carries what the strict rubric discards: the sub-Notable atoms that
/// moved (a `$HOME` read, a base64 heredoc) and a full line diff. An attack
/// composed entirely of individually-innocent atoms — no single trait reaching
/// the finding floor — leaves its whole fingerprint here.
#[derive(Debug)]
pub(crate) struct SourceChange {
    /// How the file is named in output.
    pub label: String,
    /// Trait atoms that appeared or vanished, worst criticality first. Includes
    /// the baseline/component tiers [`crate::rubric::is_finding`] filters out.
    pub atoms: Vec<Atom>,
    /// Full line diff of the file (`+` added, `-` removed), for the LLM.
    pub diff: String,
}

/// One trait that appeared or vanished on a source file.
#[derive(Debug)]
pub(crate) struct Atom {
    pub id: String,
    pub desc: String,
    pub crit: cleave::Criticality,
    /// True when the trait is present on the new side but not the old.
    pub gained: bool,
}

impl<'a> Analysis<'a> {
    /// Judge a completed cleave diff.
    pub(crate) fn new(
        verb: &'static str,
        old: &'a Path,
        new: &'a Path,
        options: &'a cleave::AnalysisOptions,
        report: &'a AnalysisReport,
        cli: &Cli,
    ) -> Result<Self> {
        let diff = report
            .diff
            .as_ref()
            .context("diff_paths returned a report without a diff")?;

        let pairs = Pair::from_roots(old, new, diff);

        // One walk over both sides: the base's capability classes (so a wholly
        // new class is distinguishable from one that merely gained a trait)
        // and the ATT&CK / MBC annotations each side carries.
        let survey = crate::evidence::survey(&pairs, options);
        let assessment = crate::rubric::assess(diff, &survey.base_classes);
        let naming = Naming::resolve(old, new, cli);
        let prop = Proportionality::eval(&assessment, &naming, diff);

        // Azoth ML risk is the *primary* detector: a jump into a worse band
        // drives the verdict on its own, even when no trait or signature
        // fired. `None` when no model is available — then the hand-coded
        // rubric stands alone.
        let risk = crate::risk::score(&pairs);
        let risk_now = risk.map_or(Severity::None, |r| risk_band(r.new));
        let risk_jump = risk.map_or(Severity::None, |r| {
            if risk_band(r.new) > risk_band(r.old) {
                risk_band(r.new)
            } else {
                Severity::None
            }
        });

        let verdict = assessment.severity.max(risk_now);
        let new_verdict = assessment.new_severity().max(risk_jump);
        let gated = match cli.gate {
            Gate::New => new_verdict,
            Gate::Any => verdict,
        };

        let mut a = Self {
            verb,
            options,
            report,
            diff,
            pairs,
            survey,
            assessment,
            naming,
            prop,
            risk,
            verdict,
            new_verdict,
            gated,
            clean: !gated.fails(cli.fail_on),
            interp: None,
            scope: None,
            deps: Vec::new(),
            hunks: OnceCell::new(),
            source_changes: OnceCell::new(),
        };
        // The LLM read is asked for only when there is a change worth
        // describing — a silent diff has nothing to interpret, and the call
        // costs a round trip. Failures log and never block the verdict.
        if a.speaks(cli)
            && let Some(cfg) = crate::llm::config(cli)
        {
            a.interp = match crate::llm::interpret(&cfg, &a.llm_context()) {
                Ok(i) => Some(i),
                Err(e) => {
                    eprintln!("isomer: llm interpretation failed: {e:#}");
                    None
                }
            };
        }
        Ok(a)
    }

    /// Render one output format.
    pub(crate) fn render(&self, format: Format, cli: &Cli) -> Result<String> {
        match format {
            Format::Terminal => Ok(crate::terminal::report(self, cli)),
            Format::Json => Ok(format!("{}\n", self.json(cli)?)),
            Format::Markdown => Ok(crate::markdown::report(self, cli)),
            Format::Sarif => Ok(format!("{}\n", crate::sarif::report(self)?)),
            Format::Interpret => Ok(format!("{}\n", self.llm_context())),
        }
    }

    /// Whether there is anything worth saying.
    ///
    /// Everything the rubric measures is *change* — a finding present
    /// unchanged on both sides never enters the diff — so an assessment
    /// reaching Notable means this change introduced something worth naming,
    /// hostile or not. Saying so is also how a reviewer knows the scanner is
    /// alive between real incidents; keeping it [`brief`](Self::detailed) is
    /// what stops that from becoming noise. A run with nothing to report still
    /// says nothing at all.
    pub(crate) fn speaks(&self, cli: &Cli) -> bool {
        cli.explain
            || self.gated.fails(cli.fail_on)
            // Notable+ is the reporting floor; the tiers below it are atoms
            // and unremarkable observations (see `rubric::is_finding`).
            || self.assessment.severity >= Severity::Medium
            || self.risk_band_moved()
            || self.prop.disproportionate
            // An implant-shaped change always deserves words.
            || self.prop.skew.is_some()
            // Gained external code — a runtime dependency or a new/moved
            // GitHub Action — is a supply-chain event worth surfacing on its
            // own, even when it stays below the gate.
            || self.assessment.structure.adds_external_code()
            // A source file that gained behavior-bearing atoms below the finding
            // floor (a `$HOME` read, a base64 heredoc) changed how it behaves
            // even when no single trait rose to a finding. Say so — a silent
            // verdict on a file that plainly gained obfuscation is the exact
            // blind spot an atom-composed attack aims for.
            || !self.observations().is_empty()
    }

    /// Whether to render the full report — grid, metrics, touched files, and
    /// evidence — rather than the short "here is what we noticed" form. Only a
    /// change that actually fails the gate has earned a reviewer's full
    /// attention; everything else gets a few lines.
    pub(crate) fn detailed(&self, cli: &Cli) -> bool {
        cli.explain || !self.clean
    }

    /// Whether the model's read moved between risk bands, in either direction.
    /// A drop matters too: it is how a reviewer sees that a fix landed.
    pub(crate) fn risk_band_moved(&self) -> bool {
        self.risk
            .is_some_and(|r| risk_band(r.new) != risk_band(r.old))
    }

    /// The judgement, in one line, before any detail. What a reader wants
    /// first is not what changed, but what isomer makes of it.
    pub(crate) fn judgement(&self) -> String {
        if !self.clean {
            return self.headline();
        }
        let noted = self.assessment.behavioral.categories.len()
            + self.assessment.signature.ids.len()
            + self.assessment.identity.changes.len()
            + self.assessment.structure.facts.len();
        match (noted, self.risk_band_moved()) {
            (0, false) => "no behavioral change".to_string(),
            (0, true) => "no new capabilities, but the model reads this differently".to_string(),
            (n, _) => format!(
                "nothing that fails the gate — {n} change{} worth a look",
                if n == 1 { "" } else { "s" },
            ),
        }
    }

    /// The strongest `limit` evidence hunks behind the verdict, in file order.
    pub(crate) fn hunks(&self, limit: usize) -> Vec<&Hunk> {
        let all = self.hunks.get_or_init(|| {
            crate::evidence::hunks(&self.pairs, self.options, &self.assessment.gained_ids())
        });
        crate::evidence::strongest(all, limit)
    }

    /// Source files whose traits moved, each with the atoms and a full line
    /// diff. Computed once and memoized (both sides are read from disk).
    ///
    /// This is the seam that keeps a diff from going silent when an attack is
    /// composed of individually-innocent atoms: no single trait reaches the
    /// Notable finding floor, so the rubric surfaces nothing, but the file still
    /// *changed behavior* — and here that change is captured whole, both for the
    /// [`observations`](Self::observations) a reviewer sees and for the full
    /// diff the LLM reads.
    pub(crate) fn source_changes(&self) -> &[SourceChange] {
        self.source_changes
            .get_or_init(|| self.collect_source_changes())
    }

    /// Walk the pairs, keeping the source-language files whose trait scope
    /// changed, and pair each with the atoms that moved and a line diff.
    fn collect_source_changes(&self) -> Vec<SourceChange> {
        use cleave::types::FileStatus;
        // A single-file `fs` comparison names its one diff entry `<root>`, not
        // the basename, so it can't be matched to the pair by path — but there
        // is only one pair, so the lone changed entry is unambiguously its.
        let single = self.pairs.len() == 1;
        let mut out = Vec::new();
        for pair in &self.pairs {
            let (Some(old), Some(new)) = (pair.old.as_deref(), pair.new.as_deref()) else {
                continue;
            };
            let Some(entry) = self.diff.files.iter().find(|f| {
                !matches!(f.status, FileStatus::Unchanged)
                    && (single || f.path == pair.label)
                    && f.scopes
                        .traits
                        .as_ref()
                        .is_some_and(|t| !t.added.is_empty() || !t.removed.is_empty())
            }) else {
                continue;
            };
            // Cheap fileid (no full parse) on the new side decides source-ness;
            // manifests (package.json) are structured data, not a source
            // language, and are covered by the dependency path instead.
            let Ok(new_bytes) = std::fs::read(new) else {
                continue;
            };
            if !filefacts::FileId::from_path_and_bytes(new, &new_bytes)
                .file_type()
                .is_source_code()
            {
                continue;
            }
            let old_bytes = std::fs::read(old).unwrap_or_default();
            out.push(SourceChange {
                label: pair.label.clone(),
                atoms: trait_atoms(entry),
                diff: line_diff(&old_bytes, &new_bytes),
            });
        }
        out
    }

    /// The gained sub-Notable atoms across every changed source file — the
    /// behavioral changes the rubric dropped, for the report's observations
    /// line. Findings (Notable+) are already named as capability classes, so
    /// they are excluded here to avoid saying the same thing twice.
    pub(crate) fn observations(&self) -> Vec<&Atom> {
        self.source_changes()
            .iter()
            .flat_map(|c| &c.atoms)
            .filter(|a| a.gained && !crate::rubric::is_finding(a.crit))
            .collect()
    }

    /// The one-line reason a reader needs first: why the change is judged the
    /// way it is. Prefers the LLM read, then the proportionality note, then
    /// the worst capability class.
    pub(crate) fn headline(&self) -> String {
        if let Some(i) = self.interp.as_ref().filter(|i| !i.nature.trim().is_empty()) {
            return i.nature.trim().to_string();
        }
        if let Some(note) = self
            .prop
            .note
            .as_ref()
            .filter(|_| self.prop.disproportionate)
        {
            return note.clone();
        }
        if let Some(skew) = &self.prop.skew {
            return skew.clone();
        }
        if let Some(c) = self.assessment.behavioral.categories.first() {
            let verb = if self.assessment.behavioral.is_new_category(c) {
                "gained"
            } else {
                "expanded"
            };
            return format!("{verb} {}", c.label);
        }
        if let Some(s) = self.assessment.signature.ids.first() {
            return format!(
                "matched a known-bad rule — {}",
                crate::rubric::short_name(&s.id)
            );
        }
        if let Some(f) = self.assessment.structure.facts.first() {
            return format!("{}: {}", f.label, f.detail);
        }
        "no behavioral change".to_string()
    }

    /// Build the plain-text payload describing the diff, sent to the LLM (and
    /// shown verbatim by `--format interpret`). No color, no rail — just the
    /// structured behavioral delta plus the matched code/bytes.
    pub(crate) fn llm_context(&self) -> String {
        use std::fmt::Write as _;
        let (a, naming, prop) = (&self.assessment, &self.naming, &self.prop);
        let mut s = String::new();
        let _ = writeln!(s, "artifact: {}", naming.name);
        if let (Some(o), Some(n)) = (&naming.old, &naming.new) {
            let bump = naming
                .bump
                .map(|b| format!(" ({})", b.describe()))
                .unwrap_or_default();
            let _ = writeln!(s, "version: {} -> {}{bump}", o.raw, n.raw);
        }
        if let Some(r) = self.risk {
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
                let _ = writeln!(
                    s,
                    "- {} [{}]: {} ({} new traits)",
                    c.label,
                    c.severity.as_str(),
                    c.namespaces.join(", "),
                    c.new_ids.len()
                );
            }
        }
        if !expanded.is_empty() {
            let _ = writeln!(
                s,
                "\nEXPANDED capability classes (already present in old version):"
            );
            for c in &expanded {
                let _ = writeln!(
                    s,
                    "- {} [{}]: {} (+{} traits)",
                    c.label,
                    c.severity.as_str(),
                    c.namespaces.join(", "),
                    c.new_ids.len()
                );
            }
        }
        if a.signature.severity != Severity::None {
            let _ = writeln!(s, "\nknown-bad signatures matched:");
            for m in &a.signature.ids {
                let name = crate::rubric::short_name(&m.id);
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
        if !a.structure.facts.is_empty() {
            let _ = writeln!(
                s,
                "\nstructural changes (raw binary facts, no rule needed):"
            );
            for f in &a.structure.facts {
                let kind = match f.kind {
                    crate::rubric::FactKind::Added => "new",
                    crate::rubric::FactKind::Became => "became",
                };
                let _ = writeln!(
                    s,
                    "- [{}] {kind} {}: {}",
                    f.severity.as_str(),
                    f.label,
                    f.detail
                );
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

        // Compact evidence — the matched rows and their descriptions, not the
        // full surrounding dump; keeps the payload focused and the token cost
        // bounded.
        let ev = crate::evidence::render(&self.pairs, self.options, &a.gained_ids(), true);
        if !ev.trim().is_empty() {
            let _ = writeln!(s, "\nchanged code / bytes (matched by rules):");
            s.push_str(ev.trim_end());
            s.push('\n');
        }

        // The full source diff for every changed source file — the payload's
        // safety net. The sections above are what the rubric *matched*; a novel
        // attack composed of innocent atoms matches nothing, so without this the
        // model would be asked to judge a change it cannot see. Sub-Notable
        // atoms are named first as reading hints, then the diff itself.
        let changes = self.source_changes();
        if !changes.is_empty() {
            let _ = writeln!(
                s,
                "\nsource diffs (full text of every file whose behavior-bearing traits changed):"
            );
            for c in changes {
                let hints: Vec<&str> = c
                    .atoms
                    .iter()
                    .filter(|at| at.gained && !crate::rubric::is_finding(at.crit))
                    .map(|at| at.desc.as_str())
                    .filter(|d| !d.is_empty())
                    .collect();
                let _ = writeln!(s, "\n--- {} ---", c.label);
                if !hints.is_empty() {
                    let _ = writeln!(s, "(new sub-finding atoms: {})", hints.join("; "));
                }
                s.push_str(c.diff.trim_end());
                s.push('\n');
            }
        }
        s
    }

    /// Build the `--format json` envelope. Compact and typed, mirroring
    /// `../scan`: a curated `verdict` and its evidence beside the full `raw`
    /// cleave diff. See [`crate::json`].
    pub(crate) fn json(&self, cli: &Cli) -> Result<String> {
        use crate::json as j;
        let a = &self.assessment;
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
            .map(|m| j::SigId {
                id: &m.id,
                desc: &m.desc,
                crit: m.severity.as_str(),
                new: m.is_new,
            })
            .collect();
        let facts = a
            .structure
            .facts
            .iter()
            .map(|f| j::Fact {
                severity: f.severity.as_str(),
                change: match f.kind {
                    crate::rubric::FactKind::Added => "added",
                    crate::rubric::FactKind::Became => "became",
                },
                label: f.label,
                detail: &f.detail,
            })
            .collect();
        let changes = a
            .identity
            .changes
            .iter()
            .map(|c| j::IdChange {
                field: c.label,
                old: &c.old,
                new: &c.new,
            })
            .collect();

        // The proof hunks and the full identity claims — everything the UI and
        // the CLI cache need to redraw without re-reading the artifact.
        let hunks = self.hunks(EVIDENCE_JSON_CAP);
        let evidence = hunks
            .iter()
            .map(|h| j::Ev {
                member: h.member.as_deref(),
                location: &h.location,
                severity: h.severity.as_str(),
                desc: &h.desc,
                lines: h
                    .lines
                    .iter()
                    .map(|l| j::EvLine {
                        locator: &l.locator,
                        text: &l.text,
                        added: l.added,
                        is_match: l.is_match,
                    })
                    .collect(),
            })
            .collect();
        let provenance = self
            .diff
            .files
            .iter()
            .find_map(|f| f.identity.as_ref())
            .map_or((None, None), |idd| (idd.old.as_ref(), idd.new.as_ref()));

        let envelope = j::Envelope {
            v: "1",
            eng: concat!("isomer/", env!("CARGO_PKG_VERSION")),
            verb: self.verb,
            artifact: (!self.naming.name.is_empty()).then_some(self.naming.name.as_str()),
            version: j::Version {
                old: self.naming.old.as_ref().map(|v| v.raw.as_str()),
                new: self.naming.new.as_ref().map(|v| v.raw.as_str()),
                bump: self.naming.bump.map(Bump::label),
            },
            provenance: j::Provenance {
                old: provenance.0,
                new: provenance.1,
            },
            verdict: j::Verdict {
                severity: self.verdict.as_str(),
                new_severity: self.new_verdict.as_str(),
                gate: j::Gate {
                    on: match cli.gate {
                        Gate::New => "new",
                        Gate::Any => "any",
                    },
                    fail_on: cli.fail_on.as_str(),
                    severity: self.gated.as_str(),
                    fail: !self.clean,
                },
                risk: self.risk.map(|r| j::Risk {
                    old: r.old,
                    new: r.new,
                    delta: r.delta(),
                    model: "azoth",
                }),
                proportionality: j::Prop {
                    disproportionate: self.prop.disproportionate,
                    note: self.prop.note.as_deref(),
                    skew: self.prop.skew.as_deref(),
                },
                behavioral: j::Behavioral {
                    severity: a.behavioral.severity.as_str(),
                    categories,
                },
                signature: j::Signature {
                    severity: a.signature.severity.as_str(),
                    cve: a.signature.cve.as_deref(),
                    count: a.signature.ids.len(),
                    ids: sig_ids,
                },
                identity: j::Identity {
                    severity: a.identity.severity.as_str(),
                    changes,
                },
                frameworks: j::Frameworks {
                    attack: j::Ids {
                        new: self.survey.attack.gained(),
                        removed: self.survey.attack.lost(),
                        unchanged: self.survey.attack.kept(),
                    },
                    mbc: j::Ids {
                        new: self.survey.mbc.gained(),
                        removed: self.survey.mbc.lost(),
                        unchanged: self.survey.mbc.kept(),
                    },
                },
                structure: j::Structure {
                    severity: a.structure.severity.as_str(),
                    facts,
                },
            },
            evidence,
            deps: self
                .deps
                .iter()
                .map(|d| j::Dep {
                    coord: &d.coord,
                    ecosystem: d.ecosystem,
                    severity: d.severity.as_str(),
                    highlights: &d.highlights,
                    note: d.note.as_deref(),
                })
                .collect(),
            llm: self.interp.as_ref().map(|i| j::Llm {
                nature: &i.nature,
                verdict: &i.verdict,
                model: &i.model,
            }),
            raw: self.report,
        };
        Ok(serde_json::to_string(&envelope)?)
    }
}

/// Evidence hunks to embed in `--format json`. Higher than the terminal's
/// display cap: the JSON is a complete, cacheable record, not a screenful.
const EVIDENCE_JSON_CAP: usize = 24;

/// Map an ML malware probability to a severity band (mirrors the risk words:
/// benign / elevated / suspicious / malware).
pub(crate) fn risk_band(p: f32) -> Severity {
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

// ── version + naming ────────────────────────────────────────────────────────

/// Detected versions and the artifact name for the header, from the input
/// paths (or explicit `--base-version` / `--head-version`).
#[derive(Debug)]
pub(crate) struct Naming {
    pub name: String,
    pub old: Option<Version>,
    pub new: Option<Version>,
    pub bump: Option<Bump>,
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

/// A path's final component, for naming a file in output. Falls back to the
/// whole path when there is no final component (`/`, or a path ending in `..`).
pub(crate) fn basename(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// A display name: the new file's basename with the detected version token and
/// any archive extension stripped, separators tidied. Falls back to the old
/// basename when the new one empties out or is a content hash (quarantine
/// stores name samples by digest — `13ccd9….sample` is no name for a report).
fn artifact_name(new_base: &str, old_base: &str, ver: Option<&Version>) -> String {
    let new_clean = clean_name(new_base, ver);
    let old_clean = clean_name(old_base, ver);
    // A filename is attacker-chosen — a pull request names its own files, and a
    // package names its own archive — and this lands in the masthead.
    crate::printable(
        if new_clean.is_empty()
            || (hexish(&new_clean) && !old_clean.is_empty() && !hexish(&old_clean))
        {
            &old_clean
        } else {
            &new_clean
        },
    )
}

/// A name that is just a hex digest (with or without an extension).
fn hexish(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    stem.len() >= 16 && stem.chars().all(|c| c.is_ascii_hexdigit())
}

fn clean_name(base: &str, ver: Option<&Version>) -> String {
    let mut s = base.to_string();
    if let Some(v) = ver {
        s = s.replace(&v.raw, "");
    }
    // A long leading digit run is a quarantine/timestamp prefix, not a name.
    if let Some((head, rest)) = s.split_once('-')
        && head.len() >= 8
        && head.bytes().all(|b| b.is_ascii_digit())
    {
        s = rest.to_string();
    }
    for ext in [
        ".tar.gz", ".tar.xz", ".tgz", ".txz", ".tar", ".zip", ".gz", ".xz", ".whl",
    ] {
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
#[derive(Debug)]
pub(crate) struct Proportionality {
    pub disproportionate: bool,
    pub note: Option<String>,
    /// Behavioral change far outpacing content change — the implant tell. A
    /// rewrite moves both together; a surgical backdoor moves behavior on a
    /// small edit (xz: 99% of behavior on a ~20% content change).
    pub skew: Option<String>,
}

impl Proportionality {
    fn eval(a: &Assessment, naming: &Naming, diff: &DiffReportV1) -> Self {
        let skew = skew_note(a, diff);
        // Proportionality needs both halves of the comparison: a version bump
        // making a promise, and a capability gain to weigh against it.
        let Some(bump) = naming
            .bump
            .filter(|_| a.behavioral.severity != Severity::None)
        else {
            return Self {
                disproportionate: false,
                note: None,
                skew,
            };
        };
        let disproportionate = a.behavioral.severity > bump.tolerance();
        let note = if disproportionate {
            format!(
                "disproportionate — a {} bump gained a {}-severity capability",
                bump.label(),
                a.behavioral.severity.as_str()
            )
        } else {
            format!("within tolerance for a {} bump", bump.label())
        };
        Self {
            disproportionate,
            note: Some(note),
            skew,
        }
    }
}

/// Skew read over the per-scope rates of change: fires when the traits scope
/// (behavior) moved at least `SKEW_RATIO`× the mean of the content scopes and
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

#[cfg(test)]
mod tests {
    use super::line_diff;

    #[test]
    fn line_diff_marks_additions_removals_and_context() {
        // gentoo-shaped edit: one line replaced, one added; the rest is context.
        let old = b"#!/bin/bash\nexec meson build\n";
        let new = b"#!/bin/bash\nmeson=`base64 -d <<< L2Jpbi9ybQo=`\nexec ${meson} -rf $HOME\n";
        let d = line_diff(old, new);
        // Context line is unmarked; both new lines are `+`; the replaced old
        // line surfaces as `-`.
        assert!(d.contains("  #!/bin/bash"), "context line kept: {d}");
        assert!(
            d.contains("+ meson=`base64 -d <<< L2Jpbi9ybQo=`"),
            "added: {d}"
        );
        assert!(d.contains("+ exec ${meson} -rf $HOME"), "added: {d}");
        assert!(d.contains("- exec meson build"), "removed: {d}");
    }

    #[test]
    fn line_diff_neutralizes_control_chars() {
        // A crafted line can't smuggle a terminal escape into the payload.
        let d = line_diff(b"", b"evil\x1b[31mred\n");
        assert!(!d.contains('\x1b'), "escape must be neutralized: {d:?}");
    }
}
