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
use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use cleave::types::{AnalysisReport, DiffReportV1, FileDiffEntry, FileStatus};

use crate::evidence::Hunk;
use crate::member::MemberPath;
use crate::options::Options;
use crate::rubric::Assessment;
use crate::{Format, Gate, Severity};

mod archive_roots;
mod capability;
mod decoded;
mod detectors;
mod hierarchy;
mod identity;
mod llm_context;
mod naming;
mod normalize;
mod remediation;
mod source;
mod summary;
mod verdict;

use hierarchy::class;

use detectors::{
    Shape, Signals, SourceBuild, is_source_archive, source_build_macro_anomaly,
    stable_source_loader_payload_refresh,
};
pub(crate) use naming::{Naming, basename};
use normalize::normalized_archive_diff;
use remediation::{Remediation, remediation_cleanup_context};
pub(crate) use source::{Atom, SourceChange};
use summary::SummaryLine;
pub(crate) use summary::{Fact, MetricMove, metric_move};
pub(crate) use verdict::{MALWARE_BAND, SUSPICIOUS_BAND};
use verdict::{
    Proportionality, Verdicts, capability_mass_escalation, deterministic_verdicts, risk_band,
    significant_risk_escalation,
};

/// The surface a comparison came in through, as the report names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Verb {
    /// Two states of a repository in CI.
    Ci,
    /// Two local trees or files.
    Fs,
    /// Two published package versions.
    Purl,
    /// Two container images.
    Oci,
}

/// What a verb knows about a comparison that the two paths do not say.
#[derive(Debug, Default)]
pub(crate) struct Framing {
    /// The name to report the artifact under. `ci` compares two scratch trees,
    /// whose directory names are no name; `None` derives one from the paths.
    pub name: Option<String>,
    /// What the comparison covered, when the verb knows. See [`Scope`].
    pub scope: Option<Scope>,
}

/// One comparison's cleave inputs and output, owned, so the [`Analysis`] that
/// judges it can borrow them.
///
/// Every verb goes through here — `fs`, `ci`, `purl`, `oci`, and the library's
/// [`crate::judgement::judge`] — so how a pair is diffed is decided once.
pub(crate) struct Comparison {
    options: cleave::AnalysisOptions,
    report: AnalysisReport,
}

impl Comparison {
    /// Diff `old` against `new` with the options the pair calls for.
    ///
    /// Source archives often carry meaningful non-program members: build
    /// macros, test fixtures, and opaque payloads. Two of them keep every
    /// member in the differential, so a source-only attack is not reduced to
    /// the members with a recognized program type. Anything else keeps
    /// cleave's recognized-file policy: a source tree can legitimately hold
    /// corrupt fixtures.
    pub(crate) fn run(old: &Path, new: &Path) -> Result<Self> {
        let options = cleave::AnalysisOptions {
            all_files: is_source_archive(old) && is_source_archive(new),
            ..cleave::AnalysisOptions::default()
        };
        let report = diff(old, new, &options)?;
        Ok(Self { options, report })
    }

    /// Judge the comparison: the analysis, then its network half and the
    /// model's read, in that order — see [`Analysis::finish`].
    pub(crate) fn judge(
        &self,
        verb: Verb,
        old: &Path,
        new: &Path,
        opts: &Options,
        framing: Framing,
    ) -> Result<Analysis<'_>> {
        let mut a = Analysis::new(verb, old, new, &self.options, &self.report, opts)?;
        if let Some(name) = framing.name {
            a.naming.name = name;
        }
        a.scope = framing.scope;
        a.finish(opts);
        Ok(a)
    }
}

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
            .filter(|f| !MemberPath::new(&f.path).is_member())
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

/// The cleave diff plus everything isomer derived from it.
///
/// Borrows the (large) cleave report rather than owning it, so the caller
/// produces it once and every renderer reads the same copy.
pub(crate) struct Analysis<'a> {
    /// The surface that produced this analysis.
    pub verb: Verb,
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
    /// The model's measured probabilities. Never adjusted afterwards: what
    /// the reports show, with any LLM floor applied, is
    /// [`shown_risk`](Self::shown_risk).
    pub risk: Option<crate::risk::Risk>,
    /// The shape detectors' findings, for the gate and every report alike.
    pub signals: Signals,
    /// How much of the artifact's behavioral fingerprint this change moved,
    /// weighed by criticality. Computed once: the gate reads it through
    /// [`capability_mass_escalation`] and the JSON feature block reports it.
    pub shift: crate::behavior_shift::Shift,
    /// What the quantity of introduced behavior earned on its own, before the
    /// remediation suppression the verdict applies. Reported as-measured.
    pub behavior_mass: Severity,
    /// A source-release build that gained an anomalous shape. Shared by the
    /// deterministic gate, terminal view, and LLM context.
    pub source_build: Option<SourceBuild>,
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
    /// The gate this run was judged under; see [`gated`](Self::gated).
    gate: Gate,
    /// The `--fail-on` threshold; see [`clean`](Self::clean).
    fail_on: Severity,
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
    pub registry: Vec<crate::registry::Comparison>,
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
    /// The differential summary, shared by the model and the terminal. It
    /// extracts archive members to type them, so it is built once — at the
    /// model's read when there is one, which sees the finished registry and
    /// dependency evidence it reports.
    summary: OnceCell<Vec<SummaryLine>>,
}

impl<'a> Analysis<'a> {
    /// Judge a completed cleave diff — the deterministic half. Only
    /// [`Comparison::judge`] calls this, and always follows it with
    /// [`finish`](Self::finish): an analysis is never handed out half-built.
    fn new(
        verb: Verb,
        old: &Path,
        new: &Path,
        options: &'a cleave::AnalysisOptions,
        report: &'a AnalysisReport,
        opts: &Options,
    ) -> Result<Self> {
        let diff = report
            .diff
            .as_ref()
            .context("diff_paths returned a report without a diff")?;

        let pairs = Pair::from_roots(old, new, diff);
        let judged_diff = normalized_archive_diff(diff);
        let source_archive = is_source_archive(old) && is_source_archive(new);
        // A refreshed payload under a stable loader is the more specific
        // reading, so it is the one named when both shapes are present.
        let source_build = if !source_archive {
            None
        } else if stable_source_loader_payload_refresh(old, new, diff) {
            Some(SourceBuild::PayloadRefresh)
        } else if source_build_macro_anomaly(new, &judged_diff) {
            Some(SourceBuild::MacroShellEval)
        } else {
            None
        };

        // One walk over both sides: the base's capability classes (so a wholly
        // new class is distinguishable from one that merely gained a trait)
        // and the ATT&CK / MBC annotations each side carries.
        let survey = crate::evidence::survey(&pairs, options);
        let shift = survey.trait_profiles.shift();
        let mut assessment = crate::rubric::assess(&judged_diff, &survey.base_classes);
        crate::binary::enrich(&pairs, &judged_diff, &mut assessment);
        let naming = Naming::resolve(old, new, opts, &judged_diff)?;

        // A few attacks are composed of individually medium traits, so the
        // per-trait rubric never reaches the gate. Two shape signals are
        // deliberately generic: a dense capability jump in one/few files,
        // and an endgame package that deletes most of its previous tree. They
        // use cleave's existing change metrics rather than another taxonomy.
        // Computed once: proportionality reads it too, and the detectors it
        // shares with the reports are kept as `signals`.
        let shape = Shape {
            assessment: &assessment,
            diff: &judged_diff,
            bump: naming.bump,
            source_archive,
            source_build,
            runtime_entrypoints: &survey.runtime_entrypoints,
        };
        let signals = shape.signals();
        let shape_escalation = shape.escalation(&signals);
        let prop = Proportionality::eval(&assessment, &naming, &judged_diff, shape_escalation);

        // Azoth is a useful corroborating detector, but a probability barely
        // crossing a band boundary is not enough to condemn a clean release.
        // Require a material move and a high
        // absolute score before risk can stand alone; the hand-coded rubric
        // remains authoritative for known or shape-only behavior.
        let risk = crate::risk::score(&pairs);
        let risk_jump = risk.map_or(Severity::None, significant_risk_escalation);
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
        // Quantity of introduced behavior, independent of which behavior it
        // was. Suppressed under remediation for the same reason as the shape
        // rules: a release that takes an implant out is judged on what it
        // removed, and the replacement code it ships is not an injection.
        let mass_escalation = capability_mass_escalation(
            &shift,
            &judged_diff.summary,
            naming.bump,
            old.is_file() && new.is_file(),
        );
        let shape_new = if is_remediation {
            Severity::None
        } else {
            shape_escalation.max(mass_escalation)
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
        let Verdicts {
            overall: verdict,
            new: new_verdict,
        } = deterministic_verdicts(
            &assessment,
            rubric_new,
            risk_jump,
            escalation.max(shape_new),
            remediation,
        );

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
            signals,
            shift,
            behavior_mass: mass_escalation,
            source_build,
            remediation,
            verdict,
            new_verdict,
            gate: opts.gate,
            fail_on: opts.fail_on,
            deterministic_verdict: verdict,
            interp: None,
            scope: None,
            deps: Vec::new(),
            registry: Vec::new(),
            hunks: OnceCell::new(),
            source_changes: OnceCell::new(),
            summary: OnceCell::new(),
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
    fn finish(&mut self, opts: &Options) {
        if opts.follows_registry() {
            self.registry = crate::registry::audit(&self.pairs, self.diff, self.options);
            for row in &mut self.registry {
                row.apply_release_policy(self.naming.bump);
            }
            let any = self
                .registry
                .iter()
                .map(crate::registry::Comparison::severity)
                .max()
                .unwrap_or(Severity::None);
            let new = self
                .registry
                .iter()
                .map(|r| r.new_severity)
                .max()
                .unwrap_or(Severity::None);
            self.raise(any, new);
        }
        if opts.deps && !opts.offline {
            let profiles = crate::deps::profiles(self.diff, self.options, opts.progress);
            // Keep absolute current risk for `any`, but gate `new` on the
            // comparative dependency profile when a predecessor is known.
            // Independent evidence is never lowered by an equivalent or
            // reduced dependency profile.
            self.raise(
                crate::deps::severity(&profiles),
                crate::deps::new_severity(&profiles),
            );
            self.deps = profiles;
        }
        self.interpret(opts);
    }

    /// Fold deterministic evidence found after construction — the registry,
    /// the dependency profiles — into every verdict: `any` raises the overall
    /// reading, `new` the newly-introduced one. The gate and exit code follow
    /// from these, so there is nothing else to keep in step.
    fn raise(&mut self, any: Severity, new: Severity) {
        self.deterministic_verdict = self.deterministic_verdict.max(any);
        self.verdict = self.verdict.max(any);
        self.new_verdict = self.new_verdict.max(new);
    }

    /// The severity the active `--gate` compares against `--fail-on`. Always
    /// deterministic: the model's read raises the displayed verdict, never
    /// this.
    pub(crate) fn gated(&self) -> Severity {
        match self.gate {
            Gate::New => self.new_verdict,
            Gate::Any => self.deterministic_verdict,
        }
    }

    /// Whether the run passes at `--fail-on` — the exit code.
    pub(crate) fn clean(&self) -> bool {
        !self.gated().fails(self.fail_on)
    }

    /// The gate this run was judged under.
    pub(crate) fn gate(&self) -> Gate {
        self.gate
    }

    /// The `--fail-on` threshold this run was judged at.
    pub(crate) fn fail_on(&self) -> Severity {
        self.fail_on
    }

    /// The risk the reports show: the model's measurement, with its new score
    /// pulled up to the band the interpreter's call implies when that call is
    /// worse — see [`risk_llm_raised`](Self::risk_llm_raised).
    pub(crate) fn shown_risk(&self) -> Option<crate::risk::Risk> {
        self.risk.map(|r| r.floored(self.llm_floor()))
    }

    /// Whether the interpreter's call raised the shown score above what the
    /// model measured — so the report attributes the number honestly
    /// (`azoth+llm`) instead of crediting azoth with a value it did not emit.
    pub(crate) fn risk_llm_raised(&self) -> bool {
        self.risk.is_some_and(|r| r.raised_by(self.llm_floor()))
    }

    fn llm_floor(&self) -> f32 {
        self.interp
            .as_ref()
            .map_or(0.0, crate::llm::Interpretation::risk_floor)
    }

    fn interpret(&mut self, opts: &Options) {
        // The read is best-effort: a misconfigured or unreachable endpoint
        // costs the read, never the verdict, and is said once, here.
        if opts.format != Format::Interpret && crate::llm::requested(opts) && self.speaks() {
            let read = crate::llm::config(opts).and_then(|cfg| {
                cfg.map(|cfg| crate::llm::interpret(&cfg, &self.llm_context()?))
                    .transpose()
            });
            self.interp = match read {
                Ok(read) => read,
                Err(e) => {
                    log::warn!("llm interpretation failed: {e:#}");
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
        {
            self.verdict = self.verdict.max(sev);
        }
    }

    /// Render one output format. Everything a renderer needs is on the
    /// analysis, so every format reads the one case.
    pub(crate) fn render(&self, format: Format) -> Result<String> {
        match format {
            Format::Terminal => Ok(crate::terminal::report(self)?),
            // Appended in place: the JSON carries the whole raw report, and
            // `format!` would copy every byte of it to add one.
            Format::Json => Ok(with_newline(crate::json::envelope(self)?)),
            Format::Markdown => Ok(crate::markdown::report(self)?),
            Format::Sarif => Ok(with_newline(crate::sarif::report(self)?)),
            // Keep this byte-for-byte identical to the user message passed to
            // `llm::interpret`: no system prompt, verdict line, or added
            // newline. This mirrors scan's `--format interpret` contract and
            // makes the payload independently inspectable/replayable.
            Format::Interpret => Ok(self.llm_context()?),
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
    pub(crate) fn speaks(&self) -> bool {
        !self.clean()
            // Notable+ is the reporting floor; the tiers below it are atoms
            // and unremarkable observations (see `rubric::is_finding`).
            || self.assessment.severity() >= Severity::Medium
            || self.risk_band_moved()
            || self.prop.drift.is_disproportionate()
            // Removing attack behavior is itself a notable change. The
            // remediation floor lives above `assessment.severity()` because the
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
        self.shown_risk()
            .is_some_and(|r| risk_band(r.new) != risk_band(r.old))
    }

    /// The judgement, in one line, before any detail. What a reader wants
    /// first is not what changed, but what isomer makes of it.
    pub(crate) fn judgement(&self) -> String {
        if !self.clean() {
            return self.headline();
        }
        self.clean_note()
    }

    /// Like [`judgement`](Self::judgement) but with the model's read left for
    /// its own line — used by the terminal, which prints `✨ nature` separately,
    /// so the two never echo each other.
    pub(crate) fn reason(&self) -> String {
        if !self.clean() {
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
        let signals = &self.signals;
        if signals.restored_endgame {
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
        if signals.dependency_with_fallback_load {
            return "added dependency alongside fallback module load".to_string();
        }
        if let Some(expansion) = &signals.dependency_backed_api {
            return format!(
                "patch-level public API expansion pulls floating dependency {}",
                crate::printable(&expansion.dependency)
            );
        }
        if let Some(member) = &signals.source_download_execute {
            return format!(
                "auto-loaded source downloads, writes, and executes a payload in {}",
                crate::printable(member)
            );
        }
        // The gated form, as the gate saw it: in a major release a
        // script-loading join is ordinary framework behavior, and naming it as
        // the reason would credit a verdict to a signal that never raised it.
        if signals.remote_script_loader {
            return if signals.encoded_script_loading {
                "gained character-code conversion and browser script loading"
            } else {
                "gained browser script loading and remote host references"
            }
            .to_string();
        }
        if signals.binary_replacement.is_some() {
            return "same-version compiled binary was structurally replaced".to_string();
        }
        if signals.runtime_graft.is_some() {
            return "runtime entrypoint gained a timestamp-clustered external payload".to_string();
        }
        if signals.opaque_runtime_payload.is_some() {
            return "runtime entrypoint gained an opaque encoded payload".to_string();
        }
        if let Some(note) = self.prop.drift.escalation_note() {
            return note.to_string();
        }
        if let Some(note) = self.mass_note() {
            return note;
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
        if has("anti-static") && has(class::FILE) && has(class::DELETE) {
            if has(class::HTTP) {
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
            return format!("{}: {}", f.label, f.sentence());
        }
        "no behavioral change".to_string()
    }

    /// The behavior-quantity read, when it is the reason the gate rose: how
    /// much of what the artifact can do arrived with this release. Stated as a
    /// share so the number means the same thing for a one-file library and a
    /// thousand-member package.
    pub(crate) fn mass_note(&self) -> Option<String> {
        if self.remediation.is_some() || self.behavior_mass < Severity::High {
            return None;
        }
        let release = self
            .naming
            .bump
            .map_or_else(|| "this change".to_string(), crate::version::Bump::describe);
        Some(format!(
            "{release} introduced {:.0}% of the behavior this artifact now has",
            self.shift.injected_share() * 100.0,
        ))
    }
}

fn with_newline(mut s: String) -> String {
    s.push('\n');
    s
}

// ── version + naming ────────────────────────────────────────────────────────

// ── proportionality ─────────────────────────────────────────────────────────

/// A diff path as the reader sees it: the archive member alone, with the
/// container prefix dropped. Borrowed, not copied — this sits inside per-file
/// and per-payload loops, where it is a lookup key. Anything *printed* goes
/// through [`shown_member_path`].
fn display_member_path(path: &str) -> &str {
    MemberPath::new(path).display()
}

/// [`display_member_path`] for output. A member name is chosen by whoever
/// built the archive, so it is neutralized before it reaches a terminal, a
/// comment, or the model.
fn shown_member_path(path: &str) -> String {
    crate::printable(display_member_path(path))
}

/// The type cleave detected for a diff entry. `None` when the entry carries no
/// label or the label is one filefacts does not know — an unknown type is never
/// treated as evidence either way.
fn member_type(file: &FileDiffEntry) -> Option<filefacts::FileType> {
    file.file_type
        .as_deref()
        .and_then(filefacts::FileType::from_label)
}

#[cfg(test)]
mod simulations;

#[cfg(test)]
mod render_tests;
#[cfg(test)]
mod tests;
