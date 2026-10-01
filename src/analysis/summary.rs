//! The differential summary shared by the model and the terminal, and the metric movers it reports.

use cleave::types::{Changed, DiffReportV1, FileStatus, MetricChange};

use crate::member::MemberPath;
use crate::registry::Side;

use super::detectors::{
    COMPACT, executable_member_layout, is_compiled_binary_file_type, root_size_change,
};
use super::normalize::normalized_member_path;
use super::remediation::Remediation;
use super::{Analysis, member_type, shown_member_path};

/// What one line of the differential summary is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fact {
    Files,
    Scope,
    PackageSize,
    MetricMoves,
    BinaryReplacement,
    RuntimePayload,
    RuntimeGraft,
    DependencyApi,
    SourceExecution,
    DependencyProfile,
    Registry(Side),
    RegistryGap(Side),
    Restoration,
    Remediation,
    JoinedBehavior,
    Assessment,
    PrimarySignal,
    PayloadIndicators,
    SourceBuild,
    BinaryReplaced,
    BinaryAdded,
}

impl std::fmt::Display for Fact {
    /// The label the model reads the line under.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Files => "files",
            Self::Scope => "scope ROC",
            Self::PackageSize => "package size",
            Self::MetricMoves => "largest metric changes",
            Self::BinaryReplacement => "binary replacement",
            Self::RuntimePayload => "runtime payload",
            Self::RuntimeGraft => "runtime graft",
            Self::DependencyApi => "dependency-backed API expansion",
            Self::SourceExecution => "source execution chain",
            Self::DependencyProfile => "dependency profile",
            Self::Registry(side) => return write!(f, "current registry {side}"),
            Self::RegistryGap(side) => return write!(f, "registry coverage gap ({side})"),
            Self::Restoration => "restoration shape",
            Self::Remediation => "remediation shape",
            Self::JoinedBehavior => "joined behavior",
            Self::Assessment => "deterministic assessment",
            Self::PrimarySignal => "primary deterministic signal",
            Self::PayloadIndicators => "payload indicators",
            Self::SourceBuild => "source build anomaly",
            Self::BinaryReplaced => "compiled binary member replaced",
            Self::BinaryAdded => "compiled binary member added",
        };
        f.write_str(label)
    }
}

/// One line of the differential summary: what it is about, and its facts —
/// one for most lines, several for a list. Kept apart so each audience lays
/// it out without parsing a label back out of a sentence: the model reads
/// `label: facts`, the terminal grid picks the lines it shows by [`Fact`].
#[derive(Debug)]
pub(crate) struct SummaryLine {
    pub fact: Fact,
    pub items: Vec<String>,
}

impl std::fmt::Display for SummaryLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.fact, self.items.join(" · "))
    }
}

/// The summary under construction.
#[derive(Default)]
pub(super) struct Summary(Vec<SummaryLine>);

impl Summary {
    fn push(&mut self, fact: Fact, item: impl Into<String>) {
        self.0.push(SummaryLine {
            fact,
            items: vec![item.into()],
        });
    }

    fn push_items(&mut self, fact: Fact, items: Vec<String>) {
        self.0.push(SummaryLine { fact, items });
    }
}

/// The package/container size delta in words. See [`root_size_change`].
pub(super) fn root_size_delta(diff: &DiffReportV1) -> Option<String> {
    let (old, new) = root_size_change(diff)?;
    let delta = if old != 0.0 {
        format!("{:+.1}%", (new - old) / old * 100.0)
    } else {
        "new".to_string()
    };
    Some(format!("{old:.0} -> {new:.0} bytes ({delta})"))
}

/// One scalar metric that moved: its name, both values in compact form, and
/// the relative change. Shared by the terminal's metrics table, the per-file
/// evidence captions, and the prose the LLM reads.
#[derive(Clone, Debug)]
pub(crate) struct MetricMove {
    /// The file the metric belongs to, when the change spans more than one.
    pub member: Option<String>,
    /// The metric's name — a path like `elf.entry`, or a leaf.
    pub label: String,
    pub old: String,
    pub new: String,
    /// `+389%`, `-33%`, or `new` when the old value was zero.
    pub delta: String,
    /// Ranking strength, from [`metric_change_importance`].
    pub importance: f64,
}

impl MetricMove {
    /// `member:label old→new (delta)` — the one-line prose form.
    pub(crate) fn describe(&self) -> String {
        let member = self
            .member
            .as_ref()
            .map(|m| format!("{m}:"))
            .unwrap_or_default();
        format!(
            "{member}{} {}→{} ({})",
            self.label, self.old, self.new, self.delta
        )
    }
}

/// The movement in one metric change under `label`, or `None` when the metric
/// is noise here — timestamps and timing, `size_bytes` (which restates other
/// movers), and the dependency and segment facts the structure section names —
/// or when the values are non-numeric or equal.
pub(crate) fn metric_move(
    change: &Changed<MetricChange>,
    member: Option<&str>,
    label: &str,
) -> Option<MetricMove> {
    let path = change.new.path.as_str();
    if path.contains("mtime")
        || path.contains("timing")
        || path.contains("dependencies")
        || path.contains("has_direct_loader_dep")
        || path.contains("load_segment")
        || path.ends_with("size_bytes")
    {
        return None;
    }
    let (old, new) = (change.old.value.as_f64()?, change.new.value.as_f64()?);
    if old == new {
        return None;
    }
    let delta = if old == 0.0 {
        "new".to_string()
    } else {
        format!("{:+.0}%", (new - old) / old.abs() * 100.0)
    };
    Some(MetricMove {
        member: member.map(str::to_owned),
        // A metric path can carry artifact text (`elf.dynsym_funcs[name=…]`).
        label: crate::printable(label),
        old: compact_metric_number(old),
        new: compact_metric_number(new),
        delta,
        importance: metric_change_importance(old, new),
    })
}

/// Rank numeric metric changes globally by absolute relative movement. This is
/// shared differential context for humans and the LLM: structural replacement
/// clues such as a 90% code-size collapse should not be hidden behind a single
/// aggregate metric ROC.
pub(super) fn strongest_metric_changes(diff: &DiffReportV1, limit: usize) -> Vec<MetricMove> {
    let show_file = diff.files.len() > 1;
    let mut movers = Vec::new();
    for file in &diff.files {
        let Some(metrics) = file.scopes.metrics.as_ref() else {
            continue;
        };
        let member = show_file.then(|| shown_member_path(&file.path));
        for change in &metrics.changed {
            movers.extend(metric_move(change, member.as_deref(), &change.new.path));
        }
    }
    // One row per name, keeping its strongest movement. `dedup_by` only drops
    // *adjacent* equals, so the names have to be brought together first —
    // sorting by importance alone would leave two rows for the same name
    // (`a.tgz!!pkg/x.js` and `b.zip!!pkg/x.js` share one) sitting apart and both
    // would survive into the top `limit`.
    fn name(m: &MetricMove) -> (Option<&str>, &str) {
        (m.member.as_deref(), m.label.as_str())
    }
    movers.sort_by(|a, b| {
        name(a)
            .cmp(&name(b))
            .then_with(|| b.importance.total_cmp(&a.importance))
    });
    movers.dedup_by(|a, b| name(a) == name(b));
    movers.sort_by(|a, b| {
        b.importance
            .total_cmp(&a.importance)
            .then_with(|| name(a).cmp(&name(b)))
    });
    movers.truncate(limit);
    movers
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

impl Analysis<'_> {
    /// The scalar metrics that moved most across the whole change, ranked.
    /// A package-wide top six is meaningful for a compact implant, but in a
    /// thousand-file framework release it merely selects unrelated local
    /// extrema from arbitrary files, so large releases get none here; their
    /// complete metrics stay in JSON and their per-file movers ride each
    /// evidence header.
    pub(crate) fn metric_moves(&self) -> Vec<MetricMove> {
        let d = self.display_diff();
        if COMPACT.fits(&d.summary) {
            strongest_metric_changes(d, 6)
        } else {
            Vec::new()
        }
    }

    /// Compact, cross-scope facts about the *shape* of the differential. These
    /// are deliberately shared by the LLM and terminal views: they explain
    /// why a modest version change can be alarming without dumping the raw
    /// cleave report into either audience's primary view.
    pub(crate) fn differential_summary(&self) -> &[SummaryLine] {
        self.summary.get_or_init(|| self.summarize())
    }

    pub(super) fn summarize(&self) -> Vec<SummaryLine> {
        let d = self.display_diff();
        let added = d.summary.files_added as usize;
        let removed = d.summary.files_removed as usize;
        let mut changed = d.summary.files_changed as usize;
        let unchanged = d.summary.files_unchanged as usize;
        // In a nested diff the container itself is a synthetic root entry; the
        // member topology is what an analyst means by the package change.
        if d.files.iter().any(|f| MemberPath::new(&f.path).is_member())
            && d.files.iter().any(|f| MemberPath::new(&f.path).is_root())
        {
            changed = changed.saturating_sub(1);
        }
        let total = added + removed + changed + unchanged;
        // Only the counts that are non-zero; `+0 added` says nothing.
        let mut files: Vec<String> = [
            (added, "+", "added"),
            (removed, "-", "removed"),
            (changed, "~", "changed"),
        ]
        .into_iter()
        .filter(|(n, ..)| *n > 0)
        .map(|(n, sign, word)| format!("{sign}{n} {word}"))
        .collect();
        if total > 0 {
            files.push(format!("{total} compared"));
        }
        let mut lines = Summary::default();
        lines.push(Fact::Files, files.join(", "));
        lines.push(
            Fact::Scope,
            format!(
                "overall {:.0}% · traits {:.0}% · metrics {:.0}% · facts {:.0}%",
                d.summary.overall_roc * 100.0,
                d.summary.scope_roc.traits * 100.0,
                d.summary.scope_roc.metrics * 100.0,
                d.summary.scope_roc.kv * 100.0,
            ),
        );
        if let Some(size) = root_size_delta(d) {
            lines.push(Fact::PackageSize, size);
        }
        let moves = self.metric_moves();
        if !moves.is_empty() {
            lines.push_items(
                Fact::MetricMoves,
                moves.iter().map(MetricMove::describe).collect(),
            );
        }
        let signals = &self.signals;
        if let Some(replacement) = &signals.binary_replacement {
            lines.push(Fact::BinaryReplacement, format!(
                "same-version compiled binary has {} large metric movements across {} independent families",
                replacement.large_moves, replacement.metric_families,
            ));
        }
        if let Some(payload) = &signals.opaque_runtime_payload {
            lines.push(Fact::RuntimePayload, format!(
                "{} newly references {} ({:.0} bytes on {:.0} line{}, {:.0}% encoded strings, longest string {:.0} bytes)",
                shown_member_path(&payload.entrypoint),
                shown_member_path(&payload.payload),
                payload.size,
                payload.lines,
                if payload.lines == 1 { "" } else { "s" },
                payload.encoded_ratio * 100.0,
                payload.max_string,
            ));
        }
        if let Some(graft) = &signals.runtime_graft {
            lines.push(Fact::RuntimeGraft, format!(
                "{} newly references {} alongside an external URL and absolute host path; both are timestamp outliers within a {:.0}-second archive window",
                shown_member_path(&graft.entrypoint),
                shown_member_path(&graft.payload),
                graft.timestamp_spread,
            ));
        }
        if let Some(expansion) = &signals.dependency_backed_api {
            lines.push(
                Fact::DependencyApi,
                format!(
                    "{} adds {} ({}) to its public surface",
                    shown_member_path(&expansion.entrypoint),
                    crate::printable(&expansion.dependency),
                    crate::printable(&expansion.spec),
                ),
            );
        }
        if let Some(member) = &signals.source_download_execute {
            lines.push(
                Fact::SourceExecution,
                format!(
                    "{} gained platform-gated HTTP download → file write → process launch",
                    crate::printable(member),
                ),
            );
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
            lines.push(
                Fact::DependencyProfile,
                format!(
                    "{} · {} · {} · {} (new: {})",
                    dependency.coord,
                    dependency.severity.as_str(),
                    detail,
                    dependency.comparison,
                    dependency.new_severity.as_str()
                ),
            );
        }
        for row in &self.registry {
            for (side, observation) in [(Side::Before, &row.old), (Side::After, &row.new)] {
                if let Some(observation) = observation {
                    for finding in &observation.findings {
                        lines.push(
                            Fact::Registry(side),
                            format!(
                                "{} · {} (new risk: {})",
                                crate::printable(&observation.coordinate),
                                finding.description,
                                row.new_severity.as_str()
                            ),
                        );
                    }
                    if let Some(error) = &observation.error {
                        lines.push(
                            Fact::RegistryGap(side),
                            format!(
                                "{} · {}",
                                crate::printable(&observation.coordinate),
                                crate::printable(error)
                            ),
                        );
                    }
                }
            }
        }
        if signals.restored_endgame {
            lines.push(
                Fact::Restoration,
                "a previously absent declared entrypoint and its large runtime tree returned"
                    .to_string(),
            );
        }
        match self.remediation {
            Some(Remediation::FocusedCleanup) => lines.push(
                Fact::Remediation,
                "multiple handlers were disabled at function entry and a named artifact is deleted"
                    .to_string(),
            ),
            Some(Remediation::ModelRecovery) => lines.push(
                Fact::Remediation,
                "model risk fell sharply while attack behavior was removed".to_string(),
            ),
            Some(Remediation::BehaviorRemoval) => lines.push(
                Fact::Remediation,
                "high-severity attack behavior was removed without a high-severity replacement"
                    .to_string(),
            ),
            None => {}
        }
        if signals.encoded_script_loading {
            lines.push(
                Fact::JoinedBehavior, "one file gains character-code conversion and script loading; dataflow is not established"
                    .to_string(),
            );
        } else if signals.script_loading_with_host {
            lines.push(
                Fact::JoinedBehavior, "one file gains script loading and remote host references; the loaded destination is not established"
                    .to_string(),
            );
        }
        lines.push(
            Fact::Assessment,
            format!(
                "current {} · new {} · gate: {} · known-bad signatures: {}",
                self.deterministic_verdict.as_str(),
                self.new_verdict.as_str(),
                if self.clean() { "pass" } else { "fail" },
                if self.assessment.signature.ids.is_empty() {
                    "none matched"
                } else {
                    "matched"
                }
            ),
        );
        lines.push(Fact::PrimarySignal, self.headline_facts());

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
                        || (text.contains("extension") && text.contains("mismatch"))
                        || text.contains("high entropy")))
                    || text.contains("archive-incomplete")
                    || (text.contains("malformed") && archive);
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
            lines.push_items(Fact::PayloadIndicators, indicators);
        }
        if let Some(build) = self.source_build {
            lines.push(Fact::SourceBuild, build.describe());
        }

        let mut added_binaries = Vec::new();
        let mut removed_binaries = Vec::new();
        for file in &d.files {
            if !MemberPath::new(&file.path).is_member() {
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
        let removed_binaries: Vec<(String, String)> = removed_binaries
            .into_iter()
            .map(|path| (normalized_member_path(&path), path))
            .collect();
        for member in added_binaries.iter().take(4) {
            let normalized = normalized_member_path(member);
            if let Some((_, old)) = removed_binaries
                .iter()
                .find(|(removed, _)| *removed == normalized)
            {
                lines.push(
                    Fact::BinaryReplaced,
                    format!(
                        "{} -> {}",
                        shown_member_path(old),
                        shown_member_path(member)
                    ),
                );
            } else {
                lines.push(Fact::BinaryAdded, shown_member_path(member));
            }
        }
        lines.0
    }
}
