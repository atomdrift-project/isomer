//! The shape detectors: change shapes that are implant-like even when no single trait is.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use cleave::types::{DiffReportV1, DiffSummary, FileDiffEntry, FileStatus};

use crate::Severity;
use crate::member::MemberPath;
use crate::rubric::Assessment;
use crate::taxonomy::{TraitId, under};
use crate::version::{Bump, BumpKind, Promise};

use super::capability::Cue;
use super::hierarchy::class;
use super::hierarchy::trait_;
use super::normalize::{normalized_member_path, scope_diffs_changed};
use super::{display_member_path, member_type};

/// Bounds on how far a change moved: the vocabulary the shape rules are written
/// in. Each rule names its [`Movement`] below, so its numbers sit together with
/// the reason for them rather than inside a conjunction. A bound left at
/// [`Movement::ANY`]'s value does not constrain.
#[derive(Clone, Copy, Debug)]
pub(super) struct Movement {
    /// Files changed, added and removed together.
    max_touched: u32,
    max_changed: u32,
    max_added: u32,
    max_removed: u32,
    /// Files added and removed together: churn, as opposed to edits.
    max_churn: u32,
    min_added: u32,
    min_removed: u32,
    /// Bounds on cleave's rates of change.
    min_overall: f32,
    max_overall: f32,
    min_traits: f32,
    min_metrics: f32,
}

impl Movement {
    const ANY: Self = Self {
        max_touched: u32::MAX,
        max_changed: u32::MAX,
        max_added: u32::MAX,
        max_removed: u32::MAX,
        max_churn: u32::MAX,
        min_added: 0,
        min_removed: 0,
        min_overall: f32::NEG_INFINITY,
        max_overall: f32::INFINITY,
        min_traits: f32::NEG_INFINITY,
        min_metrics: f32::NEG_INFINITY,
    };

    pub(super) fn fits(&self, s: &DiffSummary) -> bool {
        let churn = s.files_added.saturating_add(s.files_removed);
        churn.saturating_add(s.files_changed) <= self.max_touched
            && s.files_changed <= self.max_changed
            && s.files_added <= self.max_added
            && s.files_removed <= self.max_removed
            && churn <= self.max_churn
            && s.files_added >= self.min_added
            && s.files_removed >= self.min_removed
            && (self.min_overall..=self.max_overall).contains(&s.overall_roc)
            && s.scope_roc.traits >= self.min_traits
            && s.scope_roc.metrics >= self.min_metrics
    }
}

/// A change small enough for the shape rules below to mean anything. They look
/// for a payload concentrated in a few files; across a thousand-file framework
/// release the same signals are just unrelated local extrema, so every one of
/// them bounds itself here — on the same count of touched files, at the same
/// number.
pub(super) const COMPACT: Movement = Movement {
    max_touched: 16,
    ..Movement::ANY
};

/// A focused source-file implant: new capabilities arriving in one or two
/// files, with enough overall and behavioral movement that this is not just a
/// metadata touch.
const FOCUSED_SOURCE: Movement = Movement {
    max_changed: 2,
    max_added: 2,
    max_removed: 2,
    min_overall: 0.20,
    min_traits: 0.40,
    ..Movement::ANY
};

/// A focused implant that also deletes a modest amount of stale package
/// content. Kept apart from [`FOCUSED_SOURCE`]: the higher movement floors keep
/// routine patch cleanup from escalating.
const FOCUSED_SOURCE_WITH_CLEANUP: Movement = Movement {
    max_changed: 4,
    max_churn: 16,
    min_overall: 0.60,
    min_traits: 0.60,
    ..Movement::ANY
};

/// A compact cross-domain capability cluster. The floors are low because the
/// rule's weight is in which classes arrived together, not in how much moved.
const CROSS_DOMAIN_CLUSTER: Movement = Movement {
    min_overall: 0.05,
    min_traits: 0.15,
    ..COMPACT
};

/// A same-version rebuild that swapped most of an archive's members while
/// editing almost nothing in place.
const SAME_VERSION_ARCHIVE_REPLACEMENT: Movement = Movement {
    min_added: 32,
    min_removed: 32,
    max_changed: 2,
    min_overall: 0.75,
    min_traits: 0.20,
    ..Movement::ANY
};

/// Hundreds of files deleted and almost nothing added: a package reduced to a
/// shell. The trait floor requires the removed tree to account for most of the
/// package's behavior as well as its content.
const ENDGAME: Movement = Movement {
    min_removed: 100,
    max_added: 2,
    max_changed: 8,
    min_overall: 0.50,
    min_traits: 0.75,
    ..Movement::ANY
};

/// [`ENDGAME`] in reverse: the stripped runtime tree coming back.
const RESTORED_ENDGAME: Movement = Movement {
    min_added: 100,
    max_removed: 2,
    max_changed: 8,
    min_overall: 0.50,
    min_traits: 0.75,
    ..Movement::ANY
};

/// A compact change whose metrics moved as a native rebuild's do.
const BINARY_REPLACEMENT: Movement = Movement {
    min_overall: 0.50,
    min_metrics: 0.30,
    ..COMPACT
};

/// A compact change that moved enough for a new payload to be in it — the
/// floor [`opaque_runtime_payload_anomaly`] and [`runtime_graft_anomaly`]
/// start from.
const COMPACT_PAYLOAD: Movement = Movement {
    min_overall: 0.30,
    ..COMPACT
};

/// A compact change that moved little overall: a dependency and a loader tweak,
/// not a rewrite.
const QUIET_DEPENDENCY_CHANGE: Movement = Movement {
    max_overall: 0.25,
    ..COMPACT
};

/// A release that claims to carry nothing new: the same version republished, a
/// patch, or a prerelease. A major bump can legitimately arrive with new
/// behavior, so the shape rules below spend their suspicion here, where the
/// version number promises there is almost nothing to see.
///
/// Narrower than [`Promise::Nothing`] on purpose: a downgrade is excluded.
/// Moving *back* to an older release is how a rollback or remediation reads,
/// and these shape rules look for an implant arriving in a forward release;
/// the quantity and executable rules, which do treat a downgrade as promising
/// nothing, weigh what arrived rather than how it is shaped.
pub(super) fn routine_release(bump: Option<Bump>) -> bool {
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
pub(super) fn has_new_class(a: &Assessment, class: &str) -> bool {
    a.behavioral
        .categories
        .iter()
        .any(|c| c.class == class && !c.new_ids.is_empty())
}

/// What the shape rules read about one change.
pub(super) struct Shape<'a> {
    pub(super) assessment: &'a Assessment,
    pub(super) diff: &'a DiffReportV1,
    pub(super) bump: Option<Bump>,
    /// Both sides are source-release tarballs.
    pub(super) source_archive: bool,
    pub(super) source_build: Option<SourceBuild>,
    pub(super) runtime_entrypoints: &'a HashSet<String>,
}

impl Shape<'_> {
    /// Run the shape detectors whose findings are also reported, once.
    pub(super) fn signals(&self) -> Signals {
        let (diff, bump, entrypoints) = (self.diff, self.bump, self.runtime_entrypoints);
        let encoded_script_loading = gained_encoded_script_loading(diff);
        let script_loading_with_host = gained_script_loading_with_host(diff);
        Signals {
            // A dependency addition paired with a new fallback module load is a
            // compact supply-chain shape: the release pulls in new code and
            // changes how it is loaded, even when neither fact is individually
            // high severity.
            dependency_with_fallback_load: dependency_with_fallback_load(self.assessment, diff),
            dependency_backed_api: dependency_backed_public_api_anomaly(diff, bump, entrypoints),
            source_download_execute: source_download_write_execute_anomaly(diff, bump, entrypoints)
                .map(str::to_owned),
            encoded_script_loading,
            script_loading_with_host,
            // Script loading alongside character-code conversion or remote
            // host references is a review signal, not proof of remote code
            // execution. Require convergence on one file and use it as
            // release-pressure evidence only for same/patch releases: a major
            // browser framework can legitimately add these behavior families
            // together.
            remote_script_loader: routine_release(bump)
                && (encoded_script_loading || script_loading_with_host),
            binary_replacement: binary_replacement_anomaly(diff, bump),
            opaque_runtime_payload: opaque_runtime_payload_anomaly(diff, bump, entrypoints),
            runtime_graft: runtime_graft_anomaly(diff, bump, entrypoints),
            restored_endgame: restored_endgame_package_shape(diff),
        }
    }

    /// The shape rules' verdict, given the [`Signals`] already found.
    pub(super) fn escalation(&self, signals: &Signals) -> Severity {
        change_shape_escalation(self, signals)
    }
}

/// The detectors' findings on one change, computed once and read by the gate,
/// the headline, and the differential summary — so the three cannot disagree
/// about what fired. The headline once named a script-loading join the gate
/// had ruled out for the release in hand, because each re-ran the detector
/// with its own conditions.
#[derive(Debug, Default)]
pub(crate) struct Signals {
    pub dependency_with_fallback_load: bool,
    pub dependency_backed_api: Option<DependencyApiExpansion>,
    /// The auto-loaded member that gained a download → write → execute chain.
    pub source_download_execute: Option<String>,
    /// One file gained character-code conversion and script loading.
    pub encoded_script_loading: bool,
    /// One file gained script loading and remote host references.
    pub script_loading_with_host: bool,
    /// Either script-loading join, in a release that promised nothing new —
    /// the form that raises the gate.
    pub remote_script_loader: bool,
    pub binary_replacement: Option<BinaryReplacementAnomaly>,
    pub opaque_runtime_payload: Option<OpaqueRuntimePayloadAnomaly>,
    pub runtime_graft: Option<RuntimeGraftAnomaly>,
    /// The package's stripped runtime tree came back. See
    /// [`restored_endgame_package_shape`].
    pub restored_endgame: bool,
}

/// Why a source-release build is anomalous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceBuild {
    /// A changed m4 macro discovers source data, transforms a carrier, and
    /// evaluates it through the shell.
    MacroShellEval,
    /// A suspicious build loader stayed byte-identical while one of its
    /// compressed test-data carriers changed: the two-release xz shape, stable
    /// activation logic with a refreshed hidden stage.
    PayloadRefresh,
}

impl SourceBuild {
    pub(super) fn describe(self) -> &'static str {
        match self {
            Self::MacroShellEval => {
                "changed m4 macro discovers source data, transforms a carrier, and evaluates it through the shell"
            }
            Self::PayloadRefresh => {
                "suspicious build loader stayed byte-identical while a compressed test-data carrier changed"
            }
        }
    }
}

/// The shape rules over loose inputs, for the simulations that exercise them
/// one case at a time.
#[cfg(test)]
pub(super) fn change_shape_escalation_for(
    a: &Assessment,
    diff: &DiffReportV1,
    bump: Option<Bump>,
    source_archive: bool,
    source_build_anomaly: bool,
    runtime_entrypoints: &HashSet<String>,
) -> Severity {
    let shape = Shape {
        assessment: a,
        diff,
        bump,
        source_archive,
        source_build: source_build_anomaly.then_some(SourceBuild::MacroShellEval),
        runtime_entrypoints,
    };
    shape.escalation(&shape.signals())
}

/// Raise a gate when the *shape* of the change is itself implant-like.
///
/// The first branch catches a focused source-file implant: several wholly new
/// capability classes arriving in one or two files, with enough overall and
/// behavioral movement that this is not just a metadata touch. The second
/// catches endgame sabotage such as a package retaining only a tiny manifest
/// after removing hundreds of library files. These are intentionally broad
/// metrics, not attack-specific trait names.
pub(super) fn change_shape_escalation(shape: &Shape<'_>, signals: &Signals) -> Severity {
    let Shape {
        assessment: a,
        diff,
        bump,
        source_archive,
        source_build,
        ..
    } = *shape;
    let source_build_anomaly = source_build.is_some();
    let s = &diff.summary;
    let same_version = bump.is_some_and(|b| matches!(b.kind, BumpKind::Same));
    // The shared size bound: a small, focused change. Several branches below
    // are meaningful only within one, and a large release trips none of them.
    let compact = COMPACT.fits(s);
    // These generic shape rules promise wholly new capabilities, not merely
    // new detector spellings inside classes already present in the baseline.
    // Packaging/metric metadata is not another behavioral capability.
    let new_classes = a
        .behavioral
        .categories
        .iter()
        .filter(|c| a.behavioral.is_new_category(c))
        .filter(|c| c.new_ids.iter().any(|id| !TraitId::new(id).is_metadata()))
        .count();
    let focused_source = routine_release(bump) && FOCUSED_SOURCE.fits(s) && new_classes >= 3;
    // A release can also delete a modest amount of stale package content
    // while concentrating several new capabilities in a few changed files.
    // Keep this separate from the small focused branch: the higher movement
    // and four-class floor prevent routine patch cleanup from escalating.
    let focused_source_with_cleanup =
        routine_release(bump) && FOCUSED_SOURCE_WITH_CLEANUP.fits(s) && new_classes >= 4;
    // A compact cross-domain capability cluster is suspicious even when the
    // individual rules remain medium: HTTP plus scheduling and serialization
    // in a small patch is a common dormant-loader shape. The class count and
    // movement floors keep ordinary single-purpose WordPress changes below
    // this branch.
    let cross_domain_cluster = routine_release(bump)
        && CROSS_DOMAIN_CLUSTER.fits(s)
        && new_classes >= 6
        && [class::HTTP, "time/schedule", "data/serialize"]
            .iter()
            .all(|class| a.behavioral.new_categories.contains(*class));
    // External content inserted as HTML in a plugin installer can turn a
    // poisoned feed into code running with administrator privileges. This is
    // a review signal, not proof of taint flow: require all four new legs in
    // one file and a routine release. Ordinary fetch/UI/storage combinations
    // across an application are too common to be useful evidence.
    let external_admin_html = routine_release(bump)
        && compact
        && file_gained_all_hierarchies(
            diff,
            &[
                "micro-behaviors/communications/http/request/json",
                "micro-behaviors/communications/http/request/client",
                "micro-behaviors/ui/window/manage/html-insert",
                "micro-behaviors/communications/http/request/plugin-install",
            ],
        );
    let endgame = endgame_package_shape(s);
    let dependency_with_fallback_load = signals.dependency_with_fallback_load;
    let dependency_backed_api = signals.dependency_backed_api.is_some();
    let source_download_execute = signals.source_download_execute.is_some();
    let remote_script_loader = signals.remote_script_loader;
    // A newly added encrypted ZIP disguised as another resource format is a
    // compact payload-delivery clue. Keep the differential rule narrow: it
    // must contain many encrypted entries and an executable member, so a
    // routine password-protected source archive does not fail a release.
    let added_encrypted_payload_archive = same_version && added_disguised_encrypted_archive(diff);
    // A same-version archive replacement is unusual on its own, but it is a
    // strong supply-chain shape when the replacement also changes archive
    // protection and introduces anti-analysis signals. This catches bundled
    // desktop trojans whose payload is spread across a rebuilt app bundle and
    // never produces one high trait.
    let same_version_archive_replacement = same_version
        && SAME_VERSION_ARCHIVE_REPLACEMENT.fits(s)
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
            if MemberPath::new(&file.path).depth() < 2 {
                return false;
            }
            let Some(traits) = file.scopes.traits.as_ref() else {
                return false;
            };
            // Each leg is read by word from the trait namespaces the member
            // gained: `exec` is execution, `executable` is a file format.
            let namespaces: Vec<super::capability::Text> = traits
                .added
                .iter()
                .map(|t| &t.id)
                .chain(traits.changed.iter().map(|change| &change.new.id))
                .map(|id| super::capability::Text::new(TraitId::new(id).namespace()))
                .collect();
            let has = |cues: &[Cue]| {
                namespaces
                    .iter()
                    .any(|ns| cues.iter().any(|cue| ns.matches(*cue)))
            };
            has(&[
                Cue::Path("anti-static"),
                Cue::Stem("obfuscat"),
                Cue::Word("encoded"),
                Cue::Word("base64"),
                Cue::Word("rot13"),
                Cue::Stem("decod"),
            ]) && has(&[
                Cue::Path(class::INTERPRETER),
                Cue::Stem("eval"),
                Cue::Stem("include"),
                Cue::Stem("require"),
                Cue::Word("exec"),
                Cue::Word("execv"),
                Cue::Word("execve"),
                Cue::Word("execute"),
                Cue::Word("execution"),
                Cue::Word("autoexec"),
                Cue::Stem("shell"),
                Cue::Word("powershell"),
            ]) && has(&[
                Cue::Path(class::HTTP),
                Cue::Path("fs"),
                Cue::Path("file/write"),
                Cue::Word("file_get_contents"),
                Cue::Stem("network"),
            ])
        });
    let nested_capability_cluster = compact
        && diff.files.iter().any(|file| {
            if MemberPath::new(&file.path).depth() < 2 {
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
            ["anti-static", class::INTERPRETER, class::HTTP, class::FILE]
                .iter()
                .all(|class| classes.iter().any(|got| got == class))
        });
    // A newly encoded/obfuscated file plus execution and a network/file effect
    // or detached process lifetime is a compact payload shape even when files moved
    // around it. This is deliberately a class-level combination, not a
    // filename or campaign signature.
    let encoded_payload_cluster = compact && gained_encoded_execution_cluster(diff);

    // Two platform-neutral release shapes deserve a high review signal even
    // when each individual trait is only medium:
    //
    // * build-time/native hook + low-level syscall + network + anti-analysis;
    // * wallet/private-key material + encoding + an external HTTP destination.
    // These describe the xz and xrpl families without naming either campaign.
    // A class at or below `hierarchy` that gained traits. Segment-aware, so
    // `os/signal` is not `os/signals`.
    let has_prefix = |hierarchy: &str| {
        a.behavioral
            .categories
            .iter()
            .any(|category| under(&category.class, hierarchy) && !category.new_ids.is_empty())
    };
    let native_hook_cluster = has_prefix(class::PROCESS_CREATE)
        && has_prefix(class::HTTP)
        && has_prefix("anti-analysis")
        && (has_prefix(class::SYSCALL)
            || has_prefix("supply-chain/install-hook")
            || has_prefix(class::SIGNAL));
    let native_build_hook_cluster = has_prefix(class::PROCESS_CREATE)
        && has_prefix("supply-chain")
        // Read the capability namespace, not words in an arbitrary trait ID:
        // HTTP raw-content-length-header is not a raw syscall, and a string
        // mentioning sigaction is not evidence of installing a signal handler.
        && (has_prefix(class::SYSCALL) || has_prefix(class::SIGNAL))
        && (!source_archive || source_build_anomaly);
    // Release-pressure evidence, like `remote_script_loader` above: the legs
    // below are a wallet library's ordinary job description, so they only
    // indict a release whose version number promised nothing new. xrpl.js
    // 2.14.1 -> 4.2.0 satisfies every leg — HTTP, base64, seed generation and
    // a remote host URL — because that is what an XRP Ledger client does
    // across two major versions; 2.14.1 -> 2.14.2, the real key-exfiltration
    // patch, is where the same conjunction means something.
    let secret_egress_cluster = secret_egress_cluster(a, diff, bump);
    let executable_capability_bundle = executable_capability_escalation(diff, bump);
    let binary_replacement = signals.binary_replacement.is_some();
    let opaque_runtime_payload = signals.opaque_runtime_payload.is_some();
    let runtime_graft = signals.runtime_graft.is_some();
    if focused_source
        || focused_source_with_cleanup
        || source_build_anomaly
        || cross_domain_cluster
        || external_admin_html
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
pub(crate) struct BinaryReplacementAnomaly {
    pub large_moves: usize,
    pub metric_families: usize,
}

/// Detect a rebuilt compiled artifact from content facts alone. This is the
/// trait-independent fallback for an unknown supply-chain payload: a repack of
/// the *same* version changed most scopes and radically altered several
/// independent metric families in one native/bytecode member.
///
/// The conjunction is intentionally strict. Reproducible-build noise can move
/// a timestamp or a handful of layout values, while an ordinary new release is
/// licensed by its version bump. Neither should become a hostile verdict.
pub(super) fn binary_replacement_anomaly(
    diff: &DiffReportV1,
    bump: Option<Bump>,
) -> Option<BinaryReplacementAnomaly> {
    if !bump.is_some_and(|b| matches!(b.kind, BumpKind::Same))
        || !BINARY_REPLACEMENT.fits(&diff.summary)
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
pub(crate) struct OpaqueRuntimePayloadAnomaly {
    pub entrypoint: String,
    pub payload: String,
    pub size: u64,
    pub lines: u64,
    pub encoded_ratio: f64,
    pub max_string: u64,
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
pub(super) fn opaque_runtime_payload_anomaly(
    diff: &DiffReportV1,
    bump: Option<Bump>,
    runtime_entrypoints: &HashSet<String>,
) -> Option<OpaqueRuntimePayloadAnomaly> {
    if !routine_release(bump)
        || !COMPACT_PAYLOAD.fits(&diff.summary)
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
                .then_some((
                    file,
                    as_count(size)?,
                    as_count(lines)?,
                    encoded_ratio,
                    as_count(max_string)?,
                ))
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

/// A count metric as an integer. Metrics arrive as JSON floats; one that is not
/// a whole, non-negative number within `f64`'s exact integer range is not a
/// count, and is not read as one.
pub(super) fn as_count(value: f64) -> Option<u64> {
    const EXACT: f64 = 9_007_199_254_740_992.0; // 2^53
    if value.is_finite() && (0.0..EXACT).contains(&value) && value.fract() == 0.0 {
        // In range and whole, checked just above.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(value as u64)
    } else {
        None
    }
}

/// Whether a 0/1 flag metric is set on an added or changed file.
pub(super) fn new_metric_flag(file: &FileDiffEntry, path: &str) -> bool {
    new_metric_value(file, path).is_some_and(|value| value > 0.5)
}

/// The current numeric value of a metric on an added or changed file.
pub(super) fn new_metric_value(file: &FileDiffEntry, path: &str) -> Option<f64> {
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

/// The package/container's own size, old and new, when the synthetic root
/// exposed it as a metric. There can be many member sizes, so this reads only
/// the root — and only its size metric, by name: one reader for both the
/// growth rule and the report line, which once disagreed on the key and left
/// the report line unable to match the metric cleave actually emits.
pub(super) fn root_size_change(diff: &DiffReportV1) -> Option<(f64, f64)> {
    let root = diff
        .files
        .iter()
        .find(|file| MemberPath::new(&file.path).is_root())?;
    let metrics = root.scopes.metrics.as_ref()?;
    let change = metrics
        .changed
        .iter()
        .find(|change| matches!(change.new.path.as_str(), "file.size" | "file.size_bytes"))?;
    Some((change.old.value.as_f64()?, change.new.value.as_f64()?))
}

pub(super) fn root_size_growth(diff: &DiffReportV1) -> Option<f64> {
    let (old, new) = root_size_change(diff)?;
    (old > 0.0).then_some((new - old) / old)
}

/// Source extensions a module reference may leave off. Also the set that makes
/// a bare `payload.php` recognizable as a sibling file rather than a package
/// name — `include 'payload.php'` is the ordinary same-directory spelling in
/// the ecosystems this detector targets.
pub(super) const SOURCE_EXTENSIONS: [&str; 8] =
    [".js", ".cjs", ".mjs", ".json", ".ts", ".py", ".rb", ".php"];

/// Resolve a path-looking source fact relative to its referrer and compare it
/// with an archive member. Relative paths, sibling filenames, and extensionless
/// module imports are accepted; URLs, bare package names, host-absolute paths,
/// and anything escaping the package root are rejected.
pub(super) fn local_reference_matches(referrer: &str, reference: &str, target: &str) -> bool {
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
pub(crate) struct RuntimeGraftAnomaly {
    pub entrypoint: String,
    pub payload: String,
    pub timestamp_spread: f64,
}

/// Detect a focused package repack that grafts a new externally-facing source
/// member onto the package's identity-bearing runtime entrypoint. Unlike the
/// opaque-payload branch, this catches readable implants. The archive timing
/// cluster is essential corroboration: both touched members must be singled
/// out as timestamp outliers inside a very narrow build window.
pub(super) fn runtime_graft_anomaly(
    diff: &DiffReportV1,
    bump: Option<Bump>,
    runtime_entrypoints: &HashSet<String>,
) -> Option<RuntimeGraftAnomaly> {
    if !routine_release(bump) || !COMPACT_PAYLOAD.fits(&diff.summary) {
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
pub(super) fn archive_timestamp_spread(diff: &DiffReportV1) -> Option<f64> {
    let root = diff
        .files
        .iter()
        .find(|file| MemberPath::new(&file.path).is_root())?;
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
pub(super) fn timestamp_outlier_members(diff: &DiffReportV1) -> HashSet<&str> {
    diff.files
        .iter()
        .find(|file| MemberPath::new(&file.path).is_root())
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
pub(super) fn endgame_package_shape(summary: &DiffSummary) -> bool {
    ENDGAME.fits(summary)
}

/// A dependency addition paired with a new fallback module load is a compact
/// supply-chain shape even when neither signal is individually high. The file
/// count and overall movement bounds keep ordinary framework rewrites out.
pub(super) fn dependency_with_fallback_load(a: &Assessment, diff: &DiffReportV1) -> bool {
    QUIET_DEPENDENCY_CHANGE.fits(&diff.summary)
        && a.structure.adds_dependency()
        && has_new_class(a, "os/module")
}

/// A patch gains wallet/key handling, encoding, and HTTP host references
/// together in one source file, with a core capability absent from the baseline.
/// New marker IDs within existing classes cannot establish that new capability.
/// New connections between existing capabilities require a separate differential
/// behavioral finding; co-occurrence alone cannot prove a new flow of secrets.
pub(super) fn secret_egress_cluster(
    a: &Assessment,
    diff: &DiffReportV1,
    bump: Option<Bump>,
) -> bool {
    routine_release(bump)
        && diff.files.iter().any(|file| {
            if !matches!(file.status, FileStatus::Added | FileStatus::Changed)
                || !member_type(file).is_some_and(|kind| kind.is_source_code())
            {
                return false;
            }
            let Some(traits) = &file.scopes.traits else {
                return false;
            };
            let ids = || traits.added.iter().map(|change| change.id.as_str());
            let has_class = |prefix: &str| {
                ids()
                    .filter_map(crate::rubric::capability_class)
                    .any(|class| under(&class, prefix))
            };
            let gains_core_capability =
                ids()
                    .filter_map(crate::rubric::capability_class)
                    .any(|class| {
                        a.behavioral.new_categories.contains(&class)
                            && [
                                class::HTTP,
                                class::CRYPTO_LIBRARY,
                                class::CRYPTO_ASYMMETRIC,
                                "credential-access",
                            ]
                            .iter()
                            .any(|prefix| under(&class, prefix))
                    });
            let has_secret = ids().any(|id| {
                TraitId::new(id).is_under("micro-behaviors/crypto/library/blockchain/wallet")
                    || TraitId::new(id).is_under("objectives/credential-access")
            });
            gains_core_capability
                && has_secret
                && has_class(class::HTTP)
                && (has_class("data/encode")
                    || has_class("data/decode")
                    || has_class("file/encoded"))
                && (has_class(class::CRYPTO_LIBRARY) || has_class(class::CRYPTO_ASYMMETRIC))
                && ids().any(|id| TraitId::new(id).is_under(trait_::URL_DOMAIN))
        })
}

#[derive(Debug)]
pub(crate) struct DependencyApiExpansion {
    pub dependency: String,
    pub spec: String,
    pub entrypoint: String,
}

/// Detect a patch-level public API expansion backed by newly trusted,
/// floating pre-1.0 code. Each ingredient is common on its own; their join is
/// the supply-chain boundary change: the package both pulls a mutable young
/// dependency and exposes it through its declared runtime entrypoint.
pub(super) fn dependency_backed_public_api_anomaly(
    diff: &DiffReportV1,
    bump: Option<Bump>,
    runtime_entrypoints: &HashSet<String>,
) -> Option<DependencyApiExpansion> {
    if !routine_release(bump) || !COMPACT.fits(&diff.summary) {
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

pub(super) fn normalize_api_name(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

pub(super) fn floating_pre_one_spec(spec: &str) -> bool {
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
pub(super) fn source_download_write_execute_anomaly<'a>(
    diff: &'a DiffReportV1,
    bump: Option<Bump>,
    runtime_entrypoints: &HashSet<String>,
) -> Option<&'a str> {
    if !routine_release(bump) || !COMPACT.fits(&diff.summary) {
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
        let has = |hierarchy: &str| ids().any(|id| TraitId::new(id).is_under(hierarchy));
        let fetches_response = has("micro-behaviors/communications/http/download")
            || has("micro-behaviors/communications/http/client/response-body");
        // A system-information read is not a conditional platform gate.
        let platform_gated = has("micro-behaviors/os/sysinfo/platform/branch");
        (fetches_response
            && has(trait_::PROCESS_CREATE)
            && (has(trait_::FS_WRITE) || has(trait_::FILE_WRITE))
            && platform_gated)
            .then_some(path)
    })
}

/// Structural evidence on one newly added archive, independent of trait names
/// or whether YAML traits were loaded. Missing measurements are not positives.
pub(super) fn added_disguised_encrypted_archive(diff: &DiffReportV1) -> bool {
    diff.files.iter().any(|file| {
        file.status == FileStatus::Added
            && new_metric_value(file, "archive.security.encrypted_count")
                .is_some_and(|count| count >= 5.0)
            && new_metric_value(file, "archive.executable_count").is_some_and(|count| count >= 1.0)
            && new_metric_flag(
                file,
                "consistency.extension_content_mismatch.archive_as_unknown",
            )
    })
}

/// Whether one added-or-changed file gained *every* hierarchy. A local ID rename
/// within an existing hierarchy is not a new behavior. Keep the join file-local:
/// unrelated helpers scattered
/// across a normal web application must not add up to a loader.
pub(super) fn file_gained_all_hierarchies(diff: &DiffReportV1, hierarchies: &[&str]) -> bool {
    diff.files.iter().any(|file| {
        // Archive roots aggregate their members' traits. A join on that
        // synthetic scope would combine unrelated files into a false loader.
        if !matches!(file.status, FileStatus::Added | FileStatus::Changed)
            || !member_type(file).is_some_and(|kind| kind.is_source_code())
        {
            return false;
        }
        let Some(traits) = file.scopes.traits.as_ref() else {
            return false;
        };
        hierarchies.iter().all(|hierarchy| {
            traits.added.iter().any(|change| {
                change.crit >= cleave::Criticality::Notable
                    && TraitId::new(&change.id).is_under(hierarchy)
            }) && !traits
                .removed
                .iter()
                .chain(traits.changed.iter().map(|change| &change.old))
                .any(|change| {
                    change.crit >= cleave::Criticality::Notable
                        && TraitId::new(&change.id).is_under(hierarchy)
                })
        })
    })
}

/// Correlate four new evidence families in one source file. Metadata class
/// names include their leaf (`file/encoded::...`), so exact class equality
/// silently disabled this rule. Read taxonomy namespaces instead. Encoding
/// alone is not execution, and an archive's pooled traits are not one file.
pub(super) fn gained_encoded_execution_cluster(diff: &DiffReportV1) -> bool {
    diff.files.iter().any(|file| {
        if !matches!(file.status, FileStatus::Added | FileStatus::Changed)
            || !member_type(file).is_some_and(|kind| kind.is_source_code())
        {
            return false;
        }
        let Some(traits) = &file.scopes.traits else {
            return false;
        };
        let has = |hierarchy: &str| {
            traits.added.iter().any(|finding| {
                crate::rubric::is_finding(finding.crit)
                    && TraitId::new(&finding.id).is_under(hierarchy)
            })
        };
        has("metadata/file/encoded")
            && has("objectives/anti-static/obfuscation")
            && (has(trait_::PROCESS_CREATE) || has(trait_::INTERPRETER))
            && (has("micro-behaviors/communications/http/client")
                || has("micro-behaviors/communications/http/request")
                || has(trait_::FILE_WRITE)
                || has(trait_::FS_WRITE)
                || has("micro-behaviors/process/daemonize"))
    })
}

/// A single file gains character-code conversion and script loading. This is a
/// differential review signal, not proof of an external destination or hostile
/// dataflow. The release-pressure gate is applied by the caller.
pub(super) fn gained_encoded_script_loading(diff: &DiffReportV1) -> bool {
    file_gained_all_hierarchies(diff, &[trait_::CHAR_CODE, trait_::SCRIPT_LOAD])
}

/// The non-obfuscated sibling of [`gained_encoded_script_loading`]: one file
/// gains script loading and a remote host reference.
/// This catches a payload appended plainly to a distributed browser bundle;
/// the modest-release guard belongs to [`change_shape_escalation`].
pub(super) fn gained_script_loading_with_host(diff: &DiffReportV1) -> bool {
    file_gained_all_hierarchies(diff, &[trait_::URL_DOMAIN, trait_::SCRIPT_LOAD])
}

/// The inverse of [`endgame_package_shape`], strengthened with direct evidence
/// that the old package's declared npm entrypoint was absent. This lets humans
/// and the LLM distinguish restoration of a stripped package from introduction
/// of a large new payload: generic capabilities inside the returning library
/// are baseline context unless direct implant evidence says otherwise.
pub(super) fn restored_endgame_package_shape(diff: &DiffReportV1) -> bool {
    let entrypoint_restored = diff.files.iter().any(|file| {
        file.scopes.traits.as_ref().is_some_and(|traits| {
            traits.removed.iter().any(|trait_change| {
                TraitId::new(&trait_change.id).is_under("metadata/package/files/missing-entrypoint")
            })
        })
    });
    entrypoint_restored && RESTORED_ENDGAME.fits(&diff.summary)
}

/// A newly-added executable can be an implant even when every individual API
/// looks ordinary. Score capability *families* and their combinations on the
/// file that gained them, then apply the version/package context here. The
/// family names are intentionally platform-neutral; the symbols and traits
/// that feed them can be Mach-O, ELF, PE, or source-language facts.
pub(super) fn executable_capability_escalation(
    diff: &DiffReportV1,
    bump: Option<Bump>,
) -> Severity {
    // This heuristic is intentionally about a compact payload replacement.
    // A normal archive release can replace many compiled members at once; its
    // ordinary binary capabilities must not be treated as a single implant.
    if !COMPACT.fits(&diff.summary) {
        return Severity::None;
    }
    let package_context = package_payload_context(diff);
    // Every removed member's normalized path, once: the replacement test below
    // runs per candidate file and `normalized_member_path` runs
    // `Version::detect` on each archive root.
    let removed: HashSet<String> = diff
        .files
        .iter()
        .filter(|other| matches!(other.status, FileStatus::Removed))
        .map(|other| normalized_member_path(&other.path))
        .collect();
    let mut best = 0u32;

    for file in &diff.files {
        if !matches!(file.status, FileStatus::Added | FileStatus::Changed) {
            continue;
        }
        let profile = super::capability::capability_shape(file);
        if !profile.executable {
            continue;
        }
        let replacement = matches!(file.status, FileStatus::Added)
            && removed.contains(&normalized_member_path(&file.path));
        let score =
            super::capability::capability_shape_score(&profile, package_context, replacement);
        best = best.max(score);
    }

    // A patch/repack release is not expected to introduce a multi-domain
    // executable. A minor release gets a little more room, while a major
    // release relies on the ordinary trait rubric unless the new executable
    // also carries the strongest packaging concealment signal.
    // No readable version is treated as the loosest promise here: without one
    // there is no release claim for the executable to contradict.
    let high = match bump.map_or(Promise::Anything, |b| b.kind.promise()) {
        Promise::Nothing => best >= 10,
        Promise::Features => best >= 13 && package_context,
        Promise::Anything => best >= 16 && package_context,
    };
    if high {
        Severity::High
    } else if best >= 7 {
        Severity::Medium
    } else {
        Severity::None
    }
}

/// A content-level compiled-binary marker for package topology. This includes
/// native object files as well as executables, so user-facing text must call
/// these binary members rather than claiming every one is executable.
pub(super) fn is_compiled_binary_file_type(file_type: filefacts::FileType) -> bool {
    file_type.is_binary()
}

/// Conservative fallback when member extraction is unavailable. This uses
/// executable package layout, never an extension: arbitrary `.bin`/`.dat`
/// cache or resource files must not become “payloads” merely by naming.
pub(super) fn executable_member_layout(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if super::capability::EXEC_PATH_MARKERS
        .iter()
        .any(|m| lower.contains(m))
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

pub(super) fn package_payload_context(diff: &DiffReportV1) -> bool {
    diff.files.iter().any(|file| {
        matches!(file.status, FileStatus::Added | FileStatus::Changed)
            && new_metric_value(file, "archive.executable_count").is_some_and(|count| count > 0.0)
            && (new_metric_value(file, "archive.security.encrypted_count")
                .is_some_and(|count| count > 0.0)
                || new_metric_flag(
                    file,
                    "consistency.extension_content_mismatch.archive_as_unknown",
                ))
    })
}

/// Whether a path names a source-release tarball — the `xz-5.6.0.tar.xz` form a
/// project publishes its source as, whose build macros and test fixtures are
/// part of what ships. `.tgz` is deliberately not one: it is npm's package
/// container, whose members cleave already types, and reading every one of
/// them would analyze a package's fixtures as though they ran.
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
pub(super) fn source_build_macro_anomaly(new_root: &Path, diff: &DiffReportV1) -> bool {
    diff.files.iter().any(|file| {
        if !matches!(file.status, FileStatus::Added | FileStatus::Changed)
            || !scope_diffs_changed(&file.scopes)
        {
            return false;
        }
        let Some(member) = MemberPath::new(&file.path).member() else {
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
pub(super) fn stable_source_loader_payload_refresh(
    old_root: &Path,
    new_root: &Path,
    diff: &DiffReportV1,
) -> bool {
    if !diff.files.iter().any(changed_test_carrier) {
        return false;
    }
    let mut candidates: BTreeMap<String, (Option<&str>, Option<&str>)> = BTreeMap::new();
    for file in &diff.files {
        let Some(member) = MemberPath::new(&file.path).member() else {
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

pub(super) fn changed_test_carrier(file: &FileDiffEntry) -> bool {
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

pub(super) fn source_build_macro_score(bytes: &[u8]) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(changed: u32, added: u32, removed: u32, overall: f32, traits: f32) -> DiffSummary {
        let mut s = DiffSummary {
            files_changed: changed,
            files_added: added,
            files_removed: removed,
            overall_roc: overall,
            ..DiffSummary::default()
        };
        s.scope_roc.traits = traits;
        s
    }

    #[test]
    fn an_unset_bound_does_not_constrain() {
        assert!(Movement::ANY.fits(&summary(u32::MAX, u32::MAX, u32::MAX, 7.0, -1.0)));
    }

    #[test]
    fn compact_counts_every_touched_file_inclusively() {
        assert!(COMPACT.fits(&summary(6, 5, 5, 0.0, 0.0)));
        assert!(!COMPACT.fits(&summary(6, 6, 5, 0.0, 0.0)));
        // Saturating, so a huge count fails the bound instead of wrapping.
        assert!(!COMPACT.fits(&summary(u32::MAX, 2, 0, 0.0, 0.0)));
    }

    #[test]
    fn floors_and_ceilings_are_inclusive() {
        assert!(FOCUSED_SOURCE.fits(&summary(2, 2, 2, 0.20, 0.40)));
        assert!(!FOCUSED_SOURCE.fits(&summary(2, 2, 2, 0.19, 0.40)));
        assert!(!FOCUSED_SOURCE.fits(&summary(3, 0, 0, 0.50, 0.50)));
        assert!(QUIET_DEPENDENCY_CHANGE.fits(&summary(1, 0, 0, 0.25, 0.0)));
        assert!(!QUIET_DEPENDENCY_CHANGE.fits(&summary(1, 0, 0, 0.26, 0.0)));
        // A derived shape keeps its base's bounds.
        assert!(!CROSS_DOMAIN_CLUSTER.fits(&summary(17, 0, 0, 0.50, 0.50)));
    }
}
