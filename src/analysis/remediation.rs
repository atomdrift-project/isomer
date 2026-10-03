//! Recognizing a transition that removes or disables attack behavior.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use cleave::types::{DiffReportV1, FileStatus, TraitChange};

use crate::Severity;
use crate::member::MemberPath;
use crate::rubric::Assessment;
use crate::taxonomy::TraitId;

use super::Analysis;
use super::detectors::has_new_class;
use super::hierarchy::class;

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

/// Recognize a focused remediation without trusting incident prose alone.
///
/// The joined shape requires newly referenced concealed-payload evidence,
/// new file-deletion behavior, and at least two functions newly disabled by an immediate
/// entry return. The latter is executable evidence: it distinguishes a repair
/// that retains dead forensic code from an attacker merely claiming cleanup.
pub(super) fn remediation_cleanup_context(
    old_root: &Path,
    new_root: &Path,
    a: &Assessment,
    judged_diff: &DiffReportV1,
    raw_diff: &DiffReportV1,
    risk: Option<crate::risk::Risk>,
) -> Option<Remediation> {
    let payload_evidence = raw_diff.files.iter().any(|file| {
        file.scopes.traits.as_ref().is_some_and(|traits| {
            traits.added.iter().any(|finding| {
                TraitId::new(&finding.id).is_under("objectives/supply-chain/hidden-payload")
            })
        })
    });
    // Last in the chain on purpose: it extracts every added or changed member
    // from *both* roots, and the cheap predicates ahead of it are false on
    // essentially every run.
    let compact_cleanup = payload_evidence
        && has_new_class(a, class::DELETE)
        && focused_cleanup_budget(judged_diff)
        && newly_disabled_source_functions(old_root, new_root, raw_diff) >= 2;
    // A fixed release often removes the malicious code instead of adding a
    // recognizable signature. A large same-package model-risk drop is strong
    // evidence of that remediation transition; the clean baseline→fixed
    // comparison does not have the drop and remains subject to normal gates.
    let model_recovery = risk.is_some_and(|r| r.old >= 0.80 && r.old - r.new >= 0.40);
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

/// Every path some other entry descends from — the containers the diff
/// expanded into members. Gathered in one pass so the per-file checks below are
/// lookups, not a scan of every entry per entry.
pub(super) fn expanded_containers(diff: &DiffReportV1) -> HashSet<&str> {
    diff.files
        .iter()
        .flat_map(|file| MemberPath::new(&file.path).containers())
        .collect()
}

/// Expanded containers duplicate their members' changes. A tree and its ZIP
/// should have the same cleanup budget. Keep opaque archives in the count:
/// only an actual descendant proves that the container is represented below.
pub(super) fn cleanup_member_counts(
    diff: &DiffReportV1,
    expanded: &HashSet<&str>,
) -> (usize, usize) {
    let mut changed = 0;
    let mut added = 0;
    for file in &diff.files {
        if !matches!(file.status, FileStatus::Changed | FileStatus::Added)
            || expanded.contains(file.path.as_str())
        {
            continue;
        }
        changed += usize::from(matches!(file.status, FileStatus::Changed));
        added += usize::from(matches!(file.status, FileStatus::Added));
    }
    (changed, added)
}

pub(super) fn focused_cleanup_budget(diff: &DiffReportV1) -> bool {
    let expanded = expanded_containers(diff);
    let (changed, added) = cleanup_member_counts(diff, &expanded);
    changed + added <= 16 && added <= 1 && cleanup_behavior_changes(diff, &expanded) <= 4
}

/// Focus cleanup on the files gaining meaningful observations, not unrelated
/// sub-finding churn. Missing or truncated scopes cannot prove absence
/// of behavior and therefore consume the budget. Added files always count.
pub(super) fn cleanup_behavior_changes(diff: &DiffReportV1, expanded: &HashSet<&str>) -> usize {
    diff.files
        .iter()
        .filter(|file| {
            if !matches!(file.status, FileStatus::Changed | FileStatus::Added)
                || expanded.contains(file.path.as_str())
            {
                return false;
            }
            if matches!(file.status, FileStatus::Added) {
                return true;
            }
            let Some(traits) = &file.scopes.traits else {
                return true;
            };
            traits.truncated
                || traits
                    .added
                    .iter()
                    .any(|finding| crate::rubric::is_finding(finding.crit))
                || traits.changed.iter().any(|change| {
                    crate::rubric::is_finding(change.new.crit)
                        && change.new.crit.rank() > change.old.crit.rank()
                })
        })
        .count()
}

pub(super) fn removed_high_risk_traits(diff: &DiffReportV1) -> Vec<&TraitChange> {
    let mut findings = diff
        .files
        .iter()
        .filter_map(|file| file.scopes.traits.as_ref())
        .flat_map(|traits| {
            traits.removed.iter().chain(
                traits
                    .changed
                    .iter()
                    .filter(|change| change.old.crit.rank() > change.new.crit.rank())
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

pub(super) fn attack_behavior_removed(diff: &DiffReportV1, new_severity: Severity) -> bool {
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
pub(super) fn newly_disabled_source_functions(
    old_root: &Path,
    new_root: &Path,
    diff: &DiffReportV1,
) -> usize {
    diff.files
        .iter()
        .filter(|file| matches!(file.status, FileStatus::Added | FileStatus::Changed))
        .map(|file| {
            let Some(new) = diff_source_bytes(new_root, &file.path)
                .as_deref()
                .map(|bytes| immediate_entry_return_count(&file.path, bytes))
            else {
                return 0;
            };
            let old = diff_source_bytes(old_root, &file.path)
                .as_deref()
                .map(|bytes| immediate_entry_return_count(&file.path, bytes));
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

pub(super) fn diff_source_bytes(root: &Path, diff_path: &str) -> Option<Vec<u8>> {
    if let Some(member) = MemberPath::new(diff_path).member() {
        return cleave::extract_member(root, member)
            .inspect_err(|e| {
                log::warn!("could not extract {member} from {}: {e:#}", root.display())
            })
            .ok()
            .flatten();
    }
    let path = if root.is_dir() {
        root.join(diff_path)
    } else {
        root.to_path_buf()
    };
    std::fs::read(&path)
        .inspect_err(|e| log::warn!("could not read {}: {e}", path.display()))
        .ok()
}

pub(super) fn immediate_entry_return_count(path: &str, bytes: &[u8]) -> usize {
    let parsed = filefacts::OpenOptions::new()
        .path(Path::new(path))
        .open(bytes);
    let Some(ast) = parsed.source_ast() else {
        return 0;
    };
    let root = ast.tree.root_node();
    // This proof can lower a verdict. An unavailable or recovered parse is
    // unknown, never proof that code is disabled. Text examples in comments,
    // strings, and heredocs must not manufacture an entry-return signal.
    if root.has_error() {
        return 0;
    }
    let mut count = 0;
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        if matches!(
            node.kind(),
            "function_definition"
                | "function_declaration"
                | "method_declaration"
                | "method_definition"
        ) && let Some(body) = node.child_by_field_name("body")
            && matches!(body.kind(), "compound_statement" | "statement_block")
        {
            let mut body_cursor = body.walk();
            let first = body
                .named_children(&mut body_cursor)
                .find(|child| child.kind() != "comment");
            if first.is_some_and(|statement| {
                statement.kind() == "return_statement" && statement.named_child_count() == 0
            }) {
                count += 1;
            }
        }
        // Cursor traversal is iterative even for adversarial nesting.
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return count;
            }
        }
    }
}

impl Analysis<'_> {
    /// Suspicious/hostile traits that disappeared, grouped for terminal and
    /// model context. The normal rubric is intentionally gain-oriented for CI;
    /// this supplies the equally important remediation direction.
    pub(crate) fn removed_high_risk_behaviors(&self) -> Vec<RemovedBehavior> {
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for finding in removed_high_risk_traits(self.display_diff()) {
            let namespace = TraitId::new(&finding.id).path();
            let leaf = crate::rubric::short_name(&finding.id);
            let traits = groups.entry(namespace.to_owned()).or_default();
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
}
