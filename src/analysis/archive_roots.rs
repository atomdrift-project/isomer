//! Git export wrappers may include the owner (`owner-repo-commit`) or omit it
//! (`repo-commit`). A matching, root-level Composer declaration can establish
//! the correspondence without guessing from shared filename suffixes. This is
//! a pairing hint, not publisher verification or a verdict override.

use std::collections::BTreeMap;

use cleave::types::{DiffReportV1, FileStatus};

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum Key {
    Path(String),
    // A separate key variant cannot collide with a literal archive directory.
    Manifest {
        container: String,
        package: String,
        suffix: String,
    },
}

#[derive(Default)]
pub(super) struct Roots {
    packages: BTreeMap<String, String>,
}

impl Roots {
    pub(super) fn from_diff(diff: &DiffReportV1) -> Self {
        let mut declarations: BTreeMap<_, (Vec<String>, Vec<String>)> = BTreeMap::new();
        let mut prefix_counts = BTreeMap::<String, usize>::new();
        for file in &diff.files {
            let Some((container, member)) = file.path.split_once("!!") else {
                continue;
            };
            let Some((root, "composer.json")) = member.split_once('/') else {
                continue;
            };
            let Some(stem) = super::git_snapshot_root(root) else {
                continue;
            };
            let prefix = format!("{container}!!{root}");
            *prefix_counts.entry(prefix.clone()).or_default() += 1;
            if file.file_type.as_deref() != Some("composer.json") {
                continue;
            }
            let Some(kv) = &file.scopes.kv else {
                continue;
            };
            let facts = match file.status {
                FileStatus::Removed => &kv.removed,
                FileStatus::Added => &kv.added,
                _ => continue,
            };
            let mut names = facts.iter().filter(|fact| fact.path == "name");
            let Some(package) = names.next().and_then(|fact| fact.value.as_str()) else {
                continue;
            };
            if names.next().is_some() {
                continue;
            }
            let Some((owner, project)) = package.split_once('/') else {
                continue;
            };
            let valid_part = |part: &str| {
                !part.is_empty()
                    && !matches!(part, "." | "..")
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            };
            if !valid_part(owner)
                || !valid_part(project)
                || (stem != project && stem != format!("{owner}-{project}"))
            {
                continue;
            }
            let sides = declarations
                .entry((container.to_string(), package.to_string()))
                .or_default();
            let side = if file.status == FileStatus::Removed {
                &mut sides.0
            } else {
                &mut sides.1
            };
            side.push(prefix);
        }
        let mut roots = Self::default();
        for ((_, package), (old, new)) in declarations {
            let ([old], [new]) = (old.as_slice(), new.as_slice()) else {
                continue;
            };
            if old != new
                && prefix_counts.get(old) == Some(&1)
                && prefix_counts.get(new) == Some(&1)
            {
                roots.packages.insert(old.clone(), package.clone());
                roots.packages.insert(new.clone(), package);
            }
        }
        roots
    }

    pub(super) fn key(&self, path: &str) -> Key {
        if let Some((container, member)) = path.split_once("!!")
            && let Some((root, suffix)) = member.split_once('/')
            && let Some(package) = self.packages.get(&format!("{container}!!{root}"))
        {
            return Key::Manifest {
                container: container.to_string(),
                package: package.clone(),
                suffix: suffix.to_string(),
            };
        }
        Key::Path(super::normalized_member_path(path))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cleave::Criticality;
    use cleave::types::{DiffSummary, FileDiffEntry, KvChange, ScopeDiff, ScopeDiffs, TraitChange};

    use super::*;
    use crate::Severity;
    use crate::analysis::{archive_member_pair, normalized_archive_diff};

    fn file(root: &str, suffix: &str, status: FileStatus) -> FileDiffEntry {
        FileDiffEntry {
            path: format!("<root>!!{root}/{suffix}"),
            file_type: Some(
                if suffix == "composer.json" {
                    "composer.json"
                } else {
                    "php"
                }
                .into(),
            ),
            status,
            identity: None,
            scopes: ScopeDiffs::default(),
            old_formula: None,
            new_formula: None,
        }
    }

    fn fixture() -> DiffReportV1 {
        let mut files = Vec::new();
        for (root, status) in [
            ("client-abcdef1234567", FileStatus::Removed),
            ("acme-client-fedcba9876543", FileStatus::Added),
        ] {
            let mut manifest = file(root, "composer.json", status);
            let mut kv = ScopeDiff::default();
            let name = KvChange {
                path: "name".into(),
                namespace: "name".into(),
                value: "acme/client".into(),
            };
            if status == FileStatus::Removed {
                kv.removed.push(name);
            } else {
                kv.added.push(name);
            }
            manifest.scopes.kv = Some(kv);
            files.push(manifest);
            files.push(file(root, "src/Client.php", status));
        }
        DiffReportV1 {
            old_root: "before.zip".into(),
            new_root: "after.zip".into(),
            summary: DiffSummary::default(),
            scopes: ScopeDiffs::default(),
            files,
        }
    }

    #[test]
    fn matching_declarations_pair_wrappers_and_recover_literal_source_paths() {
        let raw = fixture();
        let normalized = normalized_archive_diff(&raw);
        let features = crate::analysis::feature_set(&normalized);
        assert_eq!(features.judged_summary.files_unchanged, 2);
        assert_eq!(features.judged_summary.files_added, 0);
        assert_eq!(features.judged_summary.files_removed, 0);
        assert_eq!(features.judged_summary.overall_roc, 0.0);
        assert_eq!(normalized.files.len(), 2);
        assert!(
            normalized
                .files
                .iter()
                .all(|file| file.status == FileStatus::Unchanged)
        );
        let source = normalized
            .files
            .iter()
            .find(|file| file.path.ends_with("Client.php"))
            .unwrap();
        assert_eq!(
            archive_member_pair(&raw, source),
            Some((
                "client-abcdef1234567/src/Client.php",
                "acme-client-fedcba9876543/src/Client.php",
            ))
        );
        // Raw provenance remains intact.
        assert_eq!(raw.files.len(), 4);
        assert_eq!(raw.files[0].status, FileStatus::Removed);
    }

    #[test]
    fn genuine_hostile_behavior_survives_wrapper_pairing() {
        let mut raw = fixture();
        raw.files[3].scopes.traits = Some(ScopeDiff {
            added: vec![TraitChange {
                id: "objectives/exfiltration/http::credential-upload".into(),
                trait_section: "objectives".into(),
                crit: Criticality::Hostile,
                conf: 1.0,
                count: 1,
                desc: "Uploads credentials".into(),
            }],
            ..Default::default()
        });
        let normalized = normalized_archive_diff(&raw);
        assert_eq!(
            normalized
                .files
                .iter()
                .filter(|file| file.status == FileStatus::Changed)
                .count(),
            1
        );
        assert_eq!(
            crate::rubric::assess(&normalized, &HashSet::new()).new_severity(),
            Severity::Critical
        );
    }

    #[test]
    fn new_manifest_hook_remains_a_new_fact_after_pairing() {
        let mut raw = fixture();
        raw.files[2]
            .scopes
            .kv
            .as_mut()
            .unwrap()
            .added
            .push(KvChange {
                path: "scripts.post-install-cmd".into(),
                namespace: "scripts".into(),
                value: "php payload.php".into(),
            });
        let normalized = normalized_archive_diff(&raw);
        let manifest = normalized
            .files
            .iter()
            .find(|file| file.path.ends_with("composer.json"))
            .unwrap();
        assert_eq!(manifest.status, FileStatus::Changed);
        let added = &manifest.scopes.kv.as_ref().unwrap().added;
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].path, "scripts.post-install-cmd");
        assert_eq!(added[0].value, "php payload.php");
    }

    #[test]
    fn mismatched_unknown_nested_and_unrelated_declarations_do_not_pair() {
        for case in 0..6 {
            let mut raw = fixture();
            match case {
                0 => {
                    raw.files[2].scopes.kv.as_mut().unwrap().added[0].value = "other/client".into()
                }
                1 => raw.files[2].scopes.kv = None,
                2 => raw.files[2].file_type = Some("json".into()),
                3 => {
                    raw.files[2].path = raw.files[2]
                        .path
                        .replace("/composer.json", "/vendor/composer.json")
                }
                4 => {
                    for file in &mut raw.files[2..] {
                        file.path = file
                            .path
                            .replace("acme-client-fedcba9876543", "unrelated-fedcba9876543");
                    }
                }
                _ => raw.files[2].scopes.kv.as_mut().unwrap().added[0].value = "../client".into(),
            }
            assert_eq!(normalized_archive_diff(&raw).files.len(), 4, "case {case}");
        }
    }

    #[test]
    fn duplicate_declarations_and_members_are_ambiguous_not_last_writer_wins() {
        let mut raw = fixture();
        raw.files.push(raw.files[0].clone());
        assert_eq!(normalized_archive_diff(&raw).files.len(), 5);
        let mut raw = fixture();
        raw.files.push(raw.files[1].clone());
        let normalized = normalized_archive_diff(&raw);
        assert_eq!(normalized.files.len(), 4); // only the manifest pair merges
        assert_eq!(
            normalized
                .files
                .iter()
                .filter(|file| file.status == FileStatus::Removed)
                .count(),
            2
        );
    }

    #[test]
    fn package_relative_renames_and_case_changes_remain_add_remove() {
        for replacement in ["src/Renamed.php", "src/client.php"] {
            let mut raw = fixture();
            raw.files[3].path = raw.files[3].path.replace("src/Client.php", replacement);
            let normalized = normalized_archive_diff(&raw);
            assert_eq!(normalized.files.len(), 3);
            assert_eq!(
                normalized
                    .files
                    .iter()
                    .filter(|file| file.status == FileStatus::Added)
                    .count(),
                1
            );
            assert_eq!(
                normalized
                    .files
                    .iter()
                    .filter(|file| file.status == FileStatus::Removed)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn declarations_cannot_pair_across_different_containers() {
        let mut raw = fixture();
        for file in &mut raw.files[2..] {
            file.path = file.path.replace("<root>!!", "other.zip!!");
        }
        assert_eq!(normalized_archive_diff(&raw).files.len(), 4);
    }

    #[test]
    fn conflicting_package_claims_cannot_reuse_one_archive_root() {
        let mut raw = fixture();
        let mut other_old = raw.files[0].clone();
        other_old.scopes.kv.as_mut().unwrap().removed[0].value = "other/client".into();
        let mut other_new = raw.files[2].clone();
        other_new.scopes.kv.as_mut().unwrap().added[0].value = "other/client".into();
        other_new.path = other_new.path.replace("acme-client-", "other-client-");
        raw.files.extend([other_old, other_new]);
        assert!(Roots::from_diff(&raw).packages.is_empty());
        assert_eq!(normalized_archive_diff(&raw).files.len(), 6);
    }

    #[test]
    fn changed_file_type_is_not_an_unchanged_member() {
        let mut raw = fixture();
        raw.files[3].file_type = Some("elf".into());
        let normalized = normalized_archive_diff(&raw);
        let source = normalized
            .files
            .iter()
            .find(|file| file.path.ends_with("Client.php"))
            .unwrap();
        assert_eq!(source.status, FileStatus::Changed);
        assert_eq!(source.file_type.as_deref(), Some("elf"));
    }
}
