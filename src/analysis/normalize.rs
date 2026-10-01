//! Pairing archive members across releases whose roots differ only by version or convention, before anything is judged.

use std::borrow::Cow;
use std::collections::BTreeMap;

use cleave::types::{
    Changed, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, KvChange, MetricChange,
    ScopeDiff, ScopeDiffs, ScopeRocs, SectionChange, StringChange, SymbolChange, TraitChange,
};

use crate::member::MemberPath;
use crate::version::Version;

use super::naming::clean_name;

/// Pair members when only the outer archive directory carries a version.
///
/// cleave canonicalizes two single-file roots, but directory/archive-member
/// paths are currently paired literally. Reuse the same version detector and
/// name cleaning as the report's filename logic so
/// `pkg-1.0/bin/x` and `pkg-1.1/bin/x` are judged as one file. The raw report
/// remains untouched for evidence and auditing.
pub(super) fn normalized_archive_diff(diff: &DiffReportV1) -> Cow<'_, DiffReportV1> {
    super::decoded::reconcile_traits(normalized_archive_members(diff))
}

pub(super) fn normalized_archive_members(diff: &DiffReportV1) -> Cow<'_, DiffReportV1> {
    let roots = super::archive_roots::Roots::from_diff(diff);
    let mut groups: BTreeMap<_, Vec<&FileDiffEntry>> = BTreeMap::new();
    for file in &diff.files {
        if !MemberPath::new(&file.path).is_member() {
            continue;
        }
        groups.entry(roots.key(&file.path)).or_default().push(file);
    }

    let mut aliases: Vec<(&FileDiffEntry, &FileDiffEntry)> = groups
        .values()
        .filter_map(|candidates| {
            // Neither duplicate roots nor an existing exact-path pair may be
            // overwritten by another member with the same normalized key.
            let [a, b] = candidates.as_slice() else {
                return None;
            };
            let (old, new) = match (a.status, b.status) {
                (FileStatus::Removed, FileStatus::Added) => (*a, *b),
                (FileStatus::Added, FileStatus::Removed) => (*b, *a),
                _ => return None,
            };
            (old.path != new.path).then_some((old, new))
        })
        .collect();

    // npm distribution tarballs conventionally use `package/` as their root,
    // while a clean GitHub source snapshot normally uses `name-version/`.
    // Pair identical paths beneath those roots so a source-snapshot baseline
    // does not turn a one-file payload injection into 100% archive churn.
    // Requiring exactly one literal `package/` root keeps arbitrary renamed
    // multi-root archives distinct.
    let npm = alias_across_layouts(diff, &aliases, npm_snapshot_member_key);
    aliases.extend(npm);
    // Python source distributions commonly keep importable packages beneath
    // `name-version/src/`, while wheels place the same package directly at the
    // archive root. Pair only an exact suffix match across those two layouts.
    let python = alias_across_layouts(diff, &aliases, python_distribution_member_key);
    aliases.extend(python);
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
        let status = if old.file_type != new.file_type
            || identity.as_ref().is_some_and(|diff| diff.changed)
            || scope_diffs_changed(&scopes)
        {
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

/// Which archive convention a member path follows, for pairing one member
/// across two conventions that disagree only about the root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Layout {
    /// npm's literal `package/` root.
    NpmPackage,
    /// A `name-version/` source-snapshot root.
    VersionedRoot,
    /// A versioned sdist's conventional `name-version/src/` tree.
    SdistSrc,
    /// A wheel's flat, import-path layout.
    Flat,
}

/// The path below an npm/source-snapshot archive root, and which of the two
/// roots it sits under.
pub(super) fn npm_snapshot_member_key(path: &str) -> Option<(Layout, String)> {
    let member = MemberPath::new(path).leaf();
    let (root, suffix) = member.split_once('/')?;
    if root.eq_ignore_ascii_case("package") {
        return Some((Layout::NpmPackage, suffix.to_ascii_lowercase()));
    }
    Version::detect(root).map(|_| (Layout::VersionedRoot, suffix.to_ascii_lowercase()))
}

/// An import-path key, and whether it came from a versioned sdist's `src/`
/// tree or a flat layout. Flat members are candidates only; they can pair
/// solely with an exact key from the sdist layout.
pub(super) fn python_distribution_member_key(path: &str) -> Option<(Layout, String)> {
    let member = MemberPath::new(path).leaf();
    let (root, suffix) = member.split_once('/')?;
    if Version::detect(root).is_some() {
        return suffix
            .strip_prefix("src/")
            .map(|suffix| (Layout::SdistSrc, suffix.to_ascii_lowercase()));
    }
    if root.ends_with(".dist-info") || root.ends_with(".egg-info") {
        return None;
    }
    Some((Layout::Flat, member.to_ascii_lowercase()))
}

/// Removed/added member pairs that `key` places at the same path under two
/// different layouts, among the members not already paired in `taken`.
///
/// Exactly one removed and one added member under a key, in different
/// layouts, is an unambiguous rename across conventions; anything else is a
/// genuine add or delete.
pub(super) fn alias_across_layouts<'d>(
    diff: &'d DiffReportV1,
    taken: &[(&FileDiffEntry, &FileDiffEntry)],
    key: impl Fn(&str) -> Option<(Layout, String)>,
) -> Vec<(&'d FileDiffEntry, &'d FileDiffEntry)> {
    use std::collections::BTreeSet;

    let taken: BTreeSet<&str> = taken
        .iter()
        .flat_map(|(old, new)| [old.path.as_str(), new.path.as_str()])
        .collect();
    let mut groups: BTreeMap<String, Vec<(&FileDiffEntry, Layout)>> = BTreeMap::new();
    for file in &diff.files {
        if taken.contains(file.path.as_str())
            || !matches!(file.status, FileStatus::Removed | FileStatus::Added)
        {
            continue;
        }
        if let Some((layout, suffix)) = key(&file.path) {
            groups.entry(suffix).or_default().push((file, layout));
        }
    }
    groups
        .values()
        .filter_map(|candidates| {
            let side = |status| -> Vec<&(&FileDiffEntry, Layout)> {
                candidates
                    .iter()
                    .filter(|(file, _)| file.status == status)
                    .collect()
            };
            match (
                side(FileStatus::Removed).as_slice(),
                side(FileStatus::Added).as_slice(),
            ) {
                ([(old, old_layout)], [(new, new_layout)]) if old_layout != new_layout => {
                    Some((*old, *new))
                }
                _ => None,
            }
        })
        .collect()
}

/// Whether any of the six scopes recorded an addition, removal, or change.
/// cleave's own erased per-scope view answers this, so the fan-out over the six
/// scopes stays where the scopes are defined.
pub(super) fn scope_diffs_changed(scopes: &ScopeDiffs) -> bool {
    cleave::types::Scope::ALL
        .iter()
        .any(|s| scopes.view(*s).has_changes)
}

pub(super) fn merge_identity(
    old: &FileDiffEntry,
    new: &FileDiffEntry,
) -> Option<cleave::types::IdentityDiff> {
    let old_id = old.identity.as_ref().and_then(|i| i.old.clone());
    let new_id = new.identity.as_ref().and_then(|i| i.new.clone());
    (old_id.is_some() || new_id.is_some()).then_some(cleave::types::IdentityDiff {
        changed: old_id != new_id,
        old: old_id,
        new: new_id,
    })
}

pub(super) fn merge_scopes(old: &FileDiffEntry, new: &FileDiffEntry) -> ScopeDiffs {
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
pub(super) fn merge_scope<T: Clone>(
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

pub(super) fn normalized_summary(files: &[FileDiffEntry]) -> DiffSummary {
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

/// Normalize only a version-bearing archive/package root for matching. A
/// literal `foo/bin/x` stays distinct from `bar/bin/x`; `foo-1.0/bin/x` and
/// `foo-1.1/bin/x` both become `foo/bin/x`. This is the same conservative
/// `Version::detect` + `clean_name` rule used by the filename header logic.
pub(super) fn normalized_member_path(path: &str) -> String {
    let path = MemberPath::new(path);
    if !path.is_member() {
        return path.display().to_owned();
    }
    crate::member::join(path.layers().map(|member| {
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
    }))
}

/// Strip the abbreviated/full commit suffix used by Git hosting source
/// snapshots (`project-deadbee/…`). Requiring a normal Git hash length and at
/// least one hex letter avoids treating ordinary numeric directory suffixes as
/// commits; version-bearing roots are handled separately above.
pub(super) fn git_snapshot_root(root: &str) -> Option<&str> {
    let (name, commit) = root.rsplit_once('-')?;
    (!name.is_empty()
        && (7..=40).contains(&commit.len())
        && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        && commit
            .bytes()
            .any(|byte| matches!(byte.to_ascii_lowercase(), b'a'..=b'f')))
    .then_some(name)
}
