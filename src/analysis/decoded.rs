//! A decoded fragment is another view of its source, not an independent file.
//! Offsets change when earlier code grows. Keep the physical diff intact, but
//! don't call a capability new solely because it moved between decoded views
//! or became visible in the parent's raw-text scan.

use std::borrow::Cow;
use std::collections::BTreeMap;

use cleave::types::{Changed, DiffReportV1, TraitChange};

use crate::rubric::crit_rank;

/// Recognize cleave's generated `parent!!parent##encoding@offset` names.
/// Requiring the repeated source name avoids interpreting ordinary archive
/// filenames containing `##` as decoded views.
fn owner(path: &str) -> Option<&str> {
    let (parent, leaf) = path.rsplit_once("!!")?;
    let (source, location) = leaf.rsplit_once("##")?;
    let (encoding, offset) = location.split_once('@')?;
    (source == parent.rsplit("!!").next()?
        && !encoding.is_empty()
        && encoding
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'-' || b == b'+')
        && !offset.is_empty()
        && offset.bytes().all(|b| b.is_ascii_digit()))
    .then_some(parent)
}

pub(super) fn reconcile_traits(mut diff: Cow<'_, DiffReportV1>) -> Cow<'_, DiffReportV1> {
    if !diff.files.iter().any(|file| owner(&file.path).is_some()) {
        return diff;
    }
    // Union the known old inventories at each logical source and its archive
    // ancestors. Never propagate sideways: an added sibling carrying the same
    // capability must still be judged independently.
    let mut baseline: BTreeMap<String, BTreeMap<String, TraitChange>> = BTreeMap::new();
    for file in &diff.files {
        let Some(traits) = &file.scopes.traits else {
            continue;
        };
        for old in traits
            .removed
            .iter()
            .chain(traits.changed.iter().map(|c| &c.old))
        {
            let mut path = owner(&file.path).unwrap_or(&file.path);
            loop {
                let inventory = baseline.entry(path.to_owned()).or_default();
                let entry = inventory
                    .entry(old.id.clone())
                    .or_insert_with(|| old.clone());
                if crit_rank(old.crit) > crit_rank(entry.crit) {
                    *entry = old.clone();
                }
                let Some((parent, _)) = path.rsplit_once("!!") else {
                    break;
                };
                path = parent;
            }
        }
    }
    let mut replacements = Vec::new();
    for (index, file) in diff.files.iter().enumerate() {
        let Some(inventory) = baseline.get(owner(&file.path).unwrap_or(&file.path)) else {
            continue;
        };
        let Some(traits) = &file.scopes.traits else {
            continue;
        };
        for (added_index, new) in traits.added.iter().enumerate() {
            if let Some(old) = inventory.get(&new.id) {
                replacements.push((index, added_index, old.clone()));
            }
        }
    }
    if !replacements.is_empty() {
        let judged = diff.to_mut();
        // Reverse indexes keep removal stable. Promotions remain changed
        // findings, so Gate::Any still reports severity increases.
        for (index, added_index, old) in replacements.into_iter().rev() {
            let Some(traits) = judged.files[index].scopes.traits.as_mut() else {
                continue;
            };
            let new = traits.added.remove(added_index);
            traits.changed.push(Changed { old, new });
        }
    }
    diff
}
