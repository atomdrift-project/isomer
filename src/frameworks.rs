//! Names for the MITRE ATT&CK technique ids and MBC (Malware Behavior
//! Catalog) ids a change moved, so a report can say what `T1554` *is*
//! instead of leaving the reader to look it up.
//!
//! The table is generated from the official STIX bundles by
//! `scripts/gen-framework-names.py`; isomer ships it rather than fetching at
//! run time, so a report needs no network and reads the same everywhere.

mod table;

/// The official name for an ATT&CK or MBC id, e.g. `T1027` → `Obfuscated
/// Files or Information`, `B0009` → `Virtual Machine Detection`. A
/// sub-technique carries its parent, `T1071.004` → `Application Layer
/// Protocol: DNS`, since the leaf alone (`DNS`) says too little.
///
/// An id the table lacks falls back to its parent: an MBC method such as
/// `B0001.m01` reads as its behavior. `None` when neither is known.
pub(crate) fn name(id: &str) -> Option<String> {
    let table: &[(&str, &str)] = match id.as_bytes().first()? {
        b'T' => table::ATTACK,
        b'B' | b'C' | b'E' => table::MBC,
        _ => return None,
    };
    let find = |id: &str| {
        table
            .binary_search_by(|(k, _)| k.cmp(&id))
            .ok()
            .map(|i| table[i].1)
    };
    let parent = id.split_once('.').and_then(|(p, _)| find(p));
    match (find(id), parent) {
        (Some(leaf), Some(parent)) => Some(format!("{parent}: {leaf}")),
        (Some(leaf), None) => Some(leaf.to_string()),
        (None, parent) => parent.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn known_ids_resolve_and_methods_fall_back_to_their_parent() {
        assert_eq!(
            name("T1027").as_deref(),
            Some("Obfuscated Files or Information")
        );
        assert_eq!(
            name("T1027.002").as_deref(),
            Some("Obfuscated Files or Information: Software Packing")
        );
        assert_eq!(name("B0001.m01"), name("B0001"));
        assert!(name("B0001").is_some());
        assert_eq!(name("T9999"), None);
        assert_eq!(name(""), None);
        assert_eq!(name("X1"), None);
    }

    #[test]
    fn tables_are_sorted_for_binary_search() {
        for table in [super::table::ATTACK, super::table::MBC] {
            assert!(table.windows(2).all(|w| w[0].0 < w[1].0));
        }
    }
}
