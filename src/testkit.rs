//! Fixtures shared by the unit tests: diff entries and trait changes built the
//! way cleave emits them, without spelling out every field each time.

use cleave::Criticality;
use cleave::types::{
    DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, ScopeDiffs, TraitChange,
};

/// A diff entry with nothing in it but where it is, what it is, and what
/// happened to it. Tests fill in the scopes they exercise with struct-update
/// syntax: `FileDiffEntry { scopes, ..entry("<root>!!a.js", "javascript",
/// FileStatus::Changed) }`.
pub(crate) fn entry(path: impl Into<String>, file_type: &str, status: FileStatus) -> FileDiffEntry {
    FileDiffEntry {
        path: path.into(),
        file_type: (!file_type.is_empty()).then(|| file_type.to_owned()),
        status,
        identity: None,
        scopes: ScopeDiffs::default(),
        old_formula: None,
        new_formula: None,
    }
}

/// A trait at `crit`, fully confident, matched once, described by its id.
pub(crate) fn finding(id: &str, crit: Criticality) -> TraitChange {
    TraitChange {
        id: id.to_owned(),
        trait_section: id.split('/').next().unwrap_or(id).to_owned(),
        crit,
        conf: 1.0,
        count: 1,
        desc: id.to_owned(),
    }
}

/// A diff of `files` whose summary counts exactly those files.
pub(crate) fn diff(files: Vec<FileDiffEntry>) -> DiffReportV1 {
    let mut summary = DiffSummary::default();
    for file in &files {
        match file.status {
            FileStatus::Added => summary.files_added += 1,
            FileStatus::Removed => summary.files_removed += 1,
            FileStatus::Changed => summary.files_changed += 1,
            FileStatus::Unchanged => summary.files_unchanged += 1,
        }
    }
    DiffReportV1 {
        old_root: "old".to_owned(),
        new_root: "new".to_owned(),
        summary,
        files,
        scopes: ScopeDiffs::default(),
    }
}
