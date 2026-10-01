//! The whole text of source files whose behavior moved: atoms and line diffs.

use std::collections::HashSet;
use std::path::Path;

use cleave::types::{DiffReportV1, FileDiffEntry, FileStatus};

use crate::member::MemberPath;
use crate::version::Version;

use super::{Analysis, Pair, member_type, shown_member_path};

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

/// Whether the file's trait scope moved at all — the test for "this file
/// changed behavior", regardless of how small the change was judged.
pub(super) fn traits_moved(entry: &FileDiffEntry) -> bool {
    entry
        .scopes
        .traits
        .as_ref()
        .is_some_and(|traits| !traits.added.is_empty() || !traits.removed.is_empty())
}

/// Trait atoms that moved on one file, worst criticality first. Added and
/// removed together — a reviewer wants both directions of a source change.
pub(super) fn trait_atoms(entry: &FileDiffEntry) -> Vec<Atom> {
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
    atoms.sort_by(|a, b| b.crit.rank().cmp(&a.crit.rank()).then(a.id.cmp(&b.id)));
    atoms
}

/// A full line diff of two text files: `+` for a line only on the new side,
/// `-` for one only on the old, a space for context. Set-based (not
/// positional), so a moved line reads as context and the output is
/// order-independent — enough for an LLM to see exactly what text entered or
/// left. Lines are compared by [`crate::evidence::line_key`], the same key the
/// evidence gutter uses. Control chars are neutralized; each side is capped at
/// `MAX_LINES` lines, with a marker where either was cut, so one large file
/// can't blow the context budget.
pub(super) fn line_diff(old: &[u8], new: &[u8]) -> String {
    use crate::evidence::line_key;
    const MAX_LINES: usize = 400;

    let old_text = String::from_utf8_lossy(old);
    let new_text = String::from_utf8_lossy(new);
    let old_set: HashSet<&str> = old_text.lines().map(line_key).collect();
    let new_set: HashSet<&str> = new_text.lines().map(line_key).collect();

    let mut out: Vec<String> = Vec::new();
    let mut new_lines = new_text.lines();
    for line in new_lines.by_ref().take(MAX_LINES) {
        let mark = if old_set.contains(line_key(line)) {
            ' '
        } else {
            '+'
        };
        out.push(format!("{mark} {}", crate::printable(line)));
    }
    if new_lines.next().is_some() {
        out.push("  … (new side truncated)".to_owned());
    }
    let mut removed = old_text.lines().filter(|l| !new_set.contains(line_key(l)));
    for line in removed.by_ref().take(MAX_LINES) {
        out.push(format!("- {}", crate::printable(line)));
    }
    if removed.next().is_some() {
        out.push("  … (removed lines truncated)".to_owned());
    }
    let mut s = out.join("\n");
    if !s.is_empty() {
        s.push('\n');
    }
    s
}

/// Resolve a normalized changed member back to the raw archive paths of its two
/// sides. Version-root normalization can merge a raw Removed+Added pair into a
/// Changed entry, so extraction must recover each side's literal member name.
/// `roots` is built once from `raw` by the caller: this runs per member.
pub(super) fn archive_member_pair<'a>(
    raw: &'a DiffReportV1,
    roots: &super::archive_roots::Roots,
    normalized: &FileDiffEntry,
) -> Option<(&'a str, &'a str)> {
    let key = roots.key(&normalized.path);
    // The literal name this member goes by on the side it is not `absent` from
    // — `Added` is the status missing from the old side, `Removed` from the
    // new. Only a lone candidate names a side; several would be a guess.
    let side = |absent: FileStatus| {
        let mut members = raw
            .files
            .iter()
            .filter(|entry| entry.status != absent && roots.key(&entry.path) == key)
            .filter_map(|entry| MemberPath::new(&entry.path).member())
            .filter(|member| !member.contains('!'));
        let member = members.next()?;
        members.next().is_none().then_some(member)
    };
    Some((side(FileStatus::Added)?, side(FileStatus::Removed)?))
}

/// The bytes of one archive member, or `None` when it cannot be read — an
/// absence is ordinary, a failure is worth a word on stderr.
pub(super) fn archive_member_bytes(archive: &Path, canonical_member: &str) -> Option<Vec<u8>> {
    for candidate in archive_member_candidates(archive, canonical_member) {
        match cleave::extract_member(archive, &candidate) {
            Ok(Some(bytes)) => return Some(bytes),
            Ok(None) => {}
            Err(error) => {
                log::warn!(
                    "could not extract {canonical_member} from {}: {error:#}",
                    archive.display()
                );
                return None;
            }
        }
    }
    None
}

/// Candidate literal member paths for Cleave's canonicalized archive path.
/// Source distributions conventionally change `name-version/` between
/// releases; Cleave reports the stable `name/` path, while extraction needs
/// the original root. The archive filename supplies the exact version token.
pub(super) fn archive_member_candidates(archive: &Path, canonical_member: &str) -> Vec<String> {
    let mut candidates = vec![canonical_member.to_string()];
    let Some(version) = archive
        .file_name()
        .and_then(|name| Version::detect(&name.to_string_lossy()))
    else {
        return candidates;
    };
    let Some((root, suffix)) = canonical_member.split_once('/') else {
        return candidates;
    };
    if Version::detect(root).is_none() {
        candidates.push(format!("{root}-{}/{suffix}", version.raw));
    }
    candidates
}

impl Analysis<'_> {
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
    pub(super) fn collect_source_changes(&self) -> Vec<SourceChange> {
        // A single-file `fs` comparison names its one diff entry `<root>`, not
        // the basename, so it can't be matched to the pair by path — but there
        // is only one pair, so the lone changed entry is unambiguously its.
        let single = self.pairs.len() == 1;
        // An archive comparison is one pair — the container — while the files
        // that changed are members inside it (`container!!member`). Their text
        // has to come back out of the archive, so they get their own walk.
        if let [container] = self.pairs.as_slice()
            && self
                .judged_diff
                .files
                .iter()
                .any(|file| MemberPath::new(&file.path).is_member())
        {
            return self.collect_archive_source_changes(container);
        }
        let mut out = Vec::new();
        for pair in &self.pairs {
            let (Some(old), Some(new)) = (pair.old.as_deref(), pair.new.as_deref()) else {
                continue;
            };
            let Some(entry) = self.diff.files.iter().find(|f| {
                !matches!(f.status, FileStatus::Unchanged)
                    && (single || f.path == pair.label)
                    && traits_moved(f)
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
            // An unreadable base is not an empty base. Defaulting to empty would
            // render every line of the new file as an addition and hand both the
            // reader and the LLM a whole-file rewrite that never happened.
            let old_bytes = match std::fs::read(old) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::warn!("could not read base {}: {e:#}", old.display());
                    continue;
                }
            };
            out.push(SourceChange {
                label: pair.label.clone(),
                atoms: trait_atoms(entry),
                diff: line_diff(&old_bytes, &new_bytes),
            });
        }
        out
    }

    /// The archive counterpart of [`collect_source_changes`](Self::collect_source_changes):
    /// every changed source member of the container, each side extracted so the
    /// member gets the same whole line diff a plain file would.
    pub(super) fn collect_archive_source_changes(&self, container: &Pair) -> Vec<SourceChange> {
        let (Some(old_archive), Some(new_archive)) =
            (container.old.as_deref(), container.new.as_deref())
        else {
            return Vec::new();
        };
        let roots = super::archive_roots::Roots::from_diff(self.diff);
        let mut out = Vec::new();
        for entry in &self.judged_diff.files {
            if !matches!(entry.status, FileStatus::Changed)
                || !traits_moved(entry)
                || !member_type(entry).is_some_and(|file_type| file_type.is_source_code())
            {
                continue;
            }
            let Some((old_member, new_member)) = archive_member_pair(self.diff, &roots, entry)
            else {
                continue;
            };
            let (Some(old_bytes), Some(new_bytes)) = (
                archive_member_bytes(old_archive, old_member),
                archive_member_bytes(new_archive, new_member),
            ) else {
                continue;
            };
            out.push(SourceChange {
                label: shown_member_path(&entry.path),
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

    /// Identify an archive member from its bytes, using the same content-first
    /// filefacts detector as cleave. The diff stores analysis facts but not the
    /// member bytes, so recover them from the root archive when this is a local
    /// comparison. `None` means extraction was unavailable; callers may then
    /// use only a conservative package-layout hint.
    pub(super) fn member_file_type(
        &self,
        path: &str,
        status: FileStatus,
    ) -> Option<filefacts::FileType> {
        let (root, member) = MemberPath::new(path).split()?;
        // A single-file comparison names its one diff entry `<root>`, so it
        // never matches by path — but the lone pair is unambiguously its.
        let sole = match self.pairs.as_slice() {
            [only] => Some(only),
            _ => None,
        };
        let pair = self.pairs.iter().find(|p| p.label == root).or(sole)?;
        let archive = match status {
            FileStatus::Added | FileStatus::Changed => pair.new.as_deref().or(pair.old.as_deref()),
            FileStatus::Removed => pair.old.as_deref().or(pair.new.as_deref()),
            FileStatus::Unchanged => None,
        }?;
        let bytes = cleave::extract_member(archive, member).ok().flatten()?;
        Some(filefacts::FileId::from_bytes(&bytes).file_type())
    }
}
