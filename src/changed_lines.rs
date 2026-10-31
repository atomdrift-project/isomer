//! The lines a change touched, written apart from the file around them.
//!
//! cleave and the model judge a file as a whole, so what surrounds a change
//! decides how it reads. A 7 KB implant prepended to a 3.6 MB bundle is a
//! sliver of the bundle's features, and a context rule that recognizes the
//! bundle — a VS Code extension, a vendored MIME table — suppresses the
//! implant's traits along with the bundle's own. Read on their own, the
//! changed lines are judged on what they do.
//!
//! Each side keeps its file's line numbering: unchanged lines are blanked, not
//! dropped, so evidence found in the changed lines points at the real line.
//! The file keeps its artifact-relative path too, so a repository's own
//! `test/` directory still reads as tests; only where the analyst stored the
//! artifact is left behind.

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use similar::ChangeTag;

use crate::analysis::Pair;

/// Bounds what a diff holds in memory: both sides and their blanked copies.
const MAX_BYTES: u64 = 32 << 20;
/// The longest unchanged first line kept as a preamble. A minified bundle's
/// first line can be the whole program, which is not a preamble.
const PREAMBLE: usize = 120;
/// Myers diff is O(ND). Past this it settles for coarser hunks, which only
/// widens them toward the whole file already analyzed.
const TIMEOUT: Duration = Duration::from_secs(2);

/// The changed lines of a comparison's pairs, written to a scratch directory
/// that lives as long as this does.
#[derive(Debug, Default)]
pub(crate) struct ChangedLines {
    dir: Option<tempfile::TempDir>,
    /// By the index of the pair they were read from.
    entries: Vec<(usize, Entry)>,
}

/// One pair, read through its changed lines.
#[derive(Debug)]
struct Entry {
    /// A side is present when its changed lines are a minority of its file:
    /// when they are most of it, the file around them is mostly the change
    /// itself, and reading them apart adds nothing.
    pair: Pair,
    /// The old side's changed lines, written whether or not they are a
    /// minority: what the new side's lines are diffed against.
    base: PathBuf,
}

impl ChangedLines {
    /// Read every text pair's changed lines. A pair that cannot be diffed by
    /// line — a side missing, unreadable, too large, or not text — or whose
    /// change is most of its file has none. An archive pair is not text; its
    /// members are added one by one with [`add`](Self::add).
    pub(crate) fn extract(pairs: &[Pair]) -> Self {
        let mut out = Self::default();
        for (index, pair) in pairs.iter().enumerate() {
            let (Some(old), Some(new)) = (pair.old.as_deref(), pair.new.as_deref()) else {
                continue;
            };
            let read = |path: &Path| -> Option<Vec<u8>> {
                (std::fs::metadata(path).ok()?.len() <= MAX_BYTES)
                    .then(|| std::fs::read(path).ok())
                    .flatten()
            };
            if let (Some(old), Some(new)) = (read(old), read(new)) {
                out.add(index, &pair.label, &old, &new);
            }
        }
        out
    }

    /// Read the changed lines of one file of `pairs[index]` — the pair itself,
    /// or a member of the archive it compares — named `label` by its
    /// artifact-relative path.
    pub(crate) fn add(&mut self, index: usize, label: &str, old: &[u8], new: &[u8]) {
        let (Some(old), Some(new)) = (text(old), text(new)) else {
            return;
        };
        let Some(blanked) = Blanked::between(old, new) else {
            return;
        };
        log::debug!(
            "changed lines: {label}: {} of {} bytes removed, {} of {} added",
            blanked.removed,
            old.len(),
            blanked.added,
            new.len(),
        );
        if self.dir.is_none() {
            match tempfile::Builder::new().prefix("isomer-").tempdir() {
                Ok(dir) => self.dir = Some(dir),
                Err(e) => {
                    log::warn!("changed lines of {label} not analyzed: no scratch directory: {e}");
                    return;
                }
            }
        }
        // One directory per entry: an archive's members share their pair.
        let Some(root) = self
            .dir
            .as_ref()
            .map(|dir| dir.path().join(self.entries.len().to_string()))
        else {
            return;
        };
        match blanked.write(&root, label, old.len(), new.len()) {
            Ok(entry) => self.entries.push((index, entry)),
            Err(e) => log::warn!("changed lines of {label} not written: {e}"),
        }
    }

    /// The changed-lines pairs read from `pairs[index]`: the file's own, or
    /// one per changed member of the archive it compares.
    pub(crate) fn of(&self, index: usize) -> impl Iterator<Item = &Pair> {
        self.entries
            .iter()
            .filter(move |(i, _)| *i == index)
            .map(|(_, entry)| &entry.pair)
    }

    /// Every changed-lines pair.
    pub(crate) fn pairs(&self) -> impl Iterator<Item = &Pair> {
        self.entries.iter().map(|(_, entry)| &entry.pair)
    }

    /// The `(old, new)` files to diff for what the added lines gained over the
    /// lines they replaced, for every pair whose added lines are a minority.
    pub(crate) fn diffs(&self) -> impl Iterator<Item = (&Path, &Path)> {
        self.entries
            .iter()
            .filter_map(|(_, entry)| Some((entry.base.as_path(), entry.pair.new.as_deref()?)))
    }
}

/// Bytes as text that can be diffed by line: bounded, UTF-8, and free of NUL,
/// which text does not carry but an uncompressed archive of text files does.
fn text(bytes: &[u8]) -> Option<&str> {
    if bytes.len() as u64 > MAX_BYTES || bytes.contains(&0) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

/// Both sides of a change with every unchanged line blanked, so each keeps its
/// file's line numbering.
#[derive(Debug, Default, PartialEq, Eq)]
struct Blanked {
    old: String,
    new: String,
    /// Bytes of changed lines on each side.
    removed: usize,
    added: usize,
}

impl Blanked {
    /// `None` when neither side's changed lines are a minority of its file.
    fn between(old: &str, new: &str) -> Option<Self> {
        let diff = similar::TextDiff::configure()
            .timeout(TIMEOUT)
            .diff_lines(old, new);
        let mut out = Self::default();
        for change in diff.iter_all_changes() {
            let line = change.value();
            match change.tag() {
                // A file's first line can decide how the rest is read —
                // `<?php`, a shebang, `'use strict'` — so a short one is kept.
                ChangeTag::Equal if change.new_index() == Some(0) && line.len() <= PREAMBLE => {
                    out.old.push_str(line);
                    out.new.push_str(line);
                }
                ChangeTag::Equal => {
                    let blank = if line.ends_with('\n') { "\n" } else { "" };
                    out.old.push_str(blank);
                    out.new.push_str(blank);
                }
                ChangeTag::Delete => {
                    out.old.push_str(line);
                    out.removed += line.len();
                }
                ChangeTag::Insert => {
                    out.new.push_str(line);
                    out.added += line.len();
                }
            }
        }
        (minority(out.removed, old.len()) || minority(out.added, new.len())).then_some(out)
    }

    /// Write both sides under `root`, at the pair's artifact-relative path.
    fn write(
        self,
        root: &Path,
        label: &str,
        old_len: usize,
        new_len: usize,
    ) -> std::io::Result<Entry> {
        let relative = relative(label);
        let base = root.join("old").join(&relative);
        let new = root.join("new").join(&relative);
        for (path, text) in [(&base, &self.old), (&new, &self.new)] {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, text)?;
        }
        Ok(Entry {
            pair: Pair {
                label: label.to_owned(),
                old: minority(self.removed, old_len).then(|| base.clone()),
                new: minority(self.added, new_len).then_some(new),
            },
            base,
        })
    }
}

/// Whether `changed` bytes are some, but at most half, of a `whole`-byte file.
fn minority(changed: usize, whole: usize) -> bool {
    changed > 0 && changed <= whole / 2
}

/// `label` as a relative path that stays under the directory it is joined to.
/// Labels come from the artifact, so `..`, roots and prefixes are dropped
/// rather than trusted.
fn relative(label: &str) -> PathBuf {
    let path: PathBuf = Path::new(label)
        .components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    if path.as_os_str().is_empty() {
        PathBuf::from("file")
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_lines_are_blanked_so_numbering_survives() {
        let blanked = Blanked::between("a\nb\nc\nd\ne\n", "implant\na\nb\nc\nd\ne\n")
            .expect("one added line is a minority");
        assert_eq!(blanked.new, "implant\n\n\n\n\n\n");
        assert_eq!(blanked.old, "\n\n\n\n\n");
        assert_eq!((blanked.removed, blanked.added), (0, 8));

        let blanked = Blanked::between("a\nb\nc\nd\n", "a\nB\nc\nd\n").expect("minority");
        // The unchanged first line is short, so it is kept as a preamble.
        assert_eq!(blanked.old, "a\nb\n\n\n");
        assert_eq!(blanked.new, "a\nB\n\n\n");
    }

    #[test]
    fn a_short_first_line_is_kept_so_the_language_still_reads() {
        let blanked = Blanked::between("<?php\na\nb\nc\nd\n", "<?php\na\nb\nc\nd\n$m[1]($m[2]);\n")
            .expect("minority");
        assert_eq!(blanked.new, "<?php\n\n\n\n\n$m[1]($m[2]);\n");
        assert_eq!(blanked.old, "<?php\n\n\n\n\n");
        // The preamble is context, not change.
        assert_eq!(blanked.added, "$m[1]($m[2]);\n".len());
        // A first line that is the program is not a preamble.
        let bundle = format!("{}\n", "x".repeat(PREAMBLE + 1));
        let blanked = Blanked::between(
            &format!("{bundle}a\nb\nc\n"),
            &format!("{bundle}a\nb\nc\nd\n"),
        )
        .expect("minority");
        assert!(blanked.new.starts_with("\n\n\n\n"));
    }

    #[test]
    fn a_change_that_is_most_of_its_file_is_left_to_the_whole_file() {
        assert_eq!(Blanked::between("a\nb\n", "a\nb\n"), None);
        // A single-line file that changed at all changed entirely.
        assert_eq!(Blanked::between("old", "new"), None);
        assert_eq!(Blanked::between("a\nb\n", "x\ny\n"), None);
    }

    #[test]
    fn labels_cannot_leave_the_scratch_directory() {
        assert_eq!(
            relative("test/fixture.js"),
            PathBuf::from("test/fixture.js")
        );
        assert_eq!(relative("../../etc/passwd"), PathBuf::from("etc/passwd"));
        assert_eq!(relative("/abs/path.js"), PathBuf::from("abs/path.js"));
        assert_eq!(relative(".."), PathBuf::from("file"));
    }

    #[test]
    fn only_minority_sides_are_read_on_their_own() {
        let dir = tempfile::tempdir().expect("tempdir");
        let old = "a\nb\nc\nd\n";
        let new = "a\nb\nc\nd\nimplant\n";
        let entry = Blanked::between(old, new)
            .expect("minority")
            .write(dir.path(), "pkg/index.js", old.len(), new.len())
            .expect("written");
        assert_eq!(entry.pair.old, None, "nothing was removed");
        let added = entry.pair.new.expect("the addition is a minority");
        assert!(added.ends_with("new/pkg/index.js"));
        // Both sides keep the short first line as a preamble.
        assert_eq!(
            std::fs::read_to_string(added).ok().as_deref(),
            Some("a\n\n\n\nimplant\n")
        );
        assert_eq!(
            std::fs::read_to_string(entry.base).ok().as_deref(),
            Some("a\n\n\n\n")
        );
    }
}
