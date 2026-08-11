//! Pairing files that two trees name differently.
//!
//! Build systems and package managers put volatile tokens in filenames:
//! `libssl.so.1.1` becomes `libssl.so.3`, `main.4f2a1b9c.js` becomes
//! `main.d4e5f60a.js` on every bundle, `busybox-1.37.0-r12.apk` becomes
//! `busybox-1.38.0-r1.apk`. Compared by path, all of those read as one file
//! vanishing and an unrelated one appearing — so every capability the artifact
//! has looks newly introduced, on every single change.
//!
//! The fix is to pair them before anything is judged. Rather than scoring every
//! old file against every new one, each name is reduced to an *identity*: the
//! tokens left after dropping the volatile ones. Identical identities pair.
//! That is two hash lookups per file rather than a quadratic sweep, and it
//! costs nothing to read a file's bytes because it never does.
//!
//! Deliberately conservative in three ways. The directory is part of the
//! identity, so files never pair across directories — a genuine move is git's
//! job, where `ci` already asks for rename detection. The leading token must
//! survive, so `1.2.3.tar.gz` cannot pair with `4.5.6.tar.gz` on the strength
//! of an extension. And a name with no volatile token has no identity at all,
//! leaving it to the exact-path pass.
//!
//! A wrong pairing is bounded rather than dangerous: the two files are then
//! diffed against each other, so anything the "renamed" file can do that its
//! partner could not is still reported as gained.

use std::collections::HashMap;
use std::path::Path;

/// What a filename is once its volatile tokens are removed: the directory, and
/// the tokens that survived.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct Identity<'a> {
    dir: &'a str,
    stable: Vec<&'a str>,
}

/// A token that names a build rather than the thing built.
fn volatile(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    // A version component or a date stamp: `1`, `37`, `20240101`.
    if bytes.iter().all(u8::is_ascii_digit) {
        return true;
    }
    // An APK-style revision: `r12`.
    if let Some(rest) = token.strip_prefix('r')
        && !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit())
    {
        return true;
    }
    // A content hash: `4f2a1b9c`. Eight is the shortest any bundler emits, and
    // short enough that a hex-looking English word (`deadbeef`, `facade`) can
    // reach it — hence the rule that the leading token must survive, so a file
    // actually named `deadbeef.js` keeps its identity.
    if bytes.len() >= 8 && bytes.iter().all(u8::is_ascii_hexdigit) {
        return true;
    }
    // A checksum in some wider alphabet, e.g. the base64 in an apk script name.
    // Long, mixed, and not a word: letters and digits both required.
    if bytes.len() >= 16
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'=' | b'_'))
        && bytes.iter().any(u8::is_ascii_digit)
        && bytes.iter().any(u8::is_ascii_alphabetic)
    {
        return true;
    }
    false
}

/// The identity of a path, or `None` when it has no volatile token to look
/// past — in which case only its exact path can match.
pub(crate) fn identity(path: &str) -> Option<Identity<'_>> {
    let (dir, name) = match path.rsplit_once('/') {
        Some((d, n)) => (d, n),
        None => ("", path),
    };
    let tokens: Vec<&str> = name.split(['.', '-', '_']).collect();
    // The name has to start with something that is not a build number, or
    // `1.2.3.tar.gz` and `4.5.6.tar.gz` would be the same artifact.
    if tokens.first().is_none_or(|t| t.is_empty() || volatile(t)) {
        return None;
    }
    let stable: Vec<&str> = tokens.iter().copied().filter(|t| !volatile(t)).collect();
    if stable.len() == tokens.len() {
        return None; // nothing volatile — the exact pass covers it
    }
    Some(Identity { dir, stable })
}

/// Pair each base path with the head path naming the same artifact.
///
/// Returns one entry per pairing, as indices into the two slices. Exact paths
/// pair first so an unchanged name always beats a normalized one, and every
/// head path is claimed at most once.
pub(crate) fn pair(base: &[String], head: &[String]) -> Vec<(usize, usize)> {
    let mut by_path: HashMap<&str, usize> = HashMap::with_capacity(head.len());
    // Every candidate, not just the first: two builds of the same bundle can
    // sit in one directory, and a claimed candidate must not block the others.
    let mut by_identity: HashMap<Identity<'_>, Vec<usize>> = HashMap::with_capacity(head.len());
    for (i, p) in head.iter().enumerate() {
        by_path.entry(p.as_str()).or_insert(i);
        if let Some(id) = identity(p) {
            by_identity.entry(id).or_default().push(i);
        }
    }

    let mut claimed = vec![false; head.len()];
    let mut pairs = Vec::new();
    // Exact paths first, across the whole set: a name that did not change must
    // never lose its partner to some other file's normalization.
    for (i, p) in base.iter().enumerate() {
        if let Some(&j) = by_path.get(p.as_str())
            && !claimed[j]
        {
            claimed[j] = true;
            pairs.push((i, j));
        }
    }
    let paired_base: std::collections::HashSet<usize> = pairs.iter().map(|(i, _)| *i).collect();
    for (i, p) in base.iter().enumerate() {
        if paired_base.contains(&i) {
            continue;
        }
        if let Some(id) = identity(p)
            && let Some(candidates) = by_identity.get(&id)
            && let Some(&j) = candidates.iter().find(|&&j| !claimed[j])
        {
            claimed[j] = true;
            pairs.push((i, j));
        }
    }
    pairs
}

/// Every file under `root`, as paths relative to it, sorted for determinism.
pub(crate) fn list(root: &Path) -> std::io::Result<Vec<String>> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>, depth: usize) -> std::io::Result<()> {
        if depth > 64 {
            return Ok(());
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                walk(&entry.path(), base, out, depth + 1)?;
            } else if let Ok(rel) = entry.path().strip_prefix(base) {
                out.push(rel.to_string_lossy().into_owned());
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out, 0)?;
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(p: &str) -> Option<Vec<&str>> {
        identity(p).map(|i| i.stable)
    }

    #[test]
    fn bundler_content_hashes_normalize() {
        // The case that fires on every pull request in a webpack/vite repo.
        assert_eq!(id("dist/main.4f2a1b9c.js"), id("dist/main.d4e5f60a.js"));
        assert_eq!(id("dist/main-4f2a1b9c.js"), Some(vec!["main", "js"]));
        // Longer hashes and mixed separators land on the same identity.
        assert_eq!(
            id("dist/chunk.a1b2c3d4e5f60718.mjs"),
            id("dist/chunk-99887766aabbccdd.mjs")
        );
    }

    #[test]
    fn sonames_normalize_across_major_versions() {
        assert_eq!(id("lib/libssl.so.1.1"), id("lib/libssl.so.3"));
        assert_eq!(id("lib/libssl.so.1.1"), Some(vec!["libssl", "so"]));
        // Different libraries must not pair just because both are `.so`.
        assert_ne!(id("lib/libssl.so.3"), id("lib/libcrypto.so.3"));
    }

    #[test]
    fn apk_versions_and_revisions_normalize() {
        assert_eq!(id("busybox-1.37.0-r12.apk"), id("busybox-1.38.0-r1.apk"));
        assert_eq!(id("busybox-1.37.0-r12.apk"), Some(vec!["busybox", "apk"]));
    }

    #[test]
    fn a_leading_volatile_token_has_no_identity() {
        // Otherwise every release tarball would pair with every other.
        assert_eq!(id("1.2.3.tar.gz"), None);
        assert_eq!(id("dist/4f2a1b9c.js"), None);
    }

    #[test]
    fn a_name_with_nothing_volatile_has_no_identity() {
        // The exact-path pass already handles these; an identity would only add
        // a chance to mispair.
        assert_eq!(id("src/index.js"), None);
        assert_eq!(id("README.md"), None);
    }

    #[test]
    fn directories_are_part_of_the_identity() {
        assert_ne!(
            identity("a/main.4f2a1b9c.js"),
            identity("b/main.d4e5f60a.js")
        );
    }

    #[test]
    fn extensions_are_stable_tokens() {
        assert_ne!(id("dist/main.4f2a1b9c.js"), id("dist/main.d4e5f60a.css"));
    }

    #[test]
    fn hex_looking_words_survive_as_the_leading_token() {
        // `deadbeef` is eight hex characters, but it is this file's name.
        assert_eq!(id("dist/deadbeef.js"), None);
    }

    #[test]
    fn exact_paths_pair_before_normalized_ones() {
        // `main.aaaaaaaa.js` is present on both sides unchanged; it must keep
        // its partner rather than lose it to the other file's normalization.
        let base = vec![
            "d/main.aaaaaaaa.js".to_string(),
            "d/main.bbbbbbbb.js".to_string(),
        ];
        let head = vec![
            "d/main.aaaaaaaa.js".to_string(),
            "d/main.cccccccc.js".to_string(),
        ];
        let mut got = pair(&base, &head);
        got.sort_unstable();
        assert_eq!(got, vec![(0, 0), (1, 1)]);
    }

    #[test]
    fn each_head_file_is_claimed_once() {
        // Two base files normalize onto one head file; only one may take it.
        let base = vec![
            "d/app.11111111.js".to_string(),
            "d/app.22222222.js".to_string(),
        ];
        let head = vec!["d/app.33333333.js".to_string()];
        assert_eq!(pair(&base, &head).len(), 1);
    }

    #[test]
    fn unrelated_files_do_not_pair() {
        let base = vec!["d/alpha.11111111.js".to_string()];
        let head = vec!["d/beta.22222222.js".to_string()];
        assert!(pair(&base, &head).is_empty());
    }

    #[test]
    fn volatile_classification() {
        assert!(volatile("1"));
        assert!(volatile("20240101"));
        assert!(volatile("r12"));
        assert!(volatile("4f2a1b9c"));
        assert!(volatile("Q1sSNCl4MTQ0d1V0NTXAhIjY7Nqo"));
        assert!(!volatile("main"));
        assert!(!volatile("so"));
        assert!(!volatile("js"));
        assert!(!volatile("v2"));
        assert!(!volatile("abc")); // too short to be a hash
        assert!(!volatile(""));
    }
}
