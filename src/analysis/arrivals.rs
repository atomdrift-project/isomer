//! Files a package release brings in that its kind of release should not.
//!
//! Two arrivals separate attacks from honest releases across the supply-chain
//! corpus, and neither depends on what any trait makes of the file:
//!
//! * **a native binary** the package never shipped — an ELF, PE or Mach-O
//!   object, by content or by name. No clean release in the corpus adds one, of
//!   any kind; injected stealers and miners routinely do.
//! * **code at the package's top level** that the previous release did not
//!   have. Clean patch releases add code deep in the tree (`dist/utils/…`);
//!   attacks drop their loader beside the manifest (`setup_bun.js`,
//!   `bundle.js`, `install.js`). Only a package that kept some of its code
//!   has a layout to stand out from: a release that replaced all of it — a
//!   `dist/` package republished as its repository — brings every file new.
//!
//! "New" is read after [`crate::rename`]'s identities, so a version stamp or a
//! bundler's content hash never makes a file new. Only package archives are
//! read: there the top level is the package's, while a repository adds
//! top-level files as a matter of course.

use std::collections::HashSet;
use std::path::Path;

use cleave::types::{DiffReportV1, FileDiffEntry, FileStatus};

use crate::Severity;
use crate::member::MemberPath;
use crate::version::{Bump, Promise};

/// Content-detected native object types.
const NATIVE_TYPES: &[&str] = &["elf", "pe", "macho", "ne"];
/// Native objects by name, for members cleave did not type.
const NATIVE_EXTENSIONS: &[&str] = &["node", "so", "dll", "dylib", "exe"];
/// Code a runtime or shell executes from source.
const CODE_EXTENSIONS: &[&str] = &[
    "js", "cjs", "mjs", "ts", "cts", "mts", "jsx", "tsx", "sh", "py",
];

/// What kind of file arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind {
    NativeBinary,
    TopLevelCode,
}

/// One file a release brought in.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Arrival {
    pub severity: Severity,
    pub kind: Kind,
    /// The member, neutralized for display: the artifact named it.
    pub path: String,
}

impl Arrival {
    /// The reason a reader needs first.
    pub(crate) fn describe(&self) -> String {
        let what = match self.kind {
            Kind::NativeBinary => "adds a native binary",
            Kind::TopLevelCode => "adds code at the package's top level",
        };
        format!("{what}: {}", self.path)
    }
}

/// Every arrival in `diff` worth a severity under `bump`, gravest first.
pub(super) fn found(diff: &DiffReportV1, bump: Option<Bump>) -> Vec<Arrival> {
    let promise = bump.map_or(Promise::Nothing, |b| b.kind.promise());
    let members = |status| members(diff, status);
    // What the old side shipped, by the identity a rename keeps.
    let removed: HashSet<_> = members(FileStatus::Removed)
        .filter_map(|((root, member), _)| Some((root, crate::rename::identity(Path::new(member))?)))
        .collect();
    let kept = kept_code(diff);
    let tops = top_directories(diff);
    let mut out: Vec<Arrival> = members(FileStatus::Added)
        .filter(|((root, member), _)| {
            crate::rename::identity(Path::new(member))
                .is_none_or(|identity| !removed.contains(&(*root, identity)))
        })
        .filter_map(|((root, member), file)| {
            let kind = if native(member, file) {
                Kind::NativeBinary
            } else if code(member)
                && kept.contains(root)
                && top_level(member, tops.get(root).copied().flatten())
            {
                Kind::TopLevelCode
            } else {
                return None;
            };
            let severity = severity(promise, kind);
            (severity > Severity::None).then(|| Arrival {
                severity,
                kind,
                path: crate::printable(member),
            })
        })
        .collect();
    out.sort_by_key(|a| std::cmp::Reverse(a.severity));
    for a in &out {
        log::debug!("arrival: {} ({:?})", a.describe(), a.severity);
    }
    out
}

/// Whether a container replaced all of its code: some was removed and none
/// survived. Such a release has no predecessor to be measured against — every
/// file, and every technique, in it reads as new.
pub(super) fn replaced_all_code(diff: &DiffReportV1) -> bool {
    let kept = kept_code(diff);
    members(diff, FileStatus::Removed)
        .any(|((root, member), _)| code(member) && !kept.contains(root))
}

/// Each container's members with `status`, outermost level only: a file
/// inside a nested archive is that archive's, not the package's.
fn members(
    diff: &DiffReportV1,
    status: FileStatus,
) -> impl Iterator<Item = ((&str, &str), &FileDiffEntry)> {
    diff.files
        .iter()
        .filter(move |f| f.status == status)
        .filter_map(|f| {
            let path = MemberPath::new(&f.path);
            (!path.is_nested()).then_some((path.split()?, f))
        })
}

/// Containers that kept some of their code: the layout a newcomer stands out
/// against.
fn kept_code(diff: &DiffReportV1) -> HashSet<&str> {
    members(diff, FileStatus::Unchanged)
        .chain(members(diff, FileStatus::Changed))
        .filter(|((_, member), _)| code(member))
        .map(|((root, _), _)| root)
        .collect()
}

fn severity(promise: Promise, kind: Kind) -> Severity {
    match (kind, promise) {
        (Kind::NativeBinary, Promise::Nothing | Promise::Features)
        | (Kind::TopLevelCode, Promise::Nothing) => Severity::High,
        (Kind::NativeBinary, Promise::Anything) | (Kind::TopLevelCode, Promise::Features) => {
            Severity::Medium
        }
        (Kind::TopLevelCode, Promise::Anything) => Severity::Low,
    }
}

fn native(member: &str, file: &FileDiffEntry) -> bool {
    file.file_type
        .as_deref()
        .is_some_and(|t| NATIVE_TYPES.contains(&t))
        || native_name(member)
}

/// `x.node`, `x.dll`, and versioned shared objects: `libx.so.1.2`.
fn native_name(member: &str) -> bool {
    let name = member
        .rsplit('/')
        .next()
        .unwrap_or(member)
        .to_ascii_lowercase();
    let mut parts = name.split('.').skip(1).collect::<Vec<_>>();
    while parts
        .last()
        .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        parts.pop();
    }
    parts
        .last()
        .is_some_and(|ext| NATIVE_EXTENSIONS.contains(ext))
}

fn code(member: &str) -> bool {
    let name = member.rsplit('/').next().unwrap_or(member);
    let declaration = [".d.ts", ".d.cts", ".d.mts"]
        .iter()
        .any(|d| name.ends_with(d));
    !declaration
        && name
            .rsplit_once('.')
            .is_some_and(|(_, ext)| CODE_EXTENSIONS.contains(&ext))
}

/// Each container's top directory when every member sits under one — npm's
/// `package/` — so the package's top level is the level below it.
fn top_directories(diff: &DiffReportV1) -> std::collections::HashMap<&str, Option<&str>> {
    let mut tops: std::collections::HashMap<&str, Option<&str>> = std::collections::HashMap::new();
    for f in &diff.files {
        let path = MemberPath::new(&f.path);
        let Some((root, member)) = path.split().filter(|_| !path.is_nested()) else {
            continue;
        };
        let top = member.split_once('/').map(|(dir, _)| dir);
        tops.entry(root)
            .and_modify(|seen| {
                if *seen != top {
                    *seen = None;
                }
            })
            .or_insert(top);
    }
    tops
}

/// Whether `member` sits directly in the package's top level.
fn top_level(member: &str, top: Option<&str>) -> bool {
    let inside = top
        .and_then(|dir| member.strip_prefix(dir)?.strip_prefix('/'))
        .unwrap_or(member);
    !inside.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::entry;
    use crate::version::BumpKind;

    fn diff(files: Vec<FileDiffEntry>) -> DiffReportV1 {
        DiffReportV1 {
            old_root: "before.tgz".to_owned(),
            new_root: "after.tgz".to_owned(),
            summary: Default::default(),
            files,
            scopes: Default::default(),
        }
    }

    fn member(path: &str, file_type: &str, status: FileStatus) -> FileDiffEntry {
        entry(format!("<root>!!package/{path}"), file_type, status)
    }

    fn kinds(files: Vec<FileDiffEntry>, bump: BumpKind) -> Vec<(Kind, Severity)> {
        found(&diff(files), Some(Bump::new(bump, 1)))
            .into_iter()
            .map(|a| (a.kind, a.severity))
            .collect()
    }

    fn package(extra: Vec<FileDiffEntry>) -> Vec<FileDiffEntry> {
        let mut files = vec![
            member("package.json", "package.json", FileStatus::Changed),
            member("index.js", "javascript", FileStatus::Unchanged),
        ];
        files.extend(extra);
        files
    }

    #[test]
    fn a_patch_that_drops_a_loader_beside_its_manifest_is_high() {
        // Shai-Hulud: two scripts beside package.json in a patch release.
        assert_eq!(
            kinds(
                package(vec![
                    member("setup_bun.js", "javascript", FileStatus::Added),
                    member("bun_environment.js", "javascript", FileStatus::Added),
                ]),
                BumpKind::Patch
            ),
            [
                (Kind::TopLevelCode, Severity::High),
                (Kind::TopLevelCode, Severity::High)
            ]
        );
        // Clean patches add code deep in the tree.
        assert_eq!(
            kinds(
                package(vec![member(
                    "src/utils/decompress.js",
                    "javascript",
                    FileStatus::Added
                )]),
                BumpKind::Patch
            ),
            []
        );
        // A new entry point is what a major release is for.
        assert_eq!(
            kinds(
                package(vec![member("flat.js", "javascript", FileStatus::Added)]),
                BumpKind::Major
            ),
            [(Kind::TopLevelCode, Severity::Low)]
        );
    }

    #[test]
    fn a_package_that_kept_none_of_its_code_has_no_layout_to_stand_out_from() {
        // ironworm's arjson 0.1.3 → 0.1.5: a built `cjs/`/`esm/` package
        // republished as its repository, build helper beside the manifest.
        let republished = |kept: FileStatus| {
            vec![
                member("package.json", "package.json", FileStatus::Changed),
                member("cjs/index.js", "javascript", kept),
                member("src/index.js", "javascript", FileStatus::Added),
                member("make.js", "javascript", FileStatus::Added),
            ]
        };
        assert_eq!(kinds(republished(FileStatus::Removed), BumpKind::Patch), []);
        assert!(replaced_all_code(&diff(republished(FileStatus::Removed))));
        assert!(!replaced_all_code(&diff(republished(
            FileStatus::Unchanged
        ))));
        // A single file has no members to replace.
        assert!(!replaced_all_code(&diff(vec![entry(
            "<root>",
            "javascript",
            FileStatus::Changed
        )])));
        assert_eq!(
            kinds(republished(FileStatus::Unchanged), BumpKind::Patch),
            [(Kind::TopLevelCode, Severity::High)]
        );
        // A binary is new whatever the package kept.
        assert_eq!(
            kinds(
                vec![
                    member("cjs/index.js", "javascript", FileStatus::Removed),
                    member("prebuilds/x.node", "", FileStatus::Added),
                ],
                BumpKind::Patch
            ),
            [(Kind::NativeBinary, Severity::High)]
        );
    }

    #[test]
    fn a_native_binary_is_high_even_in_a_minor_release() {
        let dll = || package(vec![member("node-gyp.dll", "pe", FileStatus::Added)]);
        assert_eq!(
            kinds(dll(), BumpKind::Minor),
            [(Kind::NativeBinary, Severity::High)]
        );
        assert_eq!(
            kinds(dll(), BumpKind::Major),
            [(Kind::NativeBinary, Severity::Medium)]
        );
        // By name when cleave did not type it, versioned shared objects included.
        assert_eq!(
            kinds(
                package(vec![member("lib/libx.so.1.2", "", FileStatus::Added)]),
                BumpKind::Patch
            ),
            [(Kind::NativeBinary, Severity::High)]
        );
    }

    #[test]
    fn a_renamed_build_is_not_new() {
        // A content-hashed chunk and a versioned library move every release.
        assert_eq!(
            kinds(
                package(vec![
                    member("main.4f2a1b9c.js", "javascript", FileStatus::Removed),
                    member("main.d4e5f60a.js", "javascript", FileStatus::Added),
                    member("lib/libx.so.1", "elf", FileStatus::Removed),
                    member("lib/libx.so.2", "elf", FileStatus::Added),
                ]),
                BumpKind::Patch
            ),
            []
        );
    }

    #[test]
    fn declarations_and_trees_are_not_packages() {
        assert_eq!(
            kinds(
                package(vec![member("index.d.ts", "typescript", FileStatus::Added)]),
                BumpKind::Patch
            ),
            []
        );
        // A repository's top-level files are not a package's.
        let tree = diff(vec![entry(
            "vite.config.js",
            "javascript",
            FileStatus::Added,
        )]);
        assert_eq!(found(&tree, Some(Bump::new(BumpKind::Patch, 1))), []);
    }
}
