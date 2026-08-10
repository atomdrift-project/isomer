//! `isomer ci` — the zero-configuration CI entry point.
//!
//! This is the product; the other verbs are the plumbing it composes. It
//! answers one question — *does this pull request introduce malicious code?* —
//! and answers it in every place CI can show an answer, from a single scan.
//!
//! Three decisions shape the implementation:
//!
//! **Only the delta is analyzed.** A pull request touching 5 files in a
//! 50,000-file monorepo should cost 5 files of work, so `ci` extracts just the
//! changed paths from both commits into two sparse trees and diffs those. The
//! trees mirror the repo layout, so every path isomer reports is the path the
//! reviewer sees on GitHub.
//!
//! **The fork point is the base.** Comparing against the base *branch tip*
//! would blame this pull request for every commit that landed on main while it
//! was open. `ci` resolves the merge base and diffs from there.
//!
//! **One scan, every sink.** The terminal log, the step summary, the sticky
//! comment, the SARIF upload, and the action's outputs all come from one
//! analysis — so they can never disagree, and the expensive part happens once.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::analysis::{self, Analysis};
use crate::policy::Policy;
use crate::{Cli, Format};

/// Arguments to the `ci` verb.
pub(crate) struct Args {
    pub base: Option<String>,
    pub head: Option<String>,
    pub repo: PathBuf,
    pub out_dir: Option<PathBuf>,
    pub max_files: usize,
}

/// A blob larger than this is not extracted. Nothing legitimate in a source
/// diff approaches it, and an unbounded read is a denial-of-service waiting for
/// a hostile pull request.
const MAX_BLOB: u64 = 128 << 20;

/// Analyze the change this CI run is for.
pub(crate) fn run(cli: &Cli, policy: &Policy, args: &Args) -> Result<bool> {
    let repo = args.repo.as_path();
    let refs = Refs::resolve(repo, args)?;
    eprintln!(
        "isomer: comparing {}..{}",
        short(&refs.base),
        short(&refs.head)
    );

    let changes = changed_files(repo, &refs, args.max_files, policy)?;
    if changes.is_empty() {
        // Nothing to judge. Say so on the sinks that always exist and pass;
        // a pull request that touches no analyzable file is not a finding.
        eprintln!("isomer: no analyzable files changed");
        summary("### ✅ isomer\n\nNo analyzable files changed.\n");
        outputs(&[
            ("verdict", "CLEAN"),
            ("severity", "none"),
            ("new-severity", "none"),
            ("fail", "false"),
            ("findings", "0"),
        ]);
        return Ok(true);
    }

    let work = tempfile::Builder::new()
        .prefix("isomer-ci-")
        .tempdir()
        .context("creating work directory")?;
    let (old, new) = (work.path().join("base"), work.path().join("head"));
    materialize(repo, &refs, &changes, &old, &new)?;

    let options = cleave::AnalysisOptions::default();
    let report = analysis::diff(&old, &new, &options)?;
    let mut a = Analysis::new("ci", &old, &new, &options, &report, cli, policy)?;
    a.rename(subject(repo));

    emit(&a, cli, args.out_dir.as_deref())?;
    Ok(a.clean)
}

// ── what changed ────────────────────────────────────────────────────────────

/// The two commits to compare.
struct Refs {
    base: String,
    head: String,
}

impl Refs {
    /// Explicit flags win; otherwise read the CI environment. The base is
    /// narrowed to the merge base so the report covers this change alone.
    fn resolve(repo: &Path, args: &Args) -> Result<Self> {
        let (mut base, mut head) = match (&args.base, &args.head) {
            (Some(b), Some(h)) => (b.clone(), h.clone()),
            (b, h) => {
                let env = from_env().context(
                    "could not derive the commit range from the environment. \
                     Pass --base and --head, or run inside GitHub Actions or GitLab CI",
                )?;
                (b.clone().unwrap_or(env.0), h.clone().unwrap_or(env.1))
            }
        };

        // A shallow checkout of a pull request often has the merge commit but
        // not the head commit the event names. `HEAD` is then the right — and
        // only — answer.
        if !exists(repo, &head) {
            eprintln!(
                "isomer: {} is not in this checkout; using HEAD",
                short(&head)
            );
            head = "HEAD".to_string();
        }
        if !exists(repo, &base) {
            bail!(
                "base commit {} is not in this checkout. Fetch it first:\n    \
                 git fetch --depth=50 origin {base}",
                short(&base),
            );
        }
        // The fork point, so commits that landed on the base branch after this
        // change was branched are not attributed to it.
        match git(repo, &["merge-base", &base, &head]) {
            Ok(out) => base = String::from_utf8_lossy(&out).trim().to_string(),
            Err(e) => eprintln!(
                "isomer: no merge base ({e}); comparing against {} directly",
                short(&base)
            ),
        }
        Ok(Self { base, head })
    }
}

/// What the report is about: `owner/repo#42` for a pull request, the repo
/// slug for a push, the directory name when running outside CI.
fn subject(repo: &Path) -> String {
    let slug = std::env::var("GITHUB_REPOSITORY")
        .ok()
        .or_else(|| std::env::var("CI_PROJECT_PATH").ok())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::canonicalize(repo)
                .ok()?
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    match pr_number() {
        Some(n) if !slug.is_empty() => format!("{slug}#{n}"),
        Some(n) => format!("#{n}"),
        None => slug,
    }
}

/// The pull/merge request number, when this run is for one.
fn pr_number() -> Option<u64> {
    if let Ok(n) = std::env::var("CI_MERGE_REQUEST_IID")
        && let Ok(n) = n.parse()
    {
        return Some(n);
    }
    let text = std::fs::read_to_string(std::env::var("GITHUB_EVENT_PATH").ok()?).ok()?;
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()?
        .get("pull_request")?
        .get("number")?
        .as_u64()
}

/// Read the commit range from the CI provider's environment.
fn from_env() -> Option<(String, String)> {
    // GitHub Actions: the event payload is the authoritative source for both
    // pull requests and pushes.
    if let Ok(path) = std::env::var("GITHUB_EVENT_PATH")
        && let Ok(text) = std::fs::read_to_string(&path)
        && let Ok(event) = serde_json::from_str::<serde_json::Value>(&text)
    {
        let str_at = |v: &serde_json::Value, p: &[&str]| -> Option<String> {
            let mut cur = v;
            for key in p {
                cur = cur.get(key)?;
            }
            cur.as_str().map(str::to_string)
        };
        if let (Some(b), Some(h)) = (
            str_at(&event, &["pull_request", "base", "sha"]),
            str_at(&event, &["pull_request", "head", "sha"]),
        ) {
            return Some((b, h));
        }
        if let (Some(b), Some(h)) = (str_at(&event, &["before"]), str_at(&event, &["after"]))
            && !is_null_sha(&b)
        {
            return Some((b, h));
        }
    }
    // GitLab CI.
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    if let (Some(b), Some(h)) = (var("CI_MERGE_REQUEST_DIFF_BASE_SHA"), var("CI_COMMIT_SHA")) {
        return Some((b, h));
    }
    if let (Some(b), Some(h)) = (var("CI_COMMIT_BEFORE_SHA"), var("CI_COMMIT_SHA"))
        && !is_null_sha(&b)
    {
        return Some((b, h));
    }
    None
}

/// git's "no such commit" sentinel, used for the first push to a branch.
fn is_null_sha(s: &str) -> bool {
    s.chars().all(|c| c == '0')
}

/// One changed path and which sides of the comparison it exists on.
struct Change {
    path: PathBuf,
    /// Present in the base commit (i.e. not added by this change).
    in_base: bool,
    /// Present in the head commit (i.e. not deleted by this change).
    in_head: bool,
}

/// The paths this change touches, from the fork point to head.
///
/// Rename detection is off on purpose: to isomer a rename *is* a delete plus an
/// add, and the added path is what needs analyzing.
fn changed_files(repo: &Path, refs: &Refs, max: usize, policy: &Policy) -> Result<Vec<Change>> {
    let out = git(
        repo,
        &[
            "diff",
            "--no-renames",
            "--name-status",
            "-z",
            &refs.base,
            &refs.head,
        ],
    )?;
    // `-z` frames the listing as `status\0path\0…`, so a path containing a
    // newline — or anything else a line-based parser would split on — cannot
    // hide a file from the scan.
    let mut fields = out.split(|b| *b == 0).filter(|f| !f.is_empty());
    let mut changes = Vec::new();
    let mut excluded = 0usize;
    while let (Some(status), Some(path)) = (fields.next(), fields.next()) {
        let path = os_path(path);
        if policy.excludes(&path.to_string_lossy()) {
            excluded += 1;
            continue;
        }
        let status = status.first().copied().unwrap_or(b'M');
        changes.push(Change {
            path,
            in_base: status != b'A',
            in_head: status != b'D',
        });
    }
    if excluded > 0 {
        eprintln!(
            "isomer: {excluded} file(s) excluded by {}",
            crate::policy::FILE
        );
    }
    if changes.len() > max {
        // Never silently analyze a subset: a scanner that quietly skips files
        // reports "clean" for a change it did not read.
        bail!(
            "{} changed files exceeds --max-files {max}. Raise the limit or narrow the scan \
             with `exclude` in {}",
            changes.len(),
            crate::policy::FILE,
        );
    }
    Ok(changes)
}

/// Extract both sides of every changed file into two sparse trees that mirror
/// the repository layout.
fn materialize(repo: &Path, refs: &Refs, changes: &[Change], old: &Path, new: &Path) -> Result<()> {
    for change in changes {
        if change.in_base {
            extract(repo, &refs.base, &change.path, &old.join(&change.path))?;
        }
        if change.in_head {
            extract(repo, &refs.head, &change.path, &new.join(&change.path))?;
        }
    }
    // cleave needs both roots to exist even when a change is all additions or
    // all deletions.
    for root in [old, new] {
        std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    }
    Ok(())
}

/// Stream one blob out of a commit and onto disk.
fn extract(repo: &Path, commit: &str, path: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // `<commit>:<path>` is git's blob address. The path travels as one argv
    // element, so no quoting or encoding can make it name a different file.
    let mut spec = std::ffi::OsString::from(format!("{commit}:"));
    spec.push(path);
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("show")
        .arg(&spec)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running git show")?;
    let Some(mut stdout) = child.stdout.take() else {
        bail!("git show produced no output stream");
    };

    let mut file =
        std::fs::File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
    // Bounded copy: a hostile blob cannot exhaust memory or disk here.
    let copied = std::io::copy(
        &mut std::io::Read::take(&mut stdout, MAX_BLOB + 1),
        &mut file,
    )
    .with_context(|| format!("extracting {}", path.display()))?;
    let status = child.wait().context("waiting for git show")?;
    if !status.success() {
        // A blob that cannot be read is not a silent skip: drop the empty file
        // so the side simply has no content, and say why.
        let _ = std::fs::remove_file(dest);
        eprintln!(
            "isomer: could not read {}@{}",
            path.display(),
            short(commit)
        );
        return Ok(());
    }
    if copied > MAX_BLOB {
        let _ = std::fs::remove_file(dest);
        eprintln!(
            "isomer: skipped {} — larger than {} MiB",
            path.display(),
            MAX_BLOB >> 20
        );
    }
    Ok(())
}

// ── sinks ───────────────────────────────────────────────────────────────────

/// Write the verdict everywhere this environment can show it.
fn emit(a: &Analysis<'_>, cli: &Cli, out_dir: Option<&Path>) -> Result<()> {
    // stdout keeps whatever the caller asked for, so `isomer ci --format json`
    // still pipes cleanly.
    crate::write_stdout(&a.render(cli.format, cli)?)?;

    let markdown = a.render(Format::Markdown, cli)?;
    if let Some(dir) = out_dir {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        for (name, body) in [
            ("report.json", a.render(Format::Json, cli)?),
            ("report.sarif", a.render(Format::Sarif, cli)?),
            ("report.md", markdown.clone()),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
        }
    }

    // The step summary is the one GitHub surface that works without any
    // permission at all — including on a fork's read-only token — so the full
    // report goes there even when the comment and SARIF upload cannot happen.
    summary(&markdown);

    let verdict = crate::terminal::verdict_word(a.verdict);
    let findings = a.assessment.behavioral.categories.len()
        + a.assessment.signature.ids.len()
        + a.assessment.identity.changes.len()
        + a.assessment.structure.facts.len();
    outputs(&[
        ("verdict", verdict),
        ("severity", a.verdict.as_str()),
        ("new-severity", a.new_verdict.as_str()),
        ("fail", if a.clean { "false" } else { "true" }),
        ("findings", &findings.to_string()),
        ("suppressed", &a.assessment.suppressed.len().to_string()),
    ]);

    // A failing check needs a reason visible in the job log without scrolling.
    if std::env::var_os("GITHUB_ACTIONS").is_some() && !a.clean {
        println!(
            "::error title=isomer: {verdict}::{}",
            escape_annotation(&a.headline())
        );
    }
    Ok(())
}

/// Append markdown to the GitHub step summary, when running there.
fn summary(body: &str) {
    let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") else {
        return;
    };
    if let Err(e) = append(Path::new(&path), body) {
        eprintln!("isomer: could not write step summary: {e:#}");
    }
}

/// Publish `name=value` pairs as action outputs, when running there.
///
/// The CLI writes these itself so the action needs no JSON parsing — keeping
/// the action a thin, auditable wrapper is worth twenty lines here.
fn outputs(pairs: &[(&str, &str)]) {
    let Some(path) = std::env::var_os("GITHUB_OUTPUT") else {
        return;
    };
    let body: String = pairs.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
    if let Err(e) = append(Path::new(&path), &body) {
        eprintln!("isomer: could not write outputs: {e:#}");
    }
}

fn append(path: &Path, body: &str) -> Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    f.write_all(body.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

/// Workflow-command encoding: a raw newline would end the annotation, and a
/// `::` would start a new command.
fn escape_annotation(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace("::", "%3A%3A")
}

// ── git plumbing ────────────────────────────────────────────────────────────

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    Ok(out.stdout)
}

/// Whether a commit-ish resolves in this checkout.
fn exists(repo: &Path, rev: &str) -> bool {
    git(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{rev}^{{commit}}"),
        ],
    )
    .is_ok()
}

fn short(sha: &str) -> String {
    sha.chars().take(12).collect()
}

/// A git path as the operating system sees it. On Unix a path is bytes, and
/// treating it as UTF-8 would let a file with an undecodable name evade the
/// scan; everywhere else, lossy conversion is the only option available.
#[cfg(unix)]
fn os_path(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
}

#[cfg(not(unix))]
fn os_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotation_escaping_cannot_forge_a_workflow_command() {
        let hostile = "line one\n::error::forged";
        let safe = escape_annotation(hostile);
        assert!(!safe.contains('\n'));
        assert!(!safe.contains("::"));
        assert_eq!(safe, "line one%0A%3A%3Aerror%3A%3Aforged");
    }

    #[test]
    fn null_sha_is_recognized() {
        assert!(is_null_sha("0000000000000000000000000000000000000000"));
        assert!(!is_null_sha("0000000000000000000000000000000000000001"));
    }

    #[test]
    fn short_sha_is_bounded() {
        assert_eq!(short("0123456789abcdef0123"), "0123456789ab");
        assert_eq!(short("abc"), "abc");
    }
}
