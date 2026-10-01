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

use crate::analysis::{Analysis, Comparison, Framing, Scope, Verb};
use crate::options::Options;
use crate::{Format, Outcome};

/// Arguments to the `ci` verb.
#[derive(Debug)]
pub struct Args {
    /// Base commit. `None` derives it from the CI event, then narrows to the
    /// merge base with head.
    pub base: Option<String>,
    /// Head commit. `None` derives it from the CI event, falling back to
    /// `HEAD` when the event's commit is absent from a shallow checkout.
    pub head: Option<String>,
    /// Repository to inspect.
    pub repo: PathBuf,
    /// Also write `report.{json,sarif,md}` to this directory.
    pub out_dir: Option<PathBuf>,
    /// Refuse to run when the change touches more files than this, rather than
    /// analyzing a subset and reporting it as the whole.
    pub max_files: usize,
    /// Build outputs of the base commit, laid over the base tree.
    pub base_artifacts: Option<PathBuf>,
    /// Build outputs of the head commit, laid over the head tree.
    pub head_artifacts: Option<PathBuf>,
    /// What the CI provider says about this run. The caller captures it —
    /// [`CiEnv::from_process`] for the real environment — so the library
    /// itself never reads process-global state.
    pub env: CiEnv,
}

/// What `ci` reads from the CI provider: the commit range, the pull request,
/// and where the job's step summary and outputs go.
///
/// Captured once, up front. The event payload used to be read and parsed
/// twice by two functions that each swallowed a malformed file differently.
#[derive(Debug, Default, Clone)]
pub struct CiEnv {
    /// GitHub's event payload (`GITHUB_EVENT_PATH`), parsed.
    pub github_event: Option<serde_json::Value>,
    /// `GITHUB_REPOSITORY` or, failing that, GitLab's `CI_PROJECT_PATH`.
    pub repository: Option<String>,
    /// GitLab's `CI_MERGE_REQUEST_IID`.
    pub merge_request_iid: Option<u64>,
    /// GitLab's `CI_MERGE_REQUEST_DIFF_BASE_SHA`.
    pub merge_request_base: Option<String>,
    /// GitLab's `CI_COMMIT_SHA`.
    pub commit: Option<String>,
    /// GitLab's `CI_COMMIT_BEFORE_SHA`.
    pub commit_before: Option<String>,
    /// Running under GitHub Actions (`GITHUB_ACTIONS`), so workflow commands
    /// on stdout are read as annotations.
    pub github_actions: bool,
    /// `GITHUB_STEP_SUMMARY`.
    pub step_summary: Option<PathBuf>,
    /// `GITHUB_OUTPUT`.
    pub output: Option<PathBuf>,
}

impl CiEnv {
    /// Read the CI provider's variables from this process's environment.
    ///
    /// A set-but-empty variable counts as unset. An event payload that cannot
    /// be read or parsed is reported and ignored: the range can still come
    /// from `--base`/`--head`, and failing the run over a file the job only
    /// consults for a pull request number would be the wrong trade.
    #[must_use]
    pub fn from_process() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let github_event = var("GITHUB_EVENT_PATH").and_then(|path| {
            let parsed = std::fs::read_to_string(&path)
                .map_err(anyhow::Error::from)
                .and_then(|text| Ok(serde_json::from_str(&text)?));
            match parsed {
                Ok(event) => Some(event),
                Err(e) => {
                    log::warn!("ignoring GitHub event payload {path}: {e:#}");
                    None
                }
            }
        });
        Self {
            github_event,
            repository: var("GITHUB_REPOSITORY").or_else(|| var("CI_PROJECT_PATH")),
            merge_request_iid: var("CI_MERGE_REQUEST_IID").and_then(|n| n.parse().ok()),
            merge_request_base: var("CI_MERGE_REQUEST_DIFF_BASE_SHA"),
            commit: var("CI_COMMIT_SHA"),
            commit_before: var("CI_COMMIT_BEFORE_SHA"),
            github_actions: std::env::var_os("GITHUB_ACTIONS").is_some(),
            step_summary: std::env::var_os("GITHUB_STEP_SUMMARY").map(PathBuf::from),
            output: std::env::var_os("GITHUB_OUTPUT").map(PathBuf::from),
        }
    }

    /// The commit range this run is for, from the event payload or GitLab's
    /// variables.
    fn commit_range(&self) -> Option<(String, String)> {
        // GitHub Actions: the event payload is the authoritative source for
        // both pull requests and pushes.
        if let Some(event) = &self.github_event {
            let str_at = |p: &[&str]| -> Option<String> {
                p.iter()
                    .try_fold(event, |cur, key| cur.get(key))?
                    .as_str()
                    .map(str::to_owned)
            };
            if let (Some(b), Some(h)) = (
                str_at(&["pull_request", "base", "sha"]),
                str_at(&["pull_request", "head", "sha"]),
            ) {
                return Some((b, h));
            }
            if let (Some(b), Some(h)) = (str_at(&["before"]), str_at(&["after"]))
                && !is_null_sha(&b)
            {
                return Some((b, h));
            }
        }
        // GitLab CI.
        if let (Some(b), Some(h)) = (&self.merge_request_base, &self.commit) {
            return Some((b.clone(), h.clone()));
        }
        if let (Some(b), Some(h)) = (&self.commit_before, &self.commit)
            && !is_null_sha(b)
        {
            return Some((b.clone(), h.clone()));
        }
        None
    }

    /// The pull/merge request number, when this run is for one.
    fn pr_number(&self) -> Option<u64> {
        self.merge_request_iid.or_else(|| {
            self.github_event
                .as_ref()?
                .get("pull_request")?
                .get("number")?
                .as_u64()
        })
    }
}

/// A blob larger than this is not extracted. Nothing legitimate in a source
/// diff approaches it, and an unbounded read is a denial-of-service waiting for
/// a hostile pull request.
const MAX_BLOB: u64 = 128 << 20;

/// Analyze the change this CI run is for.
///
/// The step summary and action outputs are written as the run goes, to the
/// files [`CiEnv`] names; everything meant for the step's stdout comes back in
/// the [`Outcome`].
pub fn run(opts: &Options, args: &Args) -> Result<Outcome> {
    opts.validate()?;
    let repo = args.repo.as_path();
    let env = &args.env;
    let mut sinks = Sinks {
        env,
        stdout: String::new(),
    };
    let refs = Refs::resolve(repo, args)?;
    log::info!("comparing {}..{}", short(&refs.base), short(&refs.head));

    let changes = changed_files(repo, &refs, args.max_files)?;
    // Build outputs are judged even when no source file changed: a change to a
    // lockfile or a build script can move the artifact without moving anything
    // this diff would otherwise read.
    let artifacts = args.base_artifacts.is_some() || args.head_artifacts.is_some();
    if changes.is_empty() && !artifacts {
        // Nothing to judge. Say so on the sinks that always exist and pass;
        // a pull request that touches no analyzable file is not a finding.
        log::info!("no analyzable files changed");
        sinks.summary("### ✅ isomer\n\nNo analyzable files changed.\n");
        sinks.outputs(&[
            ("verdict", "CLEAN"),
            ("severity", "none"),
            ("new-severity", "none"),
            ("fail", "false"),
            ("findings", "0"),
            ("base-sha", &refs.base),
        ]);
        return Ok(Outcome {
            report: sinks.stdout,
            clean: true,
        });
    }

    let work = tempfile::Builder::new()
        .prefix("isomer-ci-")
        .tempdir()
        .context("creating work directory")?;
    let (old, new) = (work.path().join("base"), work.path().join("head"));
    materialize(repo, &refs, &changes, &old, &new)?;
    let compared = overlay_builds(
        &mut sinks,
        args.base_artifacts.as_deref(),
        args.head_artifacts.as_deref(),
        &old,
        &new,
        args.max_files,
    )?;

    let comparison = Comparison::run(&old, &new)?;
    // `fs` names the artifact it compared; `ci` compares two states of a
    // repository, where the scratch dir the files were staged in is no name.
    // Both are settled before the model reads the case the sinks render.
    let framing = Framing {
        name: Some(subject(env, repo)),
        scope: Some(if compared {
            Scope::SourceAndBuild
        } else {
            Scope::Source
        }),
    };
    let a = comparison.judge(Verb::Ci, &old, &new, opts, framing)?;

    emit(&a, opts, &mut sinks, args.out_dir.as_deref(), &refs.base)?;
    Ok(Outcome {
        report: sinks.stdout,
        clean: a.clean(),
    })
}

// ── build outputs ───────────────────────────────────────────────────────────

/// Stage both sides' build outputs into the trees about to be compared.
///
/// Build outputs are not in git, so `ci` cannot materialize them from a commit
/// the way it does source. Copying them in at their repo-relative paths puts
/// them in the same diff as the source they were built from: one analysis, one
/// verdict, and paths the reviewer recognizes.
///
/// Files are paired first. A bundler rewrites `main.4f2a1b9c.js` to
/// `main.d4e5f60a.js` on every build and a release bumps `libssl.so.1.1` to
/// `libssl.so.3`; compared by name, the old artifact vanished and an unrelated
/// one appeared, so everything it could do would read as newly gained — on
/// every change, forever. A paired file is staged under one name so the two
/// versions are diffed against each other instead.
///
/// Returns whether outputs actually landed — not whether the caller asked for
/// them. A directory that was missing or empty leaves the artifact axis unrun,
/// and the report has to say `source only` rather than claim a comparison it
/// never made.
fn overlay_builds(
    sinks: &mut Sinks<'_>,
    base: Option<&Path>,
    head: Option<&Path>,
    old: &Path,
    new: &Path,
    max: usize,
) -> Result<bool> {
    let (Some(base), Some(head)) = (base, head) else {
        // One side without the other is a workflow that half-worked, usually a
        // build that failed. Every artifact would read as added or deleted
        // wholesale, which is noise wearing the costume of a finding.
        if base.is_some() || head.is_some() {
            sinks.warn("only one side's build outputs were supplied; the comparison needs both");
        }
        return Ok(false);
    };
    for dir in [base, head] {
        if !dir.is_dir() {
            // The workflow asked for a comparison and the artifacts are not
            // there. An axis that silently did not run reads exactly like an
            // axis that ran and found nothing.
            sinks.warn(&format!(
                "{} does not exist — build outputs were NOT compared",
                dir.display()
            ));
            return Ok(false);
        }
    }

    let base_files =
        crate::rename::list(base).with_context(|| format!("reading {}", base.display()))?;
    let head_files =
        crate::rename::list(head).with_context(|| format!("reading {}", head.display()))?;
    if base_files.is_empty() || head_files.is_empty() {
        sinks.warn("build output directories are empty — build outputs were NOT compared");
        return Ok(false);
    }
    if base_files.len() + head_files.len() > max {
        // Same rule as the source diff: never analyze a subset and report it as
        // the whole.
        bail!(
            "build outputs exceed --max-files {max}. Point the artifact directories at what \
             you ship rather than the whole build tree"
        );
    }

    // Paired files share the head's name, because that is the one that exists
    // going forward and the one a reviewer will look for.
    let pairs = crate::rename::pair(&base_files, &head_files);
    let mut staged_as: Vec<Option<&Path>> = vec![None; base_files.len()];
    let mut renamed = 0usize;
    for &(b, h) in &pairs {
        staged_as[b] = Some(head_files[h].as_path());
        if base_files[b] != head_files[h] {
            renamed += 1;
        }
    }

    for (rel, staged) in base_files.iter().zip(staged_as) {
        stage(&base.join(rel), &old.join(staged.unwrap_or(rel)))?;
    }
    for rel in &head_files {
        stage(&head.join(rel), &new.join(rel))?;
    }

    log::info!(
        "{} build output(s) from {}, {} from {}{}",
        base_files.len(),
        base.display(),
        head_files.len(),
        head.display(),
        match renamed {
            0 => String::new(),
            n => format!(" ({n} renamed)"),
        }
    );
    Ok(true)
}

/// Copy one build output into the tree, bounded the way an extracted blob is.
///
/// The bound is enforced on the bytes actually read, not on a stat taken first:
/// a file that grows between the two would otherwise copy without limit.
/// Special files never get here — [`crate::rename::list`] lists regular files
/// only, since opening a FIFO with no writer blocks before any read.
fn stage(src: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut input =
        std::fs::File::open(src).with_context(|| format!("opening {}", src.display()))?;
    let mut output =
        std::fs::File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
    let copied = std::io::copy(
        &mut std::io::Read::take(&mut input, MAX_BLOB + 1),
        &mut output,
    )
    .with_context(|| format!("copying {}", src.display()))?;
    if copied > MAX_BLOB {
        drop(output);
        discard(dest)?;
        log::warn!(
            "skipped {} — larger than {} MiB",
            src.display(),
            MAX_BLOB >> 20
        );
    }
    Ok(())
}

// ── what changed ────────────────────────────────────────────────────────────

/// The two commits to compare, as full object names.
///
/// Resolved once, up front: every later git call addresses a fixed SHA, so a
/// ref that moves mid-run — or a revision spelled like an option — can no
/// longer change what is read.
struct Refs {
    base: String,
    head: String,
}

impl Refs {
    /// Explicit flags win; otherwise read the CI environment. The base is
    /// narrowed to the merge base so the report covers this change alone.
    fn resolve(repo: &Path, args: &Args) -> Result<Self> {
        let derived = if args.base.is_some() && args.head.is_some() {
            None
        } else {
            Some(args.env.commit_range().context(
                "could not derive the commit range from the environment. \
                 Pass --base and --head, or run inside GitHub Actions or GitLab CI",
            )?)
        };
        // Before either value reaches git. Neither source is under our
        // control: `--base`/`--head` come from whatever wrapper invoked us,
        // and the rest from a CI environment. See [`checked_rev`].
        let (base, head) = match (&args.base, &args.head, derived) {
            (Some(b), Some(h), _) => (b.clone(), Source::Flag(h.clone())),
            (b, h, Some((env_base, env_head))) => (
                b.clone().unwrap_or(env_base),
                h.clone()
                    .map_or(Source::Environment(env_head), Source::Flag),
            ),
            // `derived` is only `None` when both flags were given.
            (_, _, None) => bail!("--base and --head must be given together"),
        };
        let base = checked_rev(base, "base")?;

        let head = match head {
            Source::Flag(rev) => {
                let rev = checked_rev(rev, "head")?;
                resolve_commit(repo, &rev)?.with_context(|| {
                    format!(
                        "head revision {} is not in this checkout",
                        crate::printable(&rev)
                    )
                })?
            }
            // A shallow checkout of a pull request often has the merge commit
            // but not the head commit the event names. `HEAD` is then the
            // right — and only — answer. An explicit `--head` gets no such
            // fallback: a typo there must not silently analyze something else.
            Source::Environment(rev) => {
                let rev = checked_rev(rev, "head")?;
                match resolve_commit(repo, &rev)? {
                    Some(sha) => sha,
                    None => {
                        log::warn!("{} is not in this checkout; using HEAD", short(&rev));
                        resolve_commit(repo, "HEAD")?.context("HEAD does not name a commit")?
                    }
                }
            }
        };
        let Some(mut base) = resolve_commit(repo, &base)? else {
            bail!(
                "base commit {} is not in this checkout. Fetch it first:\n    \
                 git fetch --depth=50 origin {}",
                short(&base),
                crate::printable(&base),
            );
        };
        // The fork point, so commits that landed on the base branch after this
        // change was branched are not attributed to it.
        match git(repo, &["merge-base", &base, &head]) {
            Ok(out) => base = String::from_utf8_lossy(&out).trim().to_owned(),
            Err(e) => log::warn!(
                "no merge base ({e}); comparing against {} directly",
                short(&base)
            ),
        }
        Ok(Self { base, head })
    }
}

/// Where a head revision came from, which decides what a missing one means.
enum Source {
    /// `--head`: the caller named it, so it must exist.
    Flag(String),
    /// The CI event, which a shallow checkout may not contain.
    Environment(String),
}

/// What the report is about: `owner/repo#42` for a pull request, the repo
/// slug for a push, the directory name when running outside CI.
fn subject(env: &CiEnv, repo: &Path) -> String {
    let slug = env
        .repository
        .clone()
        .or_else(|| {
            std::fs::canonicalize(repo)
                .ok()?
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    match env.pr_number() {
        Some(n) if !slug.is_empty() => format!("{slug}#{n}"),
        Some(n) => format!("#{n}"),
        None => slug,
    }
}

/// Reject a revision that git would read as an option rather than a commit.
///
/// Every revision here is passed positionally (`git diff <base> <head>`,
/// `git show <commit>:<path>`), and git has no way to say "this argument is
/// data". A value like `--output=/etc/cron.d/isomer` is a real `git diff`
/// flag, so an unchecked revision turns a read-only scan into an arbitrary
/// file write. One check at the boundary covers every call below.
fn checked_rev(rev: String, side: &str) -> Result<String> {
    if rev.is_empty() || rev.starts_with('-') {
        bail!(
            "refusing {side} revision `{}`: a revision cannot be empty or begin with `-`",
            crate::printable(&rev),
        );
    }
    Ok(rev)
}

/// Whether a path stays inside the tree it is joined onto — every component is
/// an ordinary name, with no root, prefix, or `..` to escape through.
fn is_contained(path: &Path) -> bool {
    path.components()
        .all(|c| matches!(c, std::path::Component::Normal(_)))
}

/// git's "no such commit" sentinel, used for the first push to a branch.
fn is_null_sha(s: &str) -> bool {
    s.chars().all(|c| c == '0')
}

/// One changed path and which sides of the comparison it exists on.
///
/// An enum rather than two `Option`s so "exists on neither side" cannot be
/// written down. That state is unreachable — git cannot report it — but this is
/// the type feeding the path-containment boundary below, and an empty staged
/// path would resolve to the scratch *root*.
enum Change {
    Added(PathBuf),
    Deleted(PathBuf),
    Modified(PathBuf),
    Renamed { from: PathBuf, to: PathBuf },
}

impl Change {
    /// The single path both sides are staged under. A rename stages the base
    /// blob beside its head name, so the comparison sees one file that changed
    /// rather than one that vanished and another that appeared.
    fn staged(&self) -> &Path {
        match self {
            Self::Added(p) | Self::Deleted(p) | Self::Modified(p) => p,
            Self::Renamed { to, .. } => to,
        }
    }

    /// Where the file lives in the base commit; `None` when this change adds it.
    fn base(&self) -> Option<&Path> {
        match self {
            Self::Added(_) => None,
            Self::Deleted(p) | Self::Modified(p) => Some(p),
            Self::Renamed { from, .. } => Some(from),
        }
    }

    /// Where it lives in the head commit; `None` when this change deletes it.
    fn head(&self) -> Option<&Path> {
        match self {
            Self::Deleted(_) => None,
            Self::Added(p) | Self::Modified(p) => Some(p),
            Self::Renamed { to, .. } => Some(to),
        }
    }
}

/// The paths this change touches, from the fork point to head.
///
/// Rename detection is on. Without it a moved file is a delete plus an add, and
/// everything the added path can do reads as newly introduced — so renaming a
/// vendored library is indistinguishable from vendoring a hostile one. git
/// resolves this far more cheaply than we could: identical blobs match by hash,
/// and `diff.renameLimit` already bounds the similarity search.
///
/// Scoped to `repo` with the `.` pathspec: `git -C subdir diff` otherwise lists
/// every change in the enclosing repository, and `--repo` (the action's
/// `working-directory`) would narrow nothing. Paths stay relative to the
/// repository root, which is how `<commit>:<path>` addresses a blob.
fn changed_files(repo: &Path, refs: &Refs, max: usize) -> Result<Vec<Change>> {
    let out = git(
        repo,
        &[
            "diff",
            "--find-renames",
            "--name-status",
            "-z",
            &refs.base,
            &refs.head,
            "--",
            ".",
        ],
    )?;
    parse_name_status(&out, max)
}

/// Parse `git diff --name-status -z`.
///
/// Split out so the framing can be tested without a repository — it is the one
/// place a miscount silently drops a file from the scan.
///
/// `-z` frames the listing as `status\0path\0…`, so a path containing a
/// newline — or anything else a line-based parser would split on — cannot hide
/// a file. `R` and `C` are the exception: they carry the old name *and* the new
/// one, so a parser that reads one path per status walks out of step and
/// misreads every entry after the first rename.
fn parse_name_status(out: &[u8], max: usize) -> Result<Vec<Change>> {
    let mut fields = out.split(|b| *b == 0).filter(|f| !f.is_empty());
    let mut changes = Vec::new();
    // A record cut short is a listing we did not understand, not the end of
    // one: dropping it would analyze a subset and report it as the whole.
    let truncated = || anyhow::anyhow!("truncated `git diff --name-status` listing");
    while let Some(status) = fields.next() {
        let kind = status.first().copied().unwrap_or(b'M');
        let first = fields.next().ok_or_else(truncated)?;
        let (from, to) = if matches!(kind, b'R' | b'C') {
            let second = fields.next().ok_or_else(truncated)?;
            (os_path(first), os_path(second))
        } else {
            let p = os_path(first);
            (p.clone(), p)
        };
        // Every path is about to be joined onto a scratch root and written to.
        // `Path::join` *replaces* the root when handed an absolute path, and a
        // `..` component walks out of it, so a listing that is not strictly
        // repo-relative is refused rather than materialized somewhere else.
        // git cannot produce either, which is exactly why seeing one means the
        // listing is not what we think it is.
        for path in [&from, &to] {
            if !is_contained(path) {
                bail!(
                    "refusing to materialize `{}`: a changed path must be relative and free of `..`",
                    crate::printable(&path.to_string_lossy()),
                );
            }
        }
        changes.push(match kind {
            b'A' => Change::Added(to),
            b'D' => Change::Deleted(from),
            b'R' | b'C' => Change::Renamed { from, to },
            _ => Change::Modified(to),
        });
    }
    if changes.len() > max {
        // Never silently analyze a subset: a scanner that quietly skips files
        // reports "clean" for a change it did not read.
        bail!(
            "{} changed files exceeds --max-files {max}. Raise the limit or narrow the scan \
             with the action's `working-directory`",
            changes.len(),
        );
    }
    Ok(changes)
}

/// Extract both sides of every changed file into two sparse trees that mirror
/// the repository layout.
fn materialize(repo: &Path, refs: &Refs, changes: &[Change], old: &Path, new: &Path) -> Result<()> {
    for change in changes {
        let staged = change.staged();
        if let Some(from) = change.base() {
            extract(repo, &refs.base, from, &old.join(staged))?;
        }
        if let Some(to) = change.head() {
            extract(repo, &refs.head, to, &new.join(staged))?;
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
    extract_bounded(repo, commit, path, dest, MAX_BLOB)
}

/// [`extract`], with the size bound as a parameter so a test can exceed it
/// without writing 128 MiB.
fn extract_bounded(repo: &Path, commit: &str, path: &Path, dest: &Path, limit: u64) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // `<commit>:<path>` is git's blob address. The path travels as one argv
    // element, so no quoting or encoding can make it name a different file.
    // `cat-file` is the plumbing read: raw bytes, no porcelain conversion.
    let mut spec = std::ffi::OsString::from(format!("{commit}:"));
    spec.push(path);
    let mut child = git_command(repo)
        .args(["cat-file", "blob"])
        .arg(&spec)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running git cat-file")?;
    let Some(mut stdout) = child.stdout.take() else {
        bail!("git cat-file produced no output stream");
    };

    let file = std::fs::File::create(dest);
    // Bounded copy: a hostile blob cannot exhaust memory or disk here.
    let copied = file.map_err(anyhow::Error::from).and_then(|mut file| {
        Ok(std::io::copy(
            &mut std::io::Read::take(&mut stdout, limit + 1),
            &mut file,
        )?)
    });
    // Close our end of the pipe before waiting. Past the bound, git is still
    // blocked writing the rest of the blob; held open, `wait_with_output` would
    // drain stderr forever against a child that can never finish. Closed, git
    // takes EPIPE and exits.
    drop(stdout);
    // `wait_with_output` drains the stderr pipe, so git's own account of a
    // failure is kept — and reaped even when the copy above failed.
    let out = child
        .wait_with_output()
        .context("waiting for git cat-file")?;
    let copied = copied.with_context(|| format!("extracting {}", path.display()))?;
    // Checked before the exit status: an oversized blob is the case where we
    // closed the pipe on git, so its failure is ours, not the blob's.
    if copied > limit {
        discard(dest)?;
        log::warn!(
            "skipped {} — larger than {} MiB",
            path.display(),
            limit >> 20
        );
        return Ok(());
    }
    if !out.status.success() {
        // A blob that cannot be read is not a silent skip: drop the partial file
        // so the side simply has no content, and say why. If even that fails,
        // the run must not continue — a truncated prefix analyzed as a whole
        // file is a wrong answer, not a missing one.
        discard(dest)?;
        log::warn!(
            "could not read {}@{}: {}",
            path.display(),
            short(commit),
            crate::printable(String::from_utf8_lossy(&out.stderr).trim())
        );
        return Ok(());
    }
    Ok(())
}

/// Remove a staged file isomer has decided not to analyze. Failing to remove it
/// is fatal: what stays behind would be read as the file's real content.
fn discard(dest: &Path) -> Result<()> {
    std::fs::remove_file(dest).with_context(|| format!("discarding {}", dest.display()))
}

// ── sinks ───────────────────────────────────────────────────────────────────

/// Write the verdict everywhere this environment can show it.
fn emit(
    a: &Analysis<'_>,
    opts: &Options,
    sinks: &mut Sinks<'_>,
    out_dir: Option<&Path>,
    base: &str,
) -> Result<()> {
    // stdout keeps whatever the caller asked for, so `isomer ci --format json`
    // still pipes cleanly.
    sinks.stdout.push_str(&a.render(opts.format)?);

    let markdown = a.render(Format::Markdown)?;
    if let Some(dir) = out_dir {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let json = a.render(Format::Json)?;
        let sarif = a.render(Format::Sarif)?;
        for (name, body) in [
            ("report.json", &json),
            ("report.sarif", &sarif),
            ("report.md", &markdown),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
        }
    }

    // The step summary is the one GitHub surface that works without any
    // permission at all — including on a fork's read-only token — so the full
    // report goes there even when the comment and SARIF upload cannot happen.
    //
    // Which is exactly why a clean run must not spend it. One line when there
    // is nothing to report; everything when there is.
    if a.clean() {
        sinks.summary(&crate::markdown::one_line(a));
    } else {
        sinks.summary(&markdown);
    }

    let verdict = crate::view::verdict_word(a.verdict);
    let findings = a.assessment.finding_count();
    sinks.outputs(&[
        ("verdict", verdict),
        ("severity", a.verdict.as_str()),
        ("new-severity", a.new_verdict.as_str()),
        ("fail", if a.clean() { "false" } else { "true" }),
        ("findings", &findings.to_string()),
        // The fork point, not the base branch tip — so a workflow that
        // builds this commit to produce `--base-artifacts` measures both
        // halves of the report from the same place.
        ("base-sha", base),
    ]);

    // A failing check needs a reason visible in the job log without scrolling.
    // Workflow commands are read from the step's stdout, so this shares the
    // report's stream.
    if sinks.env.github_actions && !a.clean() {
        sinks.stdout.push_str(&format!(
            "::error title=isomer: {verdict}::{}\n",
            escape_annotation(&a.headline())
        ));
    }
    Ok(())
}

/// Where `ci` reports.
///
/// GitHub reads workflow commands from the step's stdout, so they collect in
/// `stdout` beside the report and reach the log in the order they were raised.
/// The step summary and the outputs file are the environment's to name, and
/// are written as the run goes.
struct Sinks<'a> {
    env: &'a CiEnv,
    stdout: String,
}

impl Sinks<'_> {
    /// Report an axis that could not run, where CI will actually show it.
    ///
    /// Degrading quietly is the one failure this tool cannot afford: a scan
    /// missing its artifact comparison must not read like a scan that made it
    /// and found nothing.
    fn warn(&mut self, message: &str) {
        log::warn!("{message}");
        if self.env.github_actions {
            self.stdout.push_str(&format!(
                "::warning title=isomer::{}\n",
                escape_annotation(message)
            ));
        }
    }

    /// Append markdown to the GitHub step summary, when running there.
    fn summary(&self, body: &str) {
        let Some(path) = &self.env.step_summary else {
            return;
        };
        if let Err(e) = append(path, body) {
            log::warn!("could not write step summary: {e:#}");
        }
    }

    /// Publish `name=value` pairs as action outputs, when running there.
    ///
    /// The CLI writes these itself so the action needs no JSON parsing —
    /// keeping the action a thin, auditable wrapper is worth twenty lines here.
    fn outputs(&self, pairs: &[(&str, &str)]) {
        let Some(path) = &self.env.output else {
            return;
        };
        // `k=v` is line-delimited, so a newline inside a value would forge
        // further outputs. `base-sha` carries a caller-supplied `--base`, so
        // this is attacker-reachable; strip the delimiters rather than trust
        // the source.
        let body: String = pairs
            .iter()
            .map(|(k, v)| format!("{k}={}\n", v.replace(['\r', '\n'], " ")))
            .collect();
        if let Err(e) = append(path, &body) {
            log::warn!("could not write outputs: {e:#}");
        }
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

/// `git -C <repo>`, isolated from the caller's repository environment.
///
/// `GIT_DIR` and its relatives override `-C`. Inherited from a hook or a
/// wrapper script, they would point every command below at some other
/// repository while the report named this one.
fn git_command(repo: &Path) -> Command {
    let mut cmd = Command::new("git");
    for var in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
    ] {
        cmd.env_remove(var);
    }
    cmd.arg("-C").arg(repo);
    cmd
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = git_command(repo)
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

/// The full object name of the commit `rev` names in this checkout.
///
/// `Ok(None)` means git ran and the revision names no commit here. Any other
/// failure — git missing, `repo` not a repository — is an error, not an
/// absent commit: reporting it as "fetch the base first" sends the reader
/// after the wrong problem.
fn resolve_commit(repo: &Path, rev: &str) -> Result<Option<String>> {
    let out = git_command(repo)
        .args(["rev-parse", "--verify", "--quiet", "--end-of-options"])
        .arg(format!("{rev}^{{commit}}"))
        .output()
        .context("running git rev-parse")?;
    match out.status.code() {
        Some(0) => Ok(Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())),
        // `--verify --quiet` exits 1, silently, for a name that resolves to
        // nothing.
        Some(1) => Ok(None),
        _ => bail!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
}

/// A revision abbreviated for a log line. Sanitized, because a revision that
/// never resolved is still caller- or environment-supplied text.
fn short(rev: &str) -> String {
    crate::printable(&rev.chars().take(12).collect::<String>())
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

    /// Revisions travel to git as positional arguments, where a leading `-`
    /// makes them options — `git diff --output=FILE` writes a file.
    #[test]
    fn option_shaped_revisions_are_refused() {
        assert!(checked_rev("--output=/etc/cron.d/x".into(), "base").is_err());
        assert!(checked_rev("-n".into(), "head").is_err());
        assert!(checked_rev(String::new(), "base").is_err());
        assert_eq!(
            checked_rev("HEAD~1".into(), "head").ok().as_deref(),
            Some("HEAD~1")
        );
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(checked_rev(sha.into(), "base").ok().as_deref(), Some(sha));
    }

    /// A changed path is joined onto a scratch root and written to; `join` with
    /// an absolute path silently discards the root.
    #[test]
    fn paths_must_stay_inside_the_scratch_tree() {
        assert!(is_contained(Path::new("src/main.rs")));
        assert!(is_contained(Path::new("a/b/c.txt")));
        assert!(!is_contained(Path::new("/etc/passwd")));
        assert!(!is_contained(Path::new("../../etc/passwd")));
        assert!(!is_contained(Path::new("a/../../b")));
    }

    /// `R`/`C` carry two paths. A parser that assumes one per status reads the
    /// *new* name as the next status byte and misreads everything after it, so
    /// a single rename would corrupt the rest of the listing.
    #[test]
    fn rename_entries_carry_both_paths_without_desynchronizing() {
        let out = b"M\0src/a.js\0R100\0vendor/old.js\0vendor/new.js\0A\0src/b.js\0D\0src/c.js\0";
        let c = parse_name_status(out, 100).expect("parses");
        assert_eq!(c.len(), 4, "a rename must not swallow the entries after it");

        assert_eq!(c[0].base(), Some(Path::new("src/a.js")));
        assert_eq!(c[0].head(), Some(Path::new("src/a.js")));

        // The rename: both sides present, under different names, staged as one.
        assert_eq!(c[1].base(), Some(Path::new("vendor/old.js")));
        assert_eq!(c[1].head(), Some(Path::new("vendor/new.js")));
        assert_eq!(c[1].staged(), Path::new("vendor/new.js"));

        // An addition has no base side, a deletion no head side.
        assert_eq!(c[2].base(), None);
        assert_eq!(c[2].staged(), Path::new("src/b.js"));
        assert_eq!(c[3].head(), None);
        assert_eq!(c[3].staged(), Path::new("src/c.js"));
    }

    #[test]
    fn a_truncated_listing_is_refused() {
        // A rename whose second path never arrived must neither be paired with
        // whatever follows nor silently dropped: either way the scan would
        // cover less than the change.
        assert!(parse_name_status(b"R100\0only/one.js\0", 100).is_err());
        assert!(parse_name_status(b"M\0", 100).is_err());
    }

    #[test]
    fn an_escaping_path_is_refused_on_either_side() {
        for out in [
            b"M\0../outside.js\0".as_slice(),
            b"R100\0../outside.js\0inside.js\0".as_slice(),
            b"R100\0inside.js\0../outside.js\0".as_slice(),
        ] {
            assert!(
                parse_name_status(out, 100).is_err(),
                "a path leaving the scratch root must be refused"
            );
        }
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

    /// A scratch repository with one commit per entry of `commits`, each a
    /// list of `(path, contents)` writes. Returns the directory and the SHAs.
    fn repo(commits: &[&[(&str, &[u8])]]) -> (tempfile::TempDir, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let out = git_command(dir.path())
                .args([
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@t",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {out:?}");
            out.stdout
        };
        run(&["init", "-q"]);
        let mut shas = Vec::new();
        for files in commits {
            for (path, body) in *files {
                let p = dir.path().join(path);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(p, body).unwrap();
            }
            run(&["add", "-A"]);
            run(&["commit", "-q", "--allow-empty", "-m", "c"]);
            shas.push(
                String::from_utf8(run(&["rev-parse", "HEAD"]))
                    .unwrap()
                    .trim()
                    .to_owned(),
            );
        }
        (dir, shas)
    }

    /// Past the bound, git is still writing; the read side must let it go
    /// rather than wait on it forever. Larger than any pipe buffer, so the old
    /// code hung here.
    #[test]
    fn an_oversized_blob_is_skipped_without_hanging() {
        let big = vec![b'x'; 4 << 20];
        let (dir, shas) = repo(&[&[("big.bin", &big), ("small.txt", b"ok")]]);
        let out = tempfile::tempdir().unwrap();
        let dest = out.path().join("big.bin");
        extract_bounded(dir.path(), &shas[0], Path::new("big.bin"), &dest, 1024).unwrap();
        assert!(!dest.exists(), "an oversized blob must not be staged");
        let dest = out.path().join("small.txt");
        extract_bounded(dir.path(), &shas[0], Path::new("small.txt"), &dest, 1024).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"ok");
    }

    /// `--repo` (the action's `working-directory`) narrows the scan; without a
    /// pathspec, git lists the whole repository's changes from a subdirectory.
    #[test]
    fn the_diff_is_scoped_to_the_repo_directory() {
        let (dir, shas) = repo(&[
            &[("a/x.js", b"1"), ("b/y.js", b"1")],
            &[("a/x.js", b"2"), ("b/y.js", b"2")],
        ]);
        let refs = Refs {
            base: shas[0].clone(),
            head: shas[1].clone(),
        };
        let changes = changed_files(&dir.path().join("a"), &refs, 100).unwrap();
        let staged: Vec<_> = changes.iter().map(Change::staged).collect();
        assert_eq!(staged, vec![Path::new("a/x.js")]);
    }

    #[test]
    fn a_missing_commit_is_absent_but_a_broken_repository_is_an_error() {
        let (dir, shas) = repo(&[&[("f", b"1")]]);
        assert_eq!(
            resolve_commit(dir.path(), "HEAD").unwrap().as_deref(),
            Some(shas[0].as_str())
        );
        assert_eq!(resolve_commit(dir.path(), "no-such-ref").unwrap(), None);
        let not_a_repo = tempfile::tempdir().unwrap();
        assert!(resolve_commit(not_a_repo.path(), "HEAD").is_err());
    }

    /// An explicit `--head` that does not resolve is the caller's mistake; only
    /// a head derived from the CI event may fall back to `HEAD`.
    #[test]
    fn an_explicit_head_never_falls_back_to_head() {
        let (dir, shas) = repo(&[&[("f", b"1")], &[("f", b"2")]]);
        let args = |head: Option<&str>, env: CiEnv| Args {
            base: Some(shas[0].clone()),
            head: head.map(str::to_owned),
            repo: dir.path().to_path_buf(),
            out_dir: None,
            max_files: 10,
            base_artifacts: None,
            head_artifacts: None,
            env,
        };
        assert!(Refs::resolve(dir.path(), &args(Some("typo"), CiEnv::default())).is_err());

        let env = CiEnv {
            merge_request_base: Some(shas[0].clone()),
            commit: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            ..CiEnv::default()
        };
        let refs = Refs::resolve(
            dir.path(),
            &Args {
                base: None,
                ..args(None, env)
            },
        )
        .unwrap();
        assert_eq!(refs.head, shas[1]);
    }
}
