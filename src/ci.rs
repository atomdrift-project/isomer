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
use crate::{Cli, Format};

/// Arguments to the `ci` verb.
pub(crate) struct Args {
    pub base: Option<String>,
    pub head: Option<String>,
    pub repo: PathBuf,
    pub out_dir: Option<PathBuf>,
    pub max_files: usize,
    /// Build outputs of the base commit, laid over the base tree.
    pub base_artifacts: Option<PathBuf>,
    /// Build outputs of the head commit, laid over the head tree.
    pub head_artifacts: Option<PathBuf>,
}

/// A blob larger than this is not extracted. Nothing legitimate in a source
/// diff approaches it, and an unbounded read is a denial-of-service waiting for
/// a hostile pull request.
const MAX_BLOB: u64 = 128 << 20;

/// Analyze the change this CI run is for.
pub(crate) fn run(cli: &Cli, args: &Args) -> Result<bool> {
    let repo = args.repo.as_path();
    let refs = Refs::resolve(repo, args)?;
    eprintln!(
        "isomer: comparing {}..{}",
        short(&refs.base),
        short(&refs.head)
    );

    let changes = changed_files(repo, &refs, args.max_files)?;
    // Build outputs are judged even when no source file changed: a change to a
    // lockfile or a build script can move the artifact without moving anything
    // this diff would otherwise read.
    let artifacts = args.base_artifacts.is_some() || args.head_artifacts.is_some();
    if changes.is_empty() && !artifacts {
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
            ("base-sha", &refs.base),
        ]);
        return Ok(true);
    }

    let work = tempfile::Builder::new()
        .prefix("isomer-ci-")
        .tempdir()
        .context("creating work directory")?;
    let (old, new) = (work.path().join("base"), work.path().join("head"));
    materialize(repo, &refs, &changes, &old, &new)?;
    let compared = overlay_builds(
        args.base_artifacts.as_deref(),
        args.head_artifacts.as_deref(),
        &old,
        &new,
        args.max_files,
    )?;

    let options = cleave::AnalysisOptions::default();
    let report = analysis::diff(&old, &new, &options)?;
    let mut a = Analysis::new("ci", &old, &new, &options, &report, cli)?;
    // `fs` names the artifact it compared; `ci` compares two states of a
    // repository, where the scratch dir the files were staged in is no name.
    a.naming.name = subject(repo);
    a.scope = Some(if compared {
        analysis::Scope::SourceAndBuild
    } else {
        analysis::Scope::Source
    });

    emit(&a, cli, args.out_dir.as_deref(), &refs.base)?;
    Ok(a.clean)
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
            warn("only one side's build outputs were supplied; the comparison needs both");
        }
        return Ok(false);
    };
    for dir in [base, head] {
        if !dir.is_dir() {
            // The workflow asked for a comparison and the artifacts are not
            // there. An axis that silently did not run reads exactly like an
            // axis that ran and found nothing.
            warn(&format!(
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
        warn("build output directories are empty — build outputs were NOT compared");
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
    let mut staged_as: Vec<Option<&str>> = vec![None; base_files.len()];
    let mut renamed = 0usize;
    for &(b, h) in &pairs {
        staged_as[b] = Some(head_files[h].as_str());
        if base_files[b] != head_files[h] {
            renamed += 1;
        }
    }

    for (i, rel) in base_files.iter().enumerate() {
        let dest = staged_as[i].unwrap_or(rel.as_str());
        stage(&base.join(rel), &old.join(dest))?;
    }
    for rel in &head_files {
        stage(&head.join(rel), &new.join(rel))?;
    }

    eprintln!(
        "isomer: {} build output(s) from {}, {} from {}{}",
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
fn stage(src: &Path, dest: &Path) -> Result<()> {
    let size = std::fs::metadata(src)
        .with_context(|| format!("reading {}", src.display()))?
        .len();
    if size > MAX_BLOB {
        eprintln!(
            "isomer: skipped {} — larger than {} MiB",
            src.display(),
            MAX_BLOB >> 20
        );
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::copy(src, dest).with_context(|| format!("copying {}", src.display()))?;
    Ok(())
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
        // Before either value reaches git. Both sides travel as *positional*
        // arguments, and neither source is under our control: `--base`/`--head`
        // come from whatever wrapper invoked us, and the rest from a CI
        // environment. See [`checked_rev`].
        base = checked_rev(base, "base")?;
        head = checked_rev(head, "head")?;

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
struct Change {
    /// Where the file lives in the base commit; `None` when this change adds it.
    base: Option<PathBuf>,
    /// Where it lives in the head commit; `None` when this change deletes it.
    head: Option<PathBuf>,
}

impl Change {
    /// The single path both sides are staged under. A rename stages the base
    /// blob beside its head name, so the comparison sees one file that changed
    /// rather than one that vanished and another that appeared.
    fn staged(&self) -> &Path {
        // `git diff` never reports a change with neither side.
        self.head
            .as_deref()
            .or(self.base.as_deref())
            .unwrap_or(Path::new(""))
    }
}

/// The paths this change touches, from the fork point to head.
///
/// Rename detection is on. Without it a moved file is a delete plus an add, and
/// everything the added path can do reads as newly introduced — so renaming a
/// vendored library is indistinguishable from vendoring a hostile one. git
/// resolves this far more cheaply than we could: identical blobs match by hash,
/// and `diff.renameLimit` already bounds the similarity search.
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
    while let Some(status) = fields.next() {
        let kind = status.first().copied().unwrap_or(b'M');
        let Some(first) = fields.next() else { break };
        let (from, to) = if matches!(kind, b'R' | b'C') {
            let Some(second) = fields.next() else { break };
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
        changes.push(Change {
            base: (kind != b'A').then_some(from),
            head: (kind != b'D').then_some(to),
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
        if let Some(from) = &change.base {
            extract(repo, &refs.base, from, &old.join(staged))?;
        }
        if let Some(to) = &change.head {
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
fn emit(a: &Analysis<'_>, cli: &Cli, out_dir: Option<&Path>, base: &str) -> Result<()> {
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
    //
    // Which is exactly why a clean run must not spend it. One line when there
    // is nothing to report; everything when there is.
    if a.clean {
        summary(&crate::markdown::one_line(a));
    } else {
        summary(&markdown);
    }

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
        // The fork point, not the base branch tip — so a workflow that builds
        // this commit to produce `--base-artifacts` measures both halves of the
        // report from the same place.
        ("base-sha", base),
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

/// Report an axis that could not run, where CI will actually show it.
///
/// Degrading quietly is the one failure this tool cannot afford: a scan missing
/// its artifact comparison must not read like a scan that made it and found
/// nothing.
fn warn(message: &str) {
    eprintln!("isomer: {message}");
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        println!("::warning title=isomer::{}", escape_annotation(message));
    }
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

        assert_eq!(c[0].base.as_deref(), Some(Path::new("src/a.js")));
        assert_eq!(c[0].head.as_deref(), Some(Path::new("src/a.js")));

        // The rename: both sides present, under different names, staged as one.
        assert_eq!(c[1].base.as_deref(), Some(Path::new("vendor/old.js")));
        assert_eq!(c[1].head.as_deref(), Some(Path::new("vendor/new.js")));
        assert_eq!(c[1].staged(), Path::new("vendor/new.js"));

        // An addition has no base side, a deletion no head side.
        assert_eq!(c[2].base, None);
        assert_eq!(c[2].staged(), Path::new("src/b.js"));
        assert_eq!(c[3].head, None);
        assert_eq!(c[3].staged(), Path::new("src/c.js"));
    }

    #[test]
    fn a_truncated_listing_does_not_invent_a_change() {
        // A rename whose second path never arrived must be dropped, not paired
        // with whatever follows.
        let c = parse_name_status(b"R100\0only/one.js\0", 100).expect("parses");
        assert!(c.is_empty());
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
}
