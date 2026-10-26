//! Audit the transitions stated by the supply-chain corpus's `pairs.yaml`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize)]
pub struct SampleFile {
    pub path: PathBuf,
    pub logical_name: String,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub provenance: Value,
}

#[derive(Debug, Serialize)]
pub struct SnapshotFile {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct Artifact {
    pub name: String,
    pub year: u32,
    pub before: Option<SampleFile>,
    pub during: Option<SampleFile>,
    pub after: Option<SampleFile>,
    pub baseline: Vec<SampleFile>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Transition {
    pub detected: Option<bool>,
    pub severity: String,
    pub error: Option<String>,
    pub diagnostic: Value,
}

impl Transition {
    pub fn error(error: impl ToString) -> Self {
        Self {
            detected: None,
            severity: "?".into(),
            error: Some(error.to_string()),
            diagnostic: Value::Null,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Comparison {
    pub artifact_index: usize,
    pub kind: String,
    pub old: SampleFile,
    pub new: SampleFile,
}

impl Comparison {
    fn label(&self) -> &str {
        transition_label(&self.kind)
    }
    fn expected(&self) -> bool {
        self.kind == "bd"
    }
}

fn transition_label(kind: &str) -> &str {
    match kind {
        "bd" => "before->during",
        "da" => "during->after",
        "ba" => "before->after",
        _ => "before->before",
    }
}

pub fn issue(kind: &str, run: &Transition) -> Option<&'static str> {
    if run.error.is_some() || run.detected.is_none() {
        Some("ERROR")
    } else if run.detected != Some(kind == "bd") {
        Some(match kind {
            "bd" => "MISS",
            "da" => "FP-REMEDIATION",
            "ba" => "FP-NET",
            _ => "FP-BASELINE",
        })
    } else {
        None
    }
}

pub fn evidence_warnings(old: &SampleFile, new: &SampleFile) -> Vec<Value> {
    [("old", old), ("new", new)]
        .into_iter()
        .filter_map(|(side, sample)| {
            let classification = sample.provenance["classification"].as_str()?;
            let message = match classification {
                "affected" => "Affected context does not by itself establish a malicious payload.",
                "carrier" => {
                    "A carrier label does not by itself establish an active malicious payload."
                }
                "baseline_candidate" => "A baseline candidate is not a confirmed clean baseline.",
                _ => return None,
            };
            Some(json!({"side": side, "classification": classification, "message": message}))
        })
        .collect()
}

#[derive(Clone, Debug, Deserialize)]
struct Side {
    subject: String,
    phase: String,
    file: String,
    version: Option<serde_yaml::Value>,
    classification: Option<String>,
    sha256: Option<String>,
}

impl Side {
    fn version(&self) -> Option<String> {
        self.version.as_ref().and_then(|v| match v {
            serde_yaml::Value::String(s) => Some(s.clone()),
            serde_yaml::Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
    }
    fn key(&self) -> (String, Option<String>) {
        (self.subject.clone(), self.sha256.clone())
    }
    fn resolve(&self, tree: &Path, record: &str) -> Option<SampleFile> {
        let version = self.version();
        let release = version
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or("unversioned");
        let path = tree
            .join(record)
            .join(&self.subject)
            .join(&self.phase)
            .join(release)
            .join(&self.file);
        path.is_file().then(|| SampleFile {
            path, logical_name: self.file.clone(),
            provenance: json!({"record": record, "phase": self.phase, "classification": self.classification,
                "version": version, "declared_sha256": self.sha256}),
        })
    }
}

#[derive(Debug, Deserialize)]
struct Pair {
    kind: String,
    old: Side,
    new: Side,
}

#[derive(Debug, Default, Deserialize)]
struct Document {
    record: Option<String>,
    pairs: Option<Vec<Pair>>,
}

fn chain_for(
    subject: &str,
    baselines: &BTreeMap<String, Vec<&Pair>>,
    chained: &mut BTreeSet<String>,
    tree: &Path,
    record: &str,
) -> Vec<SampleFile> {
    if !chained.insert(subject.into()) {
        return Vec::new();
    }
    let mut chain = Vec::new();
    if let Some(steps) = baselines.get(subject) {
        for (index, pair) in steps.iter().enumerate() {
            if index == 0
                && let Some(first) = pair.old.resolve(tree, record)
            {
                chain.push(first);
            }
            if let Some(next) = pair.new.resolve(tree, record) {
                chain.push(next);
            }
        }
    }
    chain
}

pub fn load_artifacts(tree: &Path) -> Result<Vec<Artifact>> {
    let mut manifests = fs::read_dir(tree)?
        .map(|entry| Ok(entry?.path().join("pairs.yaml")))
        .collect::<Result<Vec<_>>>()?;
    manifests.retain(|p| p.is_file());
    manifests.sort();
    let year_pattern = Regex::new(r"(?m)^\*\*When:\*\*\s*(\d{4})")?;
    let mut out = Vec::new();
    for path in manifests {
        let document: Document =
            serde_yaml::from_str::<Option<Document>>(&fs::read_to_string(&path)?)
                .with_context(|| format!("cannot read {}", path.display()))?
                .unwrap_or_default();
        let directory = path.parent().context("manifest has no directory")?;
        let record = document
            .record
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                directory
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            });
        let readme = fs::read_to_string(directory.join("README.md")).unwrap_or_default();
        let year = year_pattern
            .captures(&readme)
            .and_then(|m| m[1].parse().ok())
            .unwrap_or(0);
        let pairs = document.pairs.unwrap_or_default();
        let mut fixed_for = BTreeMap::new();
        let mut baselines: BTreeMap<String, Vec<&Pair>> = BTreeMap::new();
        let mut attacks = Vec::new();
        for pair in &pairs {
            match pair.kind.as_str() {
                "attack" => attacks.push(pair),
                "remediation" => {
                    fixed_for.insert(pair.old.key(), &pair.new);
                }
                "baseline" => {
                    baselines
                        .entry(pair.old.subject.clone())
                        .or_default()
                        .push(pair);
                }
                _ => {}
            }
        }
        let mut chained = BTreeSet::new();
        for pair in &attacks {
            let (Some(before), Some(during)) = (
                pair.old.resolve(tree, &record),
                pair.new.resolve(tree, &record),
            ) else {
                continue;
            };
            let after = fixed_for
                .get(&pair.new.key())
                .and_then(|side| side.resolve(tree, &record));
            let baseline = chain_for(&pair.new.subject, &baselines, &mut chained, tree, &record);
            out.push(Artifact {
                name: artifact_name(&record, &pair.new),
                year,
                before: Some(before),
                during: Some(during),
                after,
                baseline,
            });
        }
        let paired: BTreeSet<_> = attacks.iter().map(|p| p.new.key()).collect();
        for (key, after_side) in &fixed_for {
            if paired.contains(key) {
                continue;
            }
            let during_side = pairs
                .iter()
                .find(|p| p.kind == "remediation" && p.old.key() == *key)
                .map(|p| &p.old);
            let (Some(during), Some(after)) = (
                during_side.and_then(|s| s.resolve(tree, &record)),
                after_side.resolve(tree, &record),
            ) else {
                continue;
            };
            let side = during_side.context("missing remediation side")?;
            out.push(Artifact {
                name: format!("{} (no clean comparator)", artifact_name(&record, side)),
                year,
                before: None,
                during: Some(during),
                after: Some(after),
                baseline: Vec::new(),
            });
        }
        for subject in baselines.keys() {
            let baseline = chain_for(subject, &baselines, &mut chained, tree, &record);
            if baseline.len() > 1 {
                out.push(Artifact {
                    name: format!("{record}/{subject}"),
                    year,
                    before: baseline.first().cloned(),
                    during: None,
                    after: None,
                    baseline,
                });
            }
        }
    }
    out.sort_by(|a, b| (a.year, &a.name).cmp(&(b.year, &b.name)));
    Ok(out)
}

fn artifact_name(record: &str, side: &Side) -> String {
    let version = side
        .version()
        .filter(|v| !v.is_empty())
        .map(|v| format!("@{v}"))
        .unwrap_or_default();
    format!("{record}/{}{version}", side.subject)
}

pub fn transitions_of(artifact_index: usize, artifact: &Artifact) -> Vec<Comparison> {
    let mut work = Vec::new();
    for (kind, old, new) in [
        ("bd", &artifact.before, &artifact.during),
        ("da", &artifact.during, &artifact.after),
        ("ba", &artifact.before, &artifact.after),
    ] {
        if let (Some(old), Some(new)) = (old, new) {
            work.push(Comparison {
                artifact_index,
                kind: kind.into(),
                old: old.clone(),
                new: new.clone(),
            });
        }
    }
    for (index, sides) in artifact.baseline.windows(2).enumerate() {
        work.push(Comparison {
            artifact_index,
            kind: format!("bb{index}"),
            old: sides[0].clone(),
            new: sides[1].clone(),
        });
    }
    work
}

pub fn parse_transition(code: Option<i32>, stdout: &str, stderr: &str) -> Transition {
    if !matches!(code, Some(0 | 1)) {
        return Transition::error(
            stderr
                .lines()
                .rfind(|s| !s.trim().is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("exit {code:?}")),
        );
    }
    // A verdict produced after skipping rules cannot establish audit coverage.
    if let Some(warning) = stderr.lines().find(|line| {
        line.contains("WARNING: skipped ")
            && line.contains("trait file(s)")
            && line.contains("could not parse")
    }) {
        let paths: Vec<_> = stderr
            .lines()
            .filter_map(|line| {
                line.split_once("Failed to parse YAML in \"")
                    .and_then(|(_, rest)| rest.split_once('"').map(|(path, _)| path))
            })
            .collect();
        return Transition::error(format!(
            "incomplete trait coverage: {warning} ({})",
            paths.join(", ")
        ));
    }
    let Ok(report) = serde_json::from_str::<Value>(stdout) else {
        return Transition::error("unparseable json");
    };
    let Some(detected) = report["verdict"]["gate"]["fail"].as_bool() else {
        return Transition::error("unparseable json");
    };
    let mut diagnostic =
        json!({"verdict": report["verdict"], "summary": report["raw"]["diff"]["summary"]});
    for key in ["trait_shift", "judged_summary", "scopes", "topology"] {
        if let Some(value) = report["features"].get(key) {
            diagnostic[key] = value.clone();
        }
    }
    Transition {
        detected: Some(detected),
        severity: report["verdict"]["gate"]["severity"]
            .as_str()
            .unwrap_or("?")
            .into(),
        error: None,
        diagnostic,
    }
}

fn read_pipe(mut pipe: impl Read) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn run_transition(
    isomer: &Path,
    traits: Option<&Path>,
    fail_on: &str,
    old: &SampleFile,
    new: &SampleFile,
    timeout: Option<Duration>,
) -> Result<Transition> {
    let mut command = Command::new(isomer);
    command
        .arg("--offline")
        .arg("fs")
        .arg(&old.path)
        .arg(&new.path)
        .args(["--format", "json", "--fail-on", fail_on])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(traits) = traits {
        command.env("CLEAVE_TRAITS_DIR", traits);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().context("missing stdout pipe")?;
    let stderr = child.stderr.take().context("missing stderr pipe")?;
    std::thread::scope(|scope| {
        let stdout = scope.spawn(|| read_pipe(stdout));
        let stderr = scope.spawn(|| read_pipe(stderr));
        let started = Instant::now();
        let mut timed_out = false;
        let mut status = None;
        let status = loop {
            if status.is_none() {
                status = child.try_wait()?;
            }
            // Descendants may still own the pipes after the scanner exits.
            // Keep the deadline active until both readers have reached EOF.
            if let Some(status) = status
                && stdout.is_finished()
                && stderr.is_finished()
            {
                break status;
            }
            if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
                #[cfg(unix)]
                {
                    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id())?);
                    let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
                }
                #[cfg(not(unix))]
                {
                    let _ = child.kill();
                }
                timed_out = true;
                break match status {
                    Some(status) => status,
                    None => child.wait()?,
                };
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = stdout
            .join()
            .map_err(|_| anyhow::anyhow!("stdout reader failed"))??;
        let stderr = stderr
            .join()
            .map_err(|_| anyhow::anyhow!("stderr reader failed"))??;
        Ok(if timed_out {
            Transition::error("timeout")
        } else {
            parse_transition(status.code(), &stdout, &stderr)
        })
    })
}

fn unchanged(before: &fs::Metadata, after: &fs::Metadata, size: u64) -> bool {
    let same = before.len() == after.len()
        && before.len() == size
        && before.modified().ok() == after.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        same
    }
}

pub fn snapshot_samples<'a>(
    samples: impl IntoIterator<Item = &'a SampleFile>,
    destination: &Path,
) -> Result<BTreeMap<PathBuf, SnapshotFile>> {
    let mut snapshots = BTreeMap::new();
    for sample in samples {
        if snapshots.contains_key(&sample.path) {
            continue;
        }
        let target = destination
            .join(snapshots.len().to_string())
            .join(sample.path.file_name().context("input has no filename")?);
        fs::create_dir_all(target.parent().context("snapshot has no parent")?)?;
        let mut source = File::open(&sample.path)?;
        let before = source.metadata()?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        let mut digest = Sha256::new();
        let mut size = 0;
        let mut block = vec![0u8; 1024 * 1024];
        loop {
            let count = source.read(&mut block)?;
            if count == 0 {
                break;
            }
            output.write_all(&block[..count])?;
            digest.update(&block[..count]);
            size += count as u64;
        }
        ensure!(
            unchanged(&before, &source.metadata()?, size),
            "input changed while being copied: {}",
            sample.path.display()
        );
        snapshots.insert(
            sample.path.clone(),
            SnapshotFile {
                path: target,
                sha256: format!("{:x}", digest.finalize()),
                size,
            },
        );
    }
    Ok(snapshots)
}

pub fn snapshot_executable(command: &Path, destination: &Path) -> Result<SnapshotFile> {
    let source = which::which(command)
        .with_context(|| {
            format!(
                "executable not found or not executable: {}",
                command.display()
            )
        })?
        .canonicalize()?;
    ensure!(
        source.is_file(),
        "not an executable file: {}",
        source.display()
    );
    let sample = SampleFile {
        logical_name: source
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        path: source,
        provenance: Value::Null,
    };
    let captured = snapshot_samples([&sample], destination)?
        .remove(&sample.path)
        .context("missing detector snapshot")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&captured.path, fs::Permissions::from_mode(0o500))?;
    }
    Ok(captured)
}

fn copy_traits(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_name() == ".git" {
            continue;
        }
        let target = destination.join(entry.file_name());
        if entry.path().is_dir() {
            copy_traits(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

pub fn snapshot_traits(source: Option<&Path>, destination: &Path) -> Result<Option<PathBuf>> {
    source
        .map(|source| {
            copy_traits(source, destination)?;
            Ok(destination.to_path_buf())
        })
        .transpose()
}

pub fn default_jobs(cpus: usize) -> usize {
    (cpus / 2).clamp(1, 8)
}

pub fn write_stream_record(
    stream: &mut dyn Write,
    work: &Comparison,
    artifact: &Artifact,
    run: &Transition,
    snapshots: &BTreeMap<PathBuf, SnapshotFile>,
) -> Result<()> {
    let describe = |sample: &SampleFile| -> Result<Value> {
        let mut value = serde_json::to_value(sample)?;
        let snapshot = snapshots
            .get(&sample.path)
            .context("missing input snapshot")?;
        value["sha256"] = json!(snapshot.sha256);
        value["size"] = json!(snapshot.size);
        Ok(value)
    };
    serde_json::to_writer(
        &mut *stream,
        &json!({"event": "comparison", "artifact_index": work.artifact_index,
        "artifact": artifact.name, "year": artifact.year, "transition": work.kind,
        "old": describe(&work.old)?, "new": describe(&work.new)?, "expected_detected": work.expected(),
        "evidence_warnings": evidence_warnings(&work.old, &work.new), "issue": issue(&work.kind, run),
        "detected": run.detected, "severity": run.severity, "error": run.error, "diagnostic": run.diagnostic}),
    )?;
    writeln!(stream)?;
    stream.flush()?;
    Ok(())
}

pub fn summarize(
    artifacts: &[Artifact],
    work: &[Comparison],
    runs: &BTreeMap<(usize, String), Transition>,
) -> Value {
    let mut summary = json!({"artifacts": artifacts.len(), "errors": 0,
        "before_during_detected": 0, "before_during_total": 0,
        "during_after_false_positives": 0, "during_after_total": 0,
        "before_after_false_positives": 0, "before_after_total": 0,
        "before_before_false_positives": 0, "before_before_total": 0});
    let mut violations = Vec::new();
    let mut qualified = Vec::new();
    for (index, artifact) in artifacts.iter().enumerate() {
        let mut issues = Vec::new();
        let mut diagnostics = BTreeMap::new();
        let mut warnings = BTreeMap::new();
        for comparison in work.iter().filter(|w| w.artifact_index == index) {
            let Some(run) = runs.get(&(index, comparison.kind.clone())) else {
                continue;
            };
            let prefix = match comparison.kind.as_str() {
                "bd" => "before_during",
                "da" => "during_after",
                "ba" => "before_after",
                _ => "before_before",
            };
            if let Some(detected) = run.detected {
                increment(&mut summary, &format!("{prefix}_total"));
                if detected {
                    increment(
                        &mut summary,
                        &format!(
                            "{prefix}_{}",
                            if comparison.expected() {
                                "detected"
                            } else {
                                "false_positives"
                            }
                        ),
                    );
                }
            }
            if run.error.is_some() {
                increment(&mut summary, "errors");
            }
            if let Some(issue) = issue(&comparison.kind, run) {
                let detail = run.error.clone().unwrap_or_else(|| {
                    format!(
                        "detected={} (sev={})",
                        run.detected.unwrap_or(false),
                        run.severity
                    )
                });
                let pair = if comparison.kind.starts_with("bb") {
                    format!(
                        " {} -> {}",
                        comparison.old.logical_name, comparison.new.logical_name
                    )
                } else {
                    String::new()
                };
                issues.push(format!("{issue} {}: {detail}{pair}", comparison.label()));
                if run.detected.is_some() {
                    let name = comparison
                        .kind
                        .strip_prefix("bb")
                        .map(|index| format!("before->before[{index}]"))
                        .unwrap_or_else(|| comparison.label().into());
                    diagnostics.insert(name, run.diagnostic.clone());
                }
            }
            let evidence = evidence_warnings(&comparison.old, &comparison.new);
            if !evidence.is_empty() {
                warnings.insert(comparison.kind.clone(), evidence);
            }
        }
        if !issues.is_empty() {
            violations.push(
                json!({"artifact": artifact.name, "issues": issues, "diagnostics": diagnostics}),
            );
        }
        if !warnings.is_empty() {
            qualified.push(json!({"artifact": artifact.name, "transitions": warnings}));
        }
    }
    summary["violations"] = json!(violations);
    summary["evidence_warnings"] = json!(qualified);
    summary
}

fn increment(value: &mut Value, key: &str) {
    value[key] = json!(value[key].as_u64().unwrap_or(0) + 1);
}

fn default_corpus() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join("data/supplychain-attack-data")
}

fn default_isomer() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    ["target/release/isomer", "target/debug/isomer"]
        .into_iter()
        .map(|p| root.join(p))
        .find(|p| p.is_file())
        .unwrap_or_else(|| "isomer".into())
}

/// Audit the supply-chain artifact tree. Comparisons always run offline.
#[derive(Debug, Parser)]
pub struct Args {
    #[arg(long, env = "ISOMER_SAMPLES_DIR", default_value_os_t = default_corpus())]
    pub corpus: PathBuf,
    #[arg(long, env = "ISOMER", default_value_os_t = default_isomer())]
    pub isomer: PathBuf,
    #[arg(long, env = "CLEAVE_TRAITS_DIR")]
    pub traits: Option<PathBuf>,
    #[arg(long, default_value = "high", value_parser = ["low", "medium", "high", "critical"])]
    pub fail_on: String,
    /// Concurrent scanners (0 = half the CPUs, capped at 8).
    #[arg(long, default_value_t = 0)]
    pub jobs: usize,
    /// Per-comparison timeout in seconds (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    pub timeout: u64,
    #[arg(long, default_value_t = 0)]
    pub limit: usize,
    #[arg(long)]
    pub json: bool,
    /// Resolve corpus comparisons without running scanners.
    #[arg(long)]
    pub check_corpus: bool,
    /// Create a new JSONL file and flush each completed comparison.
    #[arg(long, env = "ISOMER_AUDIT_STREAM_RESULTS")]
    pub stream_results: Option<PathBuf>,
}

pub fn execute(args: &Args, output: &mut dyn Write) -> Result<u8> {
    ensure!(
        args.corpus.is_dir(),
        "artifact tree not found at {}; set ISOMER_SAMPLES_DIR or pass --corpus",
        args.corpus.display()
    );
    let mut artifacts = load_artifacts(&args.corpus)?;
    if args.check_corpus {
        let mut counts = BTreeMap::<String, usize>::new();
        for artifact in &artifacts {
            for comparison in transitions_of(0, artifact) {
                *counts.entry(comparison.label().into()).or_default() += 1;
            }
        }
        if args.json {
            writeln!(
                output,
                "{}",
                json!({"artifacts": artifacts.len(), "comparisons": counts})
            )?;
        } else {
            writeln!(
                output,
                "{} artifacts, {} comparisons",
                artifacts.len(),
                counts.values().sum::<usize>()
            )?;
            for (key, count) in counts {
                writeln!(output, "  {count:6}  {key}")?;
            }
        }
        return Ok(0);
    }
    if args.limit > 0 {
        artifacts.truncate(args.limit);
    }
    if artifacts.is_empty() {
        bail!(
            "no comparisons under {}; this must be the artifact tree holding <record>/pairs.yaml",
            args.corpus.display()
        );
    }
    let work: Vec<_> = artifacts
        .iter()
        .enumerate()
        .flat_map(|(index, artifact)| transitions_of(index, artifact))
        .collect();
    let jobs = if args.jobs == 0 {
        default_jobs(
            std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(2),
        )
    } else {
        args.jobs
    };
    eprintln!(
        "auditing {} artifacts ({} comparisons, {jobs} at a time) against {} (detect = fail-on {})…",
        artifacts.len(),
        work.len(),
        args.isomer.display(),
        args.fail_on
    );
    let staging = tempfile::tempdir()?;
    let detector = snapshot_executable(&args.isomer, &staging.path().join("detector"))
        .context("cannot snapshot executable")?;
    let traits = snapshot_traits(
        args.traits.as_deref().filter(|p| !p.as_os_str().is_empty()),
        &staging.path().join("traits"),
    )
    .context("cannot snapshot traits")?;
    let mut stream = args
        .stream_results
        .as_ref()
        .map(|path| OpenOptions::new().write(true).create_new(true).open(path))
        .transpose()
        .context("cannot write result stream")?;
    let snapshots = snapshot_samples(
        work.iter().flat_map(|w| [&w.old, &w.new]),
        &staging.path().join("inputs"),
    )
    .context("cannot snapshot inputs")?;
    if let Some(stream) = &mut stream {
        writeln!(
            stream,
            "{}",
            json!({"event": "run", "schema": 1, "comparisons": work.len(), "isomer": args.isomer,
            "traits_source": args.traits, "detector_snapshot": detector, "traits_snapshot": traits, "corpus": args.corpus,
            "fail_on": args.fail_on, "offline": true, "input_snapshot": "independent-copies"})
        )?;
        stream.flush()?;
    }
    let runs = execute_work(
        args,
        &work,
        &artifacts,
        &detector,
        traits.as_deref(),
        &snapshots,
        stream.as_mut().map(|s| s as &mut dyn Write),
        jobs,
    )?;
    let summary = summarize(&artifacts, &work, &runs);
    let failed = summary["violations"]
        .as_array()
        .is_some_and(|v| !v.is_empty());
    if args.json {
        writeln!(output, "{}", serde_json::to_string_pretty(&summary)?)?;
    } else {
        print_summary(output, &summary)?;
    }
    Ok(u8::from(failed))
}

#[allow(clippy::too_many_arguments)]
fn execute_work(
    args: &Args,
    work: &[Comparison],
    artifacts: &[Artifact],
    detector: &SnapshotFile,
    traits: Option<&Path>,
    snapshots: &BTreeMap<PathBuf, SnapshotFile>,
    mut stream: Option<&mut dyn Write>,
    jobs: usize,
) -> Result<BTreeMap<(usize, String), Transition>> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        for _ in 0..jobs.min(work.len()) {
            let sender = sender.clone();
            let next = &next;
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(comparison) = work.get(index) else {
                        break;
                    };
                    let copied = |sample: &SampleFile| -> Result<SampleFile> {
                        Ok(SampleFile {
                            path: snapshots
                                .get(&sample.path)
                                .context("missing snapshot")?
                                .path
                                .clone(),
                            logical_name: sample.logical_name.clone(),
                            provenance: Value::Null,
                        })
                    };
                    let run = (|| {
                        run_transition(
                            &detector.path,
                            traits,
                            &args.fail_on,
                            &copied(&comparison.old)?,
                            &copied(&comparison.new)?,
                            (args.timeout > 0).then(|| Duration::from_secs(args.timeout)),
                        )
                    })()
                    .unwrap_or_else(|error| Transition::error(format!("worker failed: {error:#}")));
                    if sender.send((index, run)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(sender);
        let mut runs = BTreeMap::new();
        for (index, run) in receiver {
            let comparison = &work[index];
            if let Some(stream) = stream.as_deref_mut() {
                write_stream_record(
                    stream,
                    comparison,
                    &artifacts[comparison.artifact_index],
                    &run,
                    snapshots,
                )?;
            }
            runs.insert((comparison.artifact_index, comparison.kind.clone()), run);
            eprint!("\r  {}/{}", runs.len(), work.len());
        }
        eprintln!();
        Ok(runs)
    })
}

fn print_summary(output: &mut dyn Write, summary: &Value) -> Result<()> {
    if let Some(warnings) = summary["evidence_warnings"].as_array()
        && !warnings.is_empty()
    {
        writeln!(
            output,
            "\nEVIDENCE WARNINGS (expectations and gates unchanged):"
        )?;
        for record in warnings {
            writeln!(
                output,
                "  {}: {}",
                record["artifact"], record["transitions"]
            )?;
        }
    }
    if let Some(violations) = summary["violations"].as_array() {
        for record in violations {
            writeln!(output, "\n{}:", record["artifact"].as_str().unwrap_or("?"))?;
            if let Some(issues) = record["issues"].as_array() {
                for issue in issues {
                    writeln!(output, "  {}", issue.as_str().unwrap_or("?"))?;
                }
            }
            writeln!(output, "  diagnostics: {}", record["diagnostics"])?;
        }
    }
    writeln!(output, "\nsummary:")?;
    for (label, prefix, result) in [
        ("before -> during", "before_during", "detected"),
        ("during -> after", "during_after", "false_positives"),
        ("before -> after", "before_after", "false_positives"),
        ("before -> before", "before_before", "false_positives"),
    ] {
        writeln!(
            output,
            "  {label:18} {}/{} {}",
            summary[format!("{prefix}_{result}")],
            summary[format!("{prefix}_total")],
            result.replace('_', " ")
        )?;
    }
    writeln!(output, "  errors: {}", summary["errors"])?;
    let failed = summary["violations"]
        .as_array()
        .is_some_and(|v| !v.is_empty());
    writeln!(output, "\n  -> {}", if failed { "FAIL" } else { "PASS" })?;
    Ok(())
}

#[cfg(test)]
mod tests;
