//! Dependency behavioral delta — what the dependencies a change *added* can do.
//!
//! "Added dependency: peacenotwar" is a tripwire, not an answer: the risk is
//! what peacenotwar *does*, and its code isn't in the package that declared it.
//! So for each runtime dependency a change adds, fetch it and analyze it, and
//! report the capability — the file-overwrite, the network egress — attributed
//! to the dependency that introduced it. This is the transitive supply-chain
//! case (event-stream → flatmap-stream) a manifest diff alone is blind to.
//!
//! A network step, gated behind `--deps`. Fetch and analysis failures are
//! reported per dependency, never swallowed — a gap in coverage must not read
//! as a clean dependency.

use cleave::AnalysisOptions;
use cleave::types::DiffReportV1;

use crate::Severity;
use crate::rubric::severity_from_crit;

/// How many findings a dependency's profile names, worst-first.
const MAX_HIGHLIGHTS: usize = 4;

/// One added dependency, fetched and profiled for what it can do.
#[derive(Debug)]
pub(crate) struct DepProfile {
    /// The declared coordinate, `peacenotwar@^9.1.3`.
    pub coord: String,
    /// The package ecosystem, `npm` / `pypi` / …, for the section's context.
    pub ecosystem: &'static str,
    /// Worst severity found in the fetched dependency.
    pub severity: Severity,
    /// Strongest finding descriptions, worst-first — what the dependency does.
    pub highlights: Vec<String>,
    /// Set when the dependency could not be fetched or analyzed, so a gap in
    /// coverage is reported rather than mistaken for a clean dependency.
    pub note: Option<String>,
}

/// Fetch and profile every runtime dependency the change added. Empty when the
/// change added none. `progress` shows the fetch spinner for a human at a
/// terminal.
pub(crate) fn profiles(
    diff: &DiffReportV1,
    options: &AnalysisOptions,
    progress: bool,
) -> Vec<DepProfile> {
    added(diff)
        .iter()
        .map(|dep| profile(dep, options, progress))
        .collect()
}

/// A runtime dependency a change declared: its ecosystem, name, and the version
/// spec as written in the manifest.
struct Added {
    ecosystem: &'static str,
    name: String,
    spec: String,
}

/// Fetch one added dependency and summarize what it does.
fn profile(dep: &Added, options: &AnalysisOptions, progress: bool) -> DepProfile {
    let coord = format!("{}@{}", dep.name, dep.spec);
    // A manifest declares a *range* (`^9.1.3`); the registry serves exact
    // versions. Without a lockfile the faithful offline choice is the range's
    // base version — the minimum it allows, always published and the release
    // the author pinned against. A range with no concrete floor (`*`, a tag, a
    // git url) falls back to the latest release.
    let purl = match concrete_version(&dep.spec) {
        Some(v) => format!("pkg:{}/{}@{}", dep.ecosystem, dep.name, v),
        None => format!("pkg:{}/{}", dep.ecosystem, dep.name),
    };
    let mut out = DepProfile {
        coord,
        ecosystem: dep.ecosystem,
        severity: Severity::None,
        highlights: Vec::new(),
        note: None,
    };
    let bytes = match crate::fetch::fetch_bytes(&purl, progress) {
        Ok((bytes, _name)) => bytes,
        Err(e) => {
            out.note = Some(format!("could not fetch: {e:#}"));
            return out;
        }
    };
    match cleave::analyze_bytes_owned(bytes, &purl, options) {
        Ok(report) => summarize(&mut out, &report),
        Err(e) => out.note = Some(format!("could not analyze: {e:#}")),
    }
    out
}

/// Fill `out` from a fetched dependency's analysis: its worst severity and the
/// strongest distinct findings — the capabilities the dependency introduces.
fn summarize(out: &mut DepProfile, report: &cleave::AnalysisReport) {
    let mut findings: Vec<(Severity, String)> = report
        .findings
        .iter()
        .chain(report.files.iter().flat_map(|f| &f.findings))
        .filter_map(|f| {
            let sev = severity_from_crit(f.crit);
            (sev != Severity::None && !f.desc.is_empty())
                .then(|| (sev, crate::printable(f.desc.as_str())))
        })
        .collect();
    // Worst first; one line per distinct description so the profile shows
    // variety, not the same rule repeated.
    findings.sort_by_key(|(sev, _)| std::cmp::Reverse(*sev));
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    findings.retain(|(_, d)| seen.insert(d.clone()));
    out.severity = findings.first().map_or(Severity::None, |(s, _)| *s);
    out.highlights = findings
        .into_iter()
        .take(MAX_HIGHLIGHTS)
        .map(|(_, d)| d)
        .collect();
}

/// The concrete version at the base of a manifest version spec — `^9.1.3` →
/// `9.1.3`, `>=1.2.3 <2` → `1.2.3` — or `None` when the spec names no numeric
/// floor (`*`, `latest`, `1.x`, a dist-tag, a git url), leaving the fetch to
/// take the latest release. Only digit-led dotted tokens (with prerelease /
/// build suffixes) count, so a wildcard or tag never resolves to a bad URL.
fn concrete_version(spec: &str) -> Option<String> {
    let stripped = spec
        .trim()
        .trim_start_matches(['^', '~', '=', 'v', '>', '<', ' ']);
    let token = stripped
        .split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '|' | ','))
        .next()
        .unwrap_or("");
    let concrete = token.chars().next().is_some_and(|c| c.is_ascii_digit())
        && token
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '+'));
    concrete.then(|| token.to_string())
}

/// The runtime dependencies a diff added, read from every changed manifest's kv
/// scope. Only `dependencies.<name>` direct children — a deeper path is a
/// sub-field of the version spec, and dev/build trees don't ship to end users.
fn added(diff: &DiffReportV1) -> Vec<Added> {
    let mut out = Vec::new();
    for file in &diff.files {
        let Some(ecosystem) = ecosystem(&file.path) else {
            continue;
        };
        let Some(kv) = file.scopes.kv.as_ref() else {
            continue;
        };
        for entry in &kv.added {
            let Some(rest) = entry.path.strip_prefix("dependencies.") else {
                continue;
            };
            if rest.is_empty() || rest.contains('.') {
                continue;
            }
            let Some(spec) = entry.value.as_str() else {
                continue;
            };
            out.push(Added {
                ecosystem,
                name: rest.to_string(),
                spec: spec.to_string(),
            });
        }
    }
    out
}

/// The PURL ecosystem for a manifest, keyed on its filename (the diff carries
/// the member path, e.g. `<root>!!package/package.json`). `None` when the file
/// declares no fetchable runtime dependencies, so no purl can be built.
fn ecosystem(path: &str) -> Option<&'static str> {
    let base = path.rsplit(['/', '!']).next().unwrap_or(path);
    match base {
        "package.json" | "package-lock.json" => Some("npm"),
        "pyproject.toml" | "requirements.txt" | "poetry.lock" | "Pipfile.lock" => Some("pypi"),
        "Cargo.toml" | "Cargo.lock" => Some("cargo"),
        "Gemfile.lock" => Some("gem"),
        "composer.json" | "composer.lock" => Some("composer"),
        _ => None,
    }
}
