//! Dependency behavioral delta for additions, changed versions and replacements.
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
use std::collections::BTreeMap;

/// Per-category maxima preserve risk increases hidden by an unchanged overall
/// maximum. Identity/packaging metadata is not a behavioral category.
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct RiskProfile {
    pub severity: Severity,
    pub categories: BTreeMap<String, Severity>,
}

impl Default for RiskProfile {
    fn default() -> Self {
        Self {
            severity: Severity::None,
            categories: BTreeMap::new(),
        }
    }
}

pub(crate) fn compare_profiles(old: &RiskProfile, new: &RiskProfile) -> Severity {
    if new.severity > old.severity
        || new.categories.iter().any(|(category, severity)| {
            old.categories
                .get(category)
                .is_none_or(|prior| severity > prior)
        })
    {
        Severity::High.max(new.severity)
    } else if new.severity < old.severity || new.categories != old.categories {
        Severity::Low
    } else {
        Severity::Medium
    }
}

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
    pub baseline: Option<String>,
    pub new_severity: Severity,
    pub comparison: String,
    pub risk: RiskProfile,
    pub baseline_risk: Option<RiskProfile>,
}

pub(crate) fn severity(profiles: &[DepProfile]) -> Severity {
    profiles
        .iter()
        .map(|profile| profile.severity.max(profile.new_severity))
        .max()
        .unwrap_or(Severity::None)
}

pub(crate) fn new_severity(profiles: &[DepProfile]) -> Severity {
    profiles
        .iter()
        .map(|p| p.new_severity)
        .max()
        .unwrap_or(Severity::None)
}

/// Fetch and profile every runtime dependency the change added. Empty when the
/// change added none. `progress` shows the fetch spinner for a human at a
/// terminal.
pub(crate) fn profiles(
    diff: &DiffReportV1,
    options: &AnalysisOptions,
    progress: bool,
) -> Vec<DepProfile> {
    profiles_with(diff, |dep| profile(dep, options, progress))
}

fn profiles_with(
    diff: &DiffReportV1,
    mut fetch: impl FnMut(&Added) -> DepProfile,
) -> Vec<DepProfile> {
    changes(diff)
        .iter()
        .map(|(old, dep)| {
            let mut new = fetch(dep);
            if let Some(old) = old {
                let old = fetch(old);
                new.baseline = Some(old.coord);
                if old.note.is_none() && new.note.is_none() {
                    new.new_severity = compare_profiles(&old.risk, &new.risk);
                    new.baseline_risk = Some(old.risk);
                    new.comparison = match new.new_severity {
                        Severity::Low => "reduced dependency capability/risk profile",
                        Severity::Medium => "equivalent dependency capability/risk profile",
                        _ => "increased dependency risk or new behavioral category",
                    }
                    .to_owned();
                } else {
                    new.new_severity = Severity::None;
                    new.comparison = "unknown dependency profile comparison".to_owned();
                    if let Some(error) = old.note {
                        new.note = Some(format!(
                            "baseline: {error}; current: {}",
                            new.note.as_deref().unwrap_or("analyzed")
                        ));
                    }
                }
            }
            new
        })
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
    // Exact pins identify one immutable release. A range (`^0.1.0`) does not:
    // fetching its floor would miss the later compatible release an installer
    // actually resolves — precisely the event-stream/flatmap-stream failure
    // mode. Resolve within the declared range, never to unconstrained latest;
    // lockfiles, when present, contribute exact pins.
    let mut out = DepProfile {
        coord,
        ecosystem: dep.ecosystem,
        severity: Severity::None,
        highlights: Vec::new(),
        note: None,
        baseline: None,
        new_severity: Severity::None,
        comparison: "unknown: no unambiguous predecessor".to_owned(),
        risk: RiskProfile::default(),
        baseline_risk: None,
    };
    let purl = match resolved_coordinate(dep) {
        Ok(purl) => purl,
        Err(error) => {
            out.note = Some(error);
            return out;
        }
    };
    let bytes = match crate::fetch::fetch_bytes(&purl, progress) {
        Ok((bytes, _name)) => bytes,
        Err(e) => {
            out.note = Some(format!("could not fetch: {e:#}"));
            return out;
        }
    };
    match cleave::analyze_bytes_owned(bytes, &purl, options) {
        Ok(report) => {
            (out.severity, out.highlights) = summarize(&report);
            out.risk.severity = out.severity;
            for finding in crate::evidence::all_findings(&report) {
                if finding.id.starts_with("metadata/") {
                    continue;
                }
                if let Some(category) = crate::rubric::capability_class(&finding.id) {
                    let severity = severity_from_crit(finding.crit);
                    if severity == Severity::None {
                        continue;
                    }
                    let prior = out
                        .risk
                        .categories
                        .entry(category)
                        .or_insert(Severity::None);
                    *prior = (*prior).max(severity);
                }
            }
            // Unpaired additions retain independently observed risk, but are
            // never described as equivalent to a nonexistent baseline.
            out.new_severity = out.severity;
        }
        Err(e) => out.note = Some(format!("could not analyze: {e:#}")),
    }
    out
}

fn resolved_coordinate(dep: &Added) -> Result<String, String> {
    let package = format!("pkg:{}/{}", dep.ecosystem, dep.name.replace('@', "%40"));
    if let Some(version) = exact_version(&dep.spec) {
        return Ok(format!("{package}@{version}"));
    }
    if dep.ecosystem != "npm" {
        return Err("dependency range resolution unavailable; profile unknown".into());
    }
    let (_, sources) =
        scan::fetch::registry_with_sources(&filefacts::RefLocator::Purl(package.clone()));
    let packument = sources
        .iter()
        .filter_map(|s| serde_json::from_slice::<serde_json::Value>(&s.bytes).ok())
        .find(|doc| doc.get("versions").is_some())
        .ok_or_else(|| "registry version catalogue unavailable; profile unknown".to_owned())?;
    let version = crate::registry::resolve_npm_spec(&dep.spec, &packument)?;
    Ok(format!("{package}@{version}"))
}

/// A fetched dependency's analysis, read down to what the profile shows: its
/// worst severity and the strongest distinct findings — the capabilities the
/// dependency introduces.
fn summarize(report: &cleave::AnalysisReport) -> (Severity, Vec<String>) {
    let mut findings: Vec<(Severity, String)> = crate::evidence::all_findings(report)
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
    let worst = findings.first().map_or(Severity::None, |(s, _)| *s);
    let highlights = findings
        .into_iter()
        .take(MAX_HIGHLIGHTS)
        .map(|(_, d)| d)
        .collect();
    (worst, highlights)
}

/// An exact manifest version, or `None` for every range/tag/URL. Treating the
/// floor of a range as the resolved dependency is unsound for security review:
/// an attacker commonly publishes a later version that still satisfies it.
fn exact_version(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec.is_empty()
        || spec.starts_with(['^', '~', '<', '>'])
        || spec.contains(|c: char| c.is_whitespace() || matches!(c, '|' | ',' | '*'))
        || spec.to_ascii_lowercase().contains('x')
        || spec.contains("://")
    {
        return None;
    }
    let token = spec
        .strip_prefix('=')
        .unwrap_or(spec)
        .trim_start_matches('v');
    let exact = token.chars().next().is_some_and(|c| c.is_ascii_digit())
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'));
    exact.then(|| token.to_string())
}

/// The runtime dependencies a diff added, read from every changed manifest's kv
/// scope. Uses the same runtime dependency roots as the risk rubric:
/// `dependencies`, `optionalDependencies`, and `peerDependencies`. Deeper paths
/// are sub-fields of a version spec; dev/build trees do not ship to end users.
fn changes(diff: &DiffReportV1) -> Vec<(Option<Added>, Added)> {
    let mut out = Vec::new();
    for file in &diff.files {
        let Some(ecosystem) = ecosystem(&file.path) else {
            continue;
        };
        let Some(kv) = file.scopes.kv.as_ref() else {
            continue;
        };
        let declaration = |path: &str, value: &serde_json::Value| {
            let name = crate::rubric::dependency_name(path)?;
            let spec = value.as_str()?;
            Some(Added {
                ecosystem,
                name: name.to_string(),
                spec: spec.to_string(),
            })
        };
        let mut removed: Vec<_> = kv
            .removed
            .iter()
            .filter_map(|e| declaration(&e.path, &e.value))
            .collect();
        let added: Vec<_> = kv
            .added
            .iter()
            .filter_map(|e| declaration(&e.path, &e.value))
            .collect();
        // Only a single removal plus single addition in the same manifest is
        // treated as a replacement. Never pair by order across unrelated files.
        let replacement = removed.len() == 1 && added.len() == 1;
        for dep in added {
            out.push((if replacement { removed.pop() } else { None }, dep));
        }
        for entry in &kv.changed {
            if entry.old.path == entry.new.path
                && let (Some(old), Some(new)) = (
                    declaration(&entry.old.path, &entry.old.value),
                    declaration(&entry.new.path, &entry.new.value),
                )
            {
                out.push((Some(old), new));
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;
    use cleave::types::{
        DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, KvChange, ScopeDiff, ScopeDiffs,
    };

    fn risk(severity: Severity, categories: &[(&str, Severity)]) -> RiskProfile {
        RiskProfile {
            severity,
            categories: categories
                .iter()
                .map(|(c, s)| (c.to_string(), *s))
                .collect(),
        }
    }

    #[test]
    fn profiles_compare_categories_and_per_category_risk_not_just_the_maximum() {
        use Severity::{Critical, High, Low, Medium};
        let old = risk(
            High,
            &[("data/read", Medium), ("communications/http", High)],
        );
        for (new, expected) in [
            (old.clone(), Medium),
            (risk(High, &[("communications/http", High)]), Low),
            (
                risk(
                    Medium,
                    &[("data/read", Medium), ("communications/http", Medium)],
                ),
                Low,
            ),
            (
                risk(High, &[("data/read", High), ("communications/http", High)]),
                High,
            ),
            (risk(High, &[("process/create", Medium)]), High),
            (risk(Critical, &[("data/read", Medium)]), Critical),
            (risk(Low, &[("new/category", Low)]), High),
        ] {
            assert_eq!(compare_profiles(&old, &new), expected);
        }
        assert_eq!(
            compare_profiles(&RiskProfile::default(), &RiskProfile::default()),
            Medium
        );
    }

    fn diff(kv: serde_json::Value) -> cleave::types::DiffReportV1 {
        let mut value = serde_json::json!({
            "old_root":"before", "new_root":"after", "summary":cleave::types::DiffSummary::default(),
            "scopes": {},
            "files":[{"path":"package/package.json", "status":"changed", "scopes":{}}]
        });
        value["files"][0]["scopes"]["kv"] = kv;
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn dependency_pairing_requires_changed_declaration_or_single_replacement() {
        let entry = |name: &str, version: &str| serde_json::json!({"path":format!("dependencies.{name}"), "value":version});
        let changed = diff(
            serde_json::json!({"changed":[{"old":entry("dep", "1.0.0"), "new":entry("dep", "1.0.1")}]}),
        );
        let pairs = changes(&changed);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0.as_ref().unwrap().spec, "1.0.0");
        assert_eq!(pairs[0].1.spec, "1.0.1");
        let replaced = diff(
            serde_json::json!({"removed":[entry("old", "1.0.0")], "added":[entry("new", "2.0.0")]}),
        );
        assert_eq!(changes(&replaced)[0].0.as_ref().unwrap().name, "old");
        let ambiguous = diff(
            serde_json::json!({"removed":[entry("old", "1.0.0"),entry("other", "1.0.0")], "added":[entry("new", "2.0.0")]}),
        );
        assert!(changes(&ambiguous)[0].0.is_none());
        let dev_only =
            diff(serde_json::json!({"added":[{"path":"devDependencies.test", "value":"1.0.0"}]}));
        assert!(changes(&dev_only).is_empty());
    }

    #[test]
    fn mock_fetch_comparison_keeps_failures_unknown_and_equivalence_below_high() {
        let diff = diff(serde_json::json!({"changed":[{
            "old":{"path":"dependencies.dep", "value":"1.0.0"},
            "new":{"path":"dependencies.dep", "value":"1.0.1"}
        }]}));
        for failing_spec in [None, Some("1.0.0"), Some("1.0.1")] {
            let rows = profiles_with(&diff, |dep| DepProfile {
                coord: format!("{}@{}", dep.name, dep.spec),
                ecosystem: "npm",
                severity: Severity::High,
                highlights: vec![],
                note: (failing_spec == Some(dep.spec.as_str())).then(|| "timeout".into()),
                baseline: None,
                new_severity: Severity::High,
                comparison: String::new(),
                risk: risk(Severity::High, &[("data/read", Severity::High)]),
                baseline_risk: None,
            });
            assert_eq!(rows[0].baseline.as_deref(), Some("dep@1.0.0"));
            assert_eq!(
                new_severity(&rows),
                if failing_spec.is_none() {
                    Severity::Medium
                } else {
                    Severity::None
                }
            );
            assert_eq!(rows[0].note.is_some(), failing_spec.is_some());
        }
    }

    #[test]
    fn dependency_fetch_only_pins_exact_versions() {
        assert_eq!(exact_version("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(
            exact_version("=v1.2.3-beta.1").as_deref(),
            Some("1.2.3-beta.1")
        );
        for range in ["^0.1.0", "~1.2.3", ">=1.2.3 <2", "1.x", "*", "latest"] {
            assert_eq!(exact_version(range), None, "{range} is not an exact pin");
        }
    }

    #[test]
    fn dependency_profiles_include_every_runtime_platform_tree() {
        let changes = [
            ("dependencies.core", "1.0.0"),
            ("optionalDependencies.tool-linux-x64", "1.0.0"),
            ("optionalDependencies.tool-darwin-arm64", "1.0.0"),
            ("peerDependencies.adapter", "^2.0.0"),
            ("devDependencies.test-only", "1.0.0"),
            ("dependencies.core.version", "1.0.0"),
        ]
        .into_iter()
        .map(|(path, version)| KvChange {
            path: path.to_string(),
            namespace: path.split('.').next().unwrap_or_default().to_string(),
            value: serde_json::Value::String(version.to_string()),
        })
        .collect();
        let diff = DiffReportV1 {
            old_root: "old".to_string(),
            new_root: "new".to_string(),
            summary: DiffSummary::default(),
            scopes: ScopeDiffs::default(),
            files: vec![FileDiffEntry {
                path: "package.json".to_string(),
                file_type: Some("package.json".to_string()),
                status: FileStatus::Changed,
                identity: None,
                scopes: ScopeDiffs {
                    kv: Some(ScopeDiff {
                        added: changes,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                old_formula: None,
                new_formula: None,
            }],
        };

        let dependencies = added(&diff);
        let names: Vec<&str> = dependencies.iter().map(|dep| dep.name.as_str()).collect();
        assert_eq!(
            names,
            ["core", "tool-linux-x64", "tool-darwin-arm64", "adapter"]
        );
    }

    #[test]
    fn added_dependency_profiles_contribute_their_worst_severity() {
        let profile = |severity| DepProfile {
            coord: "dep@1".to_string(),
            ecosystem: "npm",
            severity,
            highlights: Vec::new(),
            note: None,
            baseline: None,
            new_severity: severity,
            comparison: "unknown: no unambiguous predecessor".into(),
            risk: super::RiskProfile {
                severity,
                categories: BTreeMap::new(),
            },
            baseline_risk: None,
        };
        assert_eq!(
            severity(&[profile(Severity::Medium), profile(Severity::Critical)]),
            Severity::Critical
        );
        assert_eq!(severity(&[]), Severity::None);
        let mut expanded = profile(Severity::Medium);
        expanded.new_severity = Severity::High;
        assert_eq!(severity(&[expanded]), Severity::High);
    }
}
