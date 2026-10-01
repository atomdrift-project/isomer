//! Current registry evidence, compared independently of artifact bytes.
//! A shared dependency range is queried once and never invents a historical
//! resolution change. Registry failures remain explicit coverage gaps.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::rc::Rc;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::purl::Ecosystem;
use crate::{Severity, analysis::Pair, rubric::severity_from_crit};

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Finding {
    id: String,
    pub description: String,
    severity: Severity,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Observation {
    pub coordinate: String,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
    /// Lossless registry/provider envelope, not just the selected findings.
    document: Option<serde_json::Value>,
}

/// Which side of the comparison something was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Side {
    Before,
    After,
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Before => "before",
            Self::After => "after",
        })
    }
}

/// What a registry row is about. Rows pair across the two sides by subject, so
/// a subject is a value, not a string: replacement pairing and coverage gaps
/// ask *which manifest* a dependency was declared in, and asking that of a
/// formatted key meant parsing it back apart.
///
/// Displayed — and serialized — as the path-like key the report has always
/// shown: `<label>/dependency/<member>/<name>`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Subject {
    /// A package identity the diff itself retained, by diff path.
    DiffPackage { path: String },
    /// A package identity a compared file carries, by archive member.
    Package { label: String, member: String },
    /// A dependency a compared file's manifest declares; `name` is its
    /// versionless purl.
    Dependency {
        label: String,
        member: String,
        name: String,
    },
    /// A compared file whose references could not be discovered.
    Unreadable { label: String, side: Side },
}

impl Subject {
    /// The manifest a dependency was declared in — the scope a replacement is
    /// paired within. `None` for anything that is not a dependency.
    fn manifest(&self) -> Option<(&str, &str)> {
        match self {
            Self::Dependency { label, member, .. } => Some((label, member)),
            _ => None,
        }
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DiffPackage { path } => write!(f, "package/{path}"),
            Self::Package { label, member } => write!(f, "{label}/package/{member}"),
            Self::Dependency {
                label,
                member,
                name,
            } => write!(f, "{label}/dependency/{member}/{name}"),
            Self::Unreadable { label, side } => write!(f, "{label} ({side})"),
        }
    }
}

impl Serialize for Subject {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Comparison {
    pub subject: Subject,
    /// Shared: one coordinate looked up once can stand on several rows, and a
    /// registry document is too large to copy per row.
    pub old: Option<Rc<Observation>>,
    pub new: Option<Rc<Observation>>,
    pub new_severity: Severity,
    pub policy_reason: Option<String>,
}

impl Comparison {
    pub(crate) fn severity(&self) -> Severity {
        self.new
            .as_ref()
            .into_iter()
            .flat_map(|o| &o.findings)
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::None)
            .max(self.new_severity)
    }

    pub(crate) fn apply_release_policy(&mut self, bump: Option<crate::version::Bump>) {
        if bump.is_some_and(|b| b.kind == crate::version::BumpKind::Patch)
            && self.new_severity >= Severity::Medium
            && self.new_severity < Severity::High
            && self.old.as_ref().is_some_and(|o| o.error.is_none())
            && self.new.as_ref().is_some_and(|n| n.error.is_none())
        {
            self.new_severity = Severity::High;
            self.policy_reason =
                Some("patch release introduces new or increased registry risk".to_owned());
        }
    }
}

fn compare(
    subject: Subject,
    old: Option<Rc<Observation>>,
    new: Option<Rc<Observation>>,
) -> Comparison {
    // A failed baseline lookup cannot establish that a current finding is new.
    let baseline_known = old.as_ref().is_none_or(|o| o.error.is_none());
    let mut prior = BTreeMap::new();
    for finding in old.as_ref().into_iter().flat_map(|o| &o.findings) {
        let severity = prior.entry(finding.id.as_str()).or_insert(Severity::None);
        *severity = (*severity).max(finding.severity);
    }
    let new_severity = new
        .as_ref()
        .into_iter()
        .flat_map(|o| &o.findings)
        .filter(|f| {
            baseline_known
                && new.as_ref().is_some_and(|n| n.error.is_none())
                && f.severity > prior.get(f.id.as_str()).copied().unwrap_or(Severity::None)
        })
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::None);
    Comparison {
        subject,
        old,
        new,
        new_severity,
        policy_reason: None,
    }
}

/// Subjects and the coordinate each names, for one side.
type Coordinates = BTreeMap<Subject, String>;

/// Registry-only following: no dependency payload downloads or URL execution.
pub(crate) fn audit(
    pairs: &[Pair],
    diff: &cleave::types::DiffReportV1,
    options: &cleave::AnalysisOptions,
) -> Vec<Comparison> {
    let mut old = Coordinates::new();
    let mut new = Coordinates::new();
    let mut errors = Vec::new();
    // Compared files whose base side could not be read: nothing they declare
    // can be judged new.
    let mut unknown_baselines: BTreeSet<&str> = BTreeSet::new();
    // The diff retains normalized identities even if an archive analysis
    // report omitted its root identity during retention.
    for file in &diff.files {
        if let Some(identity) = &file.identity {
            for (side, output) in [(&identity.old, &mut old), (&identity.new, &mut new)] {
                if let Some(id) = side
                    && let (Some(name), Some(version)) = (&id.name, &id.version)
                    && name.source == "npm.name"
                    && version.source == "npm.version"
                    && let Ok(purl) =
                        crate::purl::package(Ecosystem::Npm, &name.value, Some(&version.value))
                {
                    output.insert(
                        Subject::DiffPackage {
                            path: file.path.clone(),
                        },
                        purl,
                    );
                }
            }
        }
    }
    for pair in pairs {
        for (side, path, output) in [
            (Side::Before, &pair.old, &mut old),
            (Side::After, &pair.new, &mut new),
        ] {
            let Some(path) = path else { continue };
            match cleave::analyze_file(path, options) {
                Ok(report) => collect(&report, &pair.label, output),
                Err(error) => {
                    if side == Side::Before {
                        unknown_baselines.insert(&pair.label);
                    }
                    errors.push(compare(
                        Subject::Unreadable {
                            label: pair.label.clone(),
                            side,
                        },
                        None,
                        Some(Rc::new(Observation {
                            coordinate: path.display().to_string(),
                            findings: vec![],
                            error: Some(format!(
                                "could not discover registry references: {error:#}"
                            )),
                            document: None,
                        })),
                    ));
                }
            }
        }
    }
    errors.extend(audit_with(old, &new, |coordinate| {
        lookup(coordinate, options)
    }));
    for row in &mut errors {
        if row
            .subject
            .manifest()
            .is_some_and(|(label, _)| unknown_baselines.contains(label))
        {
            row.new_severity = Severity::None;
        }
    }
    errors
}

fn audit_with(
    mut old: Coordinates,
    new: &Coordinates,
    mut lookup: impl FnMut(&str) -> Observation,
) -> Vec<Comparison> {
    pair_replacements(&mut old, new);
    let mut cache: BTreeMap<&str, Rc<Observation>> = BTreeMap::new();
    for coordinate in old.values().chain(new.values()) {
        cache
            .entry(coordinate)
            .or_insert_with(|| Rc::new(lookup(coordinate)));
    }
    let observed = |side: &Coordinates, subject: &Subject| {
        side.get(subject)
            .and_then(|c| cache.get(c.as_str()))
            .map(Rc::clone)
    };
    old.keys()
        .chain(new.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|subject| {
            compare(
                subject.clone(),
                observed(&old, subject),
                observed(new, subject),
            )
        })
        .collect()
}

/// Match a single removed/added dependency within the same retained manifest.
/// Coordinates remain on the observations so the inferred pairing is visible.
fn pair_replacements(old: &mut Coordinates, new: &Coordinates) {
    /// One manifest's dependencies present on only one side: removed, added.
    #[derive(Default)]
    struct Unpaired<'a> {
        removed: Vec<&'a Subject>,
        added: Vec<&'a Subject>,
    }
    let mut groups: BTreeMap<(&str, &str), Unpaired<'_>> = BTreeMap::new();
    for subject in old.keys().filter(|key| !new.contains_key(*key)) {
        if let Some(manifest) = subject.manifest() {
            groups.entry(manifest).or_default().removed.push(subject);
        }
    }
    for subject in new.keys().filter(|key| !old.contains_key(*key)) {
        if let Some(manifest) = subject.manifest() {
            groups.entry(manifest).or_default().added.push(subject);
        }
    }
    let moves: Vec<(Subject, Subject)> = groups
        .into_values()
        .filter_map(
            |group| match (group.removed.as_slice(), group.added.as_slice()) {
                ([removed], [added]) => Some(((*removed).clone(), (*added).clone())),
                _ => None,
            },
        )
        .collect();
    for (removed, added) in moves {
        if let Some(coordinate) = old.remove(&removed) {
            old.insert(added, coordinate);
        }
    }
}

fn collect(report: &cleave::AnalysisReport, label: &str, out: &mut Coordinates) {
    for file in &report.files {
        let member = crate::member::MemberPath::new(&file.path)
            .member()
            .unwrap_or_default();
        // Embedded package identities are authoritative over archive filenames.
        if matches!(
            file.file_type.as_str(),
            "npm" | "package.json" | "package_json"
        ) && let Some(identity) = &file.identity
            && let (Some(name), Some(version)) = (&identity.name, &identity.version)
            && !crate::rubric::filename_only_identity(identity)
            && let Ok(purl) =
                crate::purl::package(Ecosystem::Npm, &name.value, Some(&version.value))
        {
            out.insert(
                Subject::Package {
                    label: label.to_owned(),
                    member: member.to_owned(),
                },
                purl,
            );
        }
        if let Some(facts) = &file.filefacts {
            for reference in &facts.references {
                if reference.kind != filefacts::RefKind::Dependency {
                    continue;
                }
                if let filefacts::RefLocator::Purl(purl) = &reference.locator {
                    // Restore npm ranges retained in declaration evidence;
                    // filefacts itself emits versionless locators for them.
                    // A range is not a purl version, so it rides after the `@`
                    // as written, and `lookup` resolves it before querying.
                    let name = purl
                        .rsplit_once('@')
                        .filter(|(name, _)| !name.ends_with('/'))
                        .map_or(purl.as_str(), |(name, _)| name);
                    let mut coordinate = purl.clone();
                    if name == purl
                        && let Some(package) = name.strip_prefix("pkg:npm/")
                        && let Some(spec) = reference
                            .evidence
                            .strip_prefix(&format!("{}@", package.replace("%40", "@")))
                        && !spec.is_empty()
                    {
                        coordinate = format!("{purl}@{spec}");
                    }
                    out.insert(
                        Subject::Dependency {
                            label: label.to_owned(),
                            member: member.to_owned(),
                            name: name.to_owned(),
                        },
                        coordinate,
                    );
                }
            }
        }
    }
}

/// The registry's version catalogue (npm's packument) for a versionless
/// package purl, when the registry returned one.
pub(crate) fn packument(package: &str) -> Option<serde_json::Value> {
    let (_, sources) =
        scan::fetch::registry_with_sources(&filefacts::RefLocator::Purl(package.to_owned()));
    catalogue(&sources)
}

/// The one retained source document that carries a version catalogue.
fn catalogue(sources: &[fletch::fetch::RecordedSource]) -> Option<serde_json::Value> {
    sources
        .iter()
        .filter_map(|s| serde_json::from_slice::<serde_json::Value>(&s.bytes).ok())
        .find(|doc| doc.get("versions").is_some())
}

fn lookup(coordinate: &str, options: &cleave::AnalysisOptions) -> Observation {
    let mut observation = Observation {
        coordinate: coordinate.to_owned(),
        findings: vec![],
        error: None,
        document: None,
    };
    let locator = filefacts::RefLocator::Purl(coordinate.to_owned());
    let (record, sources) = scan::fetch::registry_with_sources(&locator);
    let Some(mut record) = record else {
        observation.error = Some(
            "registry lookup unavailable; status unknown (not evidence of a missing package)"
                .to_owned(),
        );
        return observation;
    };
    // The registry API accepts exact versions, not semver requirements. Resolve
    // ranges against the retained packument, then query the exact result.
    // Never mistake a range string for an unpublished release.
    if coordinate.starts_with("pkg:npm/")
        && let Some((package, spec)) = coordinate.rsplit_once('@')
        && node_semver::Version::parse(spec).is_err()
    {
        let resolved = catalogue(&sources)
            .context("registry did not retain a version catalogue")
            .and_then(|doc| resolve_npm_spec(spec, &doc));
        match resolved {
            Ok(version) => {
                let (resolved, _) = scan::fetch::registry_with_sources(
                    &filefacts::RefLocator::Purl(format!("{package}@{version}")),
                );
                if let Some(resolved) = resolved {
                    record = resolved;
                } else {
                    observation.error = Some("resolved registry lookup unavailable".to_owned());
                }
            }
            Err(error) => observation.error = Some(format!("{error:#}")),
        }
        if observation.error.is_some() {
            observation.document =
                scan::provenance::RegistryProvenance::from_record_sources(record, &sources)
                    .document_value();
            return observation;
        }
    }
    let document = scan::fetch::registry_document(&record);
    observation.document =
        scan::provenance::RegistryProvenance::from_record_sources(record, &sources)
            .document_value();
    let Some((name, bytes)) = document else {
        observation.error = Some("could not serialize registry record".to_owned());
        return observation;
    };
    match cleave::analyze_bytes_owned(bytes, &name, options) {
        Ok(report) => {
            observation.findings = crate::evidence::all_findings(&report)
                .map(|f| Finding {
                    id: f.id.to_string(),
                    description: crate::printable(&f.desc),
                    severity: severity_from_crit(f.crit),
                })
                .filter(|f| f.severity != Severity::None)
                .collect();
        }
        Err(error) => {
            observation.error = Some(format!("could not analyze registry record: {error:#}"))
        }
    }
    observation
}

/// The highest published version satisfying an npm `spec` — a dist-tag or a
/// semver range — in a packument.
pub(crate) fn resolve_npm_spec(spec: &str, doc: &serde_json::Value) -> Result<String> {
    if let Some(version) = doc
        .get("dist-tags")
        .and_then(|tags| tags.get(spec))
        .and_then(serde_json::Value::as_str)
    {
        return Ok(version.to_owned());
    }
    let range = node_semver::Range::parse(spec)
        .map_err(|e| anyhow::anyhow!("unsupported dependency range {spec:?}: {e}"))?;
    doc.get("versions")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(|versions| versions.keys())
        .filter_map(|version| {
            node_semver::Version::parse(version)
                .ok()
                .map(|parsed| (parsed, version))
        })
        .filter(|(version, _)| version.satisfies(&range))
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, version)| version.clone())
        .with_context(|| {
            format!("no published version satisfies {spec:?}; historical resolution unknown")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{Bump, BumpKind};

    fn dependency(member: &str, name: &str) -> Subject {
        Subject::Dependency {
            label: "root".into(),
            member: member.into(),
            name: format!("pkg:npm/{name}"),
        }
    }

    fn observation(coordinate: &str, id: &str, error: Option<&str>) -> Observation {
        Observation {
            coordinate: coordinate.to_owned(),
            findings: if id.is_empty() {
                vec![]
            } else {
                vec![Finding {
                    id: id.to_owned(),
                    description: id.to_owned(),
                    severity: Severity::High,
                }]
            },
            error: error.map(str::to_owned),
            document: None,
        }
    }

    fn patch() -> Bump {
        Bump::new(BumpKind::Patch, 1)
    }

    #[test]
    fn subjects_display_as_the_paths_the_report_has_always_shown() {
        assert_eq!(
            dependency("package.json", "x").to_string(),
            "root/dependency/package.json/pkg:npm/x"
        );
        assert_eq!(
            Subject::Unreadable {
                label: "a.tgz".into(),
                side: Side::Before
            }
            .to_string(),
            "a.tgz (before)"
        );
        assert_eq!(
            serde_json::to_string(&Subject::DiffPackage {
                path: "<root>".into()
            })
            .unwrap(),
            "\"package/<root>\""
        );
    }

    #[test]
    fn replacement_registry_availability_is_compared_only_within_one_manifest() {
        let old = Coordinates::from([(
            dependency("package.json", "old"),
            "pkg:npm/old@1.0.0".into(),
        )]);
        for (manifest, expected) in [
            ("package.json", Severity::High),
            ("nested/package.json", Severity::Medium),
        ] {
            let new =
                Coordinates::from([(dependency(manifest, "new"), "pkg:npm/new@1.0.0".into())]);
            let mut rows = audit_with(old.clone(), &new, |coordinate| {
                let mut value = observation(
                    coordinate,
                    if coordinate.contains("/new@") {
                        "metadata/registry::version-removed"
                    } else {
                        ""
                    },
                    None,
                );
                for finding in &mut value.findings {
                    finding.severity = Severity::Medium;
                }
                value
            });
            for row in &mut rows {
                row.apply_release_policy(Some(patch()));
            }
            let row = rows.iter().find(|row| row.new.is_some()).unwrap();
            assert_eq!(row.new_severity, expected);
            assert_eq!(row.old.is_some(), manifest == "package.json");
        }
        let mut ambiguous = old.clone();
        ambiguous.insert(
            dependency("package.json", "other"),
            "pkg:npm/other@1".into(),
        );
        let new = Coordinates::from([(dependency("package.json", "new"), "pkg:npm/new@1".into())]);
        let original = ambiguous.clone();
        pair_replacements(&mut ambiguous, &new);
        assert_eq!(ambiguous, original);
    }

    /// One row of the patch-policy table, named so a failure says which case.
    struct PolicyCase {
        name: &'static str,
        old: (&'static str, Severity),
        new: (&'static str, Severity),
        failed: Option<Side>,
        kind: BumpKind,
        expected: Severity,
    }

    #[test]
    fn patch_registry_policy_distinguishes_regression_remediation_and_unknown() {
        use Severity::{High, Medium, None as Clean};
        let cases = [
            PolicyCase {
                name: "patch newly removes a version",
                old: ("", Clean),
                new: ("version-removed", Medium),
                failed: None,
                kind: BumpKind::Patch,
                expected: High,
            },
            PolicyCase {
                name: "patch raises an existing finding",
                old: ("risk", Medium),
                new: ("risk", High),
                failed: None,
                kind: BumpKind::Patch,
                expected: High,
            },
            PolicyCase {
                name: "patch raises a finding from nothing",
                old: ("risk", Clean),
                new: ("risk", Medium),
                failed: None,
                kind: BumpKind::Patch,
                expected: High,
            },
            PolicyCase {
                name: "an unchanged finding is not new",
                old: ("risk", Medium),
                new: ("risk", Medium),
                failed: None,
                kind: BumpKind::Patch,
                expected: Clean,
            },
            PolicyCase {
                name: "remediation removes the finding",
                old: ("version-removed", Medium),
                new: ("", Clean),
                failed: None,
                kind: BumpKind::Patch,
                expected: Clean,
            },
            PolicyCase {
                name: "an unreadable baseline proves nothing new",
                old: ("", Clean),
                new: ("version-removed", Medium),
                failed: Some(Side::Before),
                kind: BumpKind::Patch,
                expected: Clean,
            },
            PolicyCase {
                name: "an unreadable current side proves nothing new",
                old: ("", Clean),
                new: ("version-removed", Medium),
                failed: Some(Side::After),
                kind: BumpKind::Patch,
                expected: Clean,
            },
            PolicyCase {
                name: "a minor release is not escalated",
                old: ("", Clean),
                new: ("version-removed", Medium),
                failed: None,
                kind: BumpKind::Minor,
                expected: Medium,
            },
        ];
        for case in cases {
            let side = |(id, severity): (&str, Severity), failed: bool, coordinate: &str| {
                let mut o = observation(coordinate, id, failed.then_some("timeout"));
                for f in &mut o.findings {
                    f.severity = severity;
                }
                Rc::new(o)
            };
            let old = side(case.old, case.failed == Some(Side::Before), "old");
            let new = side(case.new, case.failed == Some(Side::After), "new");
            for subject in [
                Subject::DiffPackage {
                    path: "root".into(),
                },
                dependency("package.json", "example"),
            ] {
                let mut row = compare(subject, Some(Rc::clone(&old)), Some(Rc::clone(&new)));
                row.apply_release_policy(Some(Bump::new(case.kind, 1)));
                assert_eq!(row.new_severity, case.expected, "{}", case.name);
                assert!(row.severity() >= row.new_severity, "{}", case.name);
            }
        }
    }

    #[test]
    fn retained_references_preserve_declared_ranges_including_unchanged_dependencies() {
        let mut report: cleave::AnalysisReport = serde_json::from_value(serde_json::json!({
            "version":"3", "files":[{"id":0,"path":"sample.tgz","depth":0,"file_type":"npm","sha256":"a".repeat(64),"size":100}]
        })).unwrap();
        report.files[0].filefacts = Some(cleave::types::FilefactsView {
            references: vec![filefacts::Reference {
                locator: filefacts::RefLocator::Purl("pkg:npm/%40scope/dep".into()),
                kind: filefacts::RefKind::Dependency,
                source: "package.json".into(),
                evidence: "@scope/dep@^2.0.0".into(),
                offset: 0,
                pinned_hash: None,
                content_sha256: None,
            }],
            ..Default::default()
        });
        let mut collected = Coordinates::new();
        collect(&report, "sample", &mut collected);
        assert_eq!(
            collected.values().collect::<Vec<_>>(),
            [&"pkg:npm/%40scope/dep@^2.0.0".to_owned()]
        );
    }

    #[test]
    fn npm_ranges_do_not_resolve_to_unconstrained_latest_or_removed_versions() {
        let doc = serde_json::json!({"versions":{"2.0.0":{},"2.1.4":{},"3.0.0":{}},
            "dist-tags":{"latest":"3.0.0"}, "time":{"2.1.1":"removed"}});
        assert_eq!(resolve_npm_spec("^2.0.0", &doc).unwrap(), "2.1.4");
        assert_eq!(resolve_npm_spec("~2.0.0", &doc).unwrap(), "2.0.0");
        assert_eq!(resolve_npm_spec("latest", &doc).unwrap(), "3.0.0");
        assert!(resolve_npm_spec("^4", &doc).is_err());
        assert!(resolve_npm_spec("not-a-tag", &doc).is_err());
    }

    #[test]
    fn shared_range_is_looked_up_once_and_is_not_new_risk() {
        let side = Coordinates::from([(
            dependency("package.json", "color-string"),
            "pkg:npm/color-string@^2.0.0".to_owned(),
        )]);
        let mut calls = 0;
        let rows = audit_with(side.clone(), &side, |purl| {
            calls += 1;
            observation(purl, "registry/hostile", None)
        });
        assert_eq!(calls, 1);
        assert_eq!(rows[0].severity(), Severity::High);
        assert_eq!(rows[0].new_severity, Severity::None);
        // Both sides of the row share the one observation rather than copies.
        assert!(Rc::ptr_eq(
            rows[0].old.as_ref().unwrap(),
            rows[0].new.as_ref().unwrap()
        ));
    }

    #[test]
    fn added_or_changed_coordinate_compares_registry_findings() {
        for id in ["registry/hostile", "registry/yanked", "registry/missing"] {
            let old = Rc::new(observation("pkg:npm/example@1.0.0", "", None));
            let new = Rc::new(observation("pkg:npm/example@1.0.1", id, None));
            let package = || Subject::DiffPackage {
                path: "package".into(),
            };
            assert_eq!(
                compare(package(), Some(old), Some(Rc::clone(&new))).new_severity,
                Severity::High
            );
            assert_eq!(
                compare(dependency("package.json", "example"), None, Some(new)).new_severity,
                Severity::High
            );
        }
    }

    #[test]
    fn failed_baseline_is_unknown_not_a_clean_baseline() {
        let result = compare(
            dependency("package.json", "example"),
            Some(Rc::new(observation("old", "", Some("network failure")))),
            Some(Rc::new(observation("new", "registry/hostile", None))),
        );
        assert_eq!(result.new_severity, Severity::None);
        assert_eq!(result.severity(), Severity::High);
        assert!(result.old.as_ref().is_some_and(|o| o.error.is_some()));
    }
}
