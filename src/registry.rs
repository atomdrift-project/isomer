//! Current registry evidence, compared independently of artifact bytes.
//! A shared dependency range is queried once and never invents a historical
//! resolution change. Registry failures remain explicit coverage gaps.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{Severity, analysis::Pair, rubric::severity_from_crit};

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Finding {
    id: String,
    pub(crate) description: String,
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

#[derive(Debug, Serialize)]
pub(crate) struct Comparison {
    pub subject: String,
    pub old: Option<Observation>,
    pub new: Option<Observation>,
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

/// Whether current registry metadata is consulted at all. `--offline`
/// forbids the network outright; `--no-follow` keeps it for the artifact
/// fetch but skips the metadata checks.
#[must_use]
pub fn enabled(opts: &crate::options::Options) -> bool {
    !opts.offline && !opts.no_follow
}

fn compare(subject: String, old: Option<Observation>, new: Option<Observation>) -> Comparison {
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

/// Registry-only following: no dependency payload downloads or URL execution.
pub(crate) fn audit(
    pairs: &[Pair],
    diff: &cleave::types::DiffReportV1,
    options: &cleave::AnalysisOptions,
) -> Vec<Comparison> {
    let mut old = BTreeMap::new();
    let mut new = BTreeMap::new();
    let mut errors = Vec::new();
    let mut unknown_baselines = Vec::new();
    // The diff retains normalized identities even if an archive analysis
    // report omitted its root identity during retention.
    for file in &diff.files {
        if let Some(identity) = &file.identity {
            for (side, output) in [(&identity.old, &mut old), (&identity.new, &mut new)] {
                if let Some(id) = side
                    && let (Some(name), Some(version)) = (&id.name, &id.version)
                    && name.source == "npm.name"
                    && version.source == "npm.version"
                {
                    output.insert(
                        format!("package/{}", file.path),
                        format!(
                            "pkg:npm/{}@{}",
                            name.value.replace('@', "%40"),
                            version.value
                        ),
                    );
                }
            }
        }
    }
    for pair in pairs {
        for (side, path, output) in [
            ("before", &pair.old, &mut old),
            ("after", &pair.new, &mut new),
        ] {
            let Some(path) = path else { continue };
            match cleave::analyze_file(path, options) {
                Ok(report) => collect(&report, &pair.label, output),
                Err(error) => {
                    if side == "before" {
                        unknown_baselines.push(format!("{}/dependency/", pair.label));
                    }
                    errors.push(compare(
                        format!("{} ({side})", pair.label),
                        None,
                        Some(Observation {
                            coordinate: path.display().to_string(),
                            findings: vec![],
                            error: Some(format!(
                                "could not discover registry references: {error:#}"
                            )),
                            document: None,
                        }),
                    ));
                }
            }
        }
    }
    errors.extend(audit_with(&old, &new, |coordinate| {
        lookup(coordinate, options)
    }));
    for row in &mut errors {
        if unknown_baselines
            .iter()
            .any(|prefix| row.subject.starts_with(prefix))
        {
            row.new_severity = Severity::None;
        }
    }
    errors
}

fn audit_with(
    old: &BTreeMap<String, String>,
    new: &BTreeMap<String, String>,
    mut lookup: impl FnMut(&str) -> Observation,
) -> Vec<Comparison> {
    let mut old = old.clone();
    pair_replacements(&mut old, new);
    let mut cache = BTreeMap::new();
    for coordinate in old.values().chain(new.values()) {
        cache
            .entry(coordinate.clone())
            .or_insert_with(|| lookup(coordinate));
    }
    old.keys()
        .chain(new.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|subject| {
            compare(
                subject.clone(),
                old.get(subject).and_then(|c| cache.get(c)).cloned(),
                new.get(subject).and_then(|c| cache.get(c)).cloned(),
            )
        })
        .collect()
}

/// Match a single removed/added dependency within the same retained manifest.
/// Coordinates remain on the observations so the inferred pairing is visible.
fn pair_replacements(old: &mut BTreeMap<String, String>, new: &BTreeMap<String, String>) {
    let mut groups: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    for (side, map, other) in [(0, &*old, new), (1, new, &*old)] {
        for subject in map.keys().filter(|key| !other.contains_key(*key)) {
            if subject.contains("/dependency/")
                && let Some((manifest, _)) = subject.rsplit_once("/pkg:")
            {
                let group = groups.entry(manifest.to_owned()).or_default();
                if side == 0 {
                    group.0.push(subject.clone());
                } else {
                    group.1.push(subject.clone());
                }
            }
        }
    }
    for (removed, added) in groups.values() {
        if removed.len() == 1
            && added.len() == 1
            && let Some(coordinate) = old.remove(&removed[0])
        {
            old.insert(added[0].clone(), coordinate);
        }
    }
}

fn collect(report: &cleave::AnalysisReport, label: &str, out: &mut BTreeMap<String, String>) {
    for file in &report.files {
        let member = file.path.split_once("!!").map_or("", |(_, member)| member);
        // Embedded package identities are authoritative over archive filenames.
        if matches!(
            file.file_type.as_str(),
            "npm" | "package.json" | "package_json"
        ) && let Some(identity) = &file.identity
            && let (Some(name), Some(version)) = (&identity.name, &identity.version)
            && !crate::rubric::filename_only_identity(identity)
        {
            out.insert(
                format!("{label}/package/{member}"),
                format!("pkg:npm/{}@{}", name.value, version.value),
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
                    out.insert(format!("{label}/dependency/{member}/{name}"), coordinate);
                }
            }
        }
    }
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
        let packument = sources
            .iter()
            .filter_map(|s| serde_json::from_slice::<serde_json::Value>(&s.bytes).ok())
            .find(|doc| doc.get("versions").is_some());
        let resolved = packument
            .as_ref()
            .ok_or_else(|| "registry did not retain a version catalogue".to_owned())
            .and_then(|doc| resolve_npm_spec(spec, doc));
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
            Err(error) => observation.error = Some(error),
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

pub(crate) fn resolve_npm_spec(spec: &str, doc: &serde_json::Value) -> Result<String, String> {
    if let Some(version) = doc
        .get("dist-tags")
        .and_then(|tags| tags.get(spec))
        .and_then(serde_json::Value::as_str)
    {
        return Ok(version.to_owned());
    }
    let range = node_semver::Range::parse(spec)
        .map_err(|e| format!("unsupported dependency range {spec:?}: {e}"))?;
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
        .ok_or_else(|| {
            format!("no published version satisfies {spec:?}; historical resolution unknown")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_registry_availability_is_compared_only_within_one_manifest() {
        use crate::version::{Bump, BumpKind};
        let old = BTreeMap::from([(
            "root/dependency/package.json/pkg:npm/old".into(),
            "pkg:npm/old@1.0.0".into(),
        )]);
        for (manifest, expected) in [
            ("package.json", Severity::High),
            ("nested/package.json", Severity::Medium),
        ] {
            let new = BTreeMap::from([(
                format!("root/dependency/{manifest}/pkg:npm/new"),
                "pkg:npm/new@1.0.0".into(),
            )]);
            let mut rows = audit_with(&old, &new, |coordinate| {
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
                row.apply_release_policy(Some(Bump {
                    kind: BumpKind::Patch,
                    steps: 1,
                }));
            }
            let row = rows.iter().find(|row| row.new.is_some()).unwrap();
            assert_eq!(row.new_severity, expected);
            assert_eq!(row.old.is_some(), manifest == "package.json");
        }
        let mut ambiguous = old.clone();
        ambiguous.insert(
            "root/dependency/package.json/pkg:npm/other".into(),
            "pkg:npm/other@1".into(),
        );
        let new = BTreeMap::from([(
            "root/dependency/package.json/pkg:npm/new".into(),
            "pkg:npm/new@1".into(),
        )]);
        let original = ambiguous.clone();
        pair_replacements(&mut ambiguous, &new);
        assert_eq!(ambiguous, original);
    }

    #[test]
    fn patch_registry_policy_distinguishes_regression_remediation_and_unknown() {
        use crate::version::{Bump, BumpKind};
        for (old_id, old_severity, new_id, new_severity, error_side, kind, expected) in [
            (
                "",
                Severity::None,
                "version-removed",
                Severity::Medium,
                "",
                BumpKind::Patch,
                Severity::High,
            ),
            (
                "risk",
                Severity::Medium,
                "risk",
                Severity::High,
                "",
                BumpKind::Patch,
                Severity::High,
            ),
            (
                "risk",
                Severity::None,
                "risk",
                Severity::Medium,
                "",
                BumpKind::Patch,
                Severity::High,
            ),
            (
                "risk",
                Severity::Medium,
                "risk",
                Severity::Medium,
                "",
                BumpKind::Patch,
                Severity::None,
            ),
            (
                "version-removed",
                Severity::Medium,
                "",
                Severity::None,
                "",
                BumpKind::Patch,
                Severity::None,
            ),
            (
                "",
                Severity::None,
                "version-removed",
                Severity::Medium,
                "old",
                BumpKind::Patch,
                Severity::None,
            ),
            (
                "",
                Severity::None,
                "version-removed",
                Severity::Medium,
                "new",
                BumpKind::Patch,
                Severity::None,
            ),
            (
                "",
                Severity::None,
                "version-removed",
                Severity::Medium,
                "",
                BumpKind::Minor,
                Severity::Medium,
            ),
        ] {
            let mut old = observation("old", old_id, (error_side == "old").then_some("timeout"));
            let mut new = observation("new", new_id, (error_side == "new").then_some("timeout"));
            for f in &mut old.findings {
                f.severity = old_severity;
            }
            for f in &mut new.findings {
                f.severity = new_severity;
            }
            for subject in ["package/root", "root/dependency/example"] {
                let mut row = compare(subject.into(), Some(old.clone()), Some(new.clone()));
                row.apply_release_policy(Some(Bump { kind, steps: 1 }));
                assert_eq!(
                    row.new_severity, expected,
                    "{subject}: {old_id} -> {new_id}, {error_side}, {kind:?}"
                );
                assert!(row.severity() >= row.new_severity);
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
        let mut collected = BTreeMap::new();
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

    #[test]
    fn shared_range_is_looked_up_once_and_is_not_new_risk() {
        let side = BTreeMap::from([(
            "dependency".to_owned(),
            "pkg:npm/color-string@^2.0.0".to_owned(),
        )]);
        let mut calls = 0;
        let rows = audit_with(&side, &side, |purl| {
            calls += 1;
            observation(purl, "registry/hostile", None)
        });
        assert_eq!(calls, 1);
        assert_eq!(rows[0].severity(), Severity::High);
        assert_eq!(rows[0].new_severity, Severity::None);
    }

    #[test]
    fn added_or_changed_coordinate_compares_registry_findings() {
        for id in ["registry/hostile", "registry/yanked", "registry/missing"] {
            let old = observation("pkg:npm/example@1.0.0", "", None);
            let new = observation("pkg:npm/example@1.0.1", id, None);
            assert_eq!(
                compare("package".into(), Some(old), Some(new.clone())).new_severity,
                Severity::High
            );
            assert_eq!(
                compare("dependency".into(), None, Some(new)).new_severity,
                Severity::High
            );
        }
    }

    #[test]
    fn failed_baseline_is_unknown_not_a_clean_baseline() {
        let result = compare(
            "dependency".into(),
            Some(observation("old", "", Some("network failure"))),
            Some(observation("new", "registry/hostile", None)),
        );
        assert_eq!(result.new_severity, Severity::None);
        assert_eq!(result.severity(), Severity::High);
        assert!(result.old.as_ref().is_some_and(|o| o.error.is_some()));
    }
}
