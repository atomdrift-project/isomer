//! Binary lineage and execution-layout comparisons alongside trait analysis.
//!
//! Identity is corroboration, never a prerequisite. All findings describe a
//! transition, not a property that merely exists in the replacement. Format
//! adapters normalize ELF, PE and Mach-O. This detector needs no trait matches internally, but
//! its findings always join the regular structural/trait assessment.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};

use crate::Severity;
use crate::rubric::{Assessment, FactKind, StructFact};

mod adapters;
#[cfg(test)]
use adapters::inspect;
use adapters::{inspect_all, native_magic};

/// One structural observation about the image pair. `facts` are the
/// `(name, value)` rows behind the label, in reading order; the first is the
/// headline.
#[derive(Debug, Clone)]
struct Finding {
    severity: Severity,
    label: &'static str,
    facts: Vec<(&'static str, String)>,
    caveat: Option<&'static str>,
}

const BUILD_ID_WITH_CODE_CHANGE: &str = "build ID unchanged despite code change";
const BUILD_ID_CAVEAT: &str = "a build ID is no integrity guarantee";

#[derive(Debug)]
struct Comparison {
    /// The image ABI both sides share, e.g. `elf/x86_64/elf64/little/dynamic`.
    abi: String,
    bytes_changed: bool,
    compatible_abi: bool,
    /// None means one/both extractors could not recover an ID, not a mismatch.
    retained_build_id: Option<bool>,
    original_executable_bytes: u64,
    retained_executable_bytes: u64,
    slice_traits_available: bool,
    findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
struct Region {
    kind: String,
    offset: u64,
    size: u64,
    address: u64,
    memory_size: u64,
    executable: bool,
    writable: bool,
}

impl Region {
    fn contains(&self, address: u64) -> bool {
        // Only file-backed instructions qualify; an entry in zero-fill does
        // not prove execution of an appended payload.
        address
            .checked_sub(self.address)
            .is_some_and(|d| d < self.size)
    }

    fn bytes<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let start = usize::try_from(self.offset).ok()?;
        let end = usize::try_from(self.offset.checked_add(self.size)?).ok()?;
        data.get(start..end)
    }
}

#[derive(Debug)]
struct Image<'a> {
    bytes: &'a [u8],
    abi: String,
    entry: u64,
    build_id: Option<String>,
    regions: Vec<Region>,
    /// Code sections exclude loader headers (notably in Mach-O __TEXT).
    /// None falls back to executable mappings for sectionless images.
    code: Option<Vec<Region>>,
    callbacks: HashSet<u64>,
}

impl Image<'_> {
    fn executable_code(&self) -> Vec<&Region> {
        self.code
            .as_ref()
            .unwrap_or(&self.regions)
            .iter()
            .filter(|r| r.kind == "load" && r.executable && r.size > 0)
            .collect()
    }
}

fn compare(old: &Image<'_>, new: &Image<'_>) -> Comparison {
    let old_exec: Vec<_> = old
        .regions
        .iter()
        .filter(|r| r.kind == "load" && r.executable && r.size > 0)
        .collect();
    let new_exec: Vec<_> = new
        .regions
        .iter()
        .filter(|r| r.kind == "load" && r.executable && r.size > 0)
        .collect();
    let compatible = old.abi == new.abi;
    // Compare like with like when a section table appears/disappears. A
    // change in extraction representation is not itself an executable edit.
    let (old_code, new_code) = if old.code.is_some() && new.code.is_some() {
        (old.executable_code(), new.executable_code())
    } else {
        (old_exec.clone(), new_exec.clone())
    };
    let retained: Vec<_> = old_code
        .iter()
        .filter(|r| {
            compatible
                && new_code.iter().any(|n| {
                    r.address == n.address
                        && r.size == n.size
                        && r.bytes(old.bytes).is_some()
                        && r.bytes(old.bytes) == n.bytes(new.bytes)
                })
        })
        .collect();
    let mut result = Comparison {
        abi: new.abi.clone(),
        bytes_changed: old.bytes != new.bytes,
        compatible_abi: compatible,
        retained_build_id: old
            .build_id
            .as_ref()
            .zip(new.build_id.as_ref())
            .map(|(a, b)| a == b),
        original_executable_bytes: old_code.iter().map(|r| r.size).sum(),
        retained_executable_bytes: retained.iter().map(|r| r.size).sum(),
        slice_traits_available: true,
        findings: Vec::new(),
    };
    if !result.bytes_changed || !compatible {
        return result;
    }
    let original_retained = result.original_executable_bytes > 0
        && result.retained_executable_bytes == result.original_executable_bytes;
    // Directional: code removal alone (including undoing an injection) is not
    // a code gain. Offsets can move during signing/debug layout changes.
    let changed_code: u64 = new_code
        .iter()
        .filter(|n| {
            !old_code.iter().any(|r| {
                r.address == n.address
                    && r.size == n.size
                    && r.bytes(old.bytes).is_some()
                    && r.bytes(old.bytes) == n.bytes(new.bytes)
            })
        })
        .map(|r| r.size)
        .sum();
    if result.retained_build_id == Some(true) && changed_code > 0 {
        result.findings.push(Finding {
            severity: Severity::Medium,
            label: BUILD_ID_WITH_CODE_CHANGE,
            facts: vec![("code", format!("{changed_code} executable bytes changed"))],
            caveat: Some(BUILD_ID_CAVEAT),
        });
    }
    let old_entry_valid = old_exec.iter().any(|r| r.contains(old.entry));
    for region in &new_exec {
        let old_mapping = old
            .regions
            .iter()
            .find(|r| r.kind == "load" && r.address == region.address);
        if region.writable && old_mapping.is_none_or(|r| !r.executable || !r.writable) {
            result.findings.push(Finding {
                severity: Severity::High,
                label: "writable+executable mapping",
                facts: vec![(
                    "mapping",
                    format!("{:#x} became writable+executable", region.address),
                )],
                caveat: None,
            });
        }
    }
    // An appended executable section can live in a grown existing segment;
    // it need not introduce a whole new segment/load command.
    for region in &new_code {
        // The new entry must leave the old executable address ranges, not
        // merely move between existing functions during a normal rebuild.
        let appended = region.offset >= old.bytes.len() as u64;
        let repurposed = old.regions.iter().any(|r| {
            r.kind == "load"
                && !r.executable
                && region.address.checked_sub(r.address).is_some_and(|d| {
                    d.checked_add(region.size).is_some_and(|end| end <= r.size)
                        && r.offset.checked_add(d) == Some(region.offset)
                })
        });
        if !original_retained || (!appended && !repurposed) {
            continue;
        }
        if old.entry != new.entry
            && old_entry_valid
            && region.contains(new.entry)
            && !old_exec.iter().any(|r| r.contains(new.entry))
        {
            result.findings.push(Finding {
                severity: Severity::High,
                label: "entry point grafted",
                facts: vec![
                    ("entry", format!("{:#x} → {:#x}", old.entry, new.entry)),
                    (
                        "new code",
                        format!(
                            "{} bytes {} at file offset {:#x}",
                            region.size,
                            if appended {
                                "appended"
                            } else {
                                "in a newly executable mapping"
                            },
                            region.offset
                        ),
                    ),
                    (
                        "old code",
                        format!("all {} bytes kept", result.original_executable_bytes),
                    ),
                ],
                caveat: None,
            });
        }
        let mut callbacks: Vec<_> = new
            .callbacks
            .difference(&old.callbacks)
            .filter(|addr| region.contains(**addr) && !old_exec.iter().any(|r| r.contains(**addr)))
            .copied()
            .collect();
        callbacks.sort_unstable();
        if !callbacks.is_empty() {
            result.findings.push(Finding {
                severity: Severity::High,
                label: "loader callback grafted",
                facts: vec![
                    (
                        "callbacks",
                        format!("{callbacks:#x?} target the added executable mapping"),
                    ),
                    (
                        "old code",
                        format!("all {} bytes kept", result.original_executable_bytes),
                    ),
                ],
                caveat: None,
            });
        }
    }
    result
}

fn compare_paths(old: &Path, new: &Path) -> Result<Vec<Comparison>> {
    let old_bytes = std::fs::read(old).with_context(|| format!("reading {}", old.display()))?;
    let new_bytes = std::fs::read(new).with_context(|| format!("reading {}", new.display()))?;
    let old = inspect_all(&old_bytes)?;
    let new = inspect_all(&new_bytes)?;
    Ok(compare_images(&old, &new))
}

fn compare_images(old: &[Image<'_>], new: &[Image<'_>]) -> Vec<Comparison> {
    old.iter()
        .filter_map(|a| {
            new.iter().find(|b| a.abi == b.abi).map(|b| {
                let mut c = compare(a, b);
                c.slice_traits_available = old.len() == 1 && new.len() == 1;
                c
            })
        })
        .collect()
}

/// Corroboration joining binary identity and the regular scanner's traits.
/// A stable build ID and 40% weighted churn merit review, but
/// one gained trait on a tiny baseline or pure removals do not imply an attack.
fn trait_churn(
    comparison: &Comparison,
    traits: &cleave::types::ScopeDiff<cleave::types::TraitChange>,
) -> Option<Finding> {
    if !comparison.bytes_changed
        || !comparison.slice_traits_available
        || !comparison.compatible_abi
        || comparison.retained_build_id != Some(true)
        || !traits.roc.is_finite()
        || traits.roc < 0.4
    {
        return None;
    }
    let useful = |t: &&cleave::types::TraitChange| {
        matches!(
            t.crit,
            cleave::Criticality::Notable
                | cleave::Criticality::Suspicious
                | cleave::Criticality::Hostile
        )
    };
    let gained: HashSet<_> = traits
        .added
        .iter()
        .filter(useful)
        .map(|t| t.id.as_str())
        .collect();
    let moved: HashSet<_> = traits
        .added
        .iter()
        .chain(&traits.removed)
        .filter(useful)
        .map(|t| t.id.as_str())
        .collect();
    if gained.is_empty() || moved.len() < 3 {
        return None;
    }
    Some(Finding {
        severity: Severity::Medium,
        label: "build ID unchanged despite trait churn",
        facts: vec![(
            "traits",
            format!(
                "{:.1}% trait churn, {} gained, {} lost",
                traits.roc * 100.0,
                gained.len(),
                moved.len().saturating_sub(gained.len())
            ),
        )],
        caveat: Some(BUILD_ID_CAVEAT),
    })
}

fn is_native(path: &Path) -> bool {
    let mut magic = [0; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && native_magic(&magic)
}

/// Feed the same findings to all normal renderers/gates. Archive members are
/// not reread here: only directly paired local native files have stable byte paths.
pub(crate) fn enrich(
    pairs: &[crate::analysis::Pair],
    diff: &cleave::types::DiffReportV1,
    assessment: &mut Assessment,
) {
    for pair in pairs {
        let (Some(old), Some(new)) = (pair.old.as_deref(), pair.new.as_deref()) else {
            continue;
        };
        if !is_native(old) || !is_native(new) {
            continue;
        }
        let mut comparisons = match compare_paths(old, new) {
            Ok(c) => c,
            Err(error) => {
                eprintln!(
                    "isomer: structural comparison unavailable: {}",
                    crate::printable(&error.to_string())
                );
                continue;
            }
        };
        let file = diff
            .files
            .iter()
            .find(|f| f.path == pair.label || (pairs.len() == 1 && f.path == "<root>"));
        // Universal binaries expose aggregate/preferred-slice traits. Do not
        // attach those to a different slice's identity.
        let churn = comparisons
            .first()
            .filter(|_| comparisons.len() == 1)
            .and_then(|comparison| {
                file.and_then(|f| f.scopes.traits.as_ref())
                    .and_then(|t| trait_churn(comparison, t))
            });
        // Trait churn under a retained build ID is the same observation as
        // code change under a retained build ID, seen through the scanner
        // instead of the bytes: when both fire they are one finding.
        if let Some(churn) = churn
            && let Some(comparison) = comparisons.first_mut()
        {
            match comparison
                .findings
                .iter_mut()
                .find(|f| f.label == BUILD_ID_WITH_CODE_CHANGE)
            {
                Some(finding) => finding.facts.extend(churn.facts),
                None => comparison.findings.push(churn),
            }
        }
        for comparison in comparisons {
            // Each fact names the image it was read from: the file, and the
            // slice ABI, which is what tells two slices of a universal binary
            // apart. The detail stays the bare observation.
            let subject = format!("{} · {}", crate::printable(&pair.label), comparison.abi);
            for finding in comparison.findings {
                assessment.severity = assessment.severity.max(finding.severity);
                assessment.structure.severity = assessment.structure.severity.max(finding.severity);
                assessment.structure.facts.push(StructFact {
                    severity: finding.severity,
                    kind: FactKind::Became,
                    label: finding.label,
                    subject: Some(subject.clone()),
                    facts: finding.facts,
                    caveat: finding.caveat,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests;
