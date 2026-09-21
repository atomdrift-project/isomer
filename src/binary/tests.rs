//! Fast, non-executing fixtures: byte arrays and small synthetic fact records.

use super::*;
use cleave::types::{ScopeDiff, TraitChange};

fn region(offset: u64, address: u64, size: u64, exec: bool) -> Region {
    Region {
        kind: "load".into(),
        offset,
        address,
        size,
        memory_size: size,
        executable: exec,
        writable: false,
    }
}

fn image(bytes: &[u8]) -> Image<'_> {
    Image {
        bytes,
        abi: "x86_64/elf64/little/executable".into(),
        entry: 0x1000,
        build_id: Some("original-build".into()),
        regions: vec![region(0, 0x1000, 16, true)],
        code: None,
        callbacks: HashSet::new(),
    }
}

fn graft<'a>(bytes: &'a [u8], id: Option<&str>) -> Image<'a> {
    let mut i = image(bytes);
    i.entry = 0x2000;
    i.build_id = id.map(str::to_owned);
    i.regions.push(region(32, 0x2000, 16, true));
    i
}

fn high(c: &Comparison) -> bool {
    c.findings.iter().any(|f| f.severity == Severity::High)
}

#[test]
fn graft_is_independent_of_build_identity_and_trait_inventory() {
    let old_bytes = [0x90; 32];
    let mut new_bytes = [0x90; 48];
    new_bytes[32..].fill(0xcc);
    for old_id in [None, Some("original-build")] {
        for new_id in [None, Some("original-build"), Some("different-build")] {
            let mut old = image(&old_bytes);
            old.build_id = old_id.map(str::to_owned);
            let new = graft(&new_bytes, new_id);
            let c = compare(&old, &new);
            assert!(high(&c));
            assert_eq!(c.retained_executable_bytes, 16);
            assert_eq!(c.retained_build_id, old_id.zip(new_id).map(|(a, b)| a == b));
            assert!(
                !high(&compare(&new, &old)),
                "removing a graft is not adding one"
            );
        }
    }
}

#[test]
fn inert_append_and_debug_only_edits_do_not_fail() {
    let old_bytes = [0x90; 32];
    let mut new_bytes = [0x90; 48];
    new_bytes[32..].fill(0xcc);
    let old = image(&old_bytes);
    let mut new = graft(&new_bytes, Some("original-build"));
    new.entry = old.entry;
    assert!(
        !high(&compare(&old, &new)),
        "unreached appended code is not an entry graft"
    );
    new.regions.pop();
    assert!(
        !high(&compare(&old, &new)),
        "debug/footer bytes do not change execution"
    );
    assert!(!high(&compare(&old, &old)));
}

#[test]
fn entry_destination_must_be_new_file_backed_executable_code() {
    let old_bytes = [0x90; 32];
    let new_bytes = [0x90; 48];
    let old = image(&old_bytes);
    for entry in [0, 0x1001, 0x2010, u64::MAX] {
        let mut new = graft(&new_bytes, None);
        new.entry = entry;
        assert!(
            !high(&compare(&old, &new)),
            "invalid or already executable entry {entry:x}"
        );
    }
    let mut new = graft(&new_bytes, None);
    new.regions[1].executable = false;
    assert!(!high(&compare(&old, &new)));
    new.regions[1].executable = true;
    new.regions[1].size = 0;
    assert!(!high(&compare(&old, &new)));
}

#[test]
fn rebuild_rebase_and_architecture_changes_are_not_exact_grafts() {
    let old_bytes = [0x90; 32];
    let mut new_bytes = [0x90; 48];
    new_bytes[0] = 0xcc;
    let old = image(&old_bytes);
    assert!(!high(&compare(&old, &graft(&new_bytes, None))));
    new_bytes[0] = 0x90;
    let mut new = graft(&new_bytes, None);
    new.abi = "aarch64/elf64/little/executable".into();
    assert!(!high(&compare(&old, &new)));
    new.abi = old.abi.clone();
    new.regions[0].address += 0x10000;
    assert!(!high(&compare(&old, &new)));
}

#[test]
fn header_reordering_is_not_a_conversion() {
    let bytes = [0x90; 32];
    let mut old = image(&bytes);
    old.regions.push(region(16, 0x2000, 16, false));
    let mut new = image(&bytes);
    new.regions = old.regions.iter().rev().cloned().collect();
    let c = compare(&old, &new);
    assert!(!high(&c));
    assert_eq!(c.retained_executable_bytes, 16);
}

#[test]
fn executable_permission_changes_are_directional() {
    let old_bytes = [0x90; 32];
    let mut new_bytes = old_bytes;
    new_bytes[31] = 0;
    let old = image(&old_bytes);
    let mut new = image(&new_bytes);
    new.regions[0].writable = true;
    assert!(high(&compare(&old, &new)));
    assert!(!high(&compare(&new, &old)));
}

#[test]
fn existing_data_mapping_promoted_to_entry_code_is_detected() {
    let old_bytes = [0x90; 32];
    let mut new_bytes = old_bytes;
    new_bytes[31] = 0xcc;
    let mut old = image(&old_bytes);
    old.regions.push(region(16, 0x2000, 16, false));
    let mut new = image(&new_bytes);
    new.regions = old.regions.clone();
    new.regions[1].executable = true;
    new.entry = 0x2000;
    assert!(high(&compare(&old, &new)));
}

fn traits(roc: f32) -> ScopeDiff<TraitChange> {
    ScopeDiff {
        roc,
        old_count: 20,
        new_count: 23,
        added: (0..3)
            .map(|i| TraitChange {
                id: format!("micro-behaviors/os/module/load::call-{i}"),
                crit: cleave::Criticality::Notable,
                conf: 1.0,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

#[test]
fn retained_identity_churn_is_corroboration_not_a_gate_on_percentage_alone() {
    let old_bytes = [0x90; 32];
    let mut new_bytes = old_bytes;
    new_bytes[31] = 0xcc;
    let c = compare(&image(&old_bytes), &image(&new_bytes));
    assert_eq!(
        trait_churn(&c, &traits(0.4)).unwrap().severity,
        Severity::Medium
    );
    for roc in [0.0, 0.399, f32::NAN] {
        assert!(trait_churn(&c, &traits(roc)).is_none());
    }
    let mut small = traits(1.0);
    small.added.truncate(1);
    assert!(trait_churn(&c, &small).is_none());
    let mut removed = traits(0.8);
    removed.removed = std::mem::take(&mut removed.added);
    assert!(trait_churn(&c, &removed).is_none());
    let mut baseline = traits(0.8);
    for t in &mut baseline.added {
        t.crit = cleave::Criticality::Baseline;
    }
    assert!(trait_churn(&c, &baseline).is_none());
    let same = compare(&image(&old_bytes), &image(&old_bytes));
    assert!(
        trait_churn(&same, &traits(0.8)).is_none(),
        "rule-only changes aren't binary changes"
    );
    let mut other = image(&new_bytes);
    other.build_id = Some("different".into());
    assert!(trait_churn(&compare(&image(&old_bytes), &other), &traits(0.8)).is_none());
    other.build_id = None;
    assert!(trait_churn(&compare(&image(&old_bytes), &other), &traits(0.8)).is_none());
}

fn put16(bytes: &mut [u8], off: usize, value: u16) {
    bytes[off..off + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], off: usize, value: u32) {
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], off: usize, value: u64) {
    bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

// An inert ELF header + byte ranges, never a program that tests execute.
fn elf(grafted: bool) -> Vec<u8> {
    let mut b = vec![0; if grafted { 1040 } else { 512 }];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut b, 16, 2);
    put16(&mut b, 18, 62);
    put32(&mut b, 20, 1);
    put64(&mut b, 24, if grafted { 0x500000 } else { 0x401000 });
    put64(&mut b, 32, 64);
    put16(&mut b, 52, 64);
    put16(&mut b, 54, 56);
    put16(&mut b, 56, 2);
    put32(&mut b, 64, 1);
    put32(&mut b, 68, 5);
    put64(&mut b, 72, 256);
    put64(&mut b, 80, 0x401000);
    put64(&mut b, 96, 32);
    put64(&mut b, 104, 32);
    put32(&mut b, 120, if grafted { 1 } else { 4 });
    put32(&mut b, 124, if grafted { 5 } else { 4 });
    put64(&mut b, 128, if grafted { 1024 } else { 384 });
    put64(&mut b, 136, if grafted { 0x500000 } else { 0x402000 });
    put64(&mut b, 152, 16);
    put64(&mut b, 160, 16);
    b[256..288].fill(0x90);
    if grafted {
        b[1024..1040].fill(0xcc);
    }
    b
}

#[test]
fn actual_filefacts_adapter_detects_synthetic_note_conversion_without_traits() {
    let old = elf(false);
    let new = elf(true);
    let c = compare(&inspect(&old).unwrap(), &inspect(&new).unwrap());
    assert!(high(&c));
    assert_eq!(c.retained_executable_bytes, 32);
    assert_eq!(c.retained_build_id, None);
}

#[test]
fn malformed_and_unsupported_inputs_are_errors_not_clean() {
    assert!(inspect(b"not a binary").is_err());
    assert!(inspect(b"\x7fELF").is_err());
    let mut bad = elf(true);
    put64(&mut bad, 152, u64::MAX);
    assert!(inspect(&bad).is_err());
    let r = region(u64::MAX, 0, 16, true);
    assert!(r.bytes(&[0; 16]).is_none());
}

#[test]
fn normal_assessment_keeps_traits_and_adds_structural_evidence() {
    use cleave::types::{DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, ScopeDiffs};
    for (fixture, file_type) in [
        (elf as fn(bool) -> Vec<u8>, "elf"),
        (pe, "pe"),
        (macho, "macho"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let old = temp.path().join("before");
        let new = temp.path().join("after");
        std::fs::write(&old, fixture(false)).unwrap();
        std::fs::write(&new, fixture(true)).unwrap();
        let report = DiffReportV1 {
            old_root: old.display().to_string(),
            new_root: new.display().to_string(),
            summary: DiffSummary::default(),
            scopes: ScopeDiffs::default(),
            files: vec![FileDiffEntry {
                path: "<root>".into(),
                status: FileStatus::Changed,
                file_type: Some(file_type.into()),
                identity: None,
                old_formula: None,
                new_formula: None,
                scopes: ScopeDiffs {
                    traits: Some(traits(0.4)),
                    ..Default::default()
                },
            }],
        };
        let pairs = [crate::analysis::Pair {
            label: "after".into(),
            old: Some(old),
            new: Some(new),
        }];
        let mut assessment = crate::rubric::assess(&report, &HashSet::new());
        let trait_ids: HashSet<_> = assessment
            .gained_ids()
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert!(!trait_ids.is_empty());
        enrich(&pairs, &report, &mut assessment);
        assert_eq!(assessment.structure.severity, Severity::High);
        assert!(assessment.new_severity().fails(Severity::High));
        assert_eq!(
            trait_ids,
            assessment
                .gained_ids()
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        assert!(
            assessment
                .structure
                .facts
                .iter()
                .any(|f| f.label == "entry point grafted")
        );
    }
}

fn medium(c: &Comparison) -> bool {
    c.findings.iter().any(|f| f.severity == Severity::Medium)
}

#[test]
fn retained_identity_code_change_is_directional_and_not_metadata_churn() {
    let old_bytes = [0x90; 32];
    let mut edited = old_bytes;
    edited[0] = 0xcc;
    assert!(medium(&compare(&image(&old_bytes), &image(&edited))));
    edited = old_bytes;
    edited[31] = 0xcc;
    assert!(
        compare(&image(&old_bytes), &image(&edited))
            .findings
            .is_empty()
    );
    let new_bytes = [0x90; 48];
    let old = image(&old_bytes);
    let mut new = graft(&new_bytes, Some("original-build"));
    new.entry = old.entry;
    assert!(medium(&compare(&old, &new)));
    assert!(!high(&compare(&old, &new)));
    assert!(compare(&new, &old).findings.is_empty());
    for id in [None, Some("other")] {
        new.build_id = id.map(str::to_owned);
        assert!(compare(&old, &new).findings.is_empty());
    }
}

#[test]
fn callback_graft_does_not_need_entry_or_identity_change() {
    let old_bytes = [0x90; 32];
    let new_bytes = [0x90; 48];
    let old = image(&old_bytes);
    let mut new = graft(&new_bytes, None);
    new.entry = old.entry;
    new.callbacks.insert(0x2000);
    assert!(high(&compare(&old, &new)));
    assert!(!high(&compare(&new, &old)));
    new.callbacks = HashSet::from([0x1001, 0x2010, u64::MAX]);
    assert!(!high(&compare(&old, &new)));
}

#[test]
fn existing_rwx_behavior_is_not_a_new_permission_gain() {
    let old_bytes = [0x90; 32];
    let new_bytes = [0x90; 48];
    let mut old = image(&old_bytes);
    old.regions[0].writable = true;
    let mut new = image(&new_bytes);
    new.regions[0].writable = true;
    new.regions[0].size = 32;
    new.regions[0].memory_size = 32;
    assert!(!high(&compare(&old, &new)));
}

// Minimal PE32+ with CodeView identity; ranges contain inert fixture bytes.
fn pe(grafted: bool) -> Vec<u8> {
    let mut b = vec![0; if grafted { 2048 } else { 1536 }];
    b[..2].copy_from_slice(b"MZ");
    put32(&mut b, 0x3c, 0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut b, 0x84, 0x8664);
    put16(&mut b, 0x86, if grafted { 3 } else { 2 });
    put16(&mut b, 0x94, 240);
    put16(&mut b, 0x96, 0x22);
    let opt = 0x98;
    put16(&mut b, opt, 0x20b);
    put32(&mut b, opt + 16, if grafted { 0x3000 } else { 0x1000 });
    put64(&mut b, opt + 24, 0x140000000);
    put32(&mut b, opt + 32, 0x1000);
    put32(&mut b, opt + 36, 512);
    put32(&mut b, opt + 56, if grafted { 0x4000 } else { 0x3000 });
    put32(&mut b, opt + 60, 512);
    put16(&mut b, opt + 68, 3);
    put32(&mut b, opt + 108, 16);
    // Debug directory, followed by RSDS GUID + age + NUL-terminated PDB name.
    put32(&mut b, opt + 112 + 6 * 8, 0x2000);
    put32(&mut b, opt + 116 + 6 * 8, 28);
    put32(&mut b, 1024 + 12, 2);
    put32(&mut b, 1024 + 16, 32);
    put32(&mut b, 1024 + 20, 0x2020);
    put32(&mut b, 1024 + 24, 1056);
    b[1056..1060].copy_from_slice(b"RSDS");
    b[1060..1076].fill(0x42);
    put32(&mut b, 1076, 1);
    b[1080..1086].copy_from_slice(b"x.pdb\0");
    for (i, name, address, offset, size, flags) in [
        (0, ".text", 0x1000, 512, 32, 0x60000020),
        (1, ".rdata", 0x2000, 1024, 512, 0x40000040),
        (2, ".extra", 0x3000, 1536, 32, 0x60000020),
    ] {
        if i == 2 && !grafted {
            continue;
        }
        let s = opt + 240 + i * 40;
        b[s..s + name.len()].copy_from_slice(name.as_bytes());
        put32(&mut b, s + 8, size);
        put32(&mut b, s + 12, address);
        put32(&mut b, s + 16, 512);
        put32(&mut b, s + 20, offset);
        put32(&mut b, s + 36, flags);
    }
    b[512..544].fill(0x90);
    if grafted {
        b[1536..1568].fill(0xcc);
    }
    b
}

// Mach-O has an RX __TEXT segment containing the header/load commands AND
// a __text section. Retaining code must not require retaining those headers.
fn macho(grafted: bool) -> Vec<u8> {
    let mut b = vec![0; if grafted { 4128 } else { 1024 }];
    put32(&mut b, 0, 0xfeedfacf);
    put32(&mut b, 4, 0x01000007);
    put32(&mut b, 8, 3);
    put32(&mut b, 12, 2);
    put32(&mut b, 16, if grafted { 4 } else { 3 });
    put32(&mut b, 20, if grafted { 352 } else { 200 });
    for (s, name, address, offset, size, section_offset) in [
        (32, "__TEXT", 0x100000000, 0, 1024, 512),
        (232, "__EXTRA", 0x100001000, 4096, 32, 4096),
    ] {
        if s == 232 && !grafted {
            continue;
        }
        put32(&mut b, s, 0x19);
        put32(&mut b, s + 4, 152);
        b[s + 8..s + 8 + name.len()].copy_from_slice(name.as_bytes());
        put64(&mut b, s + 24, address);
        put64(&mut b, s + 32, 0x1000);
        put64(&mut b, s + 40, offset);
        put64(&mut b, s + 48, size);
        put32(&mut b, s + 56, 5);
        put32(&mut b, s + 60, 5);
        put32(&mut b, s + 64, 1);
        let sec = s + 72;
        b[sec..sec + 6].copy_from_slice(b"__text");
        b[sec + 16..sec + 16 + name.len()].copy_from_slice(name.as_bytes());
        put64(
            &mut b,
            sec + 32,
            address + u64::from(section_offset) - offset,
        );
        put64(&mut b, sec + 40, 32);
        put32(&mut b, sec + 48, section_offset);
        put32(&mut b, sec + 64, 0x80000400);
    }
    put32(&mut b, 184, 0x1b); // LC_UUID
    put32(&mut b, 188, 24);
    b[192..208].fill(0x42);
    put32(&mut b, 208, 0x80000028); // LC_MAIN
    put32(&mut b, 212, 24);
    put64(&mut b, 216, if grafted { 0x1000 } else { 512 });
    b[512..544].fill(0x90);
    if grafted {
        b[4096..4128].fill(0xcc);
    }
    b
}

#[test]
fn native_adapters_detect_grafts_and_clean_reversals_without_traits() {
    for fixture in [elf, pe, macho] {
        let old_bytes = fixture(false);
        let new_bytes = fixture(true);
        let old = inspect(&old_bytes).unwrap();
        let new = inspect(&new_bytes).unwrap();
        let c = compare(&old, &new);
        assert!(high(&c), "{}: {:?}", old.abi, c.findings);
        assert_eq!(c.retained_executable_bytes, 32);
        assert!(compare(&new, &old).findings.is_empty(), "{}", old.abi);
        assert!(compare(&old, &old).findings.is_empty());
    }
}

#[test]
fn pe_and_macho_identities_support_code_and_trait_correlations() {
    for fixture in [pe, macho] {
        let old_bytes = fixture(false);
        let mut new_bytes = old_bytes.clone();
        new_bytes[512] = 0xcc;
        let old = inspect(&old_bytes).unwrap();
        let new = inspect(&new_bytes).unwrap();
        let c = compare(&old, &new);
        assert_eq!(c.retained_build_id, Some(true));
        assert!(medium(&c));
        assert!(!high(&c));
        assert!(trait_churn(&c, &traits(0.4)).is_some());
    }
}

#[test]
fn pe_tls_callbacks_are_normalized_to_section_rvas() {
    let old_bytes = pe(false);
    let mut new_bytes = pe(true);
    put32(&mut new_bytes, 0x98 + 16, 0x1000); // unchanged ordinary entry
    put32(&mut new_bytes, 0x98 + 112 + 9 * 8, 0x2080);
    put32(&mut new_bytes, 0x98 + 116 + 9 * 8, 40);
    put64(&mut new_bytes, 1152 + 24, 0x1400020c0); // callback table VA
    put64(&mut new_bytes, 1216, 0x140003000);
    let old = inspect(&old_bytes).unwrap();
    let new = inspect(&new_bytes).unwrap();
    assert_eq!(new.callbacks, HashSet::from([0x3000]));
    let c = compare(&old, &new);
    assert!(
        c.findings
            .iter()
            .any(|f| f.label == "loader callback grafted")
    );
    assert!(!c.findings.iter().any(|f| f.label == "entry point grafted"));
}

#[test]
fn metadata_changes_preserving_code_do_not_trigger_identity_findings() {
    for fixture in [pe, macho] {
        let old_bytes = fixture(false);
        let mut new_bytes = old_bytes.clone();
        // Appended signing/debug payload, outside executable sections.
        new_bytes.extend_from_slice(&[0x42; 64]);
        let c = compare(&inspect(&old_bytes).unwrap(), &inspect(&new_bytes).unwrap());
        assert_eq!(c.retained_build_id, Some(true));
        assert!(c.findings.is_empty());
    }
    let old_bytes = macho(false);
    let mut new_bytes = old_bytes.clone();
    put32(&mut new_bytes, 28, 1); // reserved header word inside RX __TEXT
    assert!(
        compare(&inspect(&old_bytes).unwrap(), &inspect(&new_bytes).unwrap())
            .findings
            .is_empty()
    );
}

#[test]
fn truncated_native_regions_are_not_silently_clean() {
    for fixture in [pe, macho] {
        let mut bytes = fixture(true);
        bytes.truncate(1030);
        assert!(inspect(&bytes).is_err());
    }
}

fn elf_with_id(grafted: bool) -> Vec<u8> {
    let mut b = elf(grafted);
    put16(&mut b, 56, 3);
    // Keep a GNU build-ID note in its own program header across the change.
    put32(&mut b, 176, 4);
    put32(&mut b, 180, 4);
    put64(&mut b, 184, 384);
    put64(&mut b, 192, 0x402000);
    put64(&mut b, 208, 20);
    put64(&mut b, 216, 20);
    if !grafted {
        put32(&mut b, 120, 0);
    }
    put32(&mut b, 384, 4);
    put32(&mut b, 388, 4);
    put32(&mut b, 392, 3);
    b[396..400].copy_from_slice(b"GNU\0");
    b[400..404].fill(0x42);
    b
}

#[test]
fn all_formats_correlate_same_identity_with_new_code_without_entry_redirect() {
    for fixture in [elf_with_id, pe, macho] {
        let old_bytes = fixture(false);
        let new_bytes = fixture(true);
        let old = inspect(&old_bytes).unwrap();
        let mut new = inspect(&new_bytes).unwrap();
        assert!(old.build_id.is_some(), "{}", old.abi);
        new.entry = old.entry;
        let c = compare(&old, &new);
        assert_eq!(c.retained_build_id, Some(true));
        assert!(medium(&c), "{}", old.abi);
        assert!(!high(&c));
        for id in [None, Some("other")] {
            new.build_id = id.map(str::to_owned);
            assert!(compare(&old, &new).findings.is_empty());
            new.entry = inspect(&new_bytes).unwrap().entry;
            assert!(high(&compare(&old, &new)), "graft must not need identity");
            new.entry = old.entry;
        }
    }
}

fn universal(slices: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; 1024 + slices.len() * 8192];
    b[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    b[4..8].copy_from_slice(&u32::try_from(slices.len()).unwrap().to_be_bytes());
    for (i, slice) in slices.iter().enumerate() {
        let header = 8 + 20 * i;
        let offset = 1024 + i * 8192;
        for (off, value) in [
            (0, u32::from_le_bytes(slice[4..8].try_into().unwrap())),
            (4, u32::from_le_bytes(slice[8..12].try_into().unwrap())),
            (8, u32::try_from(offset).unwrap()),
            (12, u32::try_from(slice.len()).unwrap()),
            (16, 10),
        ] {
            b[header + off..header + off + 4].copy_from_slice(&value.to_be_bytes());
        }
        b[offset..offset + slice.len()].copy_from_slice(slice);
    }
    b
}

#[test]
fn universal_macho_pairs_by_architecture_not_slice_order() {
    let x86 = macho(false);
    let mut arm = macho(false);
    put32(&mut arm, 4, 0x0100000c);
    put32(&mut arm, 8, 0);
    let old_bytes = universal(&[x86.clone(), arm.clone()]);
    let reordered_bytes = universal(&[arm.clone(), x86]);
    let old = inspect_all(&old_bytes).unwrap();
    let reordered = inspect_all(&reordered_bytes).unwrap();
    let unchanged = compare_images(&old, &reordered);
    assert_eq!(unchanged.len(), 2);
    assert!(unchanged.iter().all(|c| c.findings.is_empty()));
    let new_bytes = universal(&[arm, macho(true)]);
    let new = inspect_all(&new_bytes).unwrap();
    let comparisons = compare_images(&old, &new);
    assert_eq!(comparisons.iter().filter(|c| high(c)).count(), 1);
    assert!(
        comparisons
            .iter()
            .all(|c| trait_churn(c, &traits(0.8)).is_none())
    );
    // Even if only one ABI is shared, whole-file traits cannot be attributed
    // to that slice's retained identity.
    assert!(
        compare_images(&old, &new[1..])
            .iter()
            .all(|c| trait_churn(c, &traits(0.8)).is_none())
    );
}

#[test]
fn universal_macho_rejects_ambiguous_or_incomplete_slices() {
    assert!(inspect_all(&universal(&[macho(false), macho(false)])).is_err());
    let mut bytes = universal(&[macho(false)]);
    bytes[4..8].copy_from_slice(&2u32.to_be_bytes());
    assert!(inspect_all(&bytes).is_err());
    let java = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52];
    assert!(inspect_all(&java).unwrap().is_empty());
}

#[test]
fn section_byte_retention_tolerates_file_offset_moves_not_instruction_edits() {
    let old_bytes = [0x90; 32];
    let mut new_bytes = [0; 48];
    new_bytes[16..32].copy_from_slice(&old_bytes[..16]);
    let old = image(&old_bytes);
    let mut new = image(&new_bytes);
    new.regions[0].offset = 16;
    assert!(compare(&old, &new).findings.is_empty());
}

#[test]
fn appearing_section_table_does_not_invent_executable_changes() {
    let old_bytes = [0x90; 32];
    let mut new_bytes = old_bytes;
    new_bytes[31] = 0;
    let old = image(&old_bytes);
    let mut new = image(&new_bytes);
    new.code = Some(vec![region(0, 0x1000, 8, true)]);
    assert!(compare(&old, &new).findings.is_empty());
    assert!(compare(&new, &old).findings.is_empty());
}

#[test]
fn same_identity_new_nonexecutable_section_is_not_a_code_gain() {
    for fixture in [pe, macho] {
        let old_bytes = fixture(false);
        let mut new_bytes = fixture(true);
        if new_bytes.starts_with(b"MZ") {
            put32(&mut new_bytes, 0x98 + 16, 0x1000);
            put32(&mut new_bytes, 0x98 + 240 + 2 * 40 + 36, 0x40000040);
        } else {
            put64(&mut new_bytes, 216, 512);
            put32(&mut new_bytes, 232 + 56, 1);
            put32(&mut new_bytes, 232 + 60, 1);
            put32(&mut new_bytes, 232 + 72 + 64, 0);
        }
        let c = compare(&inspect(&old_bytes).unwrap(), &inspect(&new_bytes).unwrap());
        assert_eq!(c.retained_build_id, Some(true));
        assert!(c.findings.is_empty(), "{:?}", c.findings);
    }
}

#[test]
fn pe_identity_includes_debug_age_and_macho_entry_is_a_virtual_address() {
    let old_bytes = pe(false);
    let mut new_bytes = old_bytes.clone();
    put32(&mut new_bytes, 1076, 2);
    new_bytes[512] = 0xcc;
    let c = compare(&inspect(&old_bytes).unwrap(), &inspect(&new_bytes).unwrap());
    assert_eq!(c.retained_build_id, Some(false));
    assert!(c.findings.is_empty());
    assert_eq!(inspect(&macho(false)).unwrap().entry, 0x100000200);
    assert_eq!(inspect(&macho(true)).unwrap().entry, 0x100001000);
}

#[test]
fn macho_appended_section_in_grown_existing_segment_is_also_a_graft() {
    let old_bytes = macho(false);
    let mut new_bytes = macho(true);
    // Merge the added section into __TEXT instead of adding a segment.
    let section = new_bytes[304..384].to_vec();
    let uuid = new_bytes[184..208].to_vec();
    let main = new_bytes[208..232].to_vec();
    put32(&mut new_bytes, 16, 3);
    put32(&mut new_bytes, 20, 280);
    put32(&mut new_bytes, 36, 232);
    put64(&mut new_bytes, 64, 8192);
    put64(&mut new_bytes, 80, 4128);
    put32(&mut new_bytes, 96, 2);
    new_bytes[184..264].copy_from_slice(&section);
    new_bytes[200..216].fill(0);
    new_bytes[200..206].copy_from_slice(b"__TEXT");
    new_bytes[264..288].copy_from_slice(&uuid);
    new_bytes[288..312].copy_from_slice(&main);
    let old = inspect(&old_bytes).unwrap();
    let new = inspect(&new_bytes).unwrap();
    assert_eq!(old.regions.len(), new.regions.len());
    assert!(high(&compare(&old, &new)));
    assert!(compare(&new, &old).findings.is_empty());
}
