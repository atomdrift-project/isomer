//! Native format facts normalized for shared, directional comparison rules.

use super::{Image, Region};
use anyhow::{Context, Result, ensure};
use filefacts::{ParsedFile, Values};
use serde_json::Value;
use std::collections::HashSet;

pub(super) fn native_magic(bytes: &[u8]) -> bool {
    Format::of(bytes).is_some()
}

fn macho_magic(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(
            [0xce, 0xfa, 0xed, 0xfe]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xce]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
        )
    )
}

fn number(v: &Values, key: &str) -> Result<u64> {
    v.get(key)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing {key}"))
}

fn identity(v: &Values, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn abi(v: &Values, keys: &[&str]) -> Result<String> {
    keys.iter()
        .map(|key| {
            v.get(key)
                .and_then(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .or_else(|| v.as_u64().map(|n| n.to_string()))
                })
                .with_context(|| format!("missing ABI field {key}"))
        })
        .collect::<Result<Vec<_>>>()
        .map(|parts| parts.join("/"))
}

/// The native format an image is in, from its magic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Elf,
    Pe,
    MachO,
}

impl Format {
    fn of(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"\x7fELF") {
            Some(Self::Elf)
        } else if bytes.starts_with(b"MZ") {
            Some(Self::Pe)
        } else if macho_magic(bytes) {
            Some(Self::MachO)
        } else {
            None
        }
    }
}

/// What one format's reader extracts, before the validation every format
/// shares.
struct Layout {
    abi: String,
    entry: u64,
    build_id: Option<String>,
    regions: Vec<Region>,
    /// Executable sections, when the format's section table is trusted for
    /// them; `None` falls back to executable mappings.
    code: Option<Vec<Region>>,
    callbacks: HashSet<u64>,
}

fn segments(v: &Values, key: &str, format: Format) -> Result<Vec<Region>> {
    let elf = format == Format::Elf;
    v.get(key)
        .and_then(Value::as_array)
        .context("missing native segment table")?
        .iter()
        .map(|s| {
            let num = |key| {
                s.get(key)
                    .and_then(Value::as_u64)
                    .with_context(|| format!("missing segment {key}"))
            };
            let perms = s
                .get("perms")
                .and_then(Value::as_str)
                .context("missing segment permissions")?;
            Ok(Region {
                loadable: !elf
                    || s.get("type")
                        .and_then(Value::as_str)
                        .context("missing ELF segment type")?
                        == "load",
                address: num("vaddr")?,
                offset: num("file_offset")?,
                size: num("file_size")?,
                memory_size: num(if elf { "memory_size" } else { "vsize" })?,
                executable: perms.contains('x'),
                writable: perms.contains('w'),
            })
        })
        .collect()
}

fn section_regions(parsed: &ParsedFile<'_>, format: Format) -> Vec<Region> {
    parsed
        .sections()
        .iter()
        .map(|s| Region {
            loadable: true,
            address: s.vaddr,
            offset: s.file_offset,
            // PE raw data includes file-alignment padding beyond VirtualSize.
            size: if format == Format::Pe && s.vsize > 0 {
                s.file_size.min(s.vsize)
            } else {
                s.file_size
            },
            memory_size: s.vsize.max(s.file_size),
            executable: s.is_executable(),
            writable: s.is_writable(),
        })
        .collect()
}

fn executable_sections(parsed: &ParsedFile<'_>, format: Format) -> Option<Vec<Region>> {
    let code: Vec<_> = section_regions(parsed, format)
        .into_iter()
        .filter(|s| s.executable && s.size > 0)
        .collect();
    (!code.is_empty()).then_some(code)
}

fn callbacks(v: &Values, keys: &[&str], base: u64) -> HashSet<u64> {
    keys.iter()
        .flat_map(|key| v.get(key).and_then(Value::as_array).into_iter().flatten())
        .filter_map(|entry| entry.get("addr"))
        .filter_map(|addr| {
            addr.as_u64().or_else(|| {
                addr.as_str().and_then(|s| {
                    s.strip_prefix("0x")
                        .and_then(|s| u64::from_str_radix(s, 16).ok())
                })
            })
        })
        .filter_map(|addr| addr.checked_sub(base))
        .filter(|addr| *addr != 0)
        .collect()
}

fn elf(parsed: &ParsedFile<'_>, v: &Values) -> Result<Layout> {
    let regions = segments(v, "elf.segments", Format::Elf)?;
    for r in &regions {
        ensure!(
            !r.loadable || r.size <= r.memory_size,
            "ELF load segment exceeds memory size"
        );
    }
    Ok(Layout {
        abi: format!(
            "elf/{}",
            abi(v, &["elf.machine", "elf.class", "elf.endian", "elf.type"])?
        ),
        entry: number(v, "elf.entry")?,
        build_id: identity(v, "elf.build_id"),
        regions,
        code: executable_sections(parsed, Format::Elf),
        callbacks: callbacks(v, &["elf.init_array", "elf.fini_array"], 0),
    })
}

fn pe(parsed: &ParsedFile<'_>, v: &Values) -> Result<Layout> {
    ensure!(
        v.get("pe.partial_parse") != Some(&Value::Bool(true)),
        "partial PE parse"
    );
    let build_id = identity(v, "pe.debug.pdb.guid")
        .zip(v.get("pe.debug.pdb.age").and_then(Value::as_u64))
        .map(|(guid, age)| format!("pdb:{guid}/{age}"));
    Ok(Layout {
        abi: format!("pe/{}", abi(v, &["pe.machine_id", "pe.subsystem_raw"])?),
        // PE section addresses and entry point are RVAs, callbacks are VAs.
        entry: number(v, "pe.entry_point")?,
        build_id,
        regions: section_regions(parsed, Format::Pe),
        code: None,
        callbacks: callbacks(v, &["pe.tls_callbacks"], number(v, "pe.image_base")?),
    })
}

fn macho(parsed: &ParsedFile<'_>, v: &Values) -> Result<Layout> {
    ensure!(
        v.get("macho.slices").is_none(),
        "universal image requires slice pairing"
    );
    Ok(Layout {
        abi: format!(
            "macho/{}",
            abi(
                v,
                &[
                    "macho.cpu_type_raw",
                    "macho.cpu_subtype",
                    "macho.class_bits",
                    "macho.endian",
                    "macho.file_type_raw"
                ]
            )?
        ),
        // filefacts exposes goblin's normalized virtual address here, NOT the
        // raw LC_MAIN file offset. LC_UNIXTHREAD already contains a VA.
        entry: number(v, "macho.entry")?,
        build_id: identity(v, "macho.uuid"),
        regions: segments(v, "macho.segments", Format::MachO)?,
        code: executable_sections(parsed, Format::MachO),
        callbacks: HashSet::new(),
    })
}

pub(super) fn inspect(bytes: &[u8]) -> Result<Image<'_>> {
    let format = Format::of(bytes).context("unsupported native image")?;
    let _no_disassembly = filefacts::rizin::scoped_disable_current_thread();
    let parsed = filefacts::open(bytes)?;
    let v = parsed.values();
    let layout = match format {
        Format::Elf => elf(&parsed, v)?,
        Format::Pe => pe(&parsed, v)?,
        Format::MachO => macho(&parsed, v)?,
    };
    for region in &layout.regions {
        validate_region(region, bytes)?;
    }
    ensure!(
        layout.regions.iter().any(|r| r.loadable && r.size > 0),
        "no file-backed load regions"
    );
    if let Some(code) = &layout.code {
        for s in code {
            validate_region(s, bytes)?;
            ensure!(
                layout
                    .regions
                    .iter()
                    .any(|r| r.loadable && r.executable && r.covers(s)),
                "code section is outside its executable mapping"
            );
        }
    }
    Ok(Image {
        bytes,
        abi: layout.abi,
        entry: layout.entry,
        build_id: layout.build_id,
        regions: layout.regions,
        code: layout.code,
        callbacks: layout.callbacks,
    })
}

fn validate_region(r: &Region, bytes: &[u8]) -> Result<()> {
    ensure!(
        r.size == 0 || r.bytes(bytes).is_some(),
        "native region exceeds file bounds"
    );
    ensure!(
        r.address.checked_add(r.memory_size.max(r.size)).is_some(),
        "native virtual range overflow"
    );
    Ok(())
}

pub(super) fn inspect_all(bytes: &[u8]) -> Result<Vec<Image<'_>>> {
    if !matches!(
        bytes.get(..4),
        Some([0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca])
    ) {
        return inspect(bytes).map(|i| vec![i]);
    }
    let _no_disassembly = filefacts::rizin::scoped_disable_current_thread();
    let parsed = filefacts::open(bytes)?;
    // Java class files share CAFEBABE with universal Mach-O. They remain
    // handled by normal analysis, not a failed native-comparison warning.
    if parsed.fileid().file_type() == filefacts::FileType::JavaClass {
        return Ok(Vec::new());
    }
    let slices = parsed
        .values()
        .get("macho.slices")
        .and_then(Value::as_array)
        .context("missing Mach-O slices")?;
    ensure!(!slices.is_empty(), "empty universal image");
    let raw_count: [u8; 4] = bytes
        .get(4..8)
        .context("truncated universal header")?
        .try_into()?;
    let count = if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
        u32::from_be_bytes(raw_count)
    } else {
        u32::from_le_bytes(raw_count)
    };
    ensure!(
        usize::try_from(count)? == slices.len(),
        "incomplete universal slice extraction"
    );
    let header_end = 8usize
        .checked_add(
            slices
                .len()
                .checked_mul(20)
                .context("slice table overflow")?,
        )
        .context("slice table overflow")?;
    let mut identities = HashSet::new();
    let mut images = Vec::new();
    let mut ranges = Vec::new();
    for slice in slices {
        let start = slice
            .get("file_offset")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .context("missing slice offset")?;
        let size = slice
            .get("file_size")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .context("missing slice size")?;
        let end = start.checked_add(size).context("slice overflow")?;
        ensure!(
            start >= header_end && !ranges.iter().any(|(a, b)| start < *b && *a < end),
            "overlapping universal slice"
        );
        ranges.push((start, end));
        let data = bytes.get(start..end).context("slice exceeds file bounds")?;
        ensure!(macho_magic(data), "non-Mach-O universal member");
        let image = inspect(data)?;
        ensure!(
            identities.insert(image.abi.clone()),
            "ambiguous duplicate Mach-O architecture"
        );
        images.push(image);
    }
    Ok(images)
}
