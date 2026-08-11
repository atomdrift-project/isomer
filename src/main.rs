//! isomer — supply-chain attack detection at a molecular level.
//!
//! Detects whether a change is malicious — introduced by a human, an AI, or
//! the dependency supply chain — by comparing two states of a tree, git ref,
//! package, or OCI image and judging the delta in context.
//!
//! Exit code contract (stable; CI gates on these):
//! - `0` — clean: no findings at or above `--fail-on`
//! - `1` — findings at or above `--fail-on`
//! - `2` — operational error (never conflated with findings)

use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

mod analysis;
mod ci;
mod deps;
mod evidence;
mod fetch;
mod fs;
mod json;
mod llm;
mod markdown;
mod rename;
mod risk;
mod rubric;
mod sarif;
mod terminal;
mod version;

const EXIT_FINDINGS: u8 = 1;
const EXIT_ERROR: u8 = 2;

/// Supply-chain attack detection at a molecular level.
#[derive(Debug, Parser)]
#[command(version, about, max_term_width = 100)]
struct Cli {
    /// Minimum severity that fails the run (exit code 1).
    #[arg(long, global = true, value_enum, default_value_t = Severity::High)]
    fail_on: Severity,

    /// What the exit code gates on. `new` (default) fails only on
    /// newly-introduced risk — the CI-relevant case, so a pre-existing issue
    /// isn't re-litigated every run. `any` also fails on escalations of
    /// findings that already existed in the base version.
    #[arg(long, global = true, value_enum, default_value_t = Gate::New)]
    gate: Gate,

    /// Output format.
    #[arg(long, global = true, value_enum, default_value_t = Format::Terminal)]
    format: Format,

    /// Hard guarantee: no registry fetch, no rule update, no LLM.
    #[arg(long, global = true)]
    offline: bool,

    /// When to colorize output. `auto` (the default) colors only when stdout
    /// is a terminal; `always` forces color through pipes (e.g. into a pager
    /// or CI log); `never` disables it.
    #[arg(long, global = true, value_enum, default_value_t = Color::Auto)]
    color: Color,

    /// Show full hierarchical trait ids and cleave's diff ledger beneath the
    /// verdict. Default output stays diff-terse.
    #[arg(long, global = true)]
    explain: bool,

    /// Override the detected base version (e.g. `1.2.3`), for proportionality
    /// when the input path carries no version token.
    #[arg(long, global = true, value_name = "VER")]
    base_version: Option<String>,

    /// Override the detected head version. See `--base-version`.
    #[arg(long, global = true, value_name = "VER")]
    head_version: Option<String>,

    /// Interpret the diff with a small LLM at this OpenAI-compatible base URL
    /// (env: ISOMER_LLM). Bare `--llm` uses the default local endpoint.
    #[arg(long, global = true, value_name = "URL", num_args = 0..=1, default_missing_value = "local")]
    llm: Option<String>,

    /// Model name for `--llm` (env: ISOMER_LLM_MODEL); autodetected if omitted.
    #[arg(long, global = true, value_name = "NAME")]
    llm_model: Option<String>,

    /// Bearer token for `--llm` (env: ISOMER_LLM_KEY); omit for local endpoints.
    #[arg(long, global = true, value_name = "KEY")]
    llm_key: Option<String>,

    /// Per-request LLM timeout in seconds.
    #[arg(long, global = true, value_name = "SECS")]
    llm_timeout: Option<u64>,

    /// Follow each dependency the change *adds*: fetch it and report what it can
    /// do, attributed to the dependency. Catches the transitive supply-chain
    /// case (a benign version range pulling in a now-malicious release) a
    /// manifest diff can't see. A network step; off by default.
    #[arg(long, global = true)]
    deps: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Stable wire name for JSON output.
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Whether a finding at this severity fails the run. `--fail-on none`
    /// means report-only: nothing fails.
    fn fails(self, threshold: Severity) -> bool {
        threshold != Severity::None && self >= threshold
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    Terminal,
    Json,
    Sarif,
    Markdown,
    /// The exact payload isomer would send to the LLM (minus the prompt), for
    /// debugging `--llm`.
    Interpret,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Color {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Gate {
    /// Fail only on newly-introduced risk.
    New,
    /// Fail on any changed risk, including escalations of existing findings.
    Any,
}

impl Color {
    /// Apply the choice to the process-global colorize state that cleave's
    /// theme paints through. `auto` leaves the `colored` crate's own TTY and
    /// `NO_COLOR` detection in charge.
    fn apply(self) {
        match self {
            Self::Auto => colored::control::unset_override(),
            Self::Always => colored::control::set_override(true),
            Self::Never => colored::control::set_override(false),
        }
    }
}

/// Argument order is always old, then new (like `diff`).
#[derive(Debug, Subcommand)]
enum Command {
    /// Zero-argument CI entry point: derives base..head from the environment.
    Ci {
        /// Base commit. Default: derived from the CI event, then narrowed to
        /// the merge base with head.
        #[arg(long, value_name = "REV")]
        base: Option<String>,
        /// Head commit. Default: derived from the CI event, falling back to
        /// `HEAD` when the event's commit is absent from a shallow checkout.
        #[arg(long, value_name = "REV")]
        head: Option<String>,
        /// Repository to inspect.
        #[arg(long, value_name = "DIR", default_value = ".")]
        repo: std::path::PathBuf,
        /// Also write `report.{json,sarif,md}` to this directory.
        #[arg(long, value_name = "DIR")]
        out_dir: Option<std::path::PathBuf>,
        /// Refuse to run when the change touches more files than this, rather
        /// than analyzing a subset and reporting it as the whole.
        #[arg(long, value_name = "N", default_value_t = 1000)]
        max_files: usize,
        /// Build outputs of the base commit, laid over the base tree.
        ///
        /// Source tells you what a change says; the artifact tells you what it
        /// does. A backdoor injected by the build — the xz case — is in neither
        /// commit, so only comparing the two builds can see it.
        #[arg(long, value_name = "DIR")]
        base_artifacts: Option<std::path::PathBuf>,
        /// Build outputs of this change. See `--base-artifacts`.
        #[arg(long, value_name = "DIR")]
        head_artifacts: Option<std::path::PathBuf>,
    },
    /// Compare two local trees, following the dependency graph.
    Fs {
        /// Old (base) tree.
        old: String,
        /// New (head) tree.
        new: String,
    },
    /// Compare two commits, branches, or tags of a remote repository.
    Git {
        /// Repository URL.
        #[arg(long)]
        repo: String,
        /// Old (base) ref.
        old: String,
        /// New (head) ref.
        new: String,
    },
    /// Compare two published package versions.
    Purl {
        /// Old (base) purl, e.g. pkg:npm/left-pad@1.3.0.
        old: String,
        /// New (head) purl.
        new: String,
    },
    /// Compare two container images.
    Oci {
        /// Old (base) image reference.
        old: String,
        /// New (head) image reference.
        new: String,
    },
}

fn main() -> ExitCode {
    disable_analysis_cache_if_requested();
    let cli = Cli::parse();
    cli.color.apply();
    match run(&cli) {
        Ok(clean) if clean => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(EXIT_FINDINGS),
        Err(err) => {
            eprintln!("isomer: {err:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// `ISOMER_NO_CACHE=1` disables the analysis-result cache for the run, so a
/// scan always recomputes from the current bytes and rules — mirroring scan's
/// `SCAN_NO_ANALYSIS_CACHE`. Use it after changing traits or the analyzer, when
/// a cache hit would otherwise serve a stale verdict.
///
/// Set through cleave's process-wide override rather than by mutating the
/// environment (isomer denies `unsafe`, and Rust 2024's `set_var` is unsafe).
/// cleave turns the downstream filefacts extraction cache off with it; the YARA
/// and trait-mapper *compilation* caches stay on — they hold compiled rules,
/// not sample analysis, and recompiling costs seconds per run. An explicit
/// `CLEAVE_SKIP_CACHE` still resolves normally when this switch is off.
fn disable_analysis_cache_if_requested() {
    if std::env::var("ISOMER_NO_CACHE").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")) {
        cleave::cache::set_skip_cache_override(Some(true));
    }
}

/// Neutralize control characters in untrusted, sample-derived display text — a
/// matched evidence line, a dependency or action name lifted from the artifact.
/// Left raw, an ANSI escape (`\x1b…`) in a malicious sample could spoof the
/// terminal: clear the screen, fake a `CLEAN` verdict, or hide the real one from
/// the analyst who trusts this output. Applied where the string is built, so the
/// terminal render and the JSON envelope share one clean copy. Byte-for-byte
/// fidelity of the *matched bytes* stays available in `--format json`'s hex for
/// binaries; here the goal is a display that cannot lie about what it shows.
pub(crate) fn printable(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || reorders(c) {
                '·'
            } else {
                c
            }
        })
        .collect()
}

/// Characters that change how the *rest* of a line renders while being
/// invisible themselves — the Trojan Source family (CVE-2021-42574).
///
/// A bidi override makes a file display one thing and execute another, which is
/// exactly the deception isomer exists to expose: evidence that reproduced one
/// would show an analyst the attacker's preferred reading of the very line
/// being flagged. `char::is_control` does not cover these — they are format
/// (Cf) characters, not control (Cc) — so they are named here.
///
/// Only the explicit overrides, isolates, and zero-width padding are
/// neutralized. Ordinary right-to-left script renders normally, and ZWJ/ZWNJ
/// are left alone because Indic, Arabic, and emoji sequences need them and
/// neither reorders text.
const fn reorders(c: char) -> bool {
    matches!(c,
        '\u{200b}'                  // zero-width space
        | '\u{200e}' | '\u{200f}'   // LRM, RLM
        | '\u{202a}'..='\u{202e}'   // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}'   // LRI, RLI, FSI, PDI
        | '\u{feff}'                // BOM appearing mid-text
    )
}

/// Clip display text to `max` *characters*, marking the cut with an ellipsis.
/// Char-aware, so a multi-byte character is never split in half — and named
/// apart from `String::truncate`, which counts bytes and would panic here.
pub(crate) fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// Broken-pipe-safe write: a closed downstream pipe (e.g. `| head`) is a normal
/// exit, not a panic. `println!` would panic here.
pub(crate) fn write_stdout(s: &str) -> anyhow::Result<()> {
    use std::io::{self, Write};
    let mut out = io::stdout().lock();
    match out.write_all(s.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Runs the selected verb; returns whether the delta is clean at `--fail-on`.
fn run(cli: &Cli) -> anyhow::Result<bool> {
    match &cli.command {
        Command::Ci {
            base,
            head,
            repo,
            out_dir,
            max_files,
            base_artifacts,
            head_artifacts,
        } => ci::run(
            cli,
            &ci::Args {
                base: base.clone(),
                head: head.clone(),
                repo: repo.clone(),
                out_dir: out_dir.clone(),
                max_files: *max_files,
                base_artifacts: base_artifacts.clone(),
                head_artifacts: head_artifacts.clone(),
            },
        ),
        Command::Fs { old, new } => fs::run(Path::new(old), Path::new(new), cli),
        Command::Git { .. } => anyhow::bail!("`isomer git` is not implemented yet"),
        Command::Purl { old, new } => fetch::compare("purl", old, new, cli),
        Command::Oci { old, new } => {
            fetch::compare("oci", &fetch::oci_purl(old), &fetch::oci_purl(new), cli)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sample is free to embed terminal escapes; the report must not replay
    /// them into the terminal of the analyst reading the verdict.
    #[test]
    fn escapes_cannot_reach_the_terminal() {
        let spoof = "\u{1b}[2J\u{1b}[H  CLEAN  no findings";
        assert!(!printable(spoof).contains('\u{1b}'));
        assert!(!printable("a\rb\nc").contains(['\r', '\n']));
        assert_eq!(printable("ordinary text"), "ordinary text");
    }

    /// Trojan Source (CVE-2021-42574): a bidi override reorders the rest of the
    /// line, so the evidence an analyst reads is not the code that runs.
    #[test]
    fn bidi_overrides_cannot_reorder_evidence() {
        // U+202E is what makes the reversed tail read as an innocuous comment;
        // rustc denies the literal character in source for the same reason, so
        // it is written here as an escape.
        let trojan = "execSync(\"id\"); /* \u{202e} evil ; )\"di\"(cnyScexe \u{202c} */";
        let safe = printable(trojan);
        for c in [
            '\u{202e}', '\u{202c}', '\u{202a}', '\u{2066}', '\u{200f}', '\u{feff}',
        ] {
            assert!(!safe.contains(c), "{c:?} survived");
        }
        // Right-to-left *script* is legitimate content and must survive intact,
        // as must ZWJ/ZWNJ, which real scripts and emoji depend on.
        assert_eq!(printable("مرحبا שלום"), "مرحبا שלום");
        assert_eq!(printable("a\u{200d}b\u{200c}c"), "a\u{200d}b\u{200c}c");
    }
}
