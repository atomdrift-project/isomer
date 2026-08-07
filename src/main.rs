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

mod evidence;
mod fs;
mod risk;
mod rubric;
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Color {
    Auto,
    Always,
    Never,
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
    Ci,
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

/// Runs the selected verb; returns whether the delta is clean at `--fail-on`.
fn run(cli: &Cli) -> anyhow::Result<bool> {
    match &cli.command {
        Command::Ci => anyhow::bail!("`isomer ci` is not implemented yet"),
        Command::Fs { old, new } => fs::run(Path::new(old), Path::new(new), cli),
        Command::Git { .. } => anyhow::bail!("`isomer git` is not implemented yet"),
        Command::Purl { .. } => anyhow::bail!("`isomer purl` is not implemented yet"),
        Command::Oci { .. } => anyhow::bail!("`isomer oci` is not implemented yet"),
    }
}
