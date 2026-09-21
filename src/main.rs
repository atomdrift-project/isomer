//! isomer — supply-chain attack detection at a molecular level.
//!
//! The command line over the `isomer` library: parse the arguments, turn them
//! into an `Options`, run the selected verb, and map its answer onto the exit code.
//!
//! Exit code contract (stable; CI gates on these):
//! - `0` — clean: no findings at or above `--fail-on`
//! - `1` — findings at or above `--fail-on`
//! - `2` — operational error (never conflated with findings)

use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use isomer::options::Options;
use isomer::{Format, Gate, Severity, ci, fetch, fs};

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

    /// Fetch added and changed runtime dependencies. Compare behavioral/risk
    /// profiles for changed versions and unambiguous replacements. A network
    /// step; off by default. Uses current, not historical, range resolutions.
    #[arg(long, global = true)]
    deps: bool,

    /// Skip current registry metadata checks for packages and declared dependencies.
    /// These checks are enabled by default; --offline also disables them.
    #[arg(long, global = true)]
    no_follow: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Color {
    Auto,
    Always,
    Never,
}

impl Cli {
    /// Whether a long network step should draw a spinner: only when a human is
    /// watching *and* reading the terminal report. A piped or JSON run stays
    /// quiet so its output is exactly the report.
    fn progress(&self) -> bool {
        self.format == Format::Terminal && std::io::IsTerminal::is_terminal(&std::io::stderr())
    }
}

impl From<&Cli> for Options {
    /// Everything the library needs from the command line, and nothing else.
    /// The verb and its operands stay behind in [`Command`].
    fn from(cli: &Cli) -> Self {
        Self {
            fail_on: cli.fail_on,
            gate: cli.gate,
            format: cli.format,
            offline: cli.offline,
            no_follow: cli.no_follow,
            deps: cli.deps,
            progress: cli.progress(),
            llm: cli.llm.clone(),
            llm_model: cli.llm_model.clone(),
            llm_key: cli.llm_key.clone(),
            llm_timeout: cli.llm_timeout,
            base_version: cli.base_version.clone(),
            head_version: cli.head_version.clone(),
        }
    }
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

/// Runs the selected verb; returns whether the delta is clean at `--fail-on`.
fn run(cli: &Cli) -> anyhow::Result<bool> {
    refresh_rules(cli);
    let opts = Options::from(cli);
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
            &opts,
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
        Command::Fs { old, new } => fs::run(Path::new(old), Path::new(new), &opts),
        Command::Git { .. } => anyhow::bail!("`isomer git` is not implemented yet"),
        Command::Purl { old, new } => fetch::compare("purl", old, new, &opts),
        Command::Oci { old, new } => {
            fetch::compare("oci", &fetch::oci_purl(old), &fetch::oci_purl(new), &opts)
        }
    }
}

/// Bring cleave's trait bundle current before the first comparison, exactly the
/// way scan does: adopt an existing traits checkout if one is present, otherwise
/// install from the update bucket, then refresh once a day.
///
/// Every isomer command analyzes both sides of a diff, so there is no command
/// that wants stale rules. Without this the first run on a fresh machine has no
/// traits at all and fails on rule resolution rather than on the artifact —
/// which is precisely how it failed in CI. `--offline` opts out, as does
/// scan's own `SCAN_NO_UPDATE`; a refresh that cannot reach the bucket stamps
/// the attempt and moves on, so an offline host degrades to whatever it has
/// rather than blocking.
fn refresh_rules(cli: &Cli) {
    scan::traits_repo::prepare_runtime_env();
    scan::auto_update::refresh_if_stale(
        false,
        cli.offline,
        scan::Mode::default(),
        cli.format == Format::Terminal,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_fs_cli_needs_no_structural_switch() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["isomer", "fs", "a", "b"]).unwrap();
        assert!(matches!(cli.command, Command::Fs { .. }));
        assert!(Cli::try_parse_from(["isomer", "fs", "a", "b", "--structural-only"]).is_err());
    }

    #[test]
    fn a_bare_command_line_and_the_library_defaults_agree() {
        // `Options::default()` states the defaults for a caller that is not a
        // command line. Two sources of truth for one default is one too many:
        // if a `default_value_t` moves and `Options::default` does not, a
        // library caller and a bare `isomer` run would silently judge the same
        // pair differently. This is the only scope holding both.
        use clap::Parser;

        let cli = Cli::try_parse_from(["isomer", "fs", "a", "b"]).unwrap();
        let mut from_argv = Options::from(&cli);
        // `progress` is the one field with no flag behind it: it is computed
        // from the format and whether stderr is a terminal, so it legitimately
        // differs between a piped test run and an interactive one.
        from_argv.progress = Options::default().progress;
        assert_eq!(from_argv, Options::default());
    }

    #[test]
    fn registry_follow_defaults_on_but_offline_and_opt_out_disable_it() {
        use clap::Parser;
        for (flags, expected) in [
            (vec![], true),
            (vec!["--offline"], false),
            (vec!["--no-follow"], false),
        ] {
            let args = [vec!["isomer"], flags, vec!["fs", "before", "after"]].concat();
            assert_eq!(
                isomer::registry::enabled(&Options::from(&Cli::try_parse_from(args).unwrap())),
                expected
            );
        }
    }
}
