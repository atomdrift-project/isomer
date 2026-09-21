//! The run's settings, as the library sees them.
//!
//! Everything the analysis, the renderers, and the network steps need from the
//! command line, and nothing else: no subcommand, no argv, no clap. The binary
//! fills one of these in from its `Cli`; another caller fills it in directly.

use crate::{Format, Gate, Severity};

/// One run's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Minimum severity that fails the run (exit code 1).
    pub fail_on: Severity,

    /// What the exit code gates on. `new` (default) fails only on
    /// newly-introduced risk — the CI-relevant case, so a pre-existing issue
    /// isn't re-litigated every run. `any` also fails on escalations of
    /// findings that already existed in the base version.
    pub gate: Gate,

    /// Output format.
    pub format: Format,

    /// Hard guarantee: no registry fetch, no rule update, no LLM.
    pub offline: bool,

    /// Skip current registry metadata checks for packages and declared
    /// dependencies. These checks are enabled by default; `offline` also
    /// disables them.
    pub no_follow: bool,

    /// Fetch added and changed runtime dependencies. Compare behavioral/risk
    /// profiles for changed versions and unambiguous replacements. A network
    /// step; off by default. Uses current, not historical, range resolutions.
    pub deps: bool,

    /// Whether a long network step should draw a spinner: only when a human is
    /// watching *and* reading the terminal report. A piped or JSON run stays
    /// quiet so its output is exactly the report.
    pub progress: bool,

    /// Interpret the diff with a small LLM at this OpenAI-compatible base URL
    /// (env: ISOMER_LLM). `Some("local")` uses the default local endpoint.
    pub llm: Option<String>,

    /// Model name for `llm` (env: ISOMER_LLM_MODEL); autodetected if omitted.
    pub llm_model: Option<String>,

    /// Bearer token for `llm` (env: ISOMER_LLM_KEY); omit for local endpoints.
    pub llm_key: Option<String>,

    /// Per-request LLM timeout in seconds.
    pub llm_timeout: Option<u64>,

    /// Override the detected base version (e.g. `1.2.3`), for proportionality
    /// when the input path carries no version token.
    pub base_version: Option<String>,

    /// Override the detected head version. See `base_version`.
    pub head_version: Option<String>,
}

/// The command line's own defaults, so a library caller and a bare `isomer`
/// invocation start from the same settings and only the overrides differ.
///
/// The steps that cost money or disclose a coordinate — `deps` and the
/// interpreter — stay off until asked for, as they are on the command line.
impl Default for Options {
    fn default() -> Self {
        Self {
            fail_on: Severity::High,
            gate: Gate::New,
            format: Format::Terminal,
            offline: false,
            no_follow: false,
            deps: false,
            progress: false,
            llm: None,
            llm_model: None,
            llm_key: None,
            llm_timeout: None,
            base_version: None,
            head_version: None,
        }
    }
}

// The check that these defaults match clap's lives in the binary's test
// module, next to the `Cli` that declares them — it is the only place both
// are in scope at once.
