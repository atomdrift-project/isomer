//! isomer — supply-chain attack detection at a molecular level.
//!
//! Detects whether a change is malicious — introduced by a human, an AI, or
//! the dependency supply chain — by comparing two states of a tree, git ref,
//! package, or OCI image and judging the delta in context.
//!
//! The `isomer` binary is a thin wrapper over this library: it parses the
//! command line into [`options::Options`] and calls one of the verbs
//! ([`ci::run`], [`fs::run`], [`fetch::compare`]).

use clap::ValueEnum;

/// This isomer build, for a caller recording which engine judged a comparison.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod analysis;
pub mod behavior_shift;
pub mod binary;
pub mod ci;
pub mod deps;
pub mod evidence;
pub mod fetch;
pub mod frameworks;
pub mod fs;
pub mod json;
pub mod judgement;
pub mod llm;
pub mod markdown;
pub mod options;
pub mod registry;
pub mod rename;
pub mod risk;
pub mod rubric;
pub mod sarif;
pub mod terminal;
pub mod version;

/// How serious a finding is, ordered worst-highest so the verdict for a set of
/// findings is its maximum. `Medium`, `High`, and `Critical` are what the
/// reports call NOTABLE, SUSPICIOUS, and HOSTILE; `Medium` is the reporting
/// floor, and `--fail-on` names the lowest one that fails a run.
///
/// The variants are deliberately undocumented: a doc comment on a `ValueEnum`
/// variant becomes clap's per-value help, which would rewrite `--fail-on`'s
/// `--help` rendering.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Stable wire name for JSON output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
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
    #[must_use]
    pub fn fails(self, threshold: Severity) -> bool {
        threshold != Severity::None && self >= threshold
    }

    /// This severity as one of scan's three classification bands.
    ///
    /// The inverse of [`risk::Risk::model_severity`], which is how a model
    /// class enters this scale in the first place: `Suspicious` arrives as
    /// `High` and `Hostile` as `Critical`, so they leave the same way.
    ///
    /// Everything below `High` is benign, `Medium` included. `Medium` is the
    /// *reporting* floor — the change is worth naming — and a scale that read
    /// "worth naming" as an alarm would convict most honest releases. The
    /// mapping lives here, rather than at each consumer, so that what
    /// isomer's grades mean stays isomer's own decision.
    #[must_use]
    pub fn band(self) -> scan::Classification {
        match self {
            Self::Critical => scan::Classification::Hostile,
            Self::High => scan::Classification::Suspicious,
            Self::None | Self::Low | Self::Medium => scan::Classification::Benign,
        }
    }
}

/// Which report [`analysis::Analysis::render`] emits: a terminal verdict, the
/// JSON envelope, SARIF for code scanning, Markdown for a step summary or pull
/// request comment, or the raw LLM payload.
///
/// Only `Interpret` is documented at the variant level, because a doc comment
/// on a `ValueEnum` variant becomes clap's per-value help and the other four
/// deliberately render bare in `--format`'s `--help`.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Terminal,
    Json,
    Sarif,
    Markdown,
    /// The exact user payload isomer would send to the LLM (without the system
    /// prompt), for inspection/replay. Like scan, this is local-only and does
    /// not contact the LLM endpoint.
    Interpret,
}

/// What the exit code gates on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Gate {
    /// Fail only on newly-introduced risk.
    New,
    /// Fail on any changed risk, including escalations of existing findings.
    Any,
}

/// Neutralize control characters in untrusted, sample-derived display text — a
/// matched evidence line, a dependency or action name lifted from the artifact.
/// Left raw, an ANSI escape (`\x1b…`) in a malicious sample could spoof the
/// terminal: clear the screen, fake a `CLEAN` verdict, or hide the real one from
/// the analyst who trusts this output. Applied where the string is built, so the
/// terminal render and the JSON envelope share one clean copy. Byte-for-byte
/// fidelity of the *matched bytes* stays available in `--format json`'s hex for
/// binaries; here the goal is a display that cannot lie about what it shows.
#[must_use]
pub fn printable(s: &str) -> String {
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
#[must_use]
pub const fn reorders(c: char) -> bool {
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
#[must_use]
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// Broken-pipe-safe write: a closed downstream pipe (e.g. `| head`) is a normal
/// exit, not a panic. `println!` would panic here.
pub fn write_stdout(s: &str) -> anyhow::Result<()> {
    use std::io::{self, Write};
    let mut out = io::stdout().lock();
    match out.write_all(s.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e.into()),
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

#[cfg(test)]
mod band_tests {
    use super::*;

    #[test]
    fn a_model_class_survives_the_round_trip_into_isomers_scale_and_back() {
        // `Risk::model_severity` is how a model class enters this scale;
        // `band` is how it leaves. A drift between them would let a hostile
        // model verdict arrive as `Critical` and leave as `suspicious`.
        for class in [
            scan::Classification::Benign,
            scan::Classification::Suspicious,
            scan::Classification::Hostile,
        ] {
            let risk = risk::Risk {
                old: 0.0,
                new: 1.0,
                new_classification: class,
            };
            assert_eq!(
                risk.model_severity().band(),
                class,
                "round trip for {class}"
            );
        }
    }

    #[test]
    fn the_reporting_floor_is_not_an_alarm() {
        // Medium is "this change is worth naming", which most honest releases
        // reach. Reading it as an alarm would convict them.
        assert_eq!(Severity::None.band(), scan::Classification::Benign);
        assert_eq!(Severity::Low.band(), scan::Classification::Benign);
        assert_eq!(Severity::Medium.band(), scan::Classification::Benign);
    }

    #[test]
    fn band_never_lowers_across_the_scale() {
        // Ordered input, ordered output: a worse isomer severity can never map
        // to a milder band than a lesser one.
        let bands: Vec<u8> = [
            Severity::None,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ]
        .iter()
        .map(|s| s.band() as u8)
        .collect();
        assert!(
            bands.windows(2).all(|w| w[0] <= w[1]),
            "band() must be monotonic over Severity, got {bands:?}"
        );
    }
}
