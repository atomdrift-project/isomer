//! Execution injected by a change's own lines, read by taxonomy role.
//!
//! A backdoor is often a line or two: request data handed to a dynamic call, a
//! decoded string handed to `eval`. Hand-written composites name these shapes
//! one at a time, and a composite goes silent when one of its building blocks
//! moves. The roles here are the taxonomy's own namespaces, so they hold across
//! languages and across trait reorganizations: a trait that reads
//! attacker-supplied request data is *input* and a trait that runs code chosen
//! at run time is *execution*, whatever the language or the rule's name.
//!
//! Both readings look only at the [changed lines](crate::changed_lines), where
//! every trait sits on a line the change touched, and each is sufficient alone:
//!
//! * **input to execution** — the changed lines put request input within a
//!   few lines of an execution the file never had.
//! * **concentrated execution** — an execution capability the release never
//!   had arrives in a handful of lines, and it is the only new capability the
//!   release brings.
//!
//! Both are read against the release promise: a patch has no business adding
//! code execution, while a major release may.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::Severity;
use crate::analysis::Pair;
use crate::behavior_shift::Profile;
use crate::version::{Bump, Promise};

/// Attacker-supplied request data. Outbound request construction shares the
/// `request/` parent and is deliberately absent.
const INPUT: &[&str] = &[
    "micro-behaviors/communications/http/request/superglobal",
    "micro-behaviors/communications/http/request/params",
    "micro-behaviors/communications/http/request/form-input",
    "micro-behaviors/communications/http/request/query",
    "micro-behaviors/communications/http/request/cgi",
];

/// Code chosen at run time: a callee, a script, an expression.
const DYNAMIC: &[&str] = &[
    "micro-behaviors/metaprogramming/reflection/invoke",
    "micro-behaviors/process/interpreter/eval",
];

/// A program started at run time.
const COMMAND: &[&str] = &["micro-behaviors/process/create"];

/// How near input must sit to an execution to be read as feeding it.
const WINDOW: usize = 3;
/// The most lines a concentrated execution may span.
const CONCENTRATED: usize = 3;
/// The fewest lines a file needs for a few of them to be a concentration
/// rather than the file itself.
const MIN_FILE_LINES: usize = 40;

/// How much an execution can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Power {
    Command,
    Dynamic,
}

/// Which reading found the injection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind {
    InputToExecution,
    ConcentratedExecution,
}

/// Execution a change's lines brought into a file.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Injection {
    pub severity: Severity,
    pub kind: Kind,
    /// The file, by its artifact-relative path.
    pub file: String,
    /// The execution's line in the new file.
    pub line: usize,
    /// The trait that read as execution.
    pub execution: String,
    /// The trait that read as input, for [`Kind::InputToExecution`].
    pub input: Option<String>,
}

impl Injection {
    /// The reason a reader needs first.
    pub(crate) fn describe(&self) -> String {
        let what = match self.kind {
            Kind::InputToExecution => "passes request data to code execution",
            Kind::ConcentratedExecution => "adds code execution in a few lines",
        };
        format!("{what} at {}:{}", self.file, self.line)
    }
}

/// One finding of a changed-lines file at one of its lines, whatever its role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Located<'a> {
    id: &'a str,
    line: usize,
    /// Absent from the whole old side: the change brought it.
    gained: bool,
}

/// What a change's lines are read against.
pub(super) struct Context<'a> {
    /// Every trait id the old side exhibited, whole file and removed lines.
    pub old: &'a Profile,
    /// Behavior classes the comparison gained that the old side lacked —
    /// what the file does, not structural facts about it.
    pub new_classes: &'a HashSet<String>,
    pub bump: Option<Bump>,
}

/// Every injection across the changed-lines pairs, analyzed with `options`,
/// gravest first. Each reading is reported on its own, so a reader sees how
/// many independent ways the change reads as injected.
pub(super) fn found<'p>(
    pairs: impl IntoIterator<Item = &'p Pair>,
    options: &cleave::AnalysisOptions,
    context: &Context<'_>,
) -> Vec<Injection> {
    let mut all: Vec<Injection> = pairs
        .into_iter()
        .filter_map(|pair| Some(in_file(&pair.label, pair.new.as_deref()?, options, context)))
        .flatten()
        .inspect(|i| {
            log::debug!(
                "injection: {} ({:?}, {:?}) via {}",
                i.describe(),
                i.kind,
                i.severity,
                i.execution
            );
        })
        .collect();
    all.sort_by_key(|i| std::cmp::Reverse(i.severity));
    all
}

/// The injections one changed-lines file's lines carry.
fn in_file(
    label: &str,
    path: &Path,
    options: &cleave::AnalysisOptions,
    context: &Context<'_>,
) -> Vec<Injection> {
    let Some(report) = crate::evidence::analyze(path, options) else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read(path) else {
        return Vec::new();
    };
    let newlines: Vec<usize> = text
        .iter()
        .enumerate()
        .filter_map(|(i, &b)| (b == b'\n').then_some(i))
        .collect();
    let line_of = |offset: u64| {
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        newlines.partition_point(|&n| n < offset) + 1
    };
    // Each finding's matches where cleave places them: exact byte offsets in
    // this file, whose lines are the real file's. A composite's note stands
    // for its building blocks at that spot: when it wins the placement, the
    // atoms it proves are read through it.
    let notes = cleave::context::notes(&report.findings, &report.context);
    let refs: HashMap<&str, &[cleave::types::Istr]> = report
        .findings
        .iter()
        .map(|f| (f.id.as_str(), f.trait_refs.as_slice()))
        .collect();
    let located: Vec<Located<'_>> = notes
        .iter()
        .flatten()
        .filter(|n| crate::rubric::is_finding(n.crit))
        .flat_map(|n| {
            let proved = refs.get(n.id.as_str()).copied().unwrap_or_default();
            std::iter::once(n.id.as_str())
                .chain(proved.iter().map(cleave::types::Istr::as_str))
                .map(|id| Located {
                    id,
                    line: line_of(n.off),
                    gained: !context.old.contains(id),
                })
        })
        .collect();
    judge(label, &located, newlines.len() + 1, context)
}

/// What a trait is, by its namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Input,
    Execution(Power),
}

fn role(id: &str) -> Option<Role> {
    let namespace = id.split_once("::").map_or(id, |(namespace, _)| namespace);
    let under = |prefixes: &[&str]| {
        prefixes.iter().any(|p| {
            namespace
                .strip_prefix(p)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
    };
    if under(INPUT) {
        Some(Role::Input)
    } else if under(DYNAMIC) {
        Some(Role::Execution(Power::Dynamic))
    } else if under(COMMAND) {
        Some(Role::Execution(Power::Command))
    } else {
        None
    }
}

/// Read one file's located findings, by both readings independently.
/// `lines` is the file's line count.
fn judge(
    label: &str,
    located: &[Located<'_>],
    lines: usize,
    context: &Context<'_>,
) -> Vec<Injection> {
    let promise = context.bump.map_or(Promise::Nothing, |b| b.kind.promise());
    let executions: Vec<(&Located<'_>, Power)> = located
        .iter()
        .filter_map(|l| match role(l.id) {
            Some(Role::Execution(power)) if l.gained => Some((l, power)),
            _ => None,
        })
        .collect();
    let injection = |kind, severity, at: &Located<'_>, input: Option<&Located<'_>>| Injection {
        severity,
        kind,
        file: label.to_owned(),
        line: at.line,
        execution: at.id.to_owned(),
        input: input.map(|i| i.id.to_owned()),
    };
    let mut out = Vec::new();

    // Input to execution: the input may be one the file always had — a
    // plugin that has read cookies for years can still start executing them.
    let fed = executions
        .iter()
        .filter_map(|&(at, power)| {
            let input = located
                .iter()
                .filter(|l| role(l.id) == Some(Role::Input))
                .find(|i| i.line.abs_diff(at.line) <= WINDOW)?;
            Some((at, power, input))
        })
        .max_by_key(|(_, power, _)| *power);
    if let Some((at, _, input)) = fed {
        let severity = match promise {
            Promise::Nothing => Severity::Critical,
            Promise::Features => Severity::High,
            Promise::Anything => Severity::Medium,
        };
        out.push(injection(Kind::InputToExecution, severity, at, Some(input)));
    }

    // Concentrated execution: the new capability is all of what the release
    // added, and it fits in a few lines of a file large enough for that to be
    // a sliver of it. Independent of any input. A new class found on those
    // same lines — a composite naming what they do — is the execution
    // described again, not a second feature. An execution whose class the
    // release already had is a new call site of an old capability: a tool
    // that always spawned `dotnet` and now also probes `dotnet --version`.
    let spans: HashSet<usize> = executions.iter().map(|(l, _)| l.line).collect();
    let classes: HashSet<String> = located
        .iter()
        .filter(|l| l.gained && spans.iter().any(|&s| s.abs_diff(l.line) <= WINDOW))
        .filter_map(|l| crate::rubric::capability_class(l.id))
        .collect();
    let alone = context.new_classes.iter().all(|c| classes.contains(c));
    let strongest = executions
        .iter()
        .filter(|(l, _)| {
            crate::rubric::capability_class(l.id).is_some_and(|c| context.new_classes.contains(&c))
        })
        .max_by_key(|(_, power)| *power);
    if let Some(&(at, power)) = strongest
        && lines >= MIN_FILE_LINES
        && spans.len() <= CONCENTRATED
        && alone
    {
        let severity = match (promise, power) {
            (Promise::Nothing, Power::Dynamic) => Severity::Critical,
            (Promise::Nothing, Power::Command) | (Promise::Features, Power::Dynamic) => {
                Severity::High
            }
            _ => Severity::None,
        };
        if severity > Severity::None {
            out.push(injection(Kind::ConcentratedExecution, severity, at, None));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::BumpKind;

    const COOKIE: &str = "micro-behaviors/communications/http/request/superglobal::cookie";
    const CALL: &str =
        "micro-behaviors/metaprogramming/reflection/invoke::array-index-dynamic-call";
    const SPAWN: &str = "micro-behaviors/process/create/spawn::child-process";
    const CLIENT: &str = "micro-behaviors/communications/http/request/client::fetch";

    fn at(id: &str, line: usize, gained: bool) -> Located<'_> {
        Located { id, line, gained }
    }

    fn judged(located: &[Located<'_>], new_classes: &[&str], bump: Option<Bump>) -> Vec<Injection> {
        let old = Profile::default();
        let new_classes = new_classes.iter().map(|c| (*c).to_owned()).collect();
        let context = Context {
            old: &old,
            new_classes: &new_classes,
            bump,
        };
        judge("pkg/wptouch.php", located, 900, &context)
    }

    #[test]
    fn roles_follow_the_taxonomy_not_the_rule() {
        assert_eq!(role(COOKIE), Some(Role::Input));
        assert_eq!(role(CALL), Some(Role::Execution(Power::Dynamic)));
        assert_eq!(role(SPAWN), Some(Role::Execution(Power::Command)));
        // Making a request is not receiving one.
        assert_eq!(role(CLIENT), None);
        // A namespace that merely shares a prefix's spelling is not under it.
        assert_eq!(
            role("micro-behaviors/communications/http/request/superglobals::x"),
            None
        );
    }

    /// The kinds that fired, with their severities.
    fn kinds(found: &[Injection]) -> Vec<(Kind, Severity)> {
        found.iter().map(|i| (i.kind, i.severity)).collect()
    }

    #[test]
    fn the_wptouch_backdoor_reads_as_injected_both_ways() {
        let patch = Some(Bump::new(BumpKind::Patch, 1));
        // The plugin always read cookies, but never called a function its
        // input named; that one call is all the release added.
        let wptouch = [at(COOKIE, 513, false), at(CALL, 513, true)];
        let found = judged(&wptouch, &["metaprogramming/reflection"], patch);
        assert_eq!(
            kinds(&found),
            [
                (Kind::InputToExecution, Severity::Critical),
                (Kind::ConcentratedExecution, Severity::Critical),
            ]
        );
        assert_eq!(
            found[0].describe(),
            "passes request data to code execution at pkg/wptouch.php:513"
        );
        // A major release may restructure: worth a look, not a gate.
        let major = Some(Bump::new(BumpKind::Major, 1));
        assert_eq!(
            kinds(&judged(&wptouch, &["metaprogramming/reflection"], major)),
            [(Kind::InputToExecution, Severity::Medium)]
        );
    }

    #[test]
    fn each_reading_stands_without_the_other() {
        let patch = Some(Bump::new(BumpKind::Patch, 1));
        // Input far from the call does not feed it, but the call is still a
        // concentrated, lone new capability.
        let apart = [at(COOKIE, 100, false), at(CALL, 513, true)];
        assert_eq!(
            kinds(&judged(&apart, &["metaprogramming/reflection"], patch)),
            [(Kind::ConcentratedExecution, Severity::Critical)]
        );
        // A composite naming the call, on its line, is the call described
        // again rather than another feature.
        let named = [
            at(CALL, 513, true),
            at(
                "objectives/command-and-control/backdoor/webshell::dispatch",
                513,
                true,
            ),
        ];
        assert_eq!(
            kinds(&judged(
                &named,
                &["metaprogramming/reflection", "command-and-control"],
                patch
            )),
            [(Kind::ConcentratedExecution, Severity::Critical)]
        );
        // Beside another new capability elsewhere it is part of a feature —
        // unless request data feeds it.
        assert_eq!(
            judged(&apart, &["metaprogramming/reflection", "fs/write"], patch),
            []
        );
        let fed = [at(COOKIE, 512, false), at(CALL, 513, true)];
        assert_eq!(
            kinds(&judged(
                &fed,
                &["metaprogramming/reflection", "fs/write"],
                patch
            )),
            [(Kind::InputToExecution, Severity::Critical)]
        );
    }

    #[test]
    fn an_execution_the_file_already_had_is_not_injected() {
        let patch = Some(Bump::new(BumpKind::Patch, 1));
        let known = [at(COOKIE, 513, false), at(CALL, 513, false)];
        assert_eq!(judged(&known, &[], patch), []);
    }

    #[test]
    fn a_new_call_site_of_an_existing_capability_is_not_concentrated() {
        // @uipath/packager-tool-workflowcompiler 0.0.17: a compiler that
        // always spawned `dotnet` adds an `execSync("dotnet --version")`
        // probe. The rule is new to the file; process creation is not new
        // to the release, so nothing new arrived in those lines.
        let patch = Some(Bump::new(BumpKind::Patch, 2));
        let probe = [at(SPAWN, 1245, true)];
        assert_eq!(judged(&probe, &[], patch), []);
        // Request data reaching it is still read, whatever the class.
        let fed = [at(COOKIE, 1244, false), at(SPAWN, 1245, true)];
        assert_eq!(
            kinds(&judged(&fed, &[], patch)),
            [(Kind::InputToExecution, Severity::Critical)]
        );
    }

    #[test]
    fn concentration_is_judged_by_power_and_promise() {
        let patch = Some(Bump::new(BumpKind::Patch, 1));
        let minor = Some(Bump::new(BumpKind::Minor, 1));
        let spawn = [at(SPAWN, 40, true)];
        assert_eq!(
            kinds(&judged(&spawn, &["process/create"], patch)),
            [(Kind::ConcentratedExecution, Severity::High)]
        );
        assert_eq!(judged(&spawn, &["process/create"], minor), []);
        // Spread over many lines, execution is a feature being built.
        let spread: Vec<_> = (0..6).map(|i| at(CALL, 100 + i * 50, true)).collect();
        assert_eq!(judged(&spread, &["metaprogramming/reflection"], patch), []);
    }
}
