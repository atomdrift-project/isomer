//! The plain-text payload the interpreter reads, and `--format interpret` prints.

use crate::Severity;

use super::Analysis;
use super::remediation::Remediation;

impl Analysis<'_> {
    /// Build the plain-text payload describing the diff, sent to the LLM (and
    /// shown verbatim by `--format interpret`). No color, no rail — just the
    /// structured behavioral delta plus the matched code/bytes.
    pub(crate) fn llm_context(&self) -> Result<String, std::fmt::Error> {
        use std::fmt::Write as _;
        let (a, naming, prop) = (&self.assessment, &self.naming, &self.prop);
        let mut s = String::new();
        writeln!(s, "artifact: {}", naming.name)?;
        if let (Some(o), Some(n)) = (&naming.old, &naming.new) {
            let bump = naming
                .bump
                .map(|b| format!(" ({})", b.describe()))
                .unwrap_or_default();
            writeln!(s, "version: {} -> {}{bump}", o.raw, n.raw)?;
        }
        if let Some(r) = self.shown_risk() {
            writeln!(s, "ml_malware_probability: {:.2} -> {:.2}", r.old, r.new)?;
        }
        // Proportionality is an attack prior only for a capability gain. Once
        // executable analysis has proved a focused cleanup, repeating the raw
        // "disproportionate gain" conclusion contradicts the stronger
        // direction-of-change evidence and predictably misleads small models.
        if self.remediation == Some(Remediation::FocusedCleanup) {
            writeln!(
                s,
                "transition: machine-verified focused remediation (proportionality escalation suppressed)"
            )?;
        } else if let Some(n) = prop.drift.note() {
            writeln!(s, "proportionality: {n}")?;
        }
        if let Some(n) = &prop.skew {
            writeln!(s, "change shape: {n}")?;
        }
        s.push_str("\nDIFFERENTIAL SHAPE (high-signal facts):\n");
        for line in self.differential_summary() {
            writeln!(s, "- {line}")?;
        }
        s.push_str(
            "\nInterpret the indicators above as a joined differential, not as isolated labels.\n",
        );
        writeln!(
            s,
            "deterministic gate is {} before any model opinion; a passing gate is not a veto, but package size, ordinary assets, or generic library behavior alone are not grounds to override it.",
            if self.clean() { "PASS" } else { "FAIL" }
        )?;
        if self.remediation == Some(Remediation::FocusedCleanup) {
            s.push_str(
                "focused-remediation proof: at least two changed handlers now have an unconditional return as their first statement, and a new cleanup routine deletes the named attack artifact. Static traits retained below those returns are inactive forensic residue. Classify the transition direction; infer live execution only from a separate reachable path shown in the differential.\n",
            );
        }
        let identities = self.identity_summary();
        if !identities.is_empty() {
            s.push_str("\nCLAIMED IDENTITY (context, not proof):\n");
            for line in identities {
                writeln!(s, "- {line}")?;
            }
        }

        let (fresh, expanded): (Vec<_>, Vec<_>) = a
            .behavioral
            .categories
            .iter()
            .partition(|c| a.behavioral.is_new_category(c));
        if !fresh.is_empty() {
            writeln!(s, "\nNEW capability classes (absent in old version):")?;
            for c in &fresh {
                writeln!(
                    s,
                    "- {} [{}]: {} ({} new traits)",
                    c.label,
                    c.severity.as_str(),
                    c.namespaces.join(", "),
                    c.new_ids.len()
                )?;
            }
        }
        if !expanded.is_empty() {
            writeln!(
                s,
                "\nEXPANDED capability classes (already present in old version):"
            )?;
            for c in &expanded {
                writeln!(
                    s,
                    "- {} [{}]: {} (+{} traits)",
                    c.label,
                    c.severity.as_str(),
                    c.namespaces.join(", "),
                    c.new_ids.len()
                )?;
            }
        }
        let removed = self.removed_high_risk_behaviors();
        if !removed.is_empty() {
            writeln!(s, "\nREMOVED high-risk behavior:")?;
            for group in removed {
                writeln!(s, "- {}: {}", group.namespace, group.traits.join(", "))?;
            }
        }
        if a.signature.severity() != Severity::None {
            writeln!(s, "\nknown-bad signatures matched:")?;
            for m in &a.signature.ids {
                let name = crate::rubric::short_name(&m.id);
                if m.desc.is_empty() {
                    writeln!(s, "- [{}] {}", m.severity.as_str(), name)?;
                } else {
                    writeln!(s, "- [{}] {} — {}", m.severity.as_str(), name, m.desc)?;
                }
            }
            if let Some(cve) = &a.signature.cve {
                writeln!(s, "  referenced CVE: {cve}")?;
            }
        }
        if !a.structure.facts.is_empty() {
            writeln!(
                s,
                "\nstructural changes (raw binary facts, no rule needed):"
            )?;
            for f in &a.structure.facts {
                let kind = f.kind.as_str();
                writeln!(
                    s,
                    "- [{}] {kind} {}: {}",
                    f.severity.as_str(),
                    f.label,
                    f.sentence()
                )?;
            }
        }
        if !a.identity.changes.is_empty() {
            writeln!(s, "\nidentity changes (publisher/signer):")?;
            for ch in &a.identity.changes {
                let (old, new) = ch.shown();
                writeln!(s, "- {}: {} -> {}", ch.label, old, new)?;
            }
        }

        // The distilled top hunks — strongest rule first, one per rule, tiered
        // context — not every match. A broad trait hitting dozens of benign
        // files must not bury the one change that matters (unrealircd's
        // `substr: SYSTEM` read to the model as a false positive when all 30
        // windows were dumped).
        let hunks = self.hunks(crate::evidence::LLM_HUNKS);
        if !hunks.is_empty() {
            writeln!(
                s,
                "\nchanged code / bytes (top {} matched regions by rule score):",
                hunks.len()
            )?;
            let mut rendered = String::new();
            crate::evidence::render_hunks(&mut rendered, &hunks)?;
            s.push_str(rendered.trim_end());
            s.push('\n');
        }

        // The full source diff for every changed source file — the payload's
        // safety net. The sections above are what the rubric *matched*; a novel
        // attack composed of innocent atoms matches nothing, so without this the
        // model would be asked to judge a change it cannot see. Sub-Notable
        // atoms are named first as reading hints, then the diff itself.
        let changes = self.source_changes();
        if !changes.is_empty() {
            writeln!(
                s,
                "\nsource diffs (full text of every file whose behavior-bearing traits changed):"
            )?;
            for c in changes {
                let hints: Vec<&str> = c
                    .atoms
                    .iter()
                    .filter(|at| at.gained && !crate::rubric::is_finding(at.crit))
                    .map(|at| at.desc.as_str())
                    .filter(|d| !d.is_empty())
                    .collect();
                writeln!(s, "\n--- {} ---", c.label)?;
                if !hints.is_empty() {
                    writeln!(s, "(new sub-finding atoms: {})", hints.join("; "))?;
                }
                s.push_str(c.diff.trim_end());
                s.push('\n');
            }
        }
        Ok(s)
    }
}
