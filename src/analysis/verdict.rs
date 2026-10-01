//! Combining the independent signals into the verdicts the gate reads.

use cleave::types::{DiffReportV1, DiffSummary};

use crate::Severity;
use crate::rubric::Assessment;
use crate::version::{Bump, Promise};

use super::detectors::COMPACT;
use super::naming::Naming;
use super::remediation::Remediation;

/// Lower bound of the `malware` risk band.
pub(crate) const MALWARE_BAND: f32 = 0.90;

/// Lower bound of the `suspicious` risk band.
pub(crate) const SUSPICIOUS_BAND: f32 = 0.50;

/// Lower bound of the `elevated` risk band.
pub(super) const ELEVATED_BAND: f32 = 0.15;

/// Map an ML malware probability to a severity band (mirrors the risk words:
/// benign / elevated / suspicious / malware). The LLM's risk floor reads the
/// same bounds, so a model call lands exactly on its band.
pub(crate) fn risk_band(p: f32) -> Severity {
    if p >= MALWARE_BAND {
        Severity::Critical
    } else if p >= SUSPICIOUS_BAND {
        Severity::High
    } else if p >= ELEVATED_BAND {
        Severity::Medium
    } else {
        Severity::None
    }
}

/// Treat Azoth as a strong differential signal only when the probability move
/// is meaningful, not merely because a release crossed 0.50 or 0.90 by a few
/// points. A high-band move needs both a high absolute score and a large jump;
/// a critical-band move still needs a visible delta. The model's calibrated
/// classification caps this signal: a benign decision is not an independent
/// alarm, and a suspicious decision cannot become Critical from probability
/// alone. Structural and behavioral evidence remain independent.
pub(super) fn significant_risk_escalation(risk: crate::risk::Risk) -> Severity {
    const MIN_DELTA: f32 = 0.10;
    const HIGH_SCORE: f32 = 0.75;
    const HIGH_DELTA: f32 = 0.40;

    if risk.delta() < MIN_DELTA {
        return Severity::None;
    }
    let ceiling = risk.model_severity();
    let escalation = match risk_band(risk.new) {
        Severity::Critical => Severity::Critical,
        Severity::High if risk.new >= HIGH_SCORE && risk.delta() >= HIGH_DELTA => Severity::High,
        _ => Severity::None,
    };
    escalation.min(ceiling)
}

/// The two deterministic readings the gate chooses between.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Verdicts {
    /// Everything this change is, new or not — `--gate any`.
    pub(super) overall: Severity,
    /// Only what this change introduced — `--gate new`.
    pub(super) new: Severity,
}

/// Combine the independent signals. Kept pure so simulations exercise the
/// same decision as the CLI without loading models or scanning archives.
pub(super) fn deterministic_verdicts(
    assessment: &Assessment,
    rubric_new: Severity,
    risk_jump: Severity,
    escalation: Severity,
    remediation: Option<Remediation>,
) -> Verdicts {
    if remediation.is_some() {
        let floor = Severity::Medium
            .max(assessment.identity.severity())
            .max(assessment.structure.severity())
            .max(assessment.signature.severity())
            .max(if rubric_new >= Severity::Critical {
                Severity::Critical
            } else {
                Severity::None
            })
            .max(risk_jump);
        Verdicts {
            overall: floor,
            new: floor,
        }
    } else {
        Verdicts {
            overall: assessment.severity().max(risk_jump).max(escalation),
            new: rubric_new.max(risk_jump).max(escalation),
        }
    }
}

/// Behavioral drift weighed against the version bump's promise.
///
/// One value rather than a `bool` beside an `Option<String>`: those encode three
/// real states in six, and every consumer had to re-join them by hand to know
/// which of the two very different sentences it was about to print.
#[derive(Debug)]
pub(crate) enum Drift {
    /// No bump to weigh against, or no capability gained to weigh.
    Unjudged,
    WithinTolerance(String),
    Disproportionate(String),
}

impl Drift {
    /// Whether the gain outran what the bump promised — the escalation signal.
    pub(crate) fn is_disproportionate(&self) -> bool {
        matches!(self, Self::Disproportionate(_))
    }

    /// The phrasing for either judgement. Both are worth telling a reader and
    /// the model: "within tolerance for a patch release" is release-pressure
    /// context, not merely the absence of a finding.
    pub(crate) fn note(&self) -> Option<&str> {
        match self {
            Self::Unjudged => None,
            Self::WithinTolerance(note) | Self::Disproportionate(note) => Some(note),
        }
    }

    /// The note *only* when it is the escalating one, for the surfaces that
    /// report findings rather than context.
    pub(crate) fn escalation_note(&self) -> Option<&str> {
        match self {
            Self::Disproportionate(note) => Some(note),
            _ => None,
        }
    }
}

/// The two change-shape reads: behavioral drift vs the version bump's promise,
/// and behavioral drift vs content drift (`skew`).
#[derive(Debug)]
pub(crate) struct Proportionality {
    pub drift: Drift,
    /// Behavioral change far outpacing content change — the implant tell. A
    /// rewrite moves both together; a surgical backdoor moves behavior on a
    /// small edit (xz: 99% of behavior on a ~20% content change).
    pub skew: Option<String>,
}

impl Proportionality {
    /// `shape` is [`change_shape_escalation`]'s verdict on the same change.
    pub(super) fn eval(
        a: &Assessment,
        naming: &Naming,
        diff: &DiffReportV1,
        shape: Severity,
    ) -> Self {
        let skew = skew_note(a, diff);
        // Proportionality needs both halves of the comparison: a version bump
        // making a promise, and a capability gain to weigh against it.
        let Some(bump) = naming
            .bump
            .filter(|_| a.behavioral.severity() != Severity::None)
        else {
            return Self {
                drift: Drift::Unjudged,
                skew,
            };
        };
        // A medium behavior in a patch is not enough by itself: ordinary
        // plugin maintenance can add one new web/API capability. Require a
        // change-shape signal as well (focused multi-capability edit,
        // endgame deletion, or the existing behavior/content skew read).
        //
        // Skew alone is not enough either. It measures how *surgically* the
        // edit was made, not how much capability arrived, and in a one-file
        // artifact or a tightly-scoped patch the traits scope always outruns
        // the content scopes — so a single added capability clears it for
        // free. An implant brings several classes at once, which is why the
        // focused-source branches below all carry a class floor; give the
        // skew branch the same footing. The case this was costing:
        // contact-form-7-multi-step's own incident-response patch, written by
        // the WordPress.org review team to reset the accounts the attacker
        // created, gained exactly one capability (a user password field) and
        // was escalated to a gate-failing High for it.
        let new_classes = a
            .behavioral
            .categories
            .iter()
            .filter(|c| !c.new_ids.is_empty())
            .count();
        let new_severity = a.new_severity();
        let shape_signal = (skew.is_some()
            && new_classes >= 2
            // A surgical medium-only maintenance change is still allowed to
            // be skewed; skew becomes release-pressure evidence only when the
            // new side contains a gate-worthy capability.
            && new_severity >= Severity::High)
            || shape >= Severity::High;
        let drift = if new_severity > bump.tolerance() && shape_signal {
            Drift::Disproportionate(format!(
                "disproportionate — {} gained a {}-severity capability",
                bump.describe(),
                new_severity.as_str()
            ))
        } else {
            Drift::WithinTolerance(format!("within tolerance for {}", bump.describe()))
        };
        Self { drift, skew }
    }
}

/// Skew read over the per-scope rates of change: fires when the traits scope
/// (behavior) moved at least `SKEW_RATIO`× the mean of the content scopes and
/// a judged capability actually appeared. Calibrated on the bundled cases: the
/// xz backdoor sits at 4.5×; full rewrites (behavior and content moving
/// together) sit below 2.5×.
pub(super) fn skew_note(a: &Assessment, diff: &DiffReportV1) -> Option<String> {
    const SKEW_RATIO: f32 = 3.0;
    // A broad release can legitimately change many traits while its metric
    // scopes stay relatively quiet (especially source-heavy packages). The
    // surgical signal is for a small focused edit; archive-root churn is
    // normalized before this point, so this is now a meaningful guard.
    if !COMPACT.fits(&diff.summary) {
        return None;
    }
    let s = &diff.summary.scope_roc;
    let content: Vec<f32> = [s.metrics, s.kv, s.symbols, s.strings, s.sections]
        .into_iter()
        .filter(|r| *r > 0.0)
        .collect();
    if content.is_empty() || a.behavioral.severity() < Severity::Medium {
        return None;
    }
    let mean = content.iter().sum::<f32>() / content.len() as f32;
    (s.traits >= 0.5 && s.traits >= mean * SKEW_RATIO).then(|| {
        format!(
            "surgical — {:.0}% of behavior changed on a {:.0}% content change",
            s.traits * 100.0,
            mean * 100.0,
        )
    })
}

/// Raise a gate on the *quantity* of behavior a release introduced, with no
/// reference to which behavior it was.
///
/// The behavioral axis grades the worst capability a change gained, so it is
/// silent when an implant arrives as a pile of individually-ordinary ones — an
/// HTTP client, a file write, an environment read, a base64 decode — none of
/// which is suspicious alone. What such a change cannot hide is its effect on
/// the artifact's behavioral fingerprint: after the release, a large share of
/// everything the package can do was not there before.
///
/// [`crate::behavior_shift`] measures that two ways, and either can raise the
/// gate:
///
/// * **weighed** — cleave's criticality x confidence summed over the trait ids
///   the new side gained, against the larger side's mass;
/// * **counted** — the same thing with every trait id worth exactly one,
///   grading none of them. This is the reading that survives the case this
///   tool exists for: a payload no rule knows contributes nothing to the
///   weighed mass but still doubles the number of distinct things the artifact
///   does.
///
/// Three bounds keep it honest:
///
/// * **Injection, not exchange.** The gained mass must dominate what was lost.
///   A remediation or a rewrite swaps one behavior set for another and is
///   judged on what it removed; an implant adds. (Of 941 attack transitions
///   measured against the supply-chain corpus, 938 are net-additive by this
///   test.)
/// * **Concentration.** Only a compact change qualifies — the same
///   [`COMPACT`] bound the other shape rules use. A thousand-file
///   framework release moves a large mass legitimately; an implant is a few
///   files.
/// * **Release promise.** The bars scale with the version bump, because that
///   is the claim the publisher made. A patch release promising bug fixes
///   earns the least room; a major release may arrive with new behavior.
///
/// It applies only where both sides were analyzed whole — two files or two
/// archives. A directory comparison profiles the touched files rather than
/// the artifact, so its shares would describe the diff, not the release.
///
/// The floors sit above every benign transition in the supply-chain corpus,
/// so this raises a gate only when a release's behavior is substantially
/// *new*, not merely large.
pub(super) fn capability_mass_escalation(
    shift: &crate::behavior_shift::Shift,
    summary: &DiffSummary,
    bump: Option<Bump>,
    whole_artifact: bool,
) -> Severity {
    // The shares below say "of everything this artifact does", which is only
    // true when both sides were analyzed whole. A directory comparison
    // profiles the touched files alone, so a new module reads as most of the
    // fingerprint; that is a statement about the diff, not the artifact.
    if !whole_artifact {
        return Severity::None;
    }
    // A partial walk cannot establish how much of the fingerprint is new: the
    // unanalyzed side reads as empty, which inflates every share below.
    if !shift.complete || !COMPACT.fits(summary) {
        return Severity::None;
    }
    // An exchange is not an injection. Judged on mass rather than ids so that
    // trading a hostile implant for ordinary code still reads as removal.
    if shift.behavior.lost > shift.behavior.gained * 0.5 {
        return Severity::None;
    }
    // No version to read is the same promise as a patch: nothing here licenses
    // a new behavioral profile.
    let (mass_floor, share_floor, ids_floor, id_share_floor) =
        match bump.map_or(Promise::Nothing, |b| b.kind.promise()) {
            Promise::Nothing => (24.0, 0.40, 24, 0.50),
            Promise::Features => (40.0, 0.55, 40, 0.60),
            Promise::Anything => (60.0, 0.70, 60, 0.75),
        };
    let weighed = shift.injected_mass() >= mass_floor && shift.injected_share() >= share_floor;
    let counted = shift.injected_ids() >= ids_floor && shift.injected_id_share() >= id_share_floor;
    if weighed || counted {
        Severity::High
    } else {
        Severity::None
    }
}
