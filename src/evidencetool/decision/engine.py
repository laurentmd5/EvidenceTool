"""
Decision Engine — per PRODUCT_CONTRACT.md Section 5.

    Decision precedence: BLOCK > HUMAN_REVIEW > ALLOW

If any required evidence resolves to a blocking state, the decision is
BLOCK regardless of risk level or human_approval. HUMAN_REVIEW only
applies when all required evidence requirements are satisfied but the
policy still demands a human decision (via `human_approval: true`).

This module has no knowledge of Recommendation. Decision is produced
strictly from Evidence + Policy, nothing else.
"""

from __future__ import annotations

from evidencetool.models.decision import Decision, DecisionStatus
from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.policy import OnUnknown, Policy


def decide(evidence: list[Evidence], policy: Policy) -> Decision:
    evidence_by_id = {e.id: e for e in evidence}

    blocking_evidence: list[str] = []

    for requirement in policy.required_evidence:
        found = evidence_by_id.get(requirement.id)

        if found is None:
            # No observation collected at all for this required evidence:
            # treated as UNKNOWN, subject to the same on_unknown rule.
            if requirement.on_unknown == OnUnknown.BLOCK:
                blocking_evidence.append(requirement.id)
            continue

        if found.status == EvidenceStatus.FAIL:
            blocking_evidence.append(requirement.id)

        elif found.status == EvidenceStatus.UNKNOWN:
            if requirement.on_unknown == OnUnknown.BLOCK:
                blocking_evidence.append(requirement.id)
            # OnUnknown.IGNORE -> not blocking, evidence noted as
            # unverifiable but does not affect the decision.

        # PASS -> requirement satisfied, nothing to do.

    if blocking_evidence:
        return Decision(
            status=DecisionStatus.BLOCK,
            reason=(
                "Required evidence "
                f"{', '.join(blocking_evidence)} not satisfied."
                if len(blocking_evidence) > 1
                else f"Required evidence {blocking_evidence[0]} is not satisfied."
            ),
            blocking_evidence=blocking_evidence,
        )

    if policy.human_approval:
        return Decision(
            status=DecisionStatus.HUMAN_REVIEW,
            reason=(
                "All required evidence satisfied, but this action "
                f"(risk: {policy.risk.value}) requires human approval."
            ),
            blocking_evidence=[],
        )

    return Decision(
        status=DecisionStatus.ALLOW,
        reason="All required evidence satisfied and no human approval required.",
        blocking_evidence=[],
    )
