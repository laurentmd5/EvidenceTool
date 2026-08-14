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

from evidencetool.models.correlation import OperationalState

def _decide_legacy(evidence: list[Evidence], policy: Policy) -> Decision:
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


def decide(
    state_or_evidence: OperationalState | list[Evidence],
    policy: Policy, 
    evidence_fallback: list[Evidence] | None = None
) -> Decision:
    """
    V0.3 Decision Engine logic based on Operational State.
    Falls back to V0.2 logic if no allow/blocked_by rules are defined in the policy.
    """
    if isinstance(state_or_evidence, list):
        evidence_fallback = state_or_evidence
        state = OperationalState()
    else:
        state = state_or_evidence
        
    if not policy.allow and not policy.blocked_by:
        return _decide_legacy(evidence_fallback or [], policy)
        
    if state.ambiguous:
        return Decision(
            status=DecisionStatus.BLOCK,
            reason="Operational state is ambiguous due to unresolved or missing evidence.",
            blocking_evidence=state.unresolved_evidence,
        )
        
    situation_ids = {s.id for s in state.situations}
    
    for blocked_id in policy.blocked_by:
        if blocked_id in situation_ids:
            return Decision(
                status=DecisionStatus.BLOCK,
                reason=f"Situation '{blocked_id}' is explicitly blocked by policy.",
                blocking_evidence=[],
            )
            
    allowed = False
    for allow_id in policy.allow:
        if allow_id in situation_ids:
            allowed = True
            break
            
    if not allowed:
        return Decision(
            status=DecisionStatus.BLOCK,
            reason="No known situation matches the allowed situations for this action.",
            blocking_evidence=[],
        )
        
    if policy.human_approval:
        return Decision(
            status=DecisionStatus.HUMAN_REVIEW,
            reason="Situation authorized, but this action requires human approval.",
            blocking_evidence=[],
        )
        
    return Decision(
        status=DecisionStatus.ALLOW,
        reason="Situation authorized and no human approval required.",
        blocking_evidence=[],
    )
