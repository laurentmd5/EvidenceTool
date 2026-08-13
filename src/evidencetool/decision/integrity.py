"""
Decision Integrity Checker.

Ensures that the DecisionEngine produces mathematically consistent results.
An integrity violation must never be silently ignored, but it also must
not alter the audited decision object.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from evidencetool.models.decision import Decision, DecisionStatus
from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.policy import OnUnknown, Policy

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IntegrityResult:
    is_valid: bool
    violations: list[str]


def validate_decision_integrity(decision: Decision, policy: Policy, evidence: list[Evidence]) -> IntegrityResult:
    violations = []

    # 1. Recommendation must not influence Decision. (This is structurally enforced
    #    because Recommendation is produced *after* Decision, but we note it).

    # 2. BLOCK invariants
    if decision.status == DecisionStatus.BLOCK:
        if not decision.blocking_evidence:
            violations.append("Decision is BLOCK but blocking_evidence is empty.")
    
    # 3. HUMAN_REVIEW invariants
    if decision.status == DecisionStatus.HUMAN_REVIEW:
        if not policy.human_approval:
            violations.append("Decision is HUMAN_REVIEW but policy.human_approval is false.")
        if decision.blocking_evidence:
            violations.append("Decision is HUMAN_REVIEW but has blocking_evidence (should be BLOCK).")

    # 4. ALLOW invariants
    if decision.status == DecisionStatus.ALLOW:
        if decision.blocking_evidence:
            violations.append("Decision is ALLOW but has blocking_evidence.")
        if policy.human_approval:
            violations.append("Decision is ALLOW but policy requires human_approval (should be HUMAN_REVIEW).")
            
        # Re-verify that all required conditions are indeed satisfied
        evidence_by_id = {e.id: e for e in evidence}
        for req in policy.required_evidence:
            e = evidence_by_id.get(req.id)
            if not e:
                if req.on_unknown == OnUnknown.BLOCK:
                    violations.append(f"Decision is ALLOW but required evidence {req.id} is missing (on_unknown: BLOCK).")
                continue

            if e.status == EvidenceStatus.FAIL:
                violations.append(f"Decision is ALLOW but required evidence {req.id} is FAIL.")
            elif e.status == EvidenceStatus.UNKNOWN and req.on_unknown == OnUnknown.BLOCK:
                violations.append(f"Decision is ALLOW but required evidence {req.id} is UNKNOWN with on_unknown: BLOCK.")

    is_valid = len(violations) == 0
    if not is_valid:
        logger.error(f"Decision Integrity Violation(s): {', '.join(violations)}")

    return IntegrityResult(is_valid=is_valid, violations=violations)
