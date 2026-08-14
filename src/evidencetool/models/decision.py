"""
Decision model — per PRODUCT_CONTRACT.md Section 5.

Precedence invariant (Section 5.1), tested explicitly in test_decision.py:

    BLOCK > HUMAN_REVIEW > ALLOW

"A human approval requirement can escalate ALLOW to HUMAN_REVIEW,
but it can never turn BLOCK into HUMAN_REVIEW."

Decision is strictly separate from Recommendation (Section 4 of the
governance discussion): a Recommendation is advisory text that can be
regenerated (e.g. later by an LLM) without ever being able to change
`decision.status`. This is enforced structurally: Recommendation is not
an input to any Decision-producing function anywhere in this codebase.
"""

from __future__ import annotations

import typing
from dataclasses import dataclass, field
from enum import Enum


class DecisionStatus(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    HUMAN_REVIEW = "HUMAN_REVIEW"


@dataclass(frozen=True)
class Decision:
    status: DecisionStatus
    reason: str
    blocking_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, typing.Any]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "blocking_evidence": list(self.blocking_evidence),
        }
