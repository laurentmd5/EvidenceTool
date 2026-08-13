"""
Evidence — the evaluated judgement derived from an Observation.

Per PRODUCT_CONTRACT.md V1.1, Section 3:
    Three states only: PASS, FAIL, UNKNOWN.
    UNKNOWN != FAIL. Whether it blocks a decision depends on the policy's
    per-evidence `on_unknown` directive, not a universal conversion rule.

Freshness (Section 2.1, revised): freshness is NOT a field set by the
provider. It is computed by the evaluator from `Observation.observed_at`
against the policy's `max_age` for that evidence id. A stale observation
is treated as UNKNOWN for evaluation purposes (see decision in TEST 05),
and `is_stale` is kept on the Evidence for transparency in output.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from evidencetool.models.observation import Observation


class EvidenceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Evidence:
    observation: Observation
    status: EvidenceStatus
    message: str
    is_stale: bool = False

    @property
    def id(self) -> str:
        return self.observation.id

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "status": self.status.value,
            "message": self.message,
            "observation": self.observation.to_dict(),
            "is_stale": self.is_stale,
        }
