"""
Policy model — per PRODUCT_CONTRACT.md Sections 4, 6, 7.

Key rules encoded here:
  - Every required evidence item declares its own `on_unknown` behavior.
  - Default when `on_unknown` is omitted: BLOCK (fail-closed, NFR-001).
  - `risk` is declared by the policy author, never computed (Section 6).
  - `max_age` (seconds) is optional per evidence item; if the observation
    backing that evidence is older than max_age, it is treated as
    effectively UNKNOWN before on_unknown is applied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class OnUnknown(str, Enum):
    BLOCK = "BLOCK"
    IGNORE = "IGNORE"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


DEFAULT_ON_UNKNOWN = OnUnknown.BLOCK


@dataclass(frozen=True)
class EvidenceRequirement:
    id: str
    on_unknown: OnUnknown = DEFAULT_ON_UNKNOWN
    max_age: float | None = None  # seconds; None = no freshness constraint


@dataclass(frozen=True)
class Policy:
    version: str
    action: str
    risk: RiskLevel
    required_evidence: list[EvidenceRequirement] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    blocked_by: list[str] = field(default_factory=list)
    human_approval: bool = False

    def requirement_for(self, evidence_id: str) -> EvidenceRequirement | None:
        for req in self.required_evidence:
            if req.id == evidence_id:
                return req
        return None
