"""
Incident Models — V1.0 Domain Model

Defines the OperationalIncident structure combining observations, situations,
causal explanation, and governance decisions into a unified explainable record.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from evidencetool.capability.models import AuthorityMetadata
from evidencetool.causality.models import CausalExplanation
from evidencetool.models.correlation import Situation
from evidencetool.models.decision import Decision
from evidencetool.models.observation import Observation
from evidencetool.models.policy import Policy


@dataclass(frozen=True)
class Incident:
    """Legacy lightweight incident identifier."""
    id: str
    type: str


@dataclass(frozen=True)
class OperationalIncident:
    """
    Unified operational incident record.
    Reconstructs the full trajectory from observed facts to causal diagnosis and policy decision.
    """
    incident_id: str
    target: str
    observations: list[Observation]
    situations: list[Situation]
    causality: CausalExplanation
    decision: Decision
    policy: Policy
    created_at: datetime
    authority: AuthorityMetadata | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "target": self.target,
            "observations_count": len(self.observations),
            "situations": [s.to_dict() for s in self.situations],
            "causality": self.causality.to_dict(),
            "decision": {
                "status": self.decision.status.value,
                "reason": self.decision.reason,
                "blocking_evidence": self.decision.blocking_evidence,
            },
            "policy": {
                "action": self.policy.action,
                "risk": self.policy.risk.value,
            },
            "created_at": self.created_at.isoformat(),
            "authority": self.authority.to_dict() if self.authority else None,
        }
