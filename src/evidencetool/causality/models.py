"""
Causal Reasoning Models — V1.0 Domain Model

Defines the core data structures for deterministic causal operational reasoning:
- CausalityStatus (IDENTIFIED, CONSTRAINED, UNKNOWN)
- CausalRelationType (PROPAGATES_TO, TRIGGERS, SYMPTOM_OF, PRECLUDES)
- CausalRule (Declarative causal rule in catalogs)
- CausalExplanation (Reconstructed causal graph and explanation)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CausalityStatus(str, Enum):
    """Deterministic status of root-cause identification."""
    ROOT_CAUSE_IDENTIFIED = "ROOT_CAUSE_IDENTIFIED"
    ROOT_CAUSE_CONSTRAINED = "ROOT_CAUSE_CONSTRAINED"
    ROOT_CAUSE_UNKNOWN = "ROOT_CAUSE_UNKNOWN"


class CausalRelationType(str, Enum):
    """Type of causal relation between situations or evidence."""
    PROPAGATES_TO = "PROPAGATES_TO"
    TRIGGERS = "TRIGGERS"
    SYMPTOM_OF = "SYMPTOM_OF"
    PRECLUDES = "PRECLUDES"


@dataclass(frozen=True)
class CausalRule:
    """
    A declarative causal rule loaded from a causality catalog.
    Example:
      id: REDIS_OOM_TO_APPLICATION_DEGRADATION
      source: REDIS_OOM_MAXMEMORY
      target: UPSTREAM_LATENCY_DEGRADATION
      relation: PROPAGATES_TO
      conditions: {"redis.memory_pressure": "FAIL", "dependency.latency_ms": "FAIL"}
      is_symptom: False
    """
    id: str
    source: str
    target: str
    relation: CausalRelationType
    conditions: dict[str, str] = field(default_factory=dict)
    description: str = ""
    is_root_cause_candidate: bool = True
    is_surface_symptom: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "relation": self.relation.value,
            "conditions": self.conditions,
            "description": self.description,
            "is_root_cause_candidate": self.is_root_cause_candidate,
            "is_surface_symptom": self.is_surface_symptom,
        }


@dataclass(frozen=True)
class CausalExplanation:
    """
    Explainable result of deterministic causal reconstruction.
    """
    status: CausalityStatus
    primary_root_cause: str | None = None
    causal_chain: list[str] = field(default_factory=list)
    propagated_symptoms: list[str] = field(default_factory=list)
    precluded_hypotheses: list[str] = field(default_factory=list)
    candidate_causes: list[str] = field(default_factory=list)
    confidence: str = "DETERMINISTIC"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "primary_root_cause": self.primary_root_cause,
            "causal_chain": self.causal_chain,
            "propagated_symptoms": self.propagated_symptoms,
            "precluded_hypotheses": self.precluded_hypotheses,
            "candidate_causes": self.candidate_causes,
            "confidence": self.confidence,
        }
