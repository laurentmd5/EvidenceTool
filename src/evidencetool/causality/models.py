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
    REQUIRES = "REQUIRES"


class CausalCandidateState(str, Enum):
    """Deterministic validation state of a causal hypothesis."""
    CONFIRMED = "CONFIRMED"
    POSSIBLE = "POSSIBLE"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class CausalCandidate:
    """
    A candidate root-cause situation evaluated by the causal engine.
    """
    id: str
    state: CausalCandidateState
    causal_path: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    description: str = ""

    def __str__(self) -> str:
        return self.id

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.id == other
        if isinstance(other, CausalCandidate):
            return (
                self.id == other.id
                and self.state == other.state
                and self.causal_path == other.causal_path
                and self.missing_evidence == other.missing_evidence
            )
        return False

    def __hash__(self) -> int:
        return hash((self.id, self.state))

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "state": self.state.value,
            "causal_path": self.causal_path,
        }
        if self.missing_evidence:
            d["missing_evidence"] = self.missing_evidence
        if self.description:
            d["description"] = self.description
        return d


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
    priority: int = 0

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
            "priority": self.priority,
        }


@dataclass(frozen=True)
class CausalExplanation:
    """
    Explainable result of deterministic causal reconstruction.
    """
    status: CausalityStatus
    primary_root_cause: str | None = None
    target_situation: str | None = None
    causal_chain: list[str] = field(default_factory=list)
    propagated_symptoms: list[str] = field(default_factory=list)
    precluded_hypotheses: list[str] = field(default_factory=list)
    unresolved_hypotheses: list[str] = field(default_factory=list)
    candidate_causes: list[CausalCandidate] = field(default_factory=list)
    confidence: str = "DETERMINISTIC"
    cycles_detected: list[list[str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        candidates_out: list[Any] = []
        for cand in self.candidate_causes:
            if hasattr(cand, "to_dict"):
                candidates_out.append(cand.to_dict())
            else:
                candidates_out.append(cand)

        d: dict[str, Any] = {
            "status": self.status.value,
            "primary_root_cause": self.primary_root_cause,
            "causal_chain": self.causal_chain,
            "propagated_symptoms": self.propagated_symptoms,
            "precluded_hypotheses": self.precluded_hypotheses,
            "candidate_causes": candidates_out,
            "confidence": self.confidence,
        }
        if self.target_situation is not None:
            d["target_situation"] = self.target_situation
        if self.unresolved_hypotheses:
            d["unresolved_hypotheses"] = self.unresolved_hypotheses
        if self.cycles_detected:
            d["cycles_detected"] = self.cycles_detected
        return d
