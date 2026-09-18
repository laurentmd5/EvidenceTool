"""
State Correlation Models — V1.0.2 Domain Model

This module defines the structures for translating individual Evidence
items into a higher-level OperationalState using deterministic Signatures.

V1.0.2 introduces SituationEvaluation: per-situation ambiguity tracking.
The fundamental invariant is:

    Uncertainty must be local to the hypothesis it affects.

A UNKNOWN Redis evidence must not make uncertain a conclusion
exclusively founded on Nginx evidence.
"""

from __future__ import annotations

import typing
from dataclasses import dataclass, field

from evidencetool.models.evidence import EvidenceStatus


@dataclass(frozen=True)
class Situation:
    """
    A named operational situation derived from a specific signature.
    Example: NGINX_SERVICE_DOWN
    """
    id: str
    description: str
    signature: dict[str, EvidenceStatus]

    def to_dict(self) -> dict[str, typing.Any]:
        return {
            "id": self.id,
            "description": self.description,
            "signature": {k: v.value for k, v in self.signature.items()}
        }


@dataclass(frozen=True)
class SituationEvaluation:
    """
    Deterministic evaluation of a single situation against collected evidence.

    Carries per-situation ambiguity: a situation is ambiguous only if
    *its own* required evidence is UNKNOWN or missing.
    """
    situation: Situation
    matched: bool
    unresolved_evidence: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    discrepant_evidence: list[str] = field(default_factory=list)

    @property
    def is_ambiguous(self) -> bool:
        """Ambiguity is local: true if THIS situation has UNKNOWN (unresolved) evidence."""
        return len(self.unresolved_evidence) > 0

    def to_dict(self) -> dict[str, typing.Any]:
        return {
            "situation_id": self.situation.id,
            "matched": self.matched,
            "is_ambiguous": self.is_ambiguous,
            "unresolved_evidence": self.unresolved_evidence,
            "missing_evidence": self.missing_evidence,
            "discrepant_evidence": self.discrepant_evidence,
        }


@dataclass(frozen=True)
class OperationalState:
    """
    The composite operational state of the incident at a given time.

    A state can contain multiple simultaneous situations (e.g., both
    NGINX_SERVICE_DOWN and TLS_CERTIFICATE_EXPIRED).

    V1.0.2: ``ambiguous`` is now a computed property derived from
    per-situation evaluations. A global UNKNOWN only makes the state
    ambiguous if it affects at least one evaluated situation.
    """
    situations: list[Situation] = field(default_factory=list)
    evaluations: list[SituationEvaluation] = field(default_factory=list)
    unresolved_evidence: list[str] = field(default_factory=list)
    discrepancies: dict[str, list[str]] = field(default_factory=dict)

    @property
    def ambiguous(self) -> bool:
        """Retrocompatible: True if at least one evaluated situation is ambiguous."""
        return any(ev.is_ambiguous for ev in self.evaluations)

    def to_dict(self) -> dict[str, typing.Any]:
        return {
            "situations": [s.to_dict() for s in self.situations],
            "evaluations": [e.to_dict() for e in self.evaluations],
            "unresolved_evidence": self.unresolved_evidence,
            "ambiguous": self.ambiguous,
            "discrepancies": self.discrepancies,
        }
