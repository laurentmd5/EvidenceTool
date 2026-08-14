"""
State Correlation Models — V0.3 Domain Model

This module defines the structures for translating individual Evidence
items into a higher-level OperationalState using deterministic Signatures.
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
class OperationalState:
    """
    The composite operational state of the incident at a given time.

    A state can contain multiple simultaneous situations (e.g., both
    NGINX_SERVICE_DOWN and TLS_CERTIFICATE_EXPIRED).

    If critical evidence is missing, UNKNOWN, or no known situation matches
    the observed evidence, the state is marked as ambiguous.
    """
    situations: list[Situation] = field(default_factory=list)
    unresolved_evidence: list[str] = field(default_factory=list)
    ambiguous: bool = False
    discrepancies: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, typing.Any]:
        return {
            "situations": [s.to_dict() for s in self.situations],
            "unresolved_evidence": self.unresolved_evidence,
            "ambiguous": self.ambiguous,
            "discrepancies": self.discrepancies,
        }
