"""
Data models for the AI-Agent SDK & Safety Gateway.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from evidencetool.capability.models import AuthorityMetadata, CallerType
from evidencetool.diagnose import DiagnosisResult


@dataclass(frozen=True)
class AgentDiagnosisRequest:
    """Request submitted by an autonomous AI agent to evaluate a planned action."""

    agent_id: str
    action: str
    target: str
    context: dict[str, Any]
    session_id: str | None = None
    policy_path: str | None = None
    caller_type: CallerType = CallerType.AI_AGENT


@dataclass(frozen=True)
class AgentDiagnosisResult:
    """Deterministic, explainable safety evaluation result returned to the agent."""

    is_allowed: bool
    status: str
    reason: str
    matching_situation: str | None
    root_cause_evidence: list[str]
    supporting_evidence: list[str]
    recommendation: str
    authority: AuthorityMetadata
    causality_status: str = "ROOT_CAUSE_IDENTIFIED"
    primary_root_cause: str | None = None
    causal_chain: list[str] = field(default_factory=list)
    propagated_symptoms: list[str] = field(default_factory=list)
    precluded_hypotheses: list[str] = field(default_factory=list)
    raw_diagnosis: DiagnosisResult = field(default=None, repr=False)  # type: ignore
