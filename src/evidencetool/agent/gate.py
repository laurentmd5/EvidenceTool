"""
AgentSafetyGate — The Deterministic Safety Gateway for AI Agents.
"""

from __future__ import annotations

from pathlib import Path

from evidencetool.agent.models import AgentDiagnosisRequest, AgentDiagnosisResult
from evidencetool.capability.loader import load_capability_policy
from evidencetool.capability.models import (
    AuthorityMetadata,
    CallerIdentity,
    CapabilityDenied,
    CapabilitySet,
    ExecutionContext,
    KubernetesCapability,
    NetworkCapability,
)
from evidencetool.causality.loader import load_causal_catalog
from evidencetool.causality.models import CausalRule
from evidencetool.diagnose import diagnose
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.models.correlation import Situation
from evidencetool.models.decision import DecisionStatus
from evidencetool.models.evidence import EvidenceStatus
from evidencetool.models.policy import Policy
from evidencetool.policy.loader import load_policy


class AgentSafetyGate:
    """
    Zero-Trust Deterministic Safety Gateway for AI Agents.

    Acts as an operational reasoning firewall between AI agents proposing actions
    and the production infrastructure.
    """

    def __init__(
        self,
        capability_policy: str | Path | CapabilitySet | None = None,
        capability_hash: str | None = None,
        catalog: str | Path | list[Situation] | None = None,
        default_policy: str | Path | Policy | None = None,
        causality_catalog: str | Path | list[CausalRule] | None = None,
    ) -> None:
        self._capabilities: CapabilitySet
        self._explicit_capability_policy = capability_policy is not None
        if isinstance(capability_policy, CapabilitySet):
            self._capabilities = capability_policy
        elif capability_policy is not None:
            self._capabilities = load_capability_policy(capability_policy, expected_hash=capability_hash)
        else:
            self._capabilities = CapabilitySet(
                network=NetworkCapability(targets=("127.0.0.0/8", "::1")),
                kubernetes=KubernetesCapability(enabled=False, operations=frozenset(), allowed_namespaces=()),
            )

        self._catalog: list[Situation] | None
        if isinstance(catalog, list):
            self._catalog = catalog
        elif catalog is not None:
            self._catalog = load_catalog(str(catalog))
        else:
            self._catalog = None

        self._causality_catalog: list[CausalRule] | None
        if isinstance(causality_catalog, list):
            self._causality_catalog = causality_catalog
        elif causality_catalog is not None:
            self._causality_catalog = load_causal_catalog(str(causality_catalog))
        else:
            self._causality_catalog = None

        self._default_policy: Policy | None
        if isinstance(default_policy, Policy):
            self._default_policy = default_policy
        elif default_policy is not None:
            self._default_policy = load_policy(str(default_policy))
        else:
            self._default_policy = None

    def evaluate(self, request: AgentDiagnosisRequest) -> AgentDiagnosisResult:
        """
        Evaluates an agent's proposed action against operational evidence and policies.
        """
        # Resolve policy (Default gate policy is authoritative in gateway mode)
        if self._default_policy:
            policy = self._default_policy
        elif request.policy_path:
            if request.caller_type.value == "AI_AGENT":
                raise CapabilityDenied("AI agents require a gate default policy; request policy_path is not trusted.")
            policy = load_policy(request.policy_path)
        else:
            raise ValueError("No policy specified in request or default gate configuration.")

        # Invariant 4: Validate that policy governs the exact requested action (SEC-03)
        if policy.action != request.action:
            raise ValueError(
                f"Policy action mismatch: policy governs '{policy.action}' but agent requested '{request.action}'."
            )

        # Build ExecutionContext with agent identity & isolated probe tracker (DES-01)
        identity = CallerIdentity(
            caller_id=request.agent_id,
            caller_type=request.caller_type,
            session_id=request.session_id,
        )

        eval_capabilities = self._capabilities.clone_isolated()

        exec_ctx = ExecutionContext(
            caller=request.agent_id,
            identity=identity,
            capabilities=eval_capabilities,
        )

        # Enforce SSH destination confinement (F-01)
        ssh_host = request.context.get("host")
        if ssh_host:
            if not self._explicit_capability_policy:
                raise CapabilityDenied("SSH transport requires an explicit capability policy.")
            eval_capabilities.require_ssh_transport(str(ssh_host))

        # Run deterministic diagnosis
        # Ensure context values are strings for ProviderContext compatibility
        str_context: dict[str, str] = {str(k): str(v) for k, v in request.context.items()}

        raw_result = diagnose(
            target=request.target,
            policy=policy,
            context=str_context,
            catalog=self._catalog,
            execution=exec_ctx,
            causality_catalog=self._causality_catalog,
        )

        # Extract root cause and supporting evidence
        root_cause: list[str] = list(raw_result.decision.blocking_evidence)
        supporting: list[str] = [
            e.id for e in raw_result.evidence
            if e.status == EvidenceStatus.PASS
        ]

        # Extract situation
        situation_id = None
        if "Situation '" in raw_result.decision.reason:
            try:
                situation_id = raw_result.decision.reason.split("'")[1]
            except IndexError:
                pass

        # Build authority metadata with per-evaluation consumed probes
        tracker = eval_capabilities.probe_tracker
        authority = AuthorityMetadata(
            caller_id=request.agent_id,
            caller_type=request.caller_type.value,
            session_id=request.session_id,
            policy_fingerprint=eval_capabilities.policy_fingerprint,
            probes_budget=tracker.max_probes,
            probes_consumed=tracker.consumed,
            probes_remaining=tracker.remaining,
        )

        # Extract causality explanation
        causality = raw_result.causality
        causality_status = causality.status.value if causality else "ROOT_CAUSE_IDENTIFIED"
        primary_root = causality.primary_root_cause if causality else (root_cause[0] if root_cause else None)
        causal_chain = causality.causal_chain if causality else root_cause
        propagated_symptoms = causality.propagated_symptoms if causality else []
        precluded_hypotheses = causality.precluded_hypotheses if causality else []

        return AgentDiagnosisResult(
            is_allowed=raw_result.decision.status == DecisionStatus.ALLOW,
            status=raw_result.decision.status.value,
            reason=raw_result.decision.reason,
            matching_situation=situation_id,
            root_cause_evidence=root_cause,
            supporting_evidence=supporting,
            recommendation=raw_result.recommendation,
            authority=authority,
            causality_status=causality_status,
            primary_root_cause=primary_root,
            causal_chain=causal_chain,
            propagated_symptoms=propagated_symptoms,
            precluded_hypotheses=precluded_hypotheses,
            raw_diagnosis=raw_result,
        )
