"""
Diagnose orchestration for EvidenceTool.

Wires providers, evaluator, policy engine, causal engine, decision engine,
and recommendation module together into a unified operational reasoning pipeline.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from evidencetool.capability.models import AuthorityMetadata, CapabilityDenied, ExecutionContext
from evidencetool.causality.engine import reconstruct_causality
from evidencetool.causality.models import CausalExplanation, CausalRule
from evidencetool.decision.engine import decide
from evidencetool.decision.integrity import validate_decision_integrity
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.models.correlation import Situation
from evidencetool.models.decision import Decision, DecisionStatus
from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.incident import Incident, OperationalIncident
from evidencetool.models.policy import Policy
from evidencetool.observability.metrics import MetricsData
from evidencetool.observability.tracing import DiagnosisTracer, TraceRecord
from evidencetool.recommendation import recommend

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiagnosisResult:
    incident: Incident | OperationalIncident
    evidence: list[Evidence]
    policy: Policy
    decision: Decision
    recommendation: str
    metrics: MetricsData
    authority: AuthorityMetadata | None = None
    causality: CausalExplanation | None = None
    trace: TraceRecord | None = None


def diagnose(  # noqa: C901
    target: str,
    policy: Policy,
    context: dict[str, str],
    catalog: list[Situation] | None = None,
    execution: ExecutionContext | None = None,
    causality_catalog: list[CausalRule] | None = None,
    tracer: DiagnosisTracer | None = None,
    traceparent: str | None = None,
) -> DiagnosisResult:
    from evidencetool.providers.base import ProviderContext
    from evidencetool.providers.registry import get_provider, get_provider_trust, load_all_providers

    # Ensure all built-in providers are registered
    load_all_providers()

    if tracer is None:
        import os

        from evidencetool.observability.tracing import has_active_trace_context

        if (
            traceparent
            or os.getenv("TRACEPARENT")
            or has_active_trace_context()
            or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
            or os.getenv("OTEL_ENABLE_TRACING", "").lower() in ("1", "true")
        ):
            tracer = DiagnosisTracer(traceparent=traceparent)

    if tracer:
        tracer.start_root_span(target=target, policy_action=policy.action)
        if execution and execution.identity and tracer.root_span:
            tracer.root_span.set_attribute("evidencetool.authority.caller_id", execution.identity.caller_id)
            tracer.root_span.set_attribute("evidencetool.authority.caller_type", execution.identity.caller_type.value)
            if execution.identity.session_id:
                tracer.root_span.set_attribute("evidencetool.authority.session_id", execution.identity.session_id)

    m = MetricsData()
    start_total = time.time()

    observations = []

    # 1. Determine which provider namespaces are needed from the policy.
    needed_namespaces = set()
    for req in policy.required_evidence:
        parts = req.id.split(".")
        if len(parts) > 1:
            needed_namespaces.add(parts[0])

    if catalog:
        for sit_id in policy.allow + policy.blocked_by:
            for sit in catalog:
                if sit.id == sit_id:
                    for ev_id in sit.signature.keys():
                        parts = ev_id.split(".")
                        if len(parts) > 1:
                            needed_namespaces.add(parts[0])

    # 2. Instantiate and run only the needed providers
    provider_context = ProviderContext(context, execution=execution)
    for namespace in sorted(needed_namespaces):
        if tracer:
            tracer.start_span(f"evidencetool.provider.{namespace}")
        t0 = time.time()
        try:
            if execution and not execution.capabilities.allows_provider(namespace):
                raise CapabilityDenied(f"Provider '{namespace}' is not authorized by capability policy.")
            if execution and execution.capabilities.require_trusted_providers:
                trust = get_provider_trust(namespace)
                if trust.value not in {"builtin", "approved"}:
                    raise CapabilityDenied(
                        f"Provider '{namespace}' has trust level '{trust.value}' and is not approved."
                    )
            provider_instance = get_provider(namespace)
            collected = provider_instance.collect(provider_context)
            for observation in collected:
                valid_namespace = (
                    observation.id.startswith(f"{namespace}.")
                    or (namespace in {"docker", "container"} and (observation.id.startswith("docker.") or observation.id.startswith("container.")))
                    or (namespace in {"k8s", "kubernetes"} and (observation.id.startswith("k8s.") or observation.id.startswith("kubernetes.")))
                )
                valid_source = observation.source in {namespace, "docker", "container", "k8s", "kubernetes"}
                if not valid_source or not valid_namespace:
                    raise CapabilityDenied(
                        f"Provider '{namespace}' returned invalid observation '{observation.id}'."
                    )
            expected_ids = {
                req.id for req in policy.required_evidence if req.id.startswith(f"{namespace}.")
            }
            if catalog:
                for sit in catalog:
                    if sit.id in policy.allow or sit.id in policy.blocked_by:
                        expected_ids.update(
                            ev_id for ev_id in sit.signature if ev_id.startswith(f"{namespace}.")
                        )
            collected_ids = {observation.id for observation in collected}
            for missing_id in sorted(expected_ids - collected_ids):
                from evidencetool.models.observation import Observation

                collected.append(
                    Observation(
                        id=missing_id,
                        source=namespace,
                        category="system",
                        collector="diagnose_engine",
                        method="partial_provider_collection",
                        value={"status": "UNKNOWN"},
                        message=f"Provider '{namespace}' did not return evidence '{missing_id}'.",
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            observations += collected
            if tracer:
                tracer.end_span(
                    f"evidencetool.provider.{namespace}",
                    status="OK",
                    attributes={"evidencetool.provider.observations_count": len(collected)},
                )
        except CapabilityDenied as exc:
            from evidencetool.models.observation import Observation

            failed_ids = [req.id for req in policy.required_evidence if req.id.startswith(f"{namespace}.")]
            if catalog:
                for sit in catalog:
                    for ev_id in sit.signature:
                        if ev_id.startswith(f"{namespace}.") and ev_id not in failed_ids:
                            failed_ids.append(ev_id)
            for req_id in failed_ids:
                observations.append(
                    Observation(
                        id=req_id,
                        source=namespace,
                        category="security",
                        collector="diagnose_engine",
                        method="capability_policy",
                        value={"status": "UNKNOWN", "capability_denied": True},
                        message=str(exc),
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            if tracer:
                tracer.end_span(
                    f"evidencetool.provider.{namespace}",
                    status="ERROR",
                    description=str(exc),
                    attributes={"evidencetool.provider.capability_denied": True},
                )
        except Exception as exc:
            import traceback

            from evidencetool.models.observation import Observation

            logger.error(f"Provider '{namespace}' execution failed: {exc}\n{traceback.format_exc()}")

            failed_ids = [req.id for req in policy.required_evidence if req.id.startswith(f"{namespace}.")]
            if catalog:
                for sit in catalog:
                    for ev_id in sit.signature:
                        if ev_id.startswith(f"{namespace}.") and ev_id not in failed_ids:
                            failed_ids.append(ev_id)
            for req_id in failed_ids:
                observations.append(
                    Observation(
                        id=req_id,
                        source=namespace,
                        category="system",
                        collector="diagnose_engine",
                        method="provider_execution",
                        value={"status": "UNKNOWN"},
                        message=f"Provider execution failed:\n{exc}",
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            if tracer:
                tracer.end_span(
                    f"evidencetool.provider.{namespace}",
                    status="ERROR",
                    description=str(exc),
                    attributes={"evidencetool.provider.error": str(exc)},
                )
        m.provider_durations[namespace] = time.time() - t0

    # 3. Evaluate observations
    t0 = time.time()
    if tracer:
        tracer.start_span("evidencetool.evaluation")
    max_ages = {
        req.id: req.max_age for req in policy.required_evidence if req.max_age is not None
    }
    evidence = [evaluate_observation(obs, max_age=max_ages.get(obs.id)) for obs in observations]
    m.evaluation_duration = time.time() - t0

    for e in evidence:
        m.evidence_status_counts[e.status] += 1

    if tracer:
        tracer.end_span(
            "evidencetool.evaluation",
            attributes={
                "evidencetool.evidence.total": len(evidence),
                "evidencetool.evidence.pass": m.evidence_status_counts.get(EvidenceStatus.PASS, 0),
                "evidencetool.evidence.fail": m.evidence_status_counts.get(EvidenceStatus.FAIL, 0),
                "evidencetool.evidence.unknown": m.evidence_status_counts.get(EvidenceStatus.UNKNOWN, 0),
            },
        )

    capability_violation = any(
        e.observation.value.get("capability_denied") is True
        for e in evidence
        if isinstance(e.observation.value, dict)
    )
    if capability_violation:
        m.integrity_violation = 1
        m.success = False

    # 4. Correlation & Deterministic Causal Reasoning
    t0 = time.time()
    from evidencetool.decision.correlation import correlate_state
    from evidencetool.models.policy import PolicySchema

    if tracer:
        tracer.start_span("evidencetool.correlation")
    state = correlate_state(evidence, catalog or [])
    if tracer:
        tracer.end_span(
            "evidencetool.correlation",
            attributes={
                "evidencetool.situations.matched": len(state.situations),
                "evidencetool.situations.unresolved": len(state.unresolved_evidence),
            },
        )

    if tracer:
        tracer.start_span("evidencetool.causality")
    causality_explanation = reconstruct_causality(evidence, state, causality_catalog or [])
    if tracer:
        primary_cause_id = causality_explanation.primary_root_cause
        tracer.record_causality(
            causality_status=causality_explanation.status.value,
            primary_root_cause=primary_cause_id,
            causal_chain=list(causality_explanation.causal_chain),
            precluded_hypotheses=causality_explanation.precluded_hypotheses,
        )

    if policy.schema == PolicySchema.V2_SITUATIONAL:
        decision = decide(state, policy)
    else:
        decision = decide(evidence, policy)
    m.decision_duration = time.time() - t0

    m.decision_status = decision.status

    if tracer:
        tracer.record_decision(
            status=decision.status.value,
            reason=decision.reason,
            blocking_evidence=list(decision.blocking_evidence),
            action=policy.action,
        )

    # 5. Integrity Check
    integrity_result = validate_decision_integrity(decision, policy, evidence, state=state)
    if not integrity_result.is_valid:
        m.integrity_violation = 1
    m.success = not capability_violation and integrity_result.is_valid

    recommendation_text = recommend(decision)

    authority_meta = None
    if execution is not None:
        tracker = execution.capabilities.probe_tracker
        authority_meta = AuthorityMetadata(
            caller_id=execution.identity.caller_id,
            caller_type=execution.identity.caller_type.value,
            session_id=execution.identity.session_id,
            policy_fingerprint=execution.capabilities.policy_fingerprint,
            probes_budget=tracker.max_probes,
            probes_consumed=tracker.consumed,
            probes_remaining=tracker.remaining,
        )

    operational_incident = OperationalIncident(
        incident_id=f"inc_{uuid.uuid4().hex[:8]}",
        target=target,
        observations=observations,
        situations=state.situations,
        causality=causality_explanation,
        decision=decision,
        policy=policy,
        created_at=datetime.now(timezone.utc),
        authority=authority_meta,
    )

    m.total_duration = time.time() - start_total

    trace_record = None
    if tracer:
        trace_status = "OK" if (m.success and decision.status == DecisionStatus.ALLOW) else "ERROR"
        trace_record = tracer.finish(status=trace_status, description=decision.reason)

    return DiagnosisResult(
        incident=operational_incident,
        evidence=evidence,
        policy=policy,
        decision=decision,
        recommendation=recommendation_text,
        metrics=m,
        authority=authority_meta,
        causality=causality_explanation,
        trace=trace_record,
    )
