"""
Diagnose orchestration for the "nginx" vertical slice.

This is the only place in the codebase that wires providers, the
evaluator, the policy engine, the decision engine, and the recommendation
module together. Providers themselves know nothing about policy or
decision (per the architectural principle locked in the design phase):

    Nginx Provider
          |
          v
     Observation
          |
          v
    Evidence Evaluator
          |
          v
     Policy Engine
          |
          v
    Decision Engine
          |
          v
     Recommendation   (advisory only, cannot influence Decision)
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass

from evidencetool.capability.models import CapabilityDenied, ExecutionContext
from evidencetool.decision.engine import decide
from evidencetool.decision.integrity import validate_decision_integrity
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.models.correlation import Situation
from evidencetool.models.decision import Decision
from evidencetool.models.evidence import Evidence
from evidencetool.models.incident import Incident
from evidencetool.models.policy import Policy
from evidencetool.observability.metrics import MetricsData
from evidencetool.recommendation import recommend

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiagnosisResult:
    incident: Incident
    evidence: list[Evidence]
    policy: Policy
    decision: Decision
    recommendation: str
    metrics: MetricsData


def diagnose(  # noqa: C901
    target: str,
    policy: Policy,
    context: dict[str, str],
    catalog: list[Situation] | None = None,
    execution: ExecutionContext | None = None,
) -> DiagnosisResult:
    from evidencetool.providers.base import ProviderContext
    from evidencetool.providers.registry import get_provider, get_provider_trust, load_all_providers

    # Ensure all built-in providers are registered
    load_all_providers()

    m = MetricsData()
    start_total = time.time()

    incident = Incident(id=f"inc_{uuid.uuid4().hex[:8]}", type=f"{target}_start_failure")

    observations = []

    # 1. Determine which provider namespaces are needed from the policy.
    # Evidence IDs are typically "namespace.check_name" (e.g. "nginx.config_valid").
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
                valid_namespace = observation.id.startswith(f"{namespace}.")
                valid_docker_alias = namespace in {"docker", "container"} and observation.id.startswith("docker.")
                valid_source = observation.source in {namespace, "docker"}
                if not valid_source or not (valid_namespace or valid_docker_alias):
                    raise CapabilityDenied(
                        f"Provider '{namespace}' returned invalid observation '{observation.id}'."
                    )
            observations += collected
        except CapabilityDenied as exc:
            from datetime import datetime, timezone

            from evidencetool.models.observation import Observation

            failed_ids = [req.id for req in policy.required_evidence if req.id.startswith(f"{namespace}.")]
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
        except Exception as exc:
            import traceback
            from datetime import datetime, timezone

            from evidencetool.models.observation import Observation

            logger.error(f"Provider '{namespace}' execution failed: {exc}\n{traceback.format_exc()}")

            # Emit a synthetic observation for every requested evidence in this namespace
            failed_ids = [req.id for req in policy.required_evidence if req.id.startswith(f"{namespace}.")]

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
        m.provider_durations[namespace] = time.time() - t0

    # 3. Evaluate observations
    t0 = time.time()
    max_ages = {
        req.id: req.max_age for req in policy.required_evidence if req.max_age is not None
    }
    evidence = [evaluate_observation(obs, max_age=max_ages.get(obs.id)) for obs in observations]
    m.evaluation_duration = time.time() - t0

    for e in evidence:
        m.evidence_status_counts[e.status] += 1

    capability_violation = any(
        e.observation.value.get("capability_denied") is True
        for e in evidence
        if isinstance(e.observation.value, dict)
    )
    if capability_violation:
        m.integrity_violation = 1
        m.success = False

    # 4. Decide
    t0 = time.time()
    from evidencetool.decision.correlation import correlate_state
    from evidencetool.models.policy import PolicySchema

    state = correlate_state(evidence, catalog or [])
    if policy.schema == PolicySchema.V2_SITUATIONAL:
        decision = decide(state, policy)
    else:
        decision = decide(evidence, policy)
    m.decision_duration = time.time() - t0

    m.decision_status = decision.status

    # 5. Integrity Check
    integrity_result = validate_decision_integrity(decision, policy, evidence, state=state)
    if not integrity_result.is_valid:
        m.integrity_violation = 1
    m.success = not capability_violation and integrity_result.is_valid

    recommendation_text = recommend(decision)

    m.total_duration = time.time() - start_total

    return DiagnosisResult(
        incident=incident,
        evidence=evidence,
        policy=policy,
        decision=decision,
        recommendation=recommendation_text,
        metrics=m,
    )

