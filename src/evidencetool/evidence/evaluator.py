"""
Evidence Evaluator.

Turns raw Observations into evaluated Evidence.

Design note:
1. Technical availability and direct command results (e.g. "nginx -t exited non-zero" -> FAIL)
   travel inside `Observation.value["status"]`.
2. Raw telemetry observations (e.g. error rate ratio, latency ms, span counts)
   carry pure numerical metrics. When a policy declares an `EvidenceRequirement` with
   a `threshold` and `comparator`, the Evaluator (not the provider) performs the
   threshold comparison to produce PASS / FAIL.
3. Freshness: if a `max_age` is given and the observation is older, it converts to UNKNOWN.
4. Absence of evidence or transport failures always resolve to UNKNOWN (Local Uncertainty Invariant).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.observation import Observation

if TYPE_CHECKING:
    from evidencetool.models.policy import EvidenceRequirement


def _compare_value(val: float, threshold: float, comparator: str) -> bool:
    if comparator == "<=":
        return val <= threshold
    if comparator == "<":
        return val < threshold
    if comparator == ">=":
        return val >= threshold
    if comparator == ">":
        return val > threshold
    if comparator == "==":
        return abs(val - threshold) < 1e-9
    return val <= threshold


def evaluate_observation(
    observation: Observation,
    max_age: float | None = None,
    requirement: EvidenceRequirement | None = None,
) -> Evidence:
    raw_status = observation.value.get("status") if isinstance(observation.value, dict) else None

    # 1. If provider explicitly flagged transport or execution status
    if raw_status is not None:
        try:
            status = EvidenceStatus(raw_status)
        except (ValueError, TypeError):
            status = EvidenceStatus.UNKNOWN
    # 2. If observation contains a raw numerical metric and requirement specifies threshold
    elif requirement is not None and requirement.threshold is not None and isinstance(observation.value, dict):
        metric_val = observation.value.get("value")
        if metric_val is None:
            metric_val = observation.value.get("count")

        if metric_val is not None and isinstance(metric_val, (int, float)):
            passed = _compare_value(float(metric_val), requirement.threshold, requirement.comparator)
            status = EvidenceStatus.PASS if passed else EvidenceStatus.FAIL
        else:
            status = EvidenceStatus.UNKNOWN
    elif isinstance(observation.value, (int, float)) and requirement is not None and requirement.threshold is not None:
        passed = _compare_value(float(observation.value), requirement.threshold, requirement.comparator)
        status = EvidenceStatus.PASS if passed else EvidenceStatus.FAIL
    else:
        status = EvidenceStatus.UNKNOWN

    age = observation.age_seconds()
    is_stale = False

    # Clock skew / future timestamp protection (SEC-06)
    if age < -5.0:
        status = EvidenceStatus.UNKNOWN
        is_stale = True
        message = f"{observation.message} (invalid timestamp: future date detected)"
    elif max_age is not None and age >= max_age:
        is_stale = True
        if status != EvidenceStatus.UNKNOWN:
            status = EvidenceStatus.UNKNOWN
        message = f"{observation.message} (stale: observed {age:.0f}s ago, max_age={max_age}s)"
    else:
        message = observation.message

    return Evidence(
        observation=observation,
        status=status,
        message=message,
        is_stale=is_stale,
    )


def evaluate_observations(
    observations: list[Observation],
    max_ages: dict[str, float] | None = None,
    requirements: dict[str, EvidenceRequirement] | None = None,
) -> list[Evidence]:
    max_ages = max_ages or {}
    requirements = requirements or {}
    return [
        evaluate_observation(
            obs,
            max_age=max_ages.get(obs.id),
            requirement=requirements.get(obs.id),
        )
        for obs in observations
    ]
