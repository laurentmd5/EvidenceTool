"""
Evidence Evaluator.

Turns raw Observations into evaluated Evidence.

Design note: providers are responsible for the substantive PASS/FAIL/UNKNOWN
judgement of *what they observed* (e.g. "nginx -t exited non-zero" -> FAIL).
That judgement travels inside `Observation.value["status"]`. The evaluator's
job, kept deliberately generic and provider-agnostic, is:

  1. Trust the provider's raw status as the starting point.
  2. Apply freshness: if a `max_age` is given (from the policy, for this
     evidence id) and the observation is older than that, the evidence is
     treated as effectively UNKNOWN, regardless of what the provider said
     (per TEST 05 in PRODUCT_CONTRACT.md: "Evidence too old -> policy
     determines outcome" -- staleness converts the effective status to
     UNKNOWN, which then flows into the normal on_unknown handling).
  3. Providers never talk to the policy or decision engine directly.
"""

from __future__ import annotations

from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.observation import Observation


def evaluate_observation(
    observation: Observation, max_age: float | None = None
) -> Evidence:
    raw_status = observation.value.get("status") if isinstance(observation.value, dict) else None

    try:
        status = EvidenceStatus(raw_status)
    except (ValueError, TypeError):
        status = EvidenceStatus.UNKNOWN

    is_stale = False
    if max_age is not None and observation.age_seconds() > max_age:
        is_stale = True
        if status != EvidenceStatus.UNKNOWN:
            status = EvidenceStatus.UNKNOWN

    message = observation.message
    if is_stale:
        message = f"{message} (stale: observed {observation.age_seconds():.0f}s ago, max_age={max_age}s)"

    return Evidence(
        observation=observation,
        status=status,
        message=message,
        is_stale=is_stale,
    )


def evaluate_observations(
    observations: list[Observation], max_ages: dict[str, float] | None = None
) -> list[Evidence]:
    max_ages = max_ages or {}
    return [
        evaluate_observation(obs, max_age=max_ages.get(obs.id))
        for obs in observations
    ]
