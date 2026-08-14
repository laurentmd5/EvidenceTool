from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from evidencetool.models.observation import Observation
from evidencetool.models.policy import EvidenceRequirement, Policy, RiskLevel


def make_observation(
    id: str,
    status: str,
    *,
    source: str = "test",
    category: str = "test",
    collector: str = "test_collector",
    method: str = "test_method",
    message: str = "",
    age_seconds: float = 0.0,
) -> Observation:
    observed_at = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
    return Observation(
        id=id,
        source=source,
        category=category,
        collector=collector,
        method=method,
        value={"status": status},
        message=message or f"{id} observed as {status}",
        observed_at=observed_at,
    )


def make_policy(
    action: str = "test_action",
    risk: str = "LOW",
    required_evidence: list | None = None,
    human_approval: bool = False,
) -> Policy:
    reqs = []
    for item in required_evidence or []:
        if isinstance(item, str):
            reqs.append(EvidenceRequirement(id=item))
        else:
            reqs.append(EvidenceRequirement(**item))
    return Policy(
        version="1",
        action=action,
        risk=RiskLevel(risk),
        required_evidence=reqs,
        human_approval=human_approval,
    )


@pytest.fixture
def observation_factory():
    return make_observation


@pytest.fixture
def policy_factory():
    return make_policy
