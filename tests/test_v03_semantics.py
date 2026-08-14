"""
Integration tests for V0.3 State Correlation and Decision Semantics.
"""

from datetime import datetime, timezone

import pytest

from evidencetool.decision.correlation import correlate_state
from evidencetool.decision.engine import decide
from evidencetool.decision.integrity import validate_decision_integrity
from evidencetool.models.correlation import Situation
from evidencetool.models.decision import Decision, DecisionStatus
from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.observation import Observation
from evidencetool.models.policy import Policy, RiskLevel


@pytest.fixture
def catalog():
    return [
        Situation(
            id="NGINX_SERVICE_DOWN",
            description="Nginx is inactive but config is valid",
            signature={
                "systemd.service_active": EvidenceStatus.FAIL,
                "nginx.config_valid": EvidenceStatus.PASS,
            }
        ),
        Situation(
            id="NGINX_CONFIG_INVALID",
            description="Nginx config is invalid",
            signature={
                "nginx.config_valid": EvidenceStatus.FAIL,
            }
        ),
        Situation(
            id="TLS_CERTIFICATE_EXPIRED",
            description="TLS cert is expired",
            signature={
                "tls.certificate_valid": EvidenceStatus.FAIL,
            }
        ),
    ]


@pytest.fixture
def policy() -> Policy:
    from evidencetool.models.policy import PolicySchema
    return Policy(
        version="1.0",
        action="restart_nginx",
        risk=RiskLevel.MEDIUM,
        schema=PolicySchema.V2_SITUATIONAL,
        allow=["NGINX_SERVICE_DOWN"],
        blocked_by=["NGINX_CONFIG_INVALID", "TLS_CERTIFICATE_EXPIRED"]
    )


def build_evidence(ev_id: str, status: EvidenceStatus) -> Evidence:
    obs = Observation(
        id=ev_id,
        source="test",
        category="system",
        collector="test",
        method="mock",
        value={},
        message="mock obs",
        observed_at=datetime.now(timezone.utc)
    )
    return Evidence(
        observation=obs,
        status=status,
        message="test"
    )


def test_scenario_1_normal(catalog, policy):
    """Test 1: Normal operational state (all PASS). No situation matches."""
    evidence = [
        build_evidence("systemd.service_active", EvidenceStatus.PASS),
        build_evidence("nginx.config_valid", EvidenceStatus.PASS),
        build_evidence("tls.certificate_valid", EvidenceStatus.PASS),
    ]

    state = correlate_state(evidence, catalog)
    assert not state.ambiguous
    assert len(state.situations) == 0

    decision = decide(state, policy)
    assert decision.status == DecisionStatus.BLOCK

    integrity = validate_decision_integrity(decision, policy, evidence, state)
    assert integrity.is_valid


def test_scenario_2_service_down_allowed(catalog, policy):
    """Test 2: Service down, config valid -> NGINX_SERVICE_DOWN -> ALLOW."""
    evidence = [
        build_evidence("systemd.service_active", EvidenceStatus.FAIL),
        build_evidence("nginx.config_valid", EvidenceStatus.PASS),
        build_evidence("tls.certificate_valid", EvidenceStatus.PASS),
    ]

    state = correlate_state(evidence, catalog)
    assert not state.ambiguous
    assert len(state.situations) == 1
    assert state.situations[0].id == "NGINX_SERVICE_DOWN"

    decision = decide(state, policy)
    assert decision.status == DecisionStatus.ALLOW

    integrity = validate_decision_integrity(decision, policy, evidence, state)
    assert integrity.is_valid


def test_scenario_3_config_invalid_blocked(catalog, policy):
    """Test 3: Service down AND config invalid -> blocked by policy."""
    evidence = [
        build_evidence("systemd.service_active", EvidenceStatus.FAIL),
        build_evidence("nginx.config_valid", EvidenceStatus.FAIL),
    ]

    state = correlate_state(evidence, catalog)
    assert not state.ambiguous
    situations = {s.id for s in state.situations}
    assert "NGINX_CONFIG_INVALID" in situations
    assert "NGINX_SERVICE_DOWN" not in situations

    decision = decide(state, policy)
    assert decision.status == DecisionStatus.BLOCK

    integrity = validate_decision_integrity(decision, policy, evidence, state)
    assert integrity.is_valid


def test_scenario_4_ambiguous_state(catalog, policy):
    """Test 4: service_active=UNKNOWN, config_valid=PASS -> AMBIGUOUS -> BLOCK."""
    evidence = [
        build_evidence("systemd.service_active", EvidenceStatus.UNKNOWN),
        build_evidence("nginx.config_valid", EvidenceStatus.PASS),
    ]

    state = correlate_state(evidence, catalog)
    assert state.ambiguous
    assert "systemd.service_active" in state.unresolved_evidence

    decision = decide(state, policy)
    assert decision.status == DecisionStatus.BLOCK

    integrity = validate_decision_integrity(decision, policy, evidence, state)
    assert integrity.is_valid


def test_scenario_5_ambiguous_state_2(catalog, policy):
    """Test 5: service_active=FAIL, config_valid=UNKNOWN -> AMBIGUOUS -> BLOCK."""
    evidence = [
        build_evidence("systemd.service_active", EvidenceStatus.FAIL),
        build_evidence("nginx.config_valid", EvidenceStatus.UNKNOWN),
    ]

    state = correlate_state(evidence, catalog)
    assert state.ambiguous
    assert "nginx.config_valid" in state.unresolved_evidence

    decision = decide(state, policy)
    assert decision.status == DecisionStatus.BLOCK

    integrity = validate_decision_integrity(decision, policy, evidence, state)
    assert integrity.is_valid


def test_scenario_6_malicious_injection(catalog, policy):
    """Test 6: Malicious injection ALLOW on AMBIGUOUS state -> Integrity Violation."""
    evidence = [
        build_evidence("systemd.service_active", EvidenceStatus.UNKNOWN),
    ]

    state = correlate_state(evidence, catalog)
    assert state.ambiguous

    # Manually force ALLOW
    decision = Decision(
        status=DecisionStatus.ALLOW,
        reason="Hacked",
        blocking_evidence=[]
    )

    integrity = validate_decision_integrity(decision, policy, evidence, state)
    assert not integrity.is_valid
    assert any("AMBIGUOUS" in v for v in integrity.violations)


def test_scenario_7_malicious_injection_blocked_situation(catalog, policy):
    """Test 7: Malicious injection ALLOW on a blocked situation -> Integrity Violation."""
    evidence = [
        build_evidence("nginx.config_valid", EvidenceStatus.FAIL),
    ]

    state = correlate_state(evidence, catalog)

    # Manually force ALLOW
    decision = Decision(
        status=DecisionStatus.ALLOW,
        reason="Hacked",
        blocking_evidence=[]
    )

    integrity = validate_decision_integrity(decision, policy, evidence, state)
    assert not integrity.is_valid
    assert any("explicitly blocked" in v for v in integrity.violations)
