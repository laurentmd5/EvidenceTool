"""
Unit and Integration Tests for V1.0 Deterministic Causal Reasoning & Operational Incidents.

Covers the 3 Canonical Reference Scenarios:
1. Single Root Cause (Redis OOM -> HTTP 503)
2. Multi-Layer Cascade (Redis OOM -> Postgres Overload -> API Latency -> Nginx 504)
3. Ambiguity & Fail-Closed Safety (HTTP 504 with UNKNOWN downstreams -> ROOT_CAUSE_UNKNOWN)
"""

from __future__ import annotations

from datetime import datetime, timezone

from evidencetool.agent.gate import AgentSafetyGate
from evidencetool.agent.models import AgentDiagnosisRequest
from evidencetool.capability.models import CapabilitySet, NetworkCapability
from evidencetool.causality.engine import reconstruct_causality
from evidencetool.causality.loader import load_causal_catalog
from evidencetool.causality.models import CausalityStatus
from evidencetool.decision.correlation import correlate_state
from evidencetool.decision.engine import decide
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.observation import Observation
from evidencetool.policy.loader import load_policy


def _make_evidence(obs_id: str, status: EvidenceStatus, value: dict | None = None) -> Evidence:
    obs = Observation(
        id=obs_id,
        source=obs_id.split(".")[0],
        category="test",
        collector="test",
        method="test",
        value=value or {"status": status.value},
        message=f"{obs_id} is {status.value}",
        observed_at=datetime.now(timezone.utc),
    )
    return evaluate_observation(obs)


def test_causality_catalog_loading():
    rules = load_causal_catalog("causality/distributed.yaml")
    assert len(rules) >= 4
    rule_ids = {r.id for r in rules}
    assert "REDIS_OOM_TO_DB_OVERLOAD" in rule_ids
    assert "POSTGRES_POOL_TO_DB_CONNECTIVITY_FAIL" in rule_ids


def test_scenario_1_single_root_cause():
    """
    Scenario 1 — Single Root Cause:
    Redis OOM -> Application degradation -> HTTP 503.
    """
    catalog = load_catalog("catalogs/data.yaml")
    policy = load_policy("policies/data.yaml")
    causal_rules = load_causal_catalog("causality/distributed.yaml")

    evidence = [
        _make_evidence("redis.reachable", EvidenceStatus.PASS),
        _make_evidence("redis.ping", EvidenceStatus.PASS),
        _make_evidence("redis.memory_pressure", EvidenceStatus.FAIL, {"status": "FAIL", "used_memory": 98000000, "maxmemory": 100000000}),
        _make_evidence("redis.role", EvidenceStatus.PASS),
        _make_evidence("dependency.http_status", EvidenceStatus.FAIL, {"status": "FAIL", "status_code": 503}),
        _make_evidence("dependency.circuit_breaker", EvidenceStatus.FAIL, {"status": "FAIL", "status_code": 503}),
        _make_evidence("dependency.latency_ms", EvidenceStatus.FAIL, {"status": "FAIL", "latency_ms": 320.0}),
        _make_evidence("dependency.sla_budget", EvidenceStatus.FAIL, {"status": "FAIL"}),
    ]

    state = correlate_state(evidence, catalog)
    causality = reconstruct_causality(evidence, state, causal_rules)
    decision = decide(state, policy)

    # Invariants verification
    assert causality.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED
    assert causality.primary_root_cause == "REDIS_OOM_MAXMEMORY"
    assert "REDIS_OOM_MAXMEMORY" in causality.causal_chain
    assert decision.status.value == "BLOCK"
    assert "REDIS_OOM_MAXMEMORY" in decision.reason


def test_scenario_2_multi_layer_cascade():
    """
    Scenario 2 — Multi-Layer Cascade:
    Redis OOM -> DB query latency overload -> API Latency -> Nginx 504.
    Precludes TOTAL_NETWORK_PARTITION and POSTGRES_UNREACHABLE because remote ports are reachable.
    """
    catalog = load_catalog("catalogs/distributed.yaml")
    policy = load_policy("policies/distributed.yaml")
    causal_rules = load_causal_catalog("causality/distributed.yaml")

    evidence = [
        _make_evidence("network.port_reachable", EvidenceStatus.PASS),
        _make_evidence("postgres.reachable", EvidenceStatus.PASS),
        _make_evidence("postgres.accepting_connections", EvidenceStatus.PASS),
        _make_evidence("postgres.pool_exhaustion", EvidenceStatus.PASS),
        _make_evidence("postgres.is_in_recovery", EvidenceStatus.PASS),
        _make_evidence("postgres.latency_ms", EvidenceStatus.FAIL, {"status": "FAIL", "latency_ms": 450.0}),
        _make_evidence("redis.reachable", EvidenceStatus.PASS),
        _make_evidence("redis.ping", EvidenceStatus.PASS),
        _make_evidence("redis.memory_pressure", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("dependency.http_status", EvidenceStatus.FAIL, {"status": "FAIL", "status_code": 504}),
        _make_evidence("dependency.latency_ms", EvidenceStatus.FAIL, {"status": "FAIL", "latency_ms": 1250.0}),
        _make_evidence("dependency.sla_budget", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("dependency.circuit_breaker", EvidenceStatus.PASS),
    ]

    state = correlate_state(evidence, catalog)
    causality = reconstruct_causality(evidence, state, causal_rules)
    decision = decide(state, policy)

    # Invariants verification
    assert causality.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED
    assert causality.primary_root_cause == "CACHE_FAILURE_DATABASE_OVERLOAD"
    assert "TOTAL_NETWORK_PARTITION" in causality.precluded_hypotheses
    assert "POSTGRES_UNREACHABLE" in causality.precluded_hypotheses
    assert decision.status.value == "BLOCK"


def test_scenario_3_ambiguity_fail_closed():
    """
    Scenario 3 — Ambiguity & Incomplete Evidence:
    HTTP 504 observed, but all downstream datastores are UNKNOWN (no access / uncollected).
    Must return ROOT_CAUSE_UNKNOWN, zero guessing, and fail-closed decision.
    """
    catalog = load_catalog("catalogs/distributed.yaml")
    policy = load_policy("policies/distributed.yaml")
    causal_rules = load_causal_catalog("causality/distributed.yaml")

    evidence = [
        _make_evidence("dependency.http_status", EvidenceStatus.FAIL, {"status": "FAIL", "status_code": 504}),
        _make_evidence("dependency.latency_ms", EvidenceStatus.FAIL, {"status": "FAIL", "latency_ms": 2500.0}),
        _make_evidence("dependency.sla_budget", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("dependency.circuit_breaker", EvidenceStatus.UNKNOWN),
        _make_evidence("postgres.reachable", EvidenceStatus.UNKNOWN),
        _make_evidence("postgres.accepting_connections", EvidenceStatus.UNKNOWN),
        _make_evidence("postgres.pool_exhaustion", EvidenceStatus.UNKNOWN),
        _make_evidence("redis.reachable", EvidenceStatus.UNKNOWN),
        _make_evidence("redis.memory_pressure", EvidenceStatus.UNKNOWN),
        _make_evidence("network.port_reachable", EvidenceStatus.UNKNOWN),
    ]

    state = correlate_state(evidence, catalog)
    causality = reconstruct_causality(evidence, state, causal_rules)
    decision = decide(state, policy)

    # Fail-closed invariants: zero guessing
    assert causality.status in (CausalityStatus.ROOT_CAUSE_UNKNOWN, CausalityStatus.ROOT_CAUSE_CONSTRAINED)
    assert causality.primary_root_cause is None
    # Policy evaluates as BLOCK or HUMAN_REVIEW under ambiguity
    assert decision.status.value in ("BLOCK", "HUMAN_REVIEW")


def test_agent_safety_gate_e2e_causal_explanation():
    """
    Verifies that the AgentSafetyGate returns fully explainable causal provenance to AI agents.
    """
    gate = AgentSafetyGate(
        capability_policy=CapabilitySet(network=NetworkCapability(targets=("127.0.0.1",))),
        catalog="catalogs/distributed.yaml",
        default_policy="policies/distributed.yaml",
        causality_catalog="causality/distributed.yaml",
    )

    request = AgentDiagnosisRequest(
        agent_id="remediation-bot-9000",
        action="restart_application",
        target="distributed-service",
        context={
            "url": "http://127.0.0.1:8080/api/checkout",
            "db_host": "127.0.0.1",
            "db_port": "5432",
            "redis_host": "127.0.0.1",
            "redis_port": "6379",
            "target": "127.0.0.1",
            "port": "5432",
        },
    )

    result = gate.evaluate(request)

    assert result.is_allowed is False
    assert result.status == "BLOCK"
    assert result.causality_status in ("ROOT_CAUSE_IDENTIFIED", "ROOT_CAUSE_CONSTRAINED", "ROOT_CAUSE_UNKNOWN")
    assert isinstance(result.causal_chain, list)
    assert isinstance(result.precluded_hypotheses, list)
    assert len(result.authority.caller_id) > 0
