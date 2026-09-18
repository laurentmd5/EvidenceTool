"""
Formal Verification Test Suite for Mode C — Hybrid Causal Reasoning.

Implements the 6 Canonical Reference Scenarios C1 to C6 defined in
mode_c_causal_contract.md Section 7:
- C1: Confirmed Cause (OTel FAIL, Postgres FAIL, Redis PASS -> Postgres CONFIRMED)
- C2: Unresolved Cause (OTel FAIL, Postgres UNKNOWN, Redis PASS -> Postgres UNRESOLVED)
- C3: Multiple Causes (OTel FAIL, Postgres FAIL, Redis FAIL -> Multi-candidate POSSIBLE, CONSTRAINED)
- C4: Precluded Cause (OTel FAIL, Postgres PASS, Redis FAIL -> Postgres PRECLUDED, Redis CONFIRMED)
- C5: UNKNOWN Non-Contaminant (OTel FAIL, Postgres FAIL, TLS UNKNOWN -> Postgres CONFIRMED)
- C6: No Declared Causality (OTel FAIL, Postgres FAIL without rules -> ROOT_CAUSE_UNKNOWN, chain=[])
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from evidencetool.causality.engine import reconstruct_causality
from evidencetool.causality.loader import load_causal_catalog
from evidencetool.causality.models import (
    CausalCandidateState,
    CausalityStatus,
    CausalRelationType,
    CausalRule,
)
from evidencetool.decision.correlation import correlate_state
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.observation import Observation


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


@pytest.fixture
def combined_catalog():
    telemetry_cat = load_catalog("catalogs/telemetry.yaml")
    data_cat = load_catalog("catalogs/data.yaml")
    return telemetry_cat + data_cat


@pytest.fixture
def telemetry_causality_rules():
    return load_causal_catalog("causality/telemetry.yaml")


def test_scenario_c1_confirmed_cause(combined_catalog, telemetry_causality_rules):
    """
    Scenario C1 — Confirmed Cause:
    OTel FAIL, Postgres FAIL, Redis PASS.
    Deterministic identification of Postgres connection pool exhaustion.
    """
    evidence = [
        _make_evidence("otel.metrics_reachable", EvidenceStatus.PASS),
        _make_evidence("otel.http_error_rate", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("otel.p99_latency_ms", EvidenceStatus.PASS),
        _make_evidence("otel.error_spans_count", EvidenceStatus.PASS),
        _make_evidence("postgres.reachable", EvidenceStatus.PASS),
        _make_evidence("postgres.accepting_connections", EvidenceStatus.PASS),
        _make_evidence("postgres.pool_exhaustion", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("redis.reachable", EvidenceStatus.PASS),
        _make_evidence("redis.ping", EvidenceStatus.PASS),
        _make_evidence("redis.memory_pressure", EvidenceStatus.PASS),
    ]

    state = correlate_state(evidence, combined_catalog)
    causality = reconstruct_causality(evidence, state, telemetry_causality_rules)

    # Invariants
    assert causality.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED
    assert causality.primary_root_cause == "POSTGRES_POOL_EXHAUSTED"
    assert "POSTGRES_POOL_EXHAUSTED" in causality.causal_chain
    assert "SERVICE_ERROR_RATE_EXCEEDED" in causality.causal_chain

    # Check candidate state
    cand_map = {c.id: c for c in causality.candidate_causes}
    assert "POSTGRES_POOL_EXHAUSTED" in cand_map
    assert cand_map["POSTGRES_POOL_EXHAUSTED"].state == CausalCandidateState.CONFIRMED
    assert len(cand_map["POSTGRES_POOL_EXHAUSTED"].missing_evidence) == 0


def test_scenario_c2_unresolved_cause(combined_catalog, telemetry_causality_rules):
    """
    Scenario C2 — Unresolved Cause:
    OTel FAIL, Postgres UNKNOWN (timeout/unreachable), Redis PASS.
    Postgres candidate becomes UNRESOLVED, ROOT_CAUSE_UNKNOWN, zero guessing.
    """
    evidence = [
        _make_evidence("otel.metrics_reachable", EvidenceStatus.PASS),
        _make_evidence("otel.http_error_rate", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("otel.p99_latency_ms", EvidenceStatus.PASS),
        _make_evidence("otel.error_spans_count", EvidenceStatus.PASS),
        _make_evidence("postgres.reachable", EvidenceStatus.PASS),
        _make_evidence("postgres.accepting_connections", EvidenceStatus.UNKNOWN),
        _make_evidence("postgres.pool_exhaustion", EvidenceStatus.UNKNOWN),
        _make_evidence("redis.reachable", EvidenceStatus.PASS),
        _make_evidence("redis.ping", EvidenceStatus.PASS),
        _make_evidence("redis.memory_pressure", EvidenceStatus.PASS),
    ]

    state = correlate_state(evidence, combined_catalog)
    causality = reconstruct_causality(evidence, state, telemetry_causality_rules)

    # Invariants: UNKNOWN != NO_MATCH, Fail-closed
    assert causality.status == CausalityStatus.ROOT_CAUSE_UNKNOWN
    assert causality.primary_root_cause is None
    assert "POSTGRES_POOL_EXHAUSTED" in causality.unresolved_hypotheses

    cand_map = {c.id: c for c in causality.candidate_causes}
    assert "POSTGRES_POOL_EXHAUSTED" in cand_map
    assert cand_map["POSTGRES_POOL_EXHAUSTED"].state == CausalCandidateState.UNRESOLVED
    assert "postgres.pool_exhaustion" in cand_map["POSTGRES_POOL_EXHAUSTED"].missing_evidence


def test_scenario_c3_multiple_causes_constrained(combined_catalog, telemetry_causality_rules):
    """
    Scenario C3 — Multiple Causes:
    OTel FAIL, Postgres FAIL, Redis FAIL simultaneously.
    Both candidates are confirmed; with no priority or hierarchy, status is CONSTRAINED
    and both candidates are retained as POSSIBLE without arbitrary tie-breaking.
    """
    evidence = [
        _make_evidence("otel.metrics_reachable", EvidenceStatus.PASS),
        _make_evidence("otel.http_error_rate", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("otel.p99_latency_ms", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("otel.error_spans_count", EvidenceStatus.PASS),
        _make_evidence("postgres.reachable", EvidenceStatus.PASS),
        _make_evidence("postgres.accepting_connections", EvidenceStatus.PASS),
        _make_evidence("postgres.pool_exhaustion", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("redis.reachable", EvidenceStatus.PASS),
        _make_evidence("redis.ping", EvidenceStatus.PASS),
        _make_evidence("redis.memory_pressure", EvidenceStatus.FAIL, {"status": "FAIL"}),
    ]

    state = correlate_state(evidence, combined_catalog)
    causality = reconstruct_causality(evidence, state, telemetry_causality_rules)

    # Invariants: Non-arbitrary resolution
    assert causality.status == CausalityStatus.ROOT_CAUSE_CONSTRAINED
    assert causality.primary_root_cause is None

    cand_map = {c.id: c for c in causality.candidate_causes}
    assert "POSTGRES_POOL_EXHAUSTED" in cand_map
    assert "REDIS_OOM_MAXMEMORY" in cand_map
    assert cand_map["POSTGRES_POOL_EXHAUSTED"].state == CausalCandidateState.POSSIBLE
    assert cand_map["REDIS_OOM_MAXMEMORY"].state == CausalCandidateState.POSSIBLE


def test_scenario_c4_precluded_cause(combined_catalog, telemetry_causality_rules):
    """
    Scenario C4 — Precluded Cause:
    OTel FAIL, Postgres PASS (pool healthy), Redis FAIL.
    Postgres pool exhaustion is precluded; Redis is confirmed as the root cause.
    """
    evidence = [
        _make_evidence("otel.metrics_reachable", EvidenceStatus.PASS),
        _make_evidence("otel.http_error_rate", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("otel.p99_latency_ms", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("otel.error_spans_count", EvidenceStatus.PASS),
        _make_evidence("postgres.reachable", EvidenceStatus.PASS),
        _make_evidence("postgres.accepting_connections", EvidenceStatus.PASS),
        _make_evidence("postgres.pool_exhaustion", EvidenceStatus.PASS),  # Healthy pool!
        _make_evidence("redis.reachable", EvidenceStatus.PASS),
        _make_evidence("redis.ping", EvidenceStatus.PASS),
        _make_evidence("redis.memory_pressure", EvidenceStatus.FAIL, {"status": "FAIL"}),
    ]

    state = correlate_state(evidence, combined_catalog)
    causality = reconstruct_causality(evidence, state, telemetry_causality_rules)

    # Invariants: Preclusion by healthy physical signal
    assert causality.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED
    assert causality.primary_root_cause == "REDIS_OOM_MAXMEMORY"
    assert "POSTGRES_POOL_EXHAUSTED" in causality.precluded_hypotheses


def test_scenario_c5_unknown_non_contaminant(combined_catalog, telemetry_causality_rules):
    """
    Scenario C5 — UNKNOWN Non-Contaminant:
    OTel FAIL, Postgres FAIL, TLS UNKNOWN (independent / disjoint probe).
    Postgres explanation is CONFIRMED and NOT contaminated by the disjoint TLS UNKNOWN.
    """
    evidence = [
        _make_evidence("otel.metrics_reachable", EvidenceStatus.PASS),
        _make_evidence("otel.http_error_rate", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("otel.p99_latency_ms", EvidenceStatus.PASS),
        _make_evidence("otel.error_spans_count", EvidenceStatus.PASS),
        _make_evidence("postgres.reachable", EvidenceStatus.PASS),
        _make_evidence("postgres.accepting_connections", EvidenceStatus.PASS),
        _make_evidence("postgres.pool_exhaustion", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("redis.reachable", EvidenceStatus.PASS),
        _make_evidence("redis.ping", EvidenceStatus.PASS),
        _make_evidence("redis.memory_pressure", EvidenceStatus.PASS),
        _make_evidence("tls.certificate_valid", EvidenceStatus.UNKNOWN),  # Disjoint UNKNOWN probe
    ]

    state = correlate_state(evidence, combined_catalog)
    causality = reconstruct_causality(evidence, state, telemetry_causality_rules)

    # Invariants: Subgraph isolation of uncertainty
    assert causality.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED
    assert causality.primary_root_cause == "POSTGRES_POOL_EXHAUSTED"
    cand_map = {c.id: c for c in causality.candidate_causes}
    assert cand_map["POSTGRES_POOL_EXHAUSTED"].state == CausalCandidateState.CONFIRMED


def test_scenario_c6_no_declared_causality(combined_catalog):
    """
    Scenario C6 — No Declared Causality:
    OTel FAIL, Postgres FAIL, but ZERO causal rules linking them.
    Engine must NOT fabricate a causal link: status is ROOT_CAUSE_UNKNOWN, chain is empty.
    """
    evidence = [
        _make_evidence("otel.metrics_reachable", EvidenceStatus.PASS),
        _make_evidence("otel.http_error_rate", EvidenceStatus.FAIL, {"status": "FAIL"}),
        _make_evidence("postgres.reachable", EvidenceStatus.PASS),
        _make_evidence("postgres.pool_exhaustion", EvidenceStatus.FAIL, {"status": "FAIL"}),
    ]

    state = correlate_state(evidence, combined_catalog)
    # Empty causal rules catalog
    causality = reconstruct_causality(evidence, state, causal_rules=[])

    # Invariants: Zero implicit causality
    assert causality.status == CausalityStatus.ROOT_CAUSE_UNKNOWN
    assert causality.primary_root_cause is None
    assert causality.causal_chain == []
    assert len(causality.candidate_causes) == 0


def test_causal_relation_type_requires():
    """
    Verifies that REQUIRES causal relations enforce prerequisite evidence checks:
    If a situation requires network reachability, and network is UNKNOWN, candidate becomes UNRESOLVED.
    """
    rule_propagates = CausalRule(
        id="RULE_DB_OUTAGE_PROPAGATES",
        source="DATABASE_OUTAGE",
        target="API_GATEWAY_502",
        relation=CausalRelationType.PROPAGATES_TO,
        is_root_cause_candidate=True,
    )
    rule_requires = CausalRule(
        id="RULE_DB_OUTAGE_REQUIRES_NET",
        source="DATABASE_OUTAGE",
        target="network.port_reachable",
        relation=CausalRelationType.REQUIRES,
    )

    evidence_unknown = [
        _make_evidence("DATABASE_OUTAGE", EvidenceStatus.FAIL),
        _make_evidence("API_GATEWAY_502", EvidenceStatus.FAIL),
        _make_evidence("network.port_reachable", EvidenceStatus.UNKNOWN),
    ]

    class FakeSituation:
        id = "DATABASE_OUTAGE"

    class FakeState:
        situations = [FakeSituation()]
        evaluations = []

    causality = reconstruct_causality(
        evidence_unknown,
        FakeState(),  # type: ignore
        [rule_propagates, rule_requires],
    )

    assert causality.status == CausalityStatus.ROOT_CAUSE_UNKNOWN
    assert causality.primary_root_cause is None
    cand_map = {c.id: c for c in causality.candidate_causes}
    assert "DATABASE_OUTAGE" in cand_map
    assert cand_map["DATABASE_OUTAGE"].state == CausalCandidateState.UNRESOLVED
    assert "network.port_reachable" in cand_map["DATABASE_OUTAGE"].missing_evidence
