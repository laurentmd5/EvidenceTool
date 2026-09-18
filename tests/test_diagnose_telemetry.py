"""
Integration tests for OpenTelemetry Mode A (Inbound Telemetry) + Mode C (Hybrid Causality).
Verifies:
- Raw observation -> Evidence Evaluator threshold application -> Situation match -> Decision.
- Telemetry availability separation and UNKNOWN != FAIL invariant.
- Hybrid causality linking surface OTel symptoms to native physical root causes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from evidencetool.causality.engine import reconstruct_causality
from evidencetool.causality.loader import load_causal_catalog
from evidencetool.causality.models import CausalityStatus
from evidencetool.decision.correlation import correlate_state
from evidencetool.diagnose import diagnose
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.models.evidence import EvidenceStatus
from evidencetool.models.observation import Observation
from evidencetool.policy.loader import load_policy


def test_telemetry_catalogs_and_policy_loading():
    catalog = load_catalog("catalogs/telemetry.yaml")
    assert len(catalog) >= 4
    sit_ids = {s.id for s in catalog}
    assert "TELEMETRY_METRICS_AVAILABLE" in sit_ids
    assert "TELEMETRY_METRICS_UNAVAILABLE" in sit_ids
    assert "SERVICE_TELEMETRY_NOMINAL" in sit_ids
    assert "SERVICE_ERROR_RATE_EXCEEDED" in sit_ids
    assert "SERVICE_P99_LATENCY_SPIKE" in sit_ids

    rules = load_causal_catalog("causality/telemetry.yaml")
    assert len(rules) >= 3
    rule_ids = {r.id for r in rules}
    assert "POSTGRES_POOL_TO_OTEL_ERROR_RATE" in rule_ids
    assert "REDIS_OOM_TO_OTEL_LATENCY_SPIKE" in rule_ids
    assert "TELEMETRY_NOMINAL_PRECLUDES_OUTAGE" in rule_ids

    policy = load_policy("policies/telemetry.yaml")
    assert policy.action == "promote_canary"
    assert "SERVICE_TELEMETRY_NOMINAL" in policy.allow
    assert "SERVICE_ERROR_RATE_EXCEEDED" in policy.blocked_by
    assert "TELEMETRY_METRICS_UNAVAILABLE" in policy.blocked_by

    # Verify thresholds loaded in required_evidence
    req_map = {r.id: r for r in policy.required_evidence}
    assert req_map["otel.http_error_rate"].threshold == 0.05
    assert req_map["otel.p99_latency_ms"].threshold == 1000.0


def test_diagnose_nominal_pipeline():
    """Nominal scenario: Metrics within policy thresholds -> ALLOW."""
    policy = load_policy("policies/telemetry.yaml")
    catalog = load_catalog("catalogs/telemetry.yaml")

    def conn_factory(*args, **kwargs):
        conn = Mock()

        def req_handler(method, path, headers=None):
            resp = Mock()
            resp.status = 200
            if "query=up" in path:
                resp.read.return_value = json.dumps({"status": "success", "data": {"result": []}}).encode("utf-8")
            elif "traces" in path:
                resp.read.return_value = json.dumps({"data": []}).encode("utf-8")
            elif "histogram_quantile" in path:
                resp.read.return_value = json.dumps(
                    {"status": "success", "data": {"result": [{"value": [100.0, "150.0"]}]}}
                ).encode("utf-8")
            else:
                resp.read.return_value = json.dumps(
                    {"status": "success", "data": {"result": [{"value": [100.0, "0.015"]}]}}
                ).encode("utf-8")
            conn.getresponse.return_value = resp

        conn.request.side_effect = req_handler
        return conn

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", side_effect=conn_factory):
        res = diagnose(
            target="checkout-service",
            policy=policy,
            context={
                "metrics_endpoint": "http://127.0.0.1:9090",
                "traces_endpoint": "http://127.0.0.1:3200",
                "service": "checkout-service",
            },
            catalog=catalog,
        )

    assert res.decision.status.value == "ALLOW"
    assert "SERVICE_TELEMETRY_NOMINAL" in res.decision.reason


def test_diagnose_service_error_rate_exceeded():
    """Threshold violation: 12% error rate > 5% threshold -> BLOCK."""
    policy = load_policy("policies/telemetry.yaml")
    catalog = load_catalog("catalogs/telemetry.yaml")

    def conn_factory(*args, **kwargs):
        conn = Mock()

        def req_handler(method, path, headers=None):
            resp = Mock()
            resp.status = 200
            if "query=up" in path:
                resp.read.return_value = json.dumps({"status": "success", "data": {"result": []}}).encode("utf-8")
            elif "traces" in path:
                resp.read.return_value = json.dumps({"data": []}).encode("utf-8")
            elif "histogram_quantile" in path:
                resp.read.return_value = json.dumps(
                    {"status": "success", "data": {"result": [{"value": [100.0, "120.0"]}]}}
                ).encode("utf-8")
            else:
                # 12% error rate violates 5% threshold
                resp.read.return_value = json.dumps(
                    {"status": "success", "data": {"result": [{"value": [100.0, "0.12"]}]}}
                ).encode("utf-8")
            conn.getresponse.return_value = resp

        conn.request.side_effect = req_handler
        return conn

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", side_effect=conn_factory):
        res = diagnose(
            target="checkout-service",
            policy=policy,
            context={
                "metrics_endpoint": "http://127.0.0.1:9090",
                "traces_endpoint": "http://127.0.0.1:3200",
                "service": "checkout-service",
            },
            catalog=catalog,
        )

    assert res.decision.status.value == "BLOCK"
    assert "SERVICE_ERROR_RATE_EXCEEDED" in res.decision.reason
    assert "otel.http_error_rate" in res.decision.blocking_evidence


def test_diagnose_backend_unreachable_unknown_not_fail():
    """
    Resilience invariant: Prometheus down -> TELEMETRY_METRICS_UNAVAILABLE matches,
    but SERVICE_ERROR_RATE_EXCEEDED does NOT match (UNKNOWN != FAIL).
    """
    policy = load_policy("policies/telemetry.yaml")
    catalog = load_catalog("catalogs/telemetry.yaml")

    def conn_factory(*args, **kwargs):
        conn = Mock()

        def req_handler(*args, **kwargs):
            raise ConnectionRefusedError("Connection refused")

        conn.request.side_effect = req_handler
        return conn

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", side_effect=conn_factory):
        res = diagnose(
            target="checkout-service",
            policy=policy,
            context={
                "metrics_endpoint": "http://127.0.0.1:9090",
                "traces_endpoint": "http://127.0.0.1:3200",
                "service": "checkout-service",
            },
            catalog=catalog,
        )

    # Decision blocks due to telemetry unavailability, NOT due to service error rate
    assert res.decision.status.value == "BLOCK"
    assert "TELEMETRY_METRICS_UNAVAILABLE" in res.decision.reason
    assert "SERVICE_ERROR_RATE_EXCEEDED" not in res.decision.reason


def test_mode_c_hybrid_causality_reconstruction():
    """
    Mode C Hybrid Causality:
    Surface symptom: otel.http_error_rate FAIL
    Physical root cause: postgres.pool_exhaustion FAIL
    Causal engine reconstructs: POSTGRES_POOL_EXHAUSTED -> SERVICE_ERROR_RATE_EXCEEDED.
    """
    def make_ev(obs_id: str, status: EvidenceStatus, value: dict | None = None):
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

    telemetry_catalog = load_catalog("catalogs/telemetry.yaml")
    data_catalog = load_catalog("catalogs/data.yaml")
    combined_catalog = telemetry_catalog + data_catalog

    causal_rules = load_causal_catalog("causality/telemetry.yaml")

    evidence = [
        make_ev("otel.metrics_reachable", EvidenceStatus.PASS),
        make_ev("otel.http_error_rate", EvidenceStatus.FAIL, {"status": "FAIL"}),
        make_ev("otel.p99_latency_ms", EvidenceStatus.PASS),
        make_ev("otel.error_spans_count", EvidenceStatus.PASS),
        make_ev("postgres.reachable", EvidenceStatus.PASS),
        make_ev("postgres.accepting_connections", EvidenceStatus.PASS),
        make_ev("postgres.pool_exhaustion", EvidenceStatus.FAIL, {"status": "FAIL", "error": "Too many clients"}),
    ]

    state = correlate_state(evidence, combined_catalog)
    causality = reconstruct_causality(evidence, state, causal_rules)

    assert causality.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED
    assert causality.primary_root_cause == "POSTGRES_POOL_EXHAUSTED"
    assert "POSTGRES_POOL_EXHAUSTED" in causality.causal_chain
    assert "SERVICE_ERROR_RATE_EXCEEDED" in causality.causal_chain
