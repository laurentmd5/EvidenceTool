"""
Unit tests for V0.8 Distributed Diagnosis & Cross-Domain Multi-Signal Correlation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import Mock, patch

from evidencetool.decision.correlation import correlate_state
from evidencetool.decision.engine import decide
from evidencetool.diagnose import diagnose
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.observation import Observation
from evidencetool.policy.loader import load_policy


def _make_evidence(ev_id: str, status: EvidenceStatus) -> Evidence:
    obs = Observation(
        id=ev_id,
        source=ev_id.split(".")[0],
        category="distributed",
        collector="test_collector",
        method="test_method",
        value={"status": status.value},
        message=f"Test observation {ev_id}",
        observed_at=datetime.now(timezone.utc),
    )
    return Evidence(observation=obs, status=status, message=f"Evaluated {ev_id}")


def test_distributed_database_connectivity_failure_correlation():
    catalog = load_catalog("catalogs/distributed.yaml")
    policy = load_policy("policies/distributed.yaml")

    # Multi-signal evidence:
    # 1. API is failing (500)
    # 2. Postgres is unreachable
    # 3. Network port 5432 connection refused
    # 4. Redis is healthy (PONG) -> rules out general network partition
    evidence = [
        _make_evidence("dependency.http_status", EvidenceStatus.FAIL),
        _make_evidence("postgres.reachable", EvidenceStatus.FAIL),
        _make_evidence("network.port_reachable", EvidenceStatus.FAIL),
        _make_evidence("redis.ping", EvidenceStatus.PASS),
    ]

    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "BLOCK"
    assert "DATABASE_CONNECTIVITY_FAILURE" in decision.reason
    assert "postgres.reachable" in decision.blocking_evidence
    assert "network.port_reachable" in decision.blocking_evidence


def test_distributed_pool_exhaustion_cascade():
    catalog = load_catalog("catalogs/distributed.yaml")
    policy = load_policy("policies/distributed.yaml")

    evidence = [
        _make_evidence("dependency.sla_budget", EvidenceStatus.FAIL),
        _make_evidence("postgres.reachable", EvidenceStatus.PASS),
        _make_evidence("postgres.pool_exhaustion", EvidenceStatus.FAIL),
        _make_evidence("redis.ping", EvidenceStatus.PASS),
    ]

    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "BLOCK"
    assert "DATABASE_POOL_EXHAUSTION_CASCADE" in decision.reason
    assert "postgres.pool_exhaustion" in decision.blocking_evidence


def test_distributed_cache_failure_database_overload():
    catalog = load_catalog("catalogs/distributed.yaml")
    policy = load_policy("policies/distributed.yaml")

    evidence = [
        _make_evidence("redis.memory_pressure", EvidenceStatus.FAIL),
        _make_evidence("postgres.reachable", EvidenceStatus.PASS),
        _make_evidence("postgres.latency_ms", EvidenceStatus.FAIL),
    ]

    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "BLOCK"
    assert "CACHE_FAILURE_DATABASE_OVERLOAD" in decision.reason
    assert "redis.memory_pressure" in decision.blocking_evidence


def test_distributed_upstream_microservice_outage():
    catalog = load_catalog("catalogs/distributed.yaml")
    policy = load_policy("policies/distributed.yaml")

    evidence = [
        _make_evidence("dependency.http_status", EvidenceStatus.FAIL),
        _make_evidence("dependency.circuit_breaker", EvidenceStatus.FAIL),
        _make_evidence("postgres.reachable", EvidenceStatus.PASS),
        _make_evidence("redis.ping", EvidenceStatus.PASS),
    ]

    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "BLOCK"
    assert "UPSTREAM_MICROSERVICE_OUTAGE" in decision.reason
    assert "dependency.http_status" in decision.blocking_evidence


def test_distributed_split_brain_or_read_only():
    catalog = load_catalog("catalogs/distributed.yaml")
    policy = load_policy("policies/distributed.yaml")

    evidence = [
        _make_evidence("postgres.reachable", EvidenceStatus.PASS),
        _make_evidence("postgres.is_in_recovery", EvidenceStatus.FAIL),
        _make_evidence("redis.ping", EvidenceStatus.PASS),
    ]

    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "BLOCK"
    assert "DISTRIBUTED_SPLIT_BRAIN_OR_READ_ONLY" in decision.reason
    assert "postgres.is_in_recovery" in decision.blocking_evidence


def test_distributed_total_network_partition():
    catalog = load_catalog("catalogs/distributed.yaml")
    policy = load_policy("policies/distributed.yaml")

    evidence = [
        _make_evidence("network.port_reachable", EvidenceStatus.FAIL),
        _make_evidence("postgres.reachable", EvidenceStatus.FAIL),
        _make_evidence("redis.reachable", EvidenceStatus.FAIL),
    ]

    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "BLOCK"
    assert "TOTAL_NETWORK_PARTITION" in decision.reason


def test_diagnose_distributed_end_to_end():
    catalog = load_catalog("catalogs/distributed.yaml")
    policy = load_policy("policies/distributed.yaml")

    # Mock Redis ping PASS and mock HTTP 500 and mock Postgres connection refused
    mock_resp = Mock()
    mock_resp.status = 500

    class MockHTTPConn:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            return mock_resp
        def close(self):
            pass

    mock_redis_sock = Mock()
    info_payload = "# Memory\r\nused_memory:10485760\r\nmaxmemory:104857600\r\n# Replication\r\nrole:master\r\n"
    mock_redis_sock.recv.side_effect = [
        b"+", b"P", b"O", b"N", b"G", b"\r", b"\n",
        b"$", b"7", b"8", b"\r", b"\n", info_payload.encode("utf-8"), b"\r", b"\n",
    ]

    def mock_socket_create(addr, *args, **kwargs):
        host, port = addr
        if port == 6379:
            return mock_redis_sock
        raise ConnectionRefusedError(f"Connection refused to {host}:{port}")

    with patch("evidencetool.providers.dependency.http.client.HTTPConnection", MockHTTPConn), \
         patch("evidencetool.providers.redis.socket.create_connection", side_effect=mock_socket_create), \
         patch("evidencetool.providers.postgres.socket.create_connection", side_effect=mock_socket_create), \
         patch("evidencetool.providers.network.socket.create_connection", side_effect=mock_socket_create):

        context = {
            "url": "http://127.0.0.1:8080/health",
            "redis_host": "127.0.0.1",
            "redis_port": "6379",
            "db_host": "127.0.0.1",
            "db_port": "5432",
            "target": "127.0.0.1",
            "port": "5432",
        }

        result = diagnose(
            target="distributed_ecommerce_api",
            policy=policy,
            context=context,
            catalog=catalog,
        )

        assert result.decision.status.value == "BLOCK"
        assert "DATABASE_CONNECTIVITY_FAILURE" in result.decision.reason
        assert "postgres.reachable" in result.decision.blocking_evidence
