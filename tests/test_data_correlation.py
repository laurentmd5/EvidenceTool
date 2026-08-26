"""
Unit tests for Dependency-Aware Root-Cause Analysis and Situations (V0.6).
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from evidencetool.decision.correlation import correlate_state
from evidencetool.decision.engine import decide
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.policy.loader import load_policy
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.dependency import DependencyProvider
from evidencetool.providers.postgres import PostgresProvider
from evidencetool.providers.redis import RedisProvider


def test_scenario_postgres_pool_exhausted_blocks_restart(monkeypatch):
    catalog = load_catalog("catalogs/data.yaml")
    policy = load_policy("policies/data.yaml")

    # Simulate Postgres Pool Exhaustion
    p = PostgresProvider()

    def mock_run_command(args, **kwargs):
        if "pg_isready" in args:
            return Mock(
                ran=True,
                returncode=1,
                stdout="127.0.0.1:5432 - rejecting connections (FATAL: remaining connection slots are reserved)",
                stderr="",
            )
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.postgres.run_command", mock_run_command)

    class MockSocket:
        def close(self):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr("evidencetool.providers.postgres.socket.create_connection", lambda *args, **kwargs: MockSocket())

    observations = p.collect(ProviderContext({"target_host": "127.0.0.1", "port": "5432"}))
    evidence = [evaluate_observation(o) for o in observations]
    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "BLOCK"
    assert "POSTGRES_POOL_EXHAUSTED" in decision.reason


def test_scenario_redis_oom_maxmemory_blocks_restart():
    catalog = load_catalog("catalogs/data.yaml")
    policy = load_policy("policies/data.yaml")

    p = RedisProvider()

    # Mock Redis INFO Memory showing 98% memory usage
    info_payload = "# Memory\r\nused_memory:98000000\r\nmaxmemory:100000000\r\n# Replication\r\nrole:master\r\n"

    mock_sock = Mock()
    mock_sock.recv.side_effect = [
        b"+", b"P", b"O", b"N", b"G", b"\r", b"\n",
        b"$", b"7", b"8", b"\r", b"\n", info_payload.encode("utf-8"), b"\r", b"\n"
    ]

    with patch("evidencetool.providers.redis.socket.create_connection", return_value=mock_sock):
        observations = p.collect(ProviderContext({"target_host": "127.0.0.1", "port": "6379", "max_mem_ratio": "0.9"}))

    evidence = [evaluate_observation(o) for o in observations]
    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "BLOCK"
    assert "REDIS_OOM_MAXMEMORY" in decision.reason


def test_scenario_upstream_latency_degradation_blocks_restart():
    catalog = load_catalog("catalogs/data.yaml")
    policy = load_policy("policies/data.yaml")

    p = DependencyProvider()

    mock_resp = Mock()
    mock_resp.status = 200

    class MockHTTPConn:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            return mock_resp
        def close(self):
            pass

    # Mock latency violation with realistic SLA: 250ms latency vs 50ms SLA budget
    with patch("evidencetool.providers.dependency.http.client.HTTPConnection", MockHTTPConn), \
         patch("evidencetool.providers.dependency.time.perf_counter", side_effect=[10.0, 10.250, 10.250]):
        observations = p.collect(ProviderContext({"url": "http://127.0.0.1:8080/api/orders", "sla_budget_ms": "50.0"}))

    evidence = [evaluate_observation(o) for o in observations]
    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "BLOCK"
    assert "UPSTREAM_LATENCY_DEGRADATION" in decision.reason


def test_remote_ssh_datastore_probes_handle_remote_cli_correctly():
    # 1. Test PostgreSQL remote inspection over SSH
    p_pg = PostgresProvider()
    with patch("evidencetool.providers.postgres.run_command") as mock_pg_cmd:
        mock_pg_cmd.side_effect = [
            Mock(ran=True, returncode=0, stdout="", stderr=""),  # nc -z port reachable
            Mock(ran=True, returncode=0, stdout="10.0.1.5:5432 - accepting connections", stderr=""),  # pg_isready
        ]
        obs_pg = p_pg.collect(ProviderContext({"target_host": "10.0.1.5", "port": "5432", "host": "db-server-01"}))
        pg_map = {o.id: o for o in obs_pg}
        assert pg_map["postgres.reachable"].value["status"] == "PASS"
        assert pg_map["postgres.accepting_connections"].value["status"] == "PASS"

    # 2. Test Redis remote inspection over SSH with redis-cli
    p_redis = RedisProvider()
    with patch("evidencetool.providers.redis.run_command") as mock_redis_cmd:
        mock_redis_cmd.side_effect = [
            Mock(ran=True, returncode=0, stdout="", stderr=""),  # nc -z port reachable
            Mock(ran=True, returncode=0, stdout="PONG", stderr=""),  # redis-cli ping
            Mock(ran=True, returncode=0, stdout="used_memory:1000\nmaxmemory:10000\n", stderr=""),
            Mock(ran=True, returncode=0, stdout="role:master\nmaster_link_status:up\n", stderr=""),
        ]
        obs_redis = p_redis.collect(ProviderContext({"target_host": "10.0.1.6", "port": "6379", "host": "cache-server-01"}))
        redis_map = {o.id: o for o in obs_redis}
        assert redis_map["redis.reachable"].value["status"] == "PASS"
        assert redis_map["redis.ping"].value["status"] == "PASS"
        assert redis_map["redis.memory_pressure"].value["status"] == "PASS"
        assert redis_map["redis.role"].value["status"] == "PASS"
        assert redis_map["redis.latency_ms"].value["status"] == "PASS"


def test_remote_redis_password_is_never_sent_in_command_arguments():
    provider = RedisProvider()
    with patch("evidencetool.providers.redis.run_command") as mock_command:
        mock_command.return_value = Mock(ran=True, returncode=0, stdout="", stderr="")
        observations = provider.collect(
            ProviderContext(
                {
                    "target_host": "10.0.1.6",
                    "port": "6379",
                    "host": "cache-server-01",
                    "password": "super-secret",
                }
            )
        )

    assert all("super-secret" not in str(call) for call in mock_command.call_args_list)
    assert {observation.id for observation in observations} == {
        "redis.reachable",
        "redis.auth",
        "redis.ping",
        "redis.latency_ms",
        "redis.memory_pressure",
        "redis.role",
    }
    assert observations[0].id == "redis.reachable"
    assert observations[0].value["status"] == "PASS"
    assert all(observation.value["status"] == "UNKNOWN" for observation in observations[1:])
