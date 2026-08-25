"""
Unit tests for PostgreSQL Provider.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from evidencetool.capability.models import CapabilitySet, ExecutionContext, NetworkCapability
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.postgres import PostgresProvider
from evidencetool.providers.registry import get_provider


def test_postgres_provider_registration():
    p = get_provider("postgres")
    assert isinstance(p, PostgresProvider)


def test_postgres_unreachable():
    p = PostgresProvider()
    with patch("evidencetool.providers.postgres.socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
        obs = p.collect(ProviderContext({"target_host": "127.0.0.1", "port": "5432"}))

    obs_map = {o.id: o for o in obs}
    assert obs_map["postgres.reachable"].value["status"] == "FAIL"
    assert obs_map["postgres.reachable"].value["failure"] == "CONNECTION_REFUSED"


def test_postgres_pg_isready_success(monkeypatch):
    p = PostgresProvider()

    def mock_run_command(args, **kwargs):
        if "pg_isready" in args:
            return Mock(ran=True, returncode=0, stdout="127.0.0.1:5432 - accepting connections", stderr="")
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

    obs = p.collect(ProviderContext({"target_host": "127.0.0.1", "port": "5432"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["postgres.reachable"].value["status"] == "PASS"
    assert obs_map["postgres.accepting_connections"].value["status"] == "PASS"
    assert obs_map["postgres.pool_exhaustion"].value["status"] == "PASS"


def test_postgres_pool_exhaustion(monkeypatch):
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

    obs = p.collect(ProviderContext({"target_host": "127.0.0.1", "port": "5432"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["postgres.accepting_connections"].value["status"] == "FAIL"
    assert obs_map["postgres.pool_exhaustion"].value["status"] == "FAIL"
    assert obs_map["postgres.pool_exhaustion"].value["failure"] == "POOL_EXHAUSTED"


def test_postgres_capability_denied():
    p = PostgresProvider()
    context = ProviderContext(
        {"target_host": "192.168.1.100", "port": "5432"},
        execution=ExecutionContext(
            capabilities=CapabilitySet(
                network=NetworkCapability(targets=("10.0.0.0/8",))
            )
        ),
    )

    obs = p.collect(context)
    obs_map = {o.id: o for o in obs}
    assert obs_map["postgres.reachable"].value["status"] == "UNKNOWN"
    assert obs_map["postgres.reachable"].value["capability_denied"] is True
