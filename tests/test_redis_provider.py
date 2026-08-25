"""
Unit tests for Redis Provider (RESP native client & observability).
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from evidencetool.capability.models import CapabilitySet, ExecutionContext, NetworkCapability
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.redis import RedisProvider
from evidencetool.providers.registry import get_provider


def test_redis_provider_registration():
    p = get_provider("redis")
    assert isinstance(p, RedisProvider)


def test_redis_unreachable():
    p = RedisProvider()
    with patch("evidencetool.providers.redis.socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
        obs = p.collect(ProviderContext({"target_host": "127.0.0.1", "port": "6379"}))

    obs_map = {o.id: o for o in obs}
    assert obs_map["redis.reachable"].value["status"] == "FAIL"
    assert obs_map["redis.reachable"].value["failure"] == "CONNECTION_REFUSED"


def test_redis_ping_success_and_info():
    p = RedisProvider()

    mock_sock = Mock()
    # Responses sequence:
    # 1. PING -> +PONG\r\n
    # 2. INFO -> $120\r\n# Memory\r\nused_memory:10485760\r\nmaxmemory:104857600\r\n# Replication\r\nrole:master\r\n\r\n
    info_payload = "# Memory\r\nused_memory:10485760\r\nmaxmemory:104857600\r\n# Replication\r\nrole:master\r\n"

    mock_sock.recv.side_effect = [b"+", b"P", b"O", b"N", b"G", b"\r", b"\n", b"$", b"7", b"8", b"\r", b"\n", info_payload.encode("utf-8"), b"\r", b"\n"]

    with patch("evidencetool.providers.redis.socket.create_connection", return_value=mock_sock):
        obs = p.collect(ProviderContext({"target_host": "127.0.0.1", "port": "6379"}))

    obs_map = {o.id: o for o in obs}
    assert obs_map["redis.reachable"].value["status"] == "PASS"
    assert obs_map["redis.ping"].value["status"] == "PASS"


def test_redis_auth_failure():
    p = RedisProvider()

    mock_sock = Mock()
    mock_sock.recv.side_effect = [b"-", b"E", b"R", b"R", b" ", b"i", b"n", b"v", b"a", b"l", b"i", b"d", b" ", b"p", b"a", b"s", b"s", b"w", b"o", b"r", b"d", b"\r", b"\n"]

    with patch("evidencetool.providers.redis.socket.create_connection", return_value=mock_sock):
        obs = p.collect(ProviderContext({"target_host": "127.0.0.1", "port": "6379", "password": "wrongpassword"}))

    obs_map = {o.id: o for o in obs}
    assert obs_map["redis.auth"].value["status"] == "FAIL"
    assert obs_map["redis.auth"].value["failure"] == "WRONGPASS"


def test_redis_capability_denied():
    p = RedisProvider()
    context = ProviderContext(
        {"target_host": "10.50.0.1", "port": "6379"},
        execution=ExecutionContext(
            capabilities=CapabilitySet(
                network=NetworkCapability(targets=("10.0.0.0/8",), ports=frozenset({80}))
            )
        ),
    )

    obs = p.collect(context)
    obs_map = {o.id: o for o in obs}
    assert obs_map["redis.reachable"].value["status"] == "UNKNOWN"
    assert obs_map["redis.reachable"].value["capability_denied"] is True
