"""
Unit tests for V0.9 AI-Agent SDK & Safety Gateway (evidencetool.agent).
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from evidencetool.agent import (
    AgentDiagnosisRequest,
    AgentDiagnosisResult,
    AgentSafetyGate,
    CapabilityDenied,
    CapabilitySet,
)
from evidencetool.capability.loader import load_capability_policy
from evidencetool.capability.models import NetworkCapability
from evidencetool.models.observation import Observation


def _now() -> datetime:
    return datetime.now(timezone.utc)


def test_agent_safety_gate_allow_remediation():
    # Setup gate with nginx policies
    gate = AgentSafetyGate(
        catalog="catalogs/nginx.yaml",
        default_policy="policies/nginx.yaml",
    )

    request = AgentDiagnosisRequest(
        agent_id="remediation-bot-01",
        action="restart_nginx",
        target="nginx",
        context={
            "service": "nginx",
            "config_path": "/etc/nginx/nginx.conf",
            "certificate_path": "/etc/ssl/certs/test.crt",
            "private_key_path": "/etc/ssl/private/test.key",
        },
        session_id="sess_12345",
    )

    # Mock nominal environment: service inactive, but config valid, TLS valid, disk space OK
    def mock_systemd_collect(context):
        return [
            Observation("systemd.service_exists", "systemd", "service", "systemd", "systemctl", {"status": "PASS"}, "Service exists", _now()),
            Observation("systemd.service_active", "systemd", "service", "systemd", "systemctl", {"status": "FAIL"}, "Service inactive", _now()),
        ]

    def mock_nginx_collect(context):
        return [
            Observation("nginx.config_valid", "nginx", "config", "nginx", "nginx -t", {"status": "PASS"}, "Syntax OK", _now()),
        ]

    def mock_tls_collect(context):
        return [
            Observation("tls.certificate_exists", "tls", "crypto", "tls", "stat", {"status": "PASS"}, "Cert exists", _now()),
            Observation("tls.certificate_valid", "tls", "crypto", "tls", "x509", {"status": "PASS"}, "Cert valid", _now()),
            Observation("tls.private_key_exists", "tls", "crypto", "tls", "stat", {"status": "PASS"}, "Key exists", _now()),
            Observation("tls.key_matches_certificate", "tls", "crypto", "tls", "modulus", {"status": "PASS"}, "Key matches", _now()),
        ]

    def mock_fs_collect(context):
        return [
            Observation("filesystem.disk_space_available", "filesystem", "storage", "fs", "statvfs", {"status": "PASS", "free_percent": 50.0}, "Disk space ok", _now()),
        ]

    with patch("evidencetool.providers.systemd.SystemdProvider.collect", side_effect=mock_systemd_collect), \
         patch("evidencetool.providers.nginx.NginxProvider.collect", side_effect=mock_nginx_collect), \
         patch("evidencetool.providers.tls.TLSProvider.collect", side_effect=mock_tls_collect), \
         patch("evidencetool.providers.filesystem.FilesystemProvider.collect", side_effect=mock_fs_collect):

        result = gate.evaluate(request)

        assert isinstance(result, AgentDiagnosisResult)
        assert result.is_allowed is True
        assert result.status == "ALLOW"
        assert result.matching_situation == "NGINX_SERVICE_DOWN"
        assert result.authority.caller_id == "remediation-bot-01"
        assert result.authority.caller_type == "AI_AGENT"
        assert result.authority.session_id == "sess_12345"


def test_agent_safety_gate_block_destructive_action():
    # Setup gate with distributed policies
    gate = AgentSafetyGate(
        catalog="catalogs/distributed.yaml",
        default_policy="policies/distributed.yaml",
    )

    request = AgentDiagnosisRequest(
        agent_id="incident-responder-ai",
        action="restart_application",
        target="orders-api",
        context={
            "url": "http://127.0.0.1:8080/health",
            "db_host": "127.0.0.1",
            "db_port": "5432",
            "redis_host": "127.0.0.1",
            "redis_port": "6379",
            "target": "127.0.0.1",
            "port": "5432",
        },
    )

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
    info_payload = "# Memory\r\nused_memory:1000\r\nmaxmemory:10000\r\n# Replication\r\nrole:master\r\n"
    mock_redis_sock.recv.side_effect = [
        b"+", b"P", b"O", b"N", b"G", b"\r", b"\n",
        b"$", b"6", b"8", b"\r", b"\n", info_payload.encode("utf-8"), b"\r", b"\n",
    ]

    def mock_socket_create(addr, *args, **kwargs):
        host, port = addr
        if port == 6379:
            return mock_redis_sock
        raise ConnectionRefusedError(f"Refused on port {port}")

    with patch("evidencetool.providers.dependency.http.client.HTTPConnection", MockHTTPConn), \
         patch("evidencetool.providers.redis.socket.create_connection", side_effect=mock_socket_create), \
         patch("evidencetool.providers.postgres.socket.create_connection", side_effect=mock_socket_create), \
         patch("evidencetool.providers.network.socket.create_connection", side_effect=mock_socket_create):

        result = gate.evaluate(request)

        assert result.is_allowed is False
        assert result.status == "BLOCK"
        assert result.matching_situation == "DATABASE_CONNECTIVITY_FAILURE"
        assert "postgres.reachable" in result.root_cause_evidence
        assert "network.port_reachable" in result.root_cause_evidence
        assert len(result.recommendation) > 0


def test_agent_safety_gate_probe_budget_exhaustion():
    # Limit budget to 2 probes
    caps = CapabilitySet(
        network=NetworkCapability(max_probes=2)
    )

    # 1. Test direct capability enforcement
    caps.require_network("tcp_connect", "127.0.0.1", 80)
    caps.require_network("tcp_connect", "127.0.0.1", 443)
    with pytest.raises(CapabilityDenied, match="Probe budget exceeded"):
        caps.require_network("tcp_connect", "127.0.0.1", 8080)

    # 2. Test gate evaluation: budget exceeded turns into BLOCK decision
    gate_caps = CapabilitySet(
        network=NetworkCapability(max_probes=1)
    )
    gate = AgentSafetyGate(
        capability_policy=gate_caps,
        catalog="catalogs/distributed.yaml",
        default_policy="policies/distributed.yaml",
    )
    request = AgentDiagnosisRequest(
        agent_id="overzealous-agent",
        action="restart_application",
        target="distributed-app",
        context={
            "url": "http://127.0.0.1:8080/health",
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


def test_agent_safety_gate_capability_tamper_proofing():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write("capabilities:\n  network:\n    max_probes: 5\n")
        tmp_path = f.name

    try:
        # Valid hash check
        import hashlib
        content = Path(tmp_path).read_text(encoding="utf-8")
        expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        loaded_caps = load_capability_policy(tmp_path, expected_hash=expected_hash)
        assert loaded_caps.policy_fingerprint == expected_hash

        # Tampered hash check
        tampered_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        with pytest.raises(CapabilityDenied, match="Capability policy tamper detected"):
            load_capability_policy(tmp_path, expected_hash=tampered_hash)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
