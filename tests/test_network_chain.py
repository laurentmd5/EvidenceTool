"""
Unit tests for the Deterministic Network Evidence Chain and Situations.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from evidencetool.decision.correlation import correlate_state
from evidencetool.decision.engine import decide
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.policy.loader import load_policy
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.network import NetworkProvider


def test_network_chain_dns_failure(monkeypatch):
    provider = NetworkProvider()

    def mock_run_command(args, **kwargs):
        if "getent" in args:
            return Mock(ran=True, returncode=2, stdout="", stderr="Unknown host")
        return Mock(ran=True, returncode=0, stdout="local", stderr="")

    monkeypatch.setattr("evidencetool.providers.network.run_command", mock_run_command)

    context = ProviderContext({"target_host": "nonexistent.example.com", "host": "srv1"})
    observations = provider.collect(context)
    obs_map = {o.id: o for o in observations}

    assert obs_map["network.dns_resolvable"].value["status"] == "FAIL"
    assert obs_map["network.dns_resolvable"].value["failure"] == "NXDOMAIN"


def test_network_chain_route_failure(monkeypatch):
    provider = NetworkProvider()

    def mock_run_command(args, **kwargs):
        if "getent" in args:
            return Mock(ran=True, returncode=0, stdout="192.0.2.50 example.com", stderr="")
        if "ip" in args and "route" in args:
            return Mock(ran=True, returncode=2, stdout="", stderr="RTNETLINK answers: Network is unreachable")
        return Mock(ran=True, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.network.run_command", mock_run_command)

    context = ProviderContext({"target_host": "192.0.2.50", "host": "srv1"})
    observations = provider.collect(context)
    obs_map = {o.id: o for o in observations}

    assert obs_map["network.dns_resolvable"].value["status"] == "PASS"
    assert obs_map["network.route_exists"].value["status"] == "FAIL"
    assert obs_map["network.route_exists"].value["failure"] == "NO_ROUTE_TO_HOST"


def test_network_chain_tcp_refused_vs_timeout(monkeypatch):
    provider = NetworkProvider()

    # Case 1: Refused
    def mock_connect_refused(*args, **kwargs):
        raise ConnectionRefusedError("Connection refused")

    monkeypatch.setattr("evidencetool.providers.network.socket.create_connection", mock_connect_refused)
    context = ProviderContext({"target_host": "127.0.0.1", "port": "5432"})
    obs = provider.collect(context)
    obs_map = {o.id: o for o in obs}

    assert obs_map["network.port_reachable"].value["status"] == "FAIL"
    assert obs_map["network.port_reachable"].value["failure"] == "CONNECTION_REFUSED"

    # Case 2: Timeout
    import socket
    def mock_connect_timeout(*args, **kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr("evidencetool.providers.network.socket.create_connection", mock_connect_timeout)
    obs2 = provider.collect(context)
    obs_map2 = {o.id: o for o in obs2}

    assert obs_map2["network.port_reachable"].value["status"] == "FAIL"
    assert obs_map2["network.port_reachable"].value["failure"] == "TIMEOUT"


def test_network_chain_tls_handshake_success_and_failure(monkeypatch):
    provider = NetworkProvider()

    # Success case
    mock_ssock = Mock()
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    class MockContext:
        check_hostname = True
        verify_mode = 0
        def wrap_socket(self, sock, **kwargs):
            class SSLContextManager:
                def __enter__(self):
                    return mock_ssock
                def __exit__(self, exc_type, exc_val, exc_tb):
                    pass
            return SSLContextManager()

    monkeypatch.setattr("evidencetool.providers.network.ssl.create_default_context", MockContext)

    class MockSocketCM:
        def close(self):
            pass
        def __enter__(self):
            return Mock()
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    monkeypatch.setattr("evidencetool.providers.network.socket.create_connection", lambda *args, **kwargs: MockSocketCM())

    context = ProviderContext({"target_host": "127.0.0.1", "port": "443", "use_tls": "true"})
    obs = provider.collect(context)
    obs_map = {o.id: o for o in obs}

    assert obs_map["network.tls_handshake"].value["status"] == "PASS"
    assert obs_map["network.tls_handshake"].value["tls_version"] == "TLSv1.3"


def test_network_chain_http_probe_5xx_and_200(monkeypatch):
    provider = NetworkProvider()

    # Mock HTTP 503 response
    mock_resp = Mock()
    mock_resp.status = 503

    class MockHTTPConn:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            return mock_resp
        def close(self):
            pass

    monkeypatch.setattr("evidencetool.providers.network.http.client.HTTPConnection", MockHTTPConn)

    class MockSocketCM:
        def close(self):
            pass
        def __enter__(self):
            return Mock()
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    monkeypatch.setattr("evidencetool.providers.network.socket.create_connection", lambda *args, **kwargs: MockSocketCM())

    context = ProviderContext({"target_host": "127.0.0.1", "port": "80", "check_http": "true"})
    obs = provider.collect(context)
    obs_map = {o.id: o for o in obs}

    assert obs_map["network.http_reachable"].value["status"] == "FAIL"
    assert obs_map["network.http_reachable"].value["failure"] == "HTTP_5XX"
    assert obs_map["network.http_reachable"].value["status_code"] == 503


def test_network_policy_and_situation_correlation(monkeypatch):
    catalog = load_catalog("catalogs/network.yaml")
    policy = load_policy("policies/network.yaml")

    # Scenario: Port Refused with Host Reachable
    provider = NetworkProvider()

    def mock_run_command(args, **kwargs):
        if "ping" in args:
            return Mock(ran=True, returncode=0, stdout="1 packets received", stderr="")
        return Mock(ran=True, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.network.run_command", mock_run_command)

    with patch("evidencetool.providers.network.socket.create_connection", side_effect=ConnectionRefusedError("Refused")):
        observations = provider.collect(ProviderContext({"target_host": "127.0.0.1", "port": "8080"}))

    evidence = [evaluate_observation(o) for o in observations]
    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "BLOCK"
    assert "NETWORK_TCP_REFUSED" in decision.reason
