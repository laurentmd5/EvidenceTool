"""
Unit tests for Dependency Provider (HTTP upstream SLA and circuit breakers).
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from evidencetool.providers.base import ProviderContext
from evidencetool.providers.dependency import DependencyProvider
from evidencetool.providers.registry import get_provider


def test_dependency_provider_registration():
    p = get_provider("dependency")
    assert isinstance(p, DependencyProvider)


def test_dependency_nominal_200_within_sla():
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

    with patch("evidencetool.providers.dependency.http.client.HTTPConnection", MockHTTPConn):
        obs = p.collect(ProviderContext({"url": "http://127.0.0.1:8080/health", "sla_budget_ms": "500.0"}))

    obs_map = {o.id: o for o in obs}
    assert obs_map["dependency.http_status"].value["status"] == "PASS"
    assert obs_map["dependency.sla_budget"].value["status"] == "PASS"
    assert obs_map["dependency.circuit_breaker"].value["status"] == "PASS"


def test_dependency_circuit_breaker_503():
    p = DependencyProvider()

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

    with patch("evidencetool.providers.dependency.http.client.HTTPConnection", MockHTTPConn):
        obs = p.collect(ProviderContext({"url": "http://127.0.0.1:8080/api/checkout"}))

    obs_map = {o.id: o for o in obs}
    assert obs_map["dependency.http_status"].value["status"] == "FAIL"
    assert obs_map["dependency.circuit_breaker"].value["status"] == "FAIL"
    assert obs_map["dependency.circuit_breaker"].value["failure"] == "HTTP_503"


def test_dependency_url_sanitization_redacts_credentials_and_tokens():
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

    with patch("evidencetool.providers.dependency.http.client.HTTPConnection", MockHTTPConn):
        obs = p.collect(ProviderContext({"url": "http://admin:secret123@127.0.0.1:8080/api/v1?token=supersecret&safe_param=hello"}))

    obs_map = {o.id: o for o in obs}
    status_obs = obs_map["dependency.http_status"]

    # Ensure credentials and sensitive token are redacted
    assert "admin:secret123" not in status_obs.method
    assert "supersecret" not in status_obs.method
    assert "token=%5BREDACTED%5D" in status_obs.method or "token=[REDACTED]" in status_obs.method
    assert "safe_param=hello" in status_obs.method
    assert "admin:secret123" not in status_obs.value["url"]
    assert "supersecret" not in status_obs.value["url"]
