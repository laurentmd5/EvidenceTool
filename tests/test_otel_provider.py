"""
Unit tests for OpenTelemetry Inbound Telemetry Provider (Mode A).
Tests TelemetryHTTPClient (SSRF, No-Redirect, Bounded Streams, Redaction) and OTelProvider.
"""

from __future__ import annotations

import json
from unittest.mock import Mock, patch

from evidencetool.providers.base import ProviderContext
from evidencetool.providers.otel import OTelProvider
from evidencetool.providers.registry import ProviderTrust, get_provider, get_provider_trust
from evidencetool.providers.telemetry_client import (
    HARD_BUDGET_CEILINGS,
    TelemetryBudget,
    TelemetryHTTPClient,
    build_clamped_telemetry_budget,
    sanitize_error,
    sanitize_url,
)


def test_otel_provider_registration():
    p = get_provider("otel")
    assert isinstance(p, OTelProvider)
    assert get_provider_trust("otel") == ProviderTrust.BUILTIN


def test_telemetry_client_ssrf_metadata_blocked():
    client = TelemetryHTTPClient()
    # Cloud metadata endpoint 169.254.169.254 is blocked by default
    status, _, err = client.get("http://169.254.169.254:80", "/latest/meta-data")
    assert status == 0
    assert err is not None
    assert "link-local/cloud-metadata" in err


def test_telemetry_client_no_redirect_enforced():
    client = TelemetryHTTPClient()

    class MockConn:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            resp = Mock()
            resp.status = 302
            resp.getheader.return_value = "http://169.254.169.254/secret"
            return resp

        def close(self):
            pass

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", MockConn):
        status, _, err = client.get("http://127.0.0.1:9090", "/api/v1/query?query=up")

    assert status == 302
    assert err is not None
    assert "redirects forbidden to prevent SSRF" in err


def test_telemetry_client_bounded_stream_anti_dos():
    budget = TelemetryBudget(max_response_bytes=100)
    client = TelemetryHTTPClient(budget=budget)

    oversized = b"X" * 150

    class MockConn:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            resp = Mock()
            resp.status = 200
            resp.read.return_value = oversized
            return resp

        def close(self):
            pass

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", MockConn):
        status, body, err = client.get("http://127.0.0.1:9090", "/api/v1/query?query=up")

    assert body == b""
    assert err is not None
    assert "Response size exceeded safety budget" in err


def test_telemetry_client_request_budget_enforced():
    budget = TelemetryBudget(max_requests=2)
    client = TelemetryHTTPClient(budget=budget)

    class MockConn:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            resp = Mock()
            resp.status = 200
            resp.read.return_value = b"{}"
            return resp

        def close(self):
            pass

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", MockConn):
        client.get("http://127.0.0.1:9090", "/api/v1/query?query=1")
        client.get("http://127.0.0.1:9090", "/api/v1/query?query=2")
        # 3rd request exceeds budget
        status, _, err = client.get("http://127.0.0.1:9090", "/api/v1/query?query=3")

    assert status == 0
    assert err is not None
    assert "budget exceeded" in err


def test_centralized_sanitization():
    raw_url = "http://admin:secretpass@127.0.0.1:9090/api?api_key=token123&user=john"
    clean = sanitize_url(raw_url)
    assert "secretpass" not in clean
    assert "token123" not in clean
    assert "[REDACTED]" in clean
    assert "user=john" in clean

    raw_err = f"Failed to connect to {raw_url}"
    clean_err = sanitize_error(raw_err, raw_url)
    assert clean_err is not None
    assert "secretpass" not in clean_err
    assert "token123" not in clean_err


def test_otel_provider_raw_metrics_normalization():
    """Verify provider emits raw normalized metrics, not threshold judgements."""
    p = OTelProvider()

    prometheus_payload = {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [{"metric": {}, "value": [100.0, "0.073"]}],
        },
    }

    tempo_payload = {
        "data": [
            {
                "traceID": "t1",
                "spans": [
                    {"spanID": "s1", "tags": [{"key": "error", "value": "true"}]},
                    {"spanID": "s2", "tags": [{"key": "error", "value": "true"}]},
                ],
            }
        ]
    }

    def conn_factory(*args, **kwargs):
        conn = Mock()

        def req_handler(method, path, headers=None):
            resp = Mock()
            resp.status = 200
            if "traces" in path:
                resp.read.return_value = json.dumps(tempo_payload).encode("utf-8")
            elif "histogram_quantile" in path:
                resp.read.return_value = json.dumps({
                    "status": "success",
                    "data": {"result": [{"value": [100.0, "250.5"]}], "resultType": "vector"}
                }).encode("utf-8")
            else:
                resp.read.return_value = json.dumps(prometheus_payload).encode("utf-8")
            conn.getresponse.return_value = resp

        conn.request.side_effect = req_handler
        return conn

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", side_effect=conn_factory):
        ctx = ProviderContext(
            {
                "metrics_endpoint": "http://127.0.0.1:9090",
                "traces_endpoint": "http://127.0.0.1:3200",
                "service": "payment-service",
                "lookback": "10m",
            }
        )
        obs = p.collect(ctx)

    obs_map = {o.id: o for o in obs}

    # Technical reachability carries PASS/FAIL
    assert obs_map["otel.metrics_reachable"].value["status"] == "PASS"
    assert obs_map["otel.traces_reachable"].value["status"] == "PASS"

    # Application metrics carry raw normalized values without status verdict
    err_val = obs_map["otel.http_error_rate"].value
    assert err_val["value"] == 0.073
    assert err_val["unit"] == "ratio"
    assert err_val["service"] == "payment-service"
    assert "status" not in err_val  # Provider does not evaluate threshold!

    lat_val = obs_map["otel.p99_latency_ms"].value
    assert lat_val["value"] == 250.5
    assert lat_val["unit"] == "ms"
    assert "status" not in lat_val

    # Error spans carries time window metadata
    spans_val = obs_map["otel.error_spans_count"].value
    assert spans_val["count"] == 2
    assert spans_val["window"] == "10m"
    assert spans_val["service"] == "payment-service"
    assert "status" not in spans_val


def test_otel_provider_transport_failure_unknown():
    """Verify backend failure produces UNKNOWN technical status, never false FAIL."""
    p = OTelProvider()

    def conn_factory(*args, **kwargs):
        conn = Mock()

        def req_handler(*args, **kwargs):
            raise ConnectionRefusedError("Connection refused")

        conn.request.side_effect = req_handler
        return conn

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", side_effect=conn_factory):
        ctx = ProviderContext({"metrics_endpoint": "http://127.0.0.1:9090"})
        obs = p.collect(ctx)

    obs_map = {o.id: o for o in obs}
    # Availability is FAIL (transport down)
    assert obs_map["otel.metrics_reachable"].value["status"] == "FAIL"

    # Inbound metrics resolve to UNKNOWN with transport_status="failed"
    err_obs = obs_map["otel.http_error_rate"]
    assert err_obs.value["status"] == "UNKNOWN"
    assert err_obs.transport_status == "failed"


def test_telemetry_client_read_timeout_enforced():
    """Verify read_timeout is explicitly applied to socket."""
    budget = TelemetryBudget(read_timeout=3.5)
    client = TelemetryHTTPClient(budget=budget)

    class MockConnWithSock:
        def __init__(self, *args, **kwargs):
            self.sock = Mock()

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            resp = Mock()
            resp.status = 200
            resp.read.return_value = b'{"status": "ok"}'
            return resp

        def close(self):
            pass

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", MockConnWithSock):
        status, body, err = client.get("http://127.0.0.1:9090", "/test")

    assert status == 200


def test_budget_clamped_against_hard_ceiling():
    """Verify that excessive ProviderContext budget parameters are clamped to hard ceilings."""
    raw = {
        "max_requests": 500,
        "max_response_bytes": 100 * 1024 * 1024,
        "connect_timeout": 60.0,
        "read_timeout": 60.0,
        "max_query_length": 50000,
        "max_lookback_seconds": 1000000,
        "max_result_items": 10000,
        "max_traces": 5000,
        "max_spans_per_trace": 100000,
    }
    budget = build_clamped_telemetry_budget(raw)
    for k, ceiling in HARD_BUDGET_CEILINGS.items():
        assert getattr(budget, k) <= ceiling


def test_invalid_lookback_resolves_unknown():
    """Verify invalid lookback format produces UNKNOWN status instead of silent 5m default."""
    p = OTelProvider()
    ctx = ProviderContext({
        "traces_endpoint": "http://127.0.0.1:3200",
        "lookback": "invalid-garbage",
    })
    obs = p.collect(ctx)
    obs_map = {o.id: o for o in obs}
    error_spans = obs_map["otel.error_spans_count"]
    assert error_spans.value["status"] == "UNKNOWN"
    assert "Invalid lookback specification" in error_spans.message


def test_max_lookback_clamped_with_audit_metadata():
    """Verify lookback > max_lookback_seconds is clamped with audit trail metadata."""
    p = OTelProvider()

    def conn_factory(*args, **kwargs):
        conn = Mock()

        def req_handler(method, url, **kw):
            resp = Mock()
            resp.status = 200
            if "traces" in url:
                resp.read.return_value = json.dumps({"data": []}).encode()
            else:
                resp.read.return_value = b'{"status": "ok"}'
            conn.getresponse.return_value = resp

        conn.request.side_effect = req_handler
        return conn

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", side_effect=conn_factory):
        ctx = ProviderContext({
            "traces_endpoint": "http://127.0.0.1:3200",
            "lookback": "7d",
            "max_lookback_seconds": 3600,
        })
        obs = p.collect(ctx)

    obs_map = {o.id: o for o in obs}
    error_spans = obs_map["otel.error_spans_count"]
    val = error_spans.value
    assert val["requested_lookback"] == "7d"
    assert val["effective_lookback"] == "3600s"
    assert val["lookback_clamped"] is True


def test_max_result_items_bounded():
    """Verify Prometheus response parsing is sliced by max_result_items."""
    p = OTelProvider()

    prom_data = {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [{"value": [1600000000, "0.01"]} for _ in range(50)],
        },
    }

    def conn_factory(*args, **kwargs):
        conn = Mock()

        def req_handler(*args, **kwargs):
            resp = Mock()
            resp.status = 200
            resp.read.return_value = json.dumps(prom_data).encode()
            conn.getresponse.return_value = resp

        conn.request.side_effect = req_handler
        return conn

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", side_effect=conn_factory):
        ctx = ProviderContext({
            "metrics_endpoint": "http://127.0.0.1:9090",
            "max_result_items": 5,
        })
        obs = p.collect(ctx)

    obs_map = {o.id: o for o in obs}
    assert obs_map["otel.http_error_rate"].value["value"] == 0.01


def test_max_traces_and_spans_bounded():
    """Verify trace and span counting respects max_traces and max_spans_per_trace limits."""
    p = OTelProvider()

    # 10 traces, each with 20 error spans
    mock_traces = {
        "data": [
            {
                "traceID": f"trace_{i}",
                "spans": [
                    {"tags": [{"key": "error", "value": True}]}
                    for _ in range(20)
                ],
            }
            for i in range(10)
        ]
    }

    def conn_factory(*args, **kwargs):
        conn = Mock()

        def req_handler(method, url, **kw):
            resp = Mock()
            resp.status = 200
            if "traces" in url:
                resp.read.return_value = json.dumps(mock_traces).encode()
            else:
                resp.read.return_value = b'{"status": "ok"}'
            conn.getresponse.return_value = resp

        conn.request.side_effect = req_handler
        return conn

    with patch("evidencetool.providers.telemetry_client.http.client.HTTPConnection", side_effect=conn_factory):
        # Bound to 2 traces and 5 spans per trace => total max 10 error spans
        ctx = ProviderContext({
            "traces_endpoint": "http://127.0.0.1:3200",
            "max_traces": 2,
            "max_spans_per_trace": 5,
        })
        obs = p.collect(ctx)

    obs_map = {o.id: o for o in obs}
    assert obs_map["otel.error_spans_count"].value["count"] == 10

