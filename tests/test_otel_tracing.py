"""
Tests for OpenTelemetry Mode B (Outbound Tracing).

Validates:
1. Pure-Python DiagnosisTracer, SpanRecord, and TraceRecord functionality.
2. W3C Trace & Span ID generation and duration calculations.
3. OTLP/JSON ResourceSpans serialization compliance.
4. End-to-end trace collection during diagnose() execution.
5. AgentSafetyGate integration with authority trace tagging.
6. JSON rendering with trace_id contract inclusion.
7. File and HTTP OTLP export mechanisms with fault tolerance.
"""

import json
from typing import Any
from unittest.mock import MagicMock, patch

from evidencetool.agent import AgentDiagnosisRequest, AgentSafetyGate
from evidencetool.capability.models import CallerType
from evidencetool.cli.render import to_contract_dict, to_text
from evidencetool.diagnose import diagnose
from evidencetool.models.policy import EvidenceRequirement, OnUnknown, Policy, PolicySchema, RiskLevel
from evidencetool.observability.tracing import DiagnosisTracer, SpanRecord, TraceRecord


def test_span_record_lifecycle():
    """Test SpanRecord creation, attribute enrichment, timing, and dictionary export."""
    span = SpanRecord(
        name="test.span",
        span_id="1234567812345678",
        parent_span_id=None,
        trace_id="12345678123456781234567812345678",
        start_time_unix_nano=1_000_000_000,
    )
    span.set_attribute("env", "staging")
    span.set_attribute("port", 8080)
    span.set_attribute("secure", True)
    span.set_attribute("tags", ["web", "edge"])
    span.end(status="OK", description="completed successfully")

    d = span.to_dict()
    assert d["name"] == "test.span"
    assert d["span_id"] == "1234567812345678"
    assert d["status"] == "OK"
    assert d["status_description"] == "completed successfully"
    assert d["attributes"]["env"] == "staging"
    assert d["attributes"]["port"] == 8080
    assert d["attributes"]["secure"] is True
    assert d["attributes"]["tags"] == ["web", "edge"]
    assert d["duration_ms"] >= 0


def test_trace_record_otlp_json_format():
    """Validate TraceRecord serialization conforms to standard OTLP/JSON ResourceSpans format."""
    root = SpanRecord(
        name="evidencetool.diagnosis",
        span_id="root000000000001",
        parent_span_id=None,
        trace_id="trace000000000000000000000000001",
        start_time_unix_nano=1_000_000_000,
        end_time_unix_nano=1_500_000_000,
        attributes={"target": "nginx", "count": 3, "active": True, "items": ["a", "b"]},
        status="OK",
    )
    child = SpanRecord(
        name="evidencetool.provider.nginx",
        span_id="child00000000001",
        parent_span_id="root000000000001",
        trace_id="trace000000000000000000000000001",
        start_time_unix_nano=1_100_000_000,
        end_time_unix_nano=1_400_000_000,
        attributes={"evidencetool.provider.observations_count": 2},
        status="OK",
    )
    trace = TraceRecord(trace_id=root.trace_id, root_span=root, spans=[child])
    otlp = trace.to_otlp_json(service_name="test-evidence")

    assert "resourceSpans" in otlp
    resource_spans = otlp["resourceSpans"][0]
    assert resource_spans["resource"]["attributes"][0]["key"] == "service.name"
    assert resource_spans["resource"]["attributes"][0]["value"]["stringValue"] == "test-evidence"

    spans = resource_spans["scopeSpans"][0]["spans"]
    assert len(spans) == 2
    root_otlp, child_otlp = spans[0], spans[1]

    assert root_otlp["name"] == "evidencetool.diagnosis"
    assert root_otlp["traceId"] == root.trace_id
    assert root_otlp["spanId"] == "root000000000001"
    assert "parentSpanId" not in root_otlp

    assert child_otlp["name"] == "evidencetool.provider.nginx"
    assert child_otlp["parentSpanId"] == "root000000000001"

    # Check attribute types
    attr_map = {a["key"]: a["value"] for a in root_otlp["attributes"]}
    assert attr_map["target"] == {"stringValue": "nginx"}
    assert attr_map["count"] == {"intValue": "3"}
    assert attr_map["active"] == {"boolValue": True}
    assert attr_map["items"] == {"arrayValue": {"values": [{"stringValue": "a"}, {"stringValue": "b"}]}}


def test_tracer_standalone_lifecycle(tmp_path):
    """Test DiagnosisTracer execution, child span tracking, and file export."""
    trace_path = tmp_path / "traces" / "out.json"
    tracer = DiagnosisTracer(service_name="custom-et", trace_file=str(trace_path))

    tracer.start_root_span(target="test_target", policy_action="test_action")
    tracer.start_span("span_1")
    tracer.end_span("span_1", attributes={"k": "v"})
    tracer.record_decision(
        status="ALLOW",
        reason="all clear",
        blocking_evidence=[],
        action="test_action",
    )
    trace = tracer.finish(status="OK")

    assert trace.trace_id == tracer.trace_id
    assert len(trace.spans) == 2  # span_1 + evidencetool.decision
    assert trace_path.exists()

    with open(trace_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["trace_id"] == trace.trace_id
    assert data["root_span"]["name"] == "evidencetool.diagnosis"


def test_tracer_export_otlp_http():
    """Test OTLP/HTTP POST export with mocked urllib."""
    tracer = DiagnosisTracer(service_name="mock-et", endpoint="http://collector.internal:4318")
    tracer.start_root_span(target="svc", policy_action="restart")
    trace = TraceRecord(trace_id=tracer.trace_id, root_span=tracer.root_span, spans=[])

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        success = tracer.export_to_otlp(trace, endpoint="http://collector.internal:4318")
        assert success is True
        assert mock_urlopen.called
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "http://collector.internal:4318/v1/traces"
        assert req.get_header("Content-type") == "application/json"


def test_tracer_export_otlp_failure_resilient():
    """Test that OTLP/HTTP export failure is caught gracefully and does not raise."""
    tracer = DiagnosisTracer(service_name="mock-et", endpoint="http://invalid.host:9999")
    tracer.start_root_span(target="svc", policy_action="restart")
    trace = TraceRecord(trace_id=tracer.trace_id, root_span=tracer.root_span, spans=[])

    with patch("urllib.request.urlopen", side_effect=OSError("Network unreachable")):
        success = tracer.export_to_otlp(trace, endpoint="http://invalid.host:9999")
        assert success is False


def test_diagnose_instruments_full_trace(tmp_path):
    """Test that diagnose() creates complete span hierarchy when tracer is supplied."""
    conf = tmp_path / "nginx.conf"
    conf.write_text("events {}\nhttp {}\n", encoding="utf-8")

    policy = Policy(
        version="1.0",
        action="restart_nginx",
        risk=RiskLevel.LOW,
        schema=PolicySchema.V1_LEGACY,
        required_evidence=[
            EvidenceRequirement(id="nginx.config_valid", on_unknown=OnUnknown.BLOCK),
            EvidenceRequirement(id="systemd.service_exists", on_unknown=OnUnknown.BLOCK),
        ],
    )

    tracer = DiagnosisTracer(service_name="test-diag")

    with patch("subprocess.run") as mock_run:
        def fake_run(cmd, *args, **kwargs):
            proc = MagicMock()
            proc.returncode = 0
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            if "LoadState" in cmd_str:
                proc.stdout = "LoadState=loaded\n"
            elif "is-active" in cmd_str:
                proc.stdout = "active\n"
            else:
                proc.stdout = "syntax is ok\ntest is successful\n"
                proc.stderr = "syntax is ok\ntest is successful\n"
            return proc

        mock_run.side_effect = fake_run

        result = diagnose(
            target="nginx",
            policy=policy,
            context={"config_path": str(conf), "service": "nginx"},
            tracer=tracer,
        )

    assert result.trace is not None
    assert result.trace.trace_id == tracer.trace_id

    # Validate root span
    root = result.trace.root_span
    assert root.name == "evidencetool.diagnosis"
    assert root.attributes["evidencetool.target"] == "nginx"
    assert root.attributes["evidencetool.policy.action"] == "restart_nginx"
    assert root.attributes["evidencetool.decision.status"] == "ALLOW"

    # Validate child spans
    span_names = [s.name for s in result.trace.spans]
    assert "evidencetool.provider.nginx" in span_names
    assert "evidencetool.provider.systemd" in span_names
    assert "evidencetool.evaluation" in span_names
    assert "evidencetool.correlation" in span_names
    assert "evidencetool.causality" in span_names
    assert "evidencetool.decision" in span_names

    # Check contract dict and rendering
    contract = to_contract_dict(result)
    assert contract["trace_id"] == result.trace.trace_id

    rendered_text = to_text(result)
    assert f"Trace ID:\n{result.trace.trace_id}" in rendered_text


def test_agent_safety_gate_tracing_enrichment(tmp_path):
    """Test that AgentSafetyGate injects caller authority metadata into the trace."""
    gate = AgentSafetyGate()
    req = AgentDiagnosisRequest(
        agent_id="test-agent-99",
        action="network_check",
        target="network",
        context={"target_host": "127.0.0.1", "port": 80},
        session_id="sess-xyz-123",
        caller_type=CallerType.AI_AGENT,
    )

    policy = Policy(
        version="1.0",
        action="network_check",
        risk=RiskLevel.LOW,
        schema=PolicySchema.V1_LEGACY,
        required_evidence=[],
    )
    gate._default_policy = policy

    tracer = DiagnosisTracer(service_name="agent-gateway")
    res = gate.evaluate(req, tracer=tracer)

    assert res.trace_id is not None
    assert res.trace_id == tracer.trace_id
    assert tracer.root_span is not None
    assert tracer.root_span.attributes["evidencetool.authority.caller_id"] == "test-agent-99"
    assert tracer.root_span.attributes["evidencetool.authority.caller_type"] == "AI_AGENT"
    assert tracer.root_span.attributes["evidencetool.authority.session_id"] == "sess-xyz-123"


def test_diagnose_auto_tracing_with_env_var(monkeypatch, tmp_path):
    """Test that setting OTEL_ENABLE_TRACING=1 automatically instruments diagnose()."""
    monkeypatch.setenv("OTEL_ENABLE_TRACING", "1")

    policy = Policy(
        version="1.0",
        action="ping",
        risk=RiskLevel.LOW,
        schema=PolicySchema.V1_LEGACY,
        required_evidence=[],
    )

    result = diagnose(target="test", policy=policy, context={})
    assert result.trace is not None
    assert len(result.trace.trace_id) == 32


def test_host_tracer_provider_non_interference():
    """
    Test Host TracerProvider Non-Interference Invariant:
    1. Host application configures an active TracerProvider with an exporter.
    2. Host starts an active parent span (e.g. agent.remediation).
    3. EvidenceTool runs within the host context.
    4. Assertions:
       - Host TracerProvider was NOT replaced or mutated.
       - EvidenceTool spans (diagnosis, evaluation, correlation, causality, decision) are captured in host exporter.
       - evidencetool.diagnosis is a direct child of agent.remediation.
       - All child spans have matching trace_id and correct parent-child relationships.
    """
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    host_provider = TracerProvider()
    exporter = InMemorySpanExporter()
    host_provider.add_span_processor(SimpleSpanProcessor(exporter))

    orig_provider = trace.get_tracer_provider()
    trace.set_tracer_provider(host_provider)

    try:
        host_tracer = trace.get_tracer("agent_mesh", "2.1.0")

        with host_tracer.start_as_current_span("agent.remediation") as agent_span:
            agent_ctx = agent_span.get_span_context()
            agent_trace_id_hex = f"{agent_ctx.trace_id:032x}"
            agent_span_id_hex = f"{agent_ctx.span_id:016x}"

            # Run EvidenceTool diagnosis within the host's active span context
            policy = Policy(
                version="1.0",
                action="restart_test",
                risk=RiskLevel.LOW,
                schema=PolicySchema.V1_LEGACY,
                required_evidence=[],
            )

            tracer = DiagnosisTracer(service_name="agent_mesh")
            result = diagnose(
                target="test_service",
                policy=policy,
                context={},
                tracer=tracer,
            )

        # 1. Non-interference: Host provider must NOT have been replaced
        assert trace.get_tracer_provider() is host_provider

        # 2. Finished spans in the host exporter
        finished_spans = exporter.get_finished_spans()
        span_names = [s.name for s in finished_spans]

        assert "agent.remediation" in span_names
        assert "evidencetool.diagnosis" in span_names
        assert "evidencetool.evaluation" in span_names
        assert "evidencetool.correlation" in span_names
        assert "evidencetool.causality" in span_names
        assert "evidencetool.decision" in span_names

        # 3. Span hierarchy: evidencetool.diagnosis must be a child of agent.remediation
        diag_span = next(s for s in finished_spans if s.name == "evidencetool.diagnosis")
        assert f"{diag_span.context.trace_id:032x}" == agent_trace_id_hex
        assert diag_span.parent is not None
        assert f"{diag_span.parent.span_id:016x}" == agent_span_id_hex

        # 4. In-memory TraceRecord also reflects the host trace context
        assert result.trace is not None
        assert result.trace.trace_id == agent_trace_id_hex
        assert result.trace.root_span.parent_span_id == agent_span_id_hex

    finally:
        trace.set_tracer_provider(orig_provider)


def test_w3c_traceparent_parser_validation():
    """Validates W3C traceparent parser against RFC 00 recommendations and edge cases."""
    from evidencetool.observability.tracing import parse_w3c_traceparent

    # Valid W3C traceparent
    valid_raw = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    parsed = parse_w3c_traceparent(valid_raw)
    assert parsed is not None
    assert parsed.version == "00"
    assert parsed.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert parsed.parent_id == "00f067aa0ba902b7"
    assert parsed.flags == "01"

    # Uppercase hex is accepted and normalized
    upper_raw = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01"
    parsed_upper = parse_w3c_traceparent(upper_raw)
    assert parsed_upper is not None
    assert parsed_upper.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert parsed_upper.parent_id == "00f067aa0ba902b7"

    # Invalid edge cases
    assert parse_w3c_traceparent(None) is None
    assert parse_w3c_traceparent("") is None
    assert parse_w3c_traceparent("   ") is None
    assert parse_w3c_traceparent("not-a-traceparent") is None
    # Version ff is explicitly forbidden by W3C
    assert parse_w3c_traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") is None
    # All-zero trace_id is forbidden
    assert parse_w3c_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01") is None
    # All-zero parent_id is forbidden
    assert parse_w3c_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01") is None
    # Wrong character length for version 00
    assert parse_w3c_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra") is None


def test_traceparent_valid_sdk_propagation():
    """Validates that passing traceparent via AgentDiagnosisRequest propagates cleanly to root span."""
    traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    gate = AgentSafetyGate(
        default_policy=Policy(
            version="1.0",
            action="restart_nginx",
            risk=RiskLevel.LOW,
            schema=PolicySchema.V1_LEGACY,
            required_evidence=[],
        )
    )

    req = AgentDiagnosisRequest(
        agent_id="remediation-bot",
        action="restart_nginx",
        target="nginx",
        context={},
        traceparent=traceparent,
    )

    res = gate.evaluate(req)
    assert res.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert res.raw_diagnosis.trace is not None
    assert res.raw_diagnosis.trace.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert res.raw_diagnosis.trace.root_span.parent_span_id == "00f067aa0ba902b7"


def test_traceparent_absent_behaviors():
    """Validates that absent traceparent generates a valid new 32-hex root trace without parent."""
    tracer = DiagnosisTracer()
    span = tracer.start_root_span("test", "restart")
    assert len(tracer.trace_id) == 32
    assert span.parent_span_id is None


def test_traceparent_invalid_edge_cases_fails_safe():
    """Validates that malformed traceparent never crashes and cleanly generates a fallback root trace."""
    tracer = DiagnosisTracer(traceparent="invalid-w3c-garbage")
    span = tracer.start_root_span("test", "restart")
    assert len(tracer.trace_id) == 32
    assert span.parent_span_id is None


def test_traceparent_precedence_hierarchy(monkeypatch):
    """
    Validates 4-tier precedence:
    Tier 1 (explicit arg) > Tier 2 (TRACEPARENT env var) > Tier 3 (host active span) > Tier 4 (new root).
    """
    monkeypatch.setenv("TRACEPARENT", "00-11111111111111111111111111111111-2222222222222222-01")

    # Tier 1 overrides Tier 2
    t1 = DiagnosisTracer(traceparent="00-33333333333333333333333333333333-4444444444444444-01")
    assert t1.trace_id == "33333333333333333333333333333333"
    assert t1._host_parent_span_id == "4444444444444444"

    # When explicit is absent, Tier 2 is used
    t2 = DiagnosisTracer()
    assert t2.trace_id == "11111111111111111111111111111111"
    assert t2._host_parent_span_id == "2222222222222222"


def test_invalid_traceparent_does_not_break_existing_context():
    """
    Validates fail-safe rule: If caller passes an invalid traceparent WHILE an active host span
    is running, EvidenceTool must fall back to the host active span instead of isolating into a new root trace.
    """
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    host_provider = TracerProvider()
    orig_provider = trace.get_tracer_provider()
    trace.set_tracer_provider(host_provider)

    try:
        host_tracer = trace.get_tracer("agent_mesh", "2.1.0")
        with host_tracer.start_as_current_span("agent.remediation") as agent_span:
            ctx = agent_span.get_span_context()
            host_trace_id_hex = f"{ctx.trace_id:032x}"
            host_span_id_hex = f"{ctx.span_id:016x}"

            # Pass malformed traceparent while host span is active
            tracer = DiagnosisTracer(traceparent="malformed-junk-header")
            root_span = tracer.start_root_span("test", "action")

            # Must have preserved the host trace and parent span
            assert tracer.trace_id == host_trace_id_hex
            assert root_span.parent_span_id == host_span_id_hex
    finally:
        trace.set_tracer_provider(orig_provider)


def test_traceparent_does_not_grant_authority():
    """
    Validates Section 24.5 Invariant: A valid traceparent must NEVER grant unauthorized
    capabilities, bypass probe budgets, or spoof authority metadata.
    """
    from evidencetool.capability.models import CapabilityDenied

    gate = AgentSafetyGate(
        default_policy=Policy(
            version="1.0",
            action="restart_nginx",
            risk=RiskLevel.LOW,
            schema=PolicySchema.V1_LEGACY,
            required_evidence=[],
        )
    )

    # Attempting to use remote SSH host without explicit capability policy MUST be denied
    # even when presenting a legitimate W3C traceparent header
    req = AgentDiagnosisRequest(
        agent_id="adversary-agent",
        action="restart_nginx",
        target="nginx",
        context={"host": "unauthorized-prod-host.internal"},
        traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    )

    import pytest
    with pytest.raises(CapabilityDenied, match="SSH transport requires an explicit capability policy"):
        gate.evaluate(req)


def test_cli_traceparent_option():
    """Validates that CLI --traceparent passes through and appears in JSON output."""
    from click.testing import CliRunner

    from evidencetool.cli.main import cli

    runner = CliRunner()
    tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    res = runner.invoke(cli, ["diagnose", "nginx", "--traceparent", tp, "--output", "json"])
    assert res.exit_code in (0, 1, 2)
    data = json.loads(res.output)
    assert data["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"


def test_mock_otlp_collector_interoperability():
    """
    Étape 3: Verifies real OTLP/HTTP transmission against a live HTTP OTLP receiver.
    Validates:
    - HTTP POST /v1/traces wire transmission
    - OTLP JSON ResourceSpans serialization
    - W3C traceparent context preservation
    - Status code 200/202 handling
    """
    import http.server
    import threading

    received_payloads: list[dict[str, Any]] = []

    class MockOTLPHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass

        def do_POST(self) -> None:  # noqa: N802
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            received_payloads.append({
                "path": self.path,
                "content_type": self.headers.get("Content-Type"),
                "json": json.loads(body.decode("utf-8")),
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"partialSuccess": {}}')

    server = http.server.HTTPServer(("127.0.0.1", 0), MockOTLPHandler)
    server_port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        endpoint = f"http://127.0.0.1:{server_port}"
        traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

        policy = Policy(
            version="1.0",
            action="restart_nginx",
            risk=RiskLevel.LOW,
            schema=PolicySchema.V1_LEGACY,
            required_evidence=[],
        )

        tracer = DiagnosisTracer(
            service_name="production-backend",
            endpoint=endpoint,
            traceparent=traceparent,
        )

        res = diagnose(
            target="nginx",
            policy=policy,
            context={},
            tracer=tracer,
        )

        assert res.decision is not None
        assert len(received_payloads) == 1

        payload = received_payloads[0]
        assert payload["path"] == "/v1/traces"
        assert payload["content_type"] == "application/json"

        otlp_data = payload["json"]
        assert "resourceSpans" in otlp_data
        resource_span = otlp_data["resourceSpans"][0]

        # Verify resource attributes
        res_attrs = {a["key"]: a["value"]["stringValue"] for a in resource_span["resource"]["attributes"]}
        assert res_attrs["service.name"] == "production-backend"

        # Verify scope and spans
        scope_spans = resource_span["scopeSpans"][0]
        assert scope_spans["scope"]["name"] == "evidencetool"

        spans = scope_spans["spans"]
        span_names = [s["name"] for s in spans]
        assert "evidencetool.diagnosis" in span_names
        assert "evidencetool.evaluation" in span_names
        assert "evidencetool.correlation" in span_names
        assert "evidencetool.causality" in span_names
        assert "evidencetool.decision" in span_names

        # Verify W3C trace and parent preservation in root span
        root_otlp = next(s for s in spans if s["name"] == "evidencetool.diagnosis")
        assert root_otlp["traceId"] == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert root_otlp["parentSpanId"] == "00f067aa0ba902b7"

    finally:
        server.shutdown()
        server.server_close()


def test_mock_otlp_collector_error_resilience():
    """
    Étape 3: Verifies that real HTTP 500 error from Collector is handled gracefully
    without raising an unhandled exception or corrupting diagnosis.
    """
    import http.server
    import threading

    class ErrorOTLPHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass

        def do_POST(self) -> None:  # noqa: N802
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Internal Collector Failure"}')

    server = http.server.HTTPServer(("127.0.0.1", 0), ErrorOTLPHandler)
    server_port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        endpoint = f"http://127.0.0.1:{server_port}"
        policy = Policy(
            version="1.0",
            action="restart_nginx",
            risk=RiskLevel.LOW,
            schema=PolicySchema.V1_LEGACY,
            required_evidence=[],
        )

        tracer = DiagnosisTracer(
            service_name="production-backend",
            endpoint=endpoint,
        )

        # Diagnose must complete successfully even when Collector returns HTTP 500
        res = diagnose(
            target="nginx",
            policy=policy,
            context={},
            tracer=tracer,
        )

        assert res.decision is not None
    finally:
        server.shutdown()
        server.server_close()


