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
