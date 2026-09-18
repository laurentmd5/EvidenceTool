**English** | [Français](opentelemetry.fr.md)

# OpenTelemetry Outbound Tracing (Mode B) Integration Guide

EvidenceTool includes native **OpenTelemetry Mode B (Outbound Distributed Tracing)** to map its operational reasoning pipeline directly into observability backends such as **Jaeger**, **Grafana Tempo**, and standard **OpenTelemetry Collectors**.

```
Host Application / AI Agent Mesh
      │ (W3C traceparent context)
      ▼
EvidenceTool DiagnosisTracer
      │
      ├── evidencetool.diagnosis (root span)
      │     ├── evidencetool.provider.<namespace>
      │     ├── evidencetool.evaluation
      │     ├── evidencetool.correlation
      │     ├── evidencetool.causality
      │     └── evidencetool.decision
      │
      ▼
OpenTelemetry Collector / Jaeger / Grafana Tempo
```

---

## 1. Core Architectural Invariants

1. **Observability Independence Invariant**: OpenTelemetry is strictly an observability layer. It **MUST NOT** influence EvidenceTool's deterministic diagnostic, causal, policy, or authority decisions. Spans describe operational reasoning; they never alter or determine it.
2. **Host TracerProvider Non-Interference Invariant**: When executing within an already instrumented host application (e.g., an AI agent framework, FastAPI service, LangChain harness), EvidenceTool obtains its tracer via standard `trace.get_tracer("evidencetool", "1.0.3")` and **NEVER** mutates, installs, or resets the host application's global `TracerProvider`.
3. **Trace Context Non-Authentication Invariant**: A W3C `traceparent` is strictly a telemetry correlation identifier. It carries zero authentication, authorization, or capability semantics, and cannot bypass `CapabilitySet`, probe budgets, or policy fingerprints.
4. **Zero-Dependency Fallback**: If `opentelemetry` is not installed, EvidenceTool collects spans in-memory and exports standard OTLP/JSON via pure standard library HTTP or file output.
5. **Span Status Semantics Invariant**: Legitimate operational decisions (`BLOCK`, `HUMAN_REVIEW`, `ALLOW`) are valid governance outcomes and produce OpenTelemetry span status `StatusCode.OK`. Span status `StatusCode.ERROR` is strictly reserved for execution or integrity failures (`metrics.success == False`), eliminating false-positive APM alarms.
6. **Dual Exporter Pipeline**: In standalone mode with `opentelemetry-exporter-otlp-proto-http` installed, EvidenceTool transmits binary Protobuf over HTTP via `OTLPSpanExporter`. In zero-dependency mode, it seamlessly falls back to pure Python standard library JSON export over HTTP.

---

## 2. Context Propagation & Precedence Hierarchy

EvidenceTool resolves trace context following a strict 4-tier precedence:

| Precedence | Source | Description |
|:---|:---|:---|
| **Tier 1** | Explicit argument | Passed directly via SDK (`AgentDiagnosisRequest.traceparent`) or CLI (`--traceparent`). |
| **Tier 2** | `TRACEPARENT` env var | W3C traceparent standard environment variable. |
| **Tier 3** | Host active span | OpenTelemetry active span context retrieved via `otel_trace.get_current_span()`. |
| **Tier 4** | Independent root trace | Generates a new 32-hex trace ID and records as an independent root trace. |

> [!NOTE]
> **Fail-Safe Rule**: If an agent passes a malformed or invalid `traceparent` while a host span is active in the execution context, EvidenceTool logs a warning and falls back to parenting under the active host span rather than isolating into a disconnected trace.

---

## 3. Configuration Reference

### Environment Variables

| Variable | Description | Default |
|:---|:---|:---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP traces endpoint (e.g. `http://localhost:4318/v1/traces`) | `None` |
| `OTEL_SERVICE_NAME` | Logical service name reporting the diagnostic trace | `evidencetool` |
| `TRACEPARENT` | W3C traceparent string | `None` |
| `OTEL_ENABLE_TRACING` | Set to `true` or `1` to enable tracing even without an explicit endpoint | `false` |

### CLI Usage

```bash
# Export trace directly to local or remote OpenTelemetry Collector
evidencetool diagnose nginx \
  --otel-endpoint http://localhost:4318/v1/traces

# Continue an existing distributed trace from an upstream caller
evidencetool diagnose nginx \
  --traceparent 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 \
  --otel-endpoint http://localhost:4318/v1/traces

# Dump trace locally to JSON file for offline inspection or CI artifacts
evidencetool diagnose nginx \
  --otel-trace-file /tmp/diagnosis_trace.json
```

---

## 4. AI Agent SDK Integration

Autonomous agents pass their W3C trace context into `AgentDiagnosisRequest`:

```python
from evidencetool.agent import AgentSafetyGate, AgentDiagnosisRequest

gate = AgentSafetyGate(
    capability_policy="capabilities/agent-restricted.yaml",
    catalog="catalogs/distributed.yaml",
    default_policy="policies/distributed.yaml",
)

# Agent creates diagnosis request linked to its distributed workflow
request = AgentDiagnosisRequest(
    agent_id="remediation-agent-01",
    action="restart_application",
    target="orders-service",
    context={"url": "http://127.0.0.1:8080/health"},
    traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
)

result = gate.evaluate(request)

# Trace ID is accessible directly from the evaluation result
print(f"Decision: {result.status}, Trace ID: {result.trace_id}")
```

---

## 5. Local Testing with Jaeger & OTel Collector (Docker Compose)

Save the following as `docker-compose.otel.yaml`:

```yaml
version: "3.8"
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686" # Jaeger Web UI
      - "4317:4317"   # OTLP gRPC receiver
      - "4318:4318"   # OTLP HTTP receiver
    environment:
      - COLLECTOR_OTLP_ENABLED=true

  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    command: ["--config=/etc/otel-collector-config.yaml"]
    volumes:
      - ./otel-collector-config.yaml:/etc/otel-collector-config.yaml
    ports:
      - "4318"        # HTTP receiver
    depends_on:
      - jaeger
```

Run Jaeger:
```bash
docker compose -f docker-compose.otel.yaml up -d
```

Run an EvidenceTool diagnosis sending traces to Jaeger:
```bash
evidencetool diagnose nginx \
  -a service=nginx \
  --otel-endpoint http://localhost:4318/v1/traces
```

Open `http://localhost:16686` in your browser to inspect the full operational reasoning trace (`evidencetool.diagnosis`, `evidencetool.provider.*`, `evidencetool.causality`, and `evidencetool.decision`).
