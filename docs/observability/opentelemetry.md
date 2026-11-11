**English** | [Français](opentelemetry.fr.md)

# OpenTelemetry Integration Guide (Mode A Inbound & Mode B Outbound)

EvidenceTool provides bi-directional OpenTelemetry integration forming a closed loop of operational trust:
- **Mode A (Inbound External Telemetry)**: Ingests surface metrics and distributed trace health from Prometheus-compatible and Tempo/Jaeger-compatible endpoints via the native `otel` provider.
- **Mode B (Outbound Distributed Tracing)**: Emits structured W3C-correlated OpenTelemetry spans projecting its operational reasoning and causal decision pipeline back into your APM backend.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   MODE A : INBOUND EXTERNAL TELEMETRY                  │
│    Queries Prometheus (Metrics/Latency) & Tempo/Jaeger (Failing Spans) │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Surface Symptoms
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   MODE C : HYBRID CAUSAL REASONING                     │
│    Correlates Surface Symptoms with Deep Native Physical Probes        │
│    (Postgres pool, Redis OOM, TLS expiration, Process deadlock)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Deterministic Decision
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   MODE B : OUTBOUND DISTRIBUTED TRACING                │
│    Emits W3C-correlated Diagnostic Trace (Root + Child Spans)          │
│    Sent to OpenTelemetry Collector / Jaeger / Grafana Tempo            │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Mode A: Inbound Telemetry Provider (`otel` namespace)

The `otel` provider enables EvidenceTool to observe external telemetry signals without turning into a secondary monitoring system. It strictly collects facts and leaves threshold evaluation to declarative policies.

### Supported Probes

| Probe ID | Target Backend | Metric / Query | Evaluated Condition |
|:---|:---|:---|:---|
| `otel.metrics_reachable` | Prometheus / Mimir / Thanos | `/api/v1/query?query=1` | Metrics backend is reachable and responsive. |
| `otel.traces_reachable` | Grafana Tempo / Jaeger | `/api/traces?limit=1` | Traces backend is reachable and responsive. |
| `otel.http_error_rate_high` | Prometheus / Mimir | PromQL query (e.g. 5xx rate > threshold) | High HTTP error rate observed on target service. |
| `otel.p99_latency_high` | Prometheus / Mimir | PromQL histogram percentile query | P99 latency exceeds configured SLA threshold. |
| `otel.active_traces_failing` | Grafana Tempo / Jaeger | Trace query filtering `status=error` | Distributed traces contain active error spans. |

### Security & Operational Invariants (Mode A)

1. **Pure Observation Invariant**: The provider only collects observable facts; it never makes diagnostic decisions or replaces physical probes.
2. **SSRF Defense**: Target endpoints must resolve to valid public IP addresses unless explicitly authorized in `CapabilitySet.network.targets` (preventing SSRF attacks against AWS/GCP metadata endpoints `169.254.169.254` or internal services).
3. **Strict Transport Limits**:
   - HTTP redirects are rejected (`allow_redirects=False`).
   - Maximum response payload size is bounded to 1 MB (`MAX_PAYLOAD_BYTES = 1048576`).
   - Network timeout is strictly enforced (`timeout_seconds = 5`).
4. **Credential Sanitization**: Bearer tokens and Basic Auth credentials passed in arguments or environment variables are stripped and sanitized (`***`) in logs and exported evidence.

### CLI Example (Mode A)

```bash
evidencetool diagnose dependency \
  --catalog catalogs/telemetry.yaml \
  --policy policies/telemetry.yaml \
  -a otel_metrics_endpoint=http://prometheus.monitoring:9090 \
  -a otel_traces_endpoint=http://tempo.monitoring:3200 \
  -a service=checkout-service
```

---

## 2. Mode B: Outbound Distributed Tracing

EvidenceTool emits structured OpenTelemetry traces mapping its entire operational reasoning pipeline to APM/tracing backends:

```
Host Application / AI Agent Mesh
      │ (W3C traceparent context)
      ▼
EvidenceTool DiagnosisTracer
      │
      ├── evidencetool.diagnosis (root span)
      │     ├── evidencetool.provider.<namespace> (collection latency & count)
      │     ├── evidencetool.evaluation (PASS / FAIL / UNKNOWN breakdown)
      │     ├── evidencetool.correlation (situation matching)
      │     ├── evidencetool.causality (root cause, DAG propagation, preclusions)
      │     └── evidencetool.decision (verdict, policy rules, blocking evidence)
      │
      ▼
OpenTelemetry Collector / Jaeger / Grafana Tempo
```

### Core Architectural Invariants (Mode B)

1. **Observability Independence**: OpenTelemetry is strictly an observability layer. It **MUST NOT** influence EvidenceTool's deterministic diagnostic, causal, policy, or authority decisions.
2. **Host TracerProvider Non-Interference**: When executing within an already instrumented host application (e.g. AI agent framework, FastAPI, LangChain), EvidenceTool obtains its tracer via `trace.get_tracer("evidencetool", "1.0.6")` and **NEVER** mutates, installs, or resets the host application's global `TracerProvider`.
3. **Trace Context Non-Authentication**: A W3C `traceparent` is strictly a telemetry correlation identifier. It carries zero authorization semantics and cannot bypass `CapabilitySet` or policy fingerprints.
4. **Zero-Dependency Fallback**: If the `opentelemetry` package is not installed, EvidenceTool collects spans in-memory and exports standard OTLP/JSON via pure standard library HTTP or file output.
5. **Span Status Semantics**: Legitimate operational decisions (`BLOCK`, `HUMAN_REVIEW`, `ALLOW`) are valid governance outcomes and produce span status `StatusCode.OK`. Span status `StatusCode.ERROR` is strictly reserved for execution or integrity failures (`metrics.success == False`), eliminating false APM alarms.

---

## 3. Context Propagation Hierarchy

EvidenceTool resolves trace context following a strict 4-tier precedence:

| Precedence | Source | Description |
|:---|:---|:---|
| **Tier 1** | Explicit argument | Passed directly via SDK (`AgentDiagnosisRequest.traceparent`) or CLI (`--traceparent`). |
| **Tier 2** | `TRACEPARENT` env var | W3C traceparent standard environment variable. |
| **Tier 3** | Host active span | OpenTelemetry active span context retrieved via `otel_trace.get_current_span()`. |
| **Tier 4** | Independent root trace | Generates a new 32-hex trace ID and records as an independent root trace. |

---

## 4. Configuration Reference

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

## 5. AI Agent SDK Integration

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

## 6. Docker Compose Recipe (Jaeger + OTel Collector)

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

Open `http://localhost:16686` in your browser to inspect the full operational reasoning trace.
