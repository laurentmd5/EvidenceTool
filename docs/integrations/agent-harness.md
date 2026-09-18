**English** | [Français](agent-harness.fr.md)

# Agent Harness Integration Guide

EvidenceTool is specifically designed to be executed by autonomous agents safely. This guide defines how an agent should wrap EvidenceTool.

## 1. Freshness Rule
Agents must re-run EvidenceTool immediately before executing an action. Observations older than the policy's configured `max_age` are considered stale and must be recollected. Policies that require a 60-second freshness window must declare `max_age: 60` explicitly.

An agent must NEVER execute an action based on a previous `ALLOW` decision if that decision relies on stale evidence.

For automated execution, the harness should provide an explicit capability policy. It may restrict network
operations, targets, ports, probe count, and provider trust without changing the diagnostic policy that interprets
the resulting evidence. Capability denial or an unapproved provider is an integrity failure and must abort the action.

External providers used by an automated harness should be listed in an external manifest and verified by SHA-256
before activation. Do not treat discovery alone as approval.

## 2. AgentSafetyGate Programmatic Integration (`evidencetool.agent`)
Autonomous AI agents can integrate EvidenceTool directly through `AgentSafetyGate`:

```python
from evidencetool.agent import AgentSafetyGate, AgentDiagnosisRequest

gate = AgentSafetyGate(
    capability_policy="capabilities/agent-restricted.yaml",
    catalog="catalogs/distributed.yaml",
    default_policy="policies/distributed.yaml",
)

request = AgentDiagnosisRequest(
    agent_id="agent-007",
    action="restart_application",
    target="orders-service",
    context={
        "url": "http://127.0.0.1:8080/health",
        "db_host": "127.0.0.1",
        "redis_host": "127.0.0.1",
    }
)

result = gate.evaluate(request)
if result.is_allowed:
    # Safely proceed with remediation
    pass
else:
    # Gated: action blocked with explainable causal reason
    print(f"Action BLOCKED: {result.reason}")
    print(f"Causal Root Cause: {result.causality.primary_root_cause if result.causality else 'N/A'}")
```

## 3. Decision Integrity & JSON Contract Verification
Every JSON output produced by EvidenceTool respects `schemas/diagnosis-result.schema.json` and includes a cryptographically stable representation of the decision.
Agents MUST validate decision integrity programmatically before acting on an `ALLOW`:

```python
import json
import jsonschema
from evidencetool.decision.integrity import validate_decision_integrity

# 1. Schema conformance validation
with open("schemas/diagnosis-result.schema.json") as f:
    schema = json.load(f)
jsonschema.validate(instance=result_dict, schema=schema)

# 2. Decision integrity validation
integrity = validate_decision_integrity(result.decision, policy, result.evidence, state=result.incident.state)
if not integrity.is_valid:
    raise SecurityViolation(f"Decision integrity compromised: {integrity.violations}")
```

## 4. HUMAN_REVIEW
If the engine returns `HUMAN_REVIEW`, the agent MUST pause execution and request explicit permission from a human operator. Treating `HUMAN_REVIEW` as a silent `ALLOW` violates the core safety invariants of the product contract.

## 5. Distributed Tracing & APM Auditability (OpenTelemetry Mode B)
For observability, governance, and audit trails in enterprise agent mesh architectures, EvidenceTool natively exports distributed traces over standard OTLP/HTTP.

The agent harness can correlate its own LLM reasoning spans with EvidenceTool's operational reasoning spans:

```python
from evidencetool.agent import AgentSafetyGate, AgentDiagnosisRequest
from evidencetool.observability.tracing import DiagnosisTracer

# Optional: Instantiate a tracer to stream spans to Jaeger / Grafana Tempo
tracer = DiagnosisTracer(
    service_name="agent-safety-gateway",
    endpoint="http://collector.monitoring:4318/v1/traces",
)

result = gate.evaluate(request, tracer=tracer)

# Retrieve the W3C trace ID to attach to agent audit logs or ticketing systems
if result.trace_id:
    print(f"Distributed Trace ID: {result.trace_id}")
    # Inspect trace spans in Jaeger:
    # http://jaeger:16686/trace/{result.trace_id}
```

The resulting trace contains:
- `evidencetool.diagnosis`: Root span tagged with `evidencetool.authority.caller_id` (`agent_id`) and `session_id`.
- `evidencetool.provider.<namespace>`: Latency and observations per infrastructure probe.
- `evidencetool.evaluation`: Evaluated evidence distribution.
- `evidencetool.correlation`: Evaluated situational hypotheses.
- `evidencetool.causality`: Primary root cause and causal propagation chain.
- `evidencetool.decision`: Deterministic verdict (`ALLOW` / `BLOCK`), reason, and blocking evidence.

