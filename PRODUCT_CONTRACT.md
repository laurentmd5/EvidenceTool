# EvidenceTool — PRODUCT_CONTRACT.md

**Version:** 10.2 (V1.0.2 Deterministic Causal Operational Reasoning Engine & Incident Model)
**Status:** Active specification for V1.0.2 Deterministic Causal Operational Reasoning Engine, Incident Model & Local Uncertainty Governance
**Scope:** This document defines the minimal functional and architectural contract that the EvidenceTool codebase must respect.

---

## 0. Founding principle

> EvidenceTool does not automate actions first. It makes operational decisions explainable first.

EvidenceTool separates **observation**, **recommendation**, **authorization**, and **execution**. It never modifies the system it inspects.

---

## 1. Scope V0.2 & V0.3

### 1.1 Execution capability boundary

Execution capabilities are separate from diagnostic policy. The capability boundary determines whether a caller may
collect a given observation; the diagnostic policy determines how collected evidence affects an operational decision.
The network provider is not globally restricted from private or loopback targets. A caller may authorize those
targets explicitly through an execution capability policy, including operation, target, port, probe-count and
timeout limits. Capability denial is a security/integrity failure, not an ordinary network result.

Provider discovery and provider trust are separate. Built-in providers are identified as `builtin`; dynamically
discovered providers are `experimental` until explicitly approved. Automated execution may require trusted providers
through its capability policy. The diagnostic decision remains independent from both capability authorization and
provider trust.

External providers may be activated through a manifest containing their namespace, import module and SHA-256 source
hash. The hash is verified before import. Legacy dynamic discovery remains available for local extension workflows;
automated callers must use explicit approval and may require trusted providers.

**Definition:**

> A read-only operational evidence and decision tool for diagnosing production incidents and determining whether a proposed remediation action is sufficiently justified by available evidence.

**Vertical slice flow:**

```
Incident
   ↓
collect observations (Providers)
   ↓
evaluate evidence (PASS / FAIL / UNKNOWN)
   ↓
correlate state (Situations & OperationalState)
   ↓
evaluate policy (V1 Legacy OR V2 Situational)
   ↓
produce decision (BLOCK / HUMAN_REVIEW / ALLOW)
   ↓
validate decision integrity (Invariants verified)
```

**In scope:** VPS/Linux → Nginx → TLS/certificates → systemd → filesystem.

**Out of scope:** see Section 10 (Known limitations).

---

## 2. Evidence Model

Every observation produced by a provider must conform to this structure:

```json
{
  "id": "tls.certificate_valid",
  "source": "tls",
  "category": "certificate",
  "collector": "tls_provider",
  "method": "openssl x509 -in /etc/letsencrypt/live/example.com/fullchain.pem -noout -checkend 0",
  "value": {
    "status": "PASS"
  },
  "message": "Certificate is valid and not expired",
  "observed_at": "2026-08-12T08:30:00Z",
  "collected_at": "2026-08-12T08:30:01Z",
  "host": "prod-web-01"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | yes | Dotted namespace: `<source>.<category>.<check>` |
| `source` | string | yes | e.g. `nginx`, `tls`, `systemd`, `filesystem` |
| `category` | string | yes | Grouping within a source, e.g. `certificate`, `configuration` |
| `collector` | string | yes | Name of the provider/collector that produced this |
| `method` | string | yes | Concrete command/API used, e.g. `nginx -t` |
| `value` | any | yes | Raw observed value, provider-specific shape |
| `message` | string | yes | Human-readable explanation of what was observed |
| `observed_at` | ISO 8601 timestamp | yes | When the underlying fact was true |
| `collected_at` | ISO 8601 timestamp | yes | When EvidenceTool actually ran the collector |
| `host` | string | no | Target host if diagnostic was run remotely (Agentless SSH) |

### 2.1 Freshness

Freshness is derived from `observed_at` relative to evaluation time when a policy sets `max_age` for an evidence item:

- `FRESH`: observed less than the configured `max_age` before evaluation.
- `STALE`: observed `max_age` seconds or more before evaluation.

If `max_age` is omitted, no freshness constraint is applied. Integrations that require a 60-second freshness
window must declare `max_age: 60` explicitly in the policy.

---

## 3. Evidence States

Three states only:

- **PASS** — the condition was checked and is satisfied.
- **FAIL** — the condition was checked and is not satisfied.
- **UNKNOWN** — the evidence could not be obtained, checked, or determined.

**Explicit rule:**

> `UNKNOWN ≠ FAIL`. UNKNOWN is a distinct state. Whether it blocks a decision depends on the policy's per-evidence `on_unknown` directive (Section 4) or situational catalog resolution (Section 14), not on an arbitrary conversion rule.

---

## 4. Evidence Requirements

A policy declares which evidence items are required for a given action, and — critically — how each one behaves when its status is `UNKNOWN`.

```yaml
required_evidence:
  - id: nginx.config.valid
    on_unknown: BLOCK
  - id: tls.certificate.exists
    on_unknown: BLOCK
  - id: tls.private_key.exists
    on_unknown: BLOCK
  - id: filesystem.disk_io
    on_unknown: IGNORE
```

**Per-evidence evaluation:**

| Evidence status | Requirement outcome |
|---|---|
| `PASS` | Requirement satisfied |
| `FAIL` | Requirement violated → contributes to `BLOCK` |
| `UNKNOWN`, `on_unknown: BLOCK` | Requirement violated → contributes to `BLOCK` |
| `UNKNOWN`, `on_unknown: IGNORE` | Requirement treated as not blocking; noted as unverifiable in output, does not affect the decision |

### 4.1 Default when `on_unknown` is omitted

> **Default: `BLOCK`.**

This preserves fail-closed behavior as the baseline. A policy author must actively opt an evidence item into `IGNORE` — silence never grants leniency.

---

## 5. Decision Model

Three decisions only:

- **ALLOW** — required conditions are satisfied and no risk rule demands human intervention.
- **BLOCK** — the action must not be executed or presented as authorized.
- **HUMAN_REVIEW** — evidence may be sufficient to understand the incident, but the action requires human sign-off before it can be proposed as ALLOW.

### 5.1 Decision precedence

When multiple conditions could apply simultaneously, they are resolved in this fixed order:

```
BLOCK  >  HUMAN_REVIEW  >  ALLOW
```

Concretely: if any required evidence resolves to a blocking state (Section 4) or a blocked situation is active (Section 14), the decision is `BLOCK` — **regardless of risk level or `human_approval` setting**. A blocked action is never eligible for human review. `HUMAN_REVIEW` only applies when all required evidence requirements are satisfied but the policy's risk/approval settings still demand human sign-off.

---

## 6. Risk Model

Four levels:

```
LOW
MEDIUM
HIGH
CRITICAL
```

**Rule:** risk is declared by the policy author, never inferred or estimated by an AI component.

---

## 7. Policy Contract

```yaml
version: "1.0"
action: restart_nginx
risk: LOW
schema: "v2"

allow:
  - NGINX_SERVICE_DOWN

blocked_by:
  - TLS_CERTIFICATE_MISSING
  - TLS_CERTIFICATE_EXPIRED
  - TLS_KEY_MISSING
  - TLS_KEY_MISMATCH
  - NGINX_SERVICE_NOT_INSTALLED
  - DISK_FULL
  - NGINX_CONFIG_INVALID

required_evidence:
  - id: nginx.config_valid
    on_unknown: BLOCK
  - id: tls.certificate_exists
    on_unknown: BLOCK
  - id: tls.certificate_valid
    on_unknown: BLOCK
  - id: tls.private_key_exists
    on_unknown: BLOCK
  - id: tls.key_matches_certificate
    on_unknown: BLOCK
  - id: systemd.service_exists
    on_unknown: BLOCK
  - id: systemd.service_active
    on_unknown: IGNORE
  - id: filesystem.disk_space_available
    on_unknown: IGNORE

human_approval: false
```

---

## 8. JSON Output Contract

The JSON is the real contract. The CLI terminal output is a renderer over this JSON — never the other way around.

```json
{
  "incident": {
    "id": "inc_001",
    "type": "nginx_start_failure"
  },

  "evidence": [
    {
      "id": "nginx.config_valid",
      "status": "FAIL",
      "message": "nginx -t failed",
      "observation": {
        "id": "nginx.config_valid",
        "source": "nginx",
        "category": "configuration",
        "collector": "nginx_provider",
        "method": "env LC_ALL=C LANG=C nginx -t -c /etc/nginx/nginx.conf",
        "value": {
          "status": "FAIL",
          "stderr": "nginx: [emerg] open() \"/etc/nginx/nginx.conf\" failed"
        },
        "message": "nginx -t failed: nginx: [emerg] open() \"/etc/nginx/nginx.conf\" failed",
        "observed_at": "2026-08-12T08:30:00Z",
        "collected_at": "2026-08-12T08:30:01Z",
        "host": "prod-web-01"
      },
      "is_stale": false
    }
  ],

  "policy": {
    "action": "restart_nginx",
    "risk": "LOW"
  },

  "decision": {
    "status": "BLOCK",
    "reason": "Situation 'NGINX_CONFIG_INVALID' is explicitly blocked by policy.",
    "blocking_evidence": [
      "nginx.config_valid"
    ]
  },

  "recommendation": {
    "action": "Validate nginx configuration before restart"
  }
}
```

---

## 9. CLI Contract

```bash
# Human-readable diagnosis
evidencetool diagnose nginx

# Machine-readable output
evidencetool diagnose nginx --output json

# Explicit policy file
evidencetool diagnose nginx --policy policies/nginx.yaml

# Remote Agentless execution
evidencetool diagnose nginx --host prod-web-01
```

---

## 10. Known limitations

EvidenceTool explicitly does **not**:

- modify the system in any way;
- automatically restart or remediate anything;
- perform auto-remediation of any kind;
- mutate or modify Kubernetes cluster state (inspection is strictly read-only via scoped kubectl CLI);
- use an LLM anywhere in the evidence, risk, or decision path;
- expose a dashboard or web UI;
- compute a single aggregate 0–100 evidence score;
- perform probabilistic, speculative, or hallucinated root-cause analysis (causal reasoning is deterministic and evidence-backed).

---

## 11. Definition of done for the vertical slice

The vertical slice is considered complete when this flow runs end-to-end against real (or reproducibly simulated) broken services:

```
Service broken
     ↓
Providers (systemd, nginx, tls, filesystem)
     ↓
Evidence (conforming to Section 2)
     ↓
State Correlation (Situations & OperationalState)
     ↓
Policy evaluation (conforming to Sections 4, 5, 7, 14)
     ↓
Decision Integrity validation (Section 13)
     ↓
JSON output (conforming to Section 8)
```

At minimum, the following scenarios must produce the exact deterministic decision per this contract:
1. Missing certificate
2. Expired certificate
3. Certificate/key mismatch
4. Invalid nginx configuration
5. Disk full
6. Permission problem
7. Port conflict

---

## 12. SLI/SLO Contract

EvidenceTool defines Service Level Indicators (SLIs) and Objectives (SLOs) to ensure it is observable and trustworthy.
A critical distinction in EvidenceTool is:
> **RUN SUCCESS ≠ OPERATIONAL SUCCESS**

A run that correctly diagnoses a broken system and returns `BLOCK` is a **successful run** of EvidenceTool, even though the underlying system being observed is failing.

### 12.1 SLI Families

**1. Reliability SLI**
- `evidencetool_last_run_success`: Gauge (1 or 0) where `1` if the run completed successfully and passed integrity validation, `0` otherwise.
- `evidencetool_integrity_violation`: Gauge (1 or 0) indicating if there were decision integrity violations in the last run.

**2. Performance SLI**
- `evidencetool_last_run_duration_seconds`: Total execution time.
- `evidencetool_provider_duration_seconds{provider="..."}`: Time spent in each provider.
- `evidencetool_evaluation_duration_seconds`: Time spent evaluating evidence.
- `evidencetool_policy_duration_seconds`: Time spent in the policy engine.
- `evidencetool_decision_duration_seconds`: Time spent in the decision engine.

**3. Decision / Operational SLI (Last Run State)**
- `evidencetool_decision{status="ALLOW"|"BLOCK"|"HUMAN_REVIEW"}`: Gauge (1 or 0) indicating the decision of the last run.
- `evidencetool_evidence{status="PASS"|"FAIL"|"UNKNOWN"}`: Gauge indicating the count of each evidence status in the last run.

### 12.2 SLO

**SLO — Diagnostic execution reliability**
> ≥ 99.5% of scheduled EvidenceTool runs complete successfully over a rolling 30-day window.

---

## 13. Decision Integrity Contract

Decision integrity is an invariant mathematical property enforced before any decision leaves the engine:

1. **Precedence Invariant**: `BLOCK > HUMAN_REVIEW > ALLOW` always holds. No policy, risk score, or caller parameter can elevate a failing or blocked state to `ALLOW`.
2. **Inviolable Rules**:
   - If any required evidence has status `FAIL`, the decision MUST be `BLOCK`.
   - If an operational state is `ambiguous` (contains unresolved `UNKNOWN` evidence in catalog signatures without an explicit match on a blocked situation), the decision MUST be `BLOCK` (fail-closed).
   - If an active situation is listed in `policy.blocked_by`, the decision MUST be `BLOCK`.
   - If `policy.human_approval` is `true` and no blocking state exists, the decision MUST be `HUMAN_REVIEW`, NEVER `ALLOW`.
3. **Runtime Validation**:
   - `validate_decision_integrity(decision, policy, evidence, state)` is executed on every diagnosis result.
   - Any integrity violation sets `metrics.success = False` and forces CLI exit code `3` (`INTEGRITY_VIOLATION`).

---

## 14. V0.3 Situational Contract — frozen

The Situational Engine model introduced in V0.3 is formally frozen:

1. **Situations**: Discrete operational states defined by unambiguous multi-evidence signatures (`catalogs/*.yaml`).
2. **OperationalState**:
   - Correlates collected `Evidence` against situation signatures.
   - Computes active situations, situation discrepancies, and unresolved evidence.
   - Marks `ambiguous = True` when key signature evidence is `UNKNOWN` and no deterministic situation can be matched.
3. **Evaluation Order in V2_SITUATIONAL**:
   - Explicit root causes (`policy.blocked_by`) are evaluated against active situations FIRST. If a root cause is definitively proven (e.g. `TLS_CERTIFICATE_MISSING`), `BLOCK` is returned immediately for that root cause.
   - If no blocking situation is active, `state.ambiguous` is evaluated. If `ambiguous` is true, the engine fails closed with `BLOCK`.
   - Next, `policy.allow` situations are checked. If an allowed situation is matched, and no `human_approval` is required, `ALLOW` is returned.
   - If `human_approval` is required, `HUMAN_REVIEW` is returned.

---

## 15. Docker Environment & Privilege Trade-off (V0.4 Contract)

### 15.1 Privilege Asymmetry & Security Trade-off

The Docker environment introduces a fundamental privilege asymmetry compared to native filesystem / TLS inspection:
- Granting `evidencetool` read access to TLS certificates via POSIX ACLs is strictly non-destructive and cannot lead to code execution or privilege escalation.
- Granting access to the standard Docker daemon socket (`/var/run/docker.sock`) is **practically equivalent to root access on the host**, as the Docker API inherently allows mounting the host root filesystem (`-v /:/host`) into a container.

### 15.2 Invariants and Guardrails for Docker Provider

To preserve the founding principle (*read-only observer, never an executor*):
1. **Strict Read-Only Provider Invariant**: The `docker` provider executes **only non-mutating subcommands**:
   - `docker inspect <container>`
   - `docker logs --tail <N> <container>`
   - `docker ps`
   The provider NEVER invokes `docker run`, `docker exec`, `docker stop`, `docker restart`, `docker kill`, or `docker rm`.
2. **Command Construction**: As with all providers, commands are strictly constructed as argument lists (`["docker", "inspect", ...]`) and executed via `run_command(args, host=host)` without a shell.
3. **Recommended Host Isolation**:
   - In standard environments: Assign `evidencetool` to the `docker` group or configure socket ACLs with explicit documentation of the host trust boundary.
   - In hardened multi-tenant environments: Use a read-only Docker socket proxy (filtering to allow only `GET /containers/json`, `GET /containers/{id}/json`, `GET /containers/{id}/logs`, while rejecting all `POST`/`DELETE`/`PUT` requests).

---

## 16. Observability Expansion (V0.5 Contract)

### 16.1 Expanded Diagnostic Providers
EvidenceTool V0.5 introduces standard operational providers for infrastructure monitoring:
1. **Network Provider (`network`)**:
   - `network.port_reachable`: Non-destructive TCP port connectivity verification.
   - `network.host_reachable`: Gateway / upstream ICMP ping or address reachability.
   - `network.dns_resolvable`: DNS name resolution verification.
2. **Process Provider (`process`)**:
   - `process.running`: Process existence and PID verification via `pgrep` or `/proc`.
   - `process.zombie`: Zombie process state (`Z`) detection.
3. **Filesystem Provider (`filesystem`)**:
   - `filesystem.disk_space_available`: Threshold check on free disk space.
   - `filesystem.disk_pressure`: Disk saturation and pressure warning.

### 16.2 Generic State Correlation Invariant
The Decision Engine and State Correlation Engine remain **strictly generic and environment-agnostic**. All provider-specific knowledge lives inside discrete providers (`src/evidencetool/providers/`) and situation signature catalogs (`catalogs/*.yaml`), ensuring zero coupling between domain decision logic and OS-level collection mechanics.

---

## 17. Application & Data Dependencies (V0.6 Contract)

### 17.1 Stateful Middleware & Upstream Dependency Providers
EvidenceTool V0.6 extends observational boundaries to middleware and distributed dependency tiers:
1. **PostgreSQL Provider (`postgres`)**:
   - `postgres.reachable`: TCP socket connectivity on port 5432.
   - `postgres.accepting_connections`: Availability probe via `pg_isready` / wire SSLRequest handshake.
   - `postgres.pool_exhaustion`: Connection slot saturation detection (`FATAL: remaining connection slots are reserved` / `too many clients already`).
   - `postgres.is_in_recovery`: Fact observation on standby / read-only replica status.
   - `postgres.latency_ms`: Handshake latency measurement.
2. **MySQL Provider (`mysql`)**:
   - `mysql.reachable`: TCP socket connectivity on port 3306.
   - `mysql.ping`: Initial handshake packet decoding and protocol validation.
   - `mysql.max_connections`: Max connection limit detection (`Error 1040 (HY000): Too many connections`).
   - `mysql.read_only`: Server `read_only` / `super_read_only` flag observation.
   - `mysql.latency_ms`: Connect round-trip latency.
3. **Redis Provider (`redis`)**:
   - Native RESP wire client (zero external client dependencies).
   - `redis.reachable`: TCP port 6379 connectivity.
   - `redis.ping`: RESP `PING` command validation (`+PONG`).
   - `redis.auth`: Credential validation (`NOAUTH` vs `WRONGPASS`).
   - `redis.memory_pressure`: `INFO memory` ratio analysis (`used_memory / maxmemory`) and `OOM_MAXMEMORY` detection.
   - `redis.role`: Node role and replication link health (`master_link_status: down`).
   - `redis.latency_ms`: Round-trip command latency.
4. **Dependency Provider (`dependency`)**:
   - `dependency.http_status`: HTTP health check endpoint status (`/health`, `/healthz`).
   - `dependency.latency_ms`: Exact round-trip response time.
   - `dependency.sla_budget`: SLA budget validation against context expectations (`latency_ms <= sla_budget_ms`).
   - `dependency.circuit_breaker`: Upstream throttling and circuit breaking detection (HTTP 503, 429, 504).

---

## 18. First-Class Causality, Provenance & Strategic Roadmap

### 18.1 Definitive Product Definition
> **EvidenceTool** is a read-only, policy-aware operational evidence engine that correlates infrastructure, application, data, and dependency signals to identify probable root causes before allowing remediation.

### 18.2 First-Class Causality Model
Every diagnosis result must expose causality and provenance as first-class citizens, distinguishing:
1. **Root Cause Evidence (`root_cause`)**: The specific triggering evidence whose failure explains the failure signature (e.g. `postgres.pool_exhaustion`).
2. **Supporting Evidence (`supporting_evidence`)**: Nominal underlying evidence proving that lower layers (network, processes, containers, OS) are healthy (e.g. `network.port_reachable: PASS`, `process.running: PASS`).
3. **Decision Confidence (`confidence`)**: Formal confidence level derived from evidence coverage (`HIGH`, `MEDIUM`, `LOW`).

```json
{
  "situation": "POSTGRES_POOL_EXHAUSTED",
  "status": "BLOCK",
  "confidence": "HIGH",
  "root_cause": {
    "evidence": ["postgres.pool_exhaustion"]
  },
  "supporting_evidence": [
    "postgres.reachable",
    "postgres.accepting_connections",
    "postgres.latency_ms",
    "network.port_reachable",
    "process.running"
  ]
}
```

### 18.3 Strategic Evolution Trajectory
- **V0.3**: Single-domain infrastructure diagnosis (Nginx / TLS / Systemd).
- **V0.5**: Multi-domain infrastructure evidence (OS, Process, Filesystem, Network, Docker).
- **V0.6**: Dependency-aware diagnosis (PostgreSQL, MySQL, Redis, Upstream APIs, SLA budgets).
- **V0.7**: Kubernetes diagnostic domain (Mode A kubectl CLI with namespace confinement).
- **V0.8**: Distributed diagnosis & cross-domain multi-signal correlation.
- **V0.9**: AI-Agent safety gateway, authority model & caller identity.
- **V1.0**: Deterministic causal operational reasoning engine & unified OperationalIncident model.
- **V1.0.1**: Enterprise security hardening (strict TLS, static provider registry, probe budget isolation).
- **V1.0.2**: Decision correctness & network robustness (per-situation local uncertainty, bounded parsers, V2 fallbacks).

---

## 19. Kubernetes Diagnostic Domain (V0.7+ Contract)

### 19.1 Execution Scoping (Mode A `kubectl` CLI)
1. **CLI-Based Subprocess Execution**: Construction of strict argument lists (`kubectl get ... -o json`) executed via `run_command` without a shell.
2. **Zero Mutation Guarantee**: Read-only operations (`get`, `describe`, `cluster-info`). Zero mutation commands (`apply`, `delete`, `scale`, `exec`, `cordon`, `drain`).
3. **Confinement by Namespace (`KubernetesCapability`)**: Strict namespace access whitelist (`allowed_namespaces`) with automated security denial on system namespaces (`kube-system`, `kube-public`, `kube-node-lease`).
4. **Transport Failure Distinction (`DES-03`)**: Transport or authentication errors (such as `403 Forbidden`, unreachable API server, or connection timeouts) degrade gracefully to `UNKNOWN` with `transport_status='failed'`, reserving `FAIL` strictly for verified pod, container, or node defects. Absence of evidence is never treated as evidence of failure.

---

## 20. Distributed Diagnosis & Cross-Domain Correlation (V0.8 Contract)

### 20.1 Cross-Domain Multi-Signal Invariant
In distributed architectures, single-layer observations cannot distinguish symptoms from root causes. The correlation engine evaluates composite multi-signal signatures across application, data, cache, and transport layers simultaneously:
- **`DATABASE_CONNECTIVITY_FAILURE`**: Application 500 + PostgreSQL unreachable + TCP/5432 connection failure + Redis ping PASS (rules out global network partition).
- **`DATABASE_POOL_EXHAUSTION_CASCADE`**: Application latency spike + Database reachable + Pool exhausted (`Too many clients`).
- **`CACHE_FAILURE_DATABASE_OVERLOAD`**: Redis memory saturation (OOM) + Database query latency spike.
- **`UPSTREAM_MICROSERVICE_OUTAGE`**: Application 503 / circuit breaker triggered + Local database PASS + Cache PASS.
- **`TOTAL_NETWORK_PARTITION`**: Multi-port simultaneous unreachable states across all remote endpoints.

---

## 21. AI-Agent Safety Gateway & Authority Model (V0.9 Contract)

### 21.1 The 4-Tier Architectural Separation
EvidenceTool establishes four strictly decoupled layers for operational reasoning:
1. **Observation (Facts)**: Pure, read-only system observations collected with zero side-effects.
2. **Situation (Semantics)**: Multi-signal state correlation evaluating composite signatures against formal catalogs.
3. **Governance (Action Policy)**: Invariant safety rules determining if a remediation action is allowed (`BLOCK > HUMAN_REVIEW > ALLOW`).
4. **Authority (Capability Boundary)**: Zero-trust execution envelope restricting the caller's allowed targets, ports, namespaces, and probe budgets.

### 21.2 Probe Budget Quota Invariant
Automated and AI-agent callers operate under strict resource and probe limits:
- Exceeding `max_probes` terminates execution immediately with `CapabilityDenied`.
- Denials are recorded in `AuthorityMetadata` and evaluated fail-closed as `BLOCK`.

### 21.3 Capability Anti-Tampering
Capability policies can be pinned to a cryptographic SHA-256 digest. Any modification of the policy content by an untrusted or prompt-injected caller is immediately rejected prior to execution.

---

## 22. Deterministic Causal Operational Reasoning & Incident Model (V1.0 Contract)

### 22.1 The 5 Causal Invariants
1. **Symptoms are Never Root Causes**: Surface effects (`HTTP 504`, `TCP timeout`, `High Latency`) cannot be designated as primary root causes.
2. **Healthy Dependencies Preclude Hypotheses**: Verified healthy signals explicitly refute competing outage hypotheses (`PRECLUDED_HYPOTHESES`).
3. **Directly Observed Failures Take Precedence**: Direct component failures (`redis.memory_pressure: FAIL`, `postgres.pool_exhaustion: FAIL`, `k8s.container_oom_killed: FAIL`) supersede indirect latency degradation.
4. **Declarative Causal Catalogs**: All valid causal propagation paths must be declared in YAML catalogs (`causality/*.yaml`); the engine never invents causal relations dynamically.
5. **Tri-State Deterministic Outcome (Fail-Closed)**:
   - `ROOT_CAUSE_IDENTIFIED`: Sufficient evidence + valid causal chain + zero contradictions.
   - `ROOT_CAUSE_CONSTRAINED`: Multiple candidate causes compatible with observations without sufficient evidence to disambiguate.
   - `ROOT_CAUSE_UNKNOWN`: Incomplete observations $\to$ **Fail-closed (`HUMAN_REVIEW` / `BLOCK`), zero guessing**.

### 22.2 Unified Operational Incident Model
Operational reasoning culminates in a typed `OperationalIncident` uniting:
- `incident_id`: Globally unique incident identifier.
- `observations`: Verified raw facts collected across all domains.
- `situations`: Formally matched signatures.
- `causality`: Primary root cause, causal propagation chain, surface symptoms, and precluded hypotheses.
- `decision`: Governance policy verdict (`BLOCK > HUMAN_REVIEW > ALLOW`).
- `authority`: Caller identity, quotas, and capability session tracing.

---

## 23. Decision Correctness & Local Uncertainty Model (V1.0.2 Contract)

### 23.1 Local Uncertainty Invariant
Uncertainty must be local to the hypothesis it affects:
- In `V2_SITUATIONAL` policies, ambiguity is tracked per-situation (`SituationEvaluation`).
- An unresolved or `UNKNOWN` observation in an unrelated domain (e.g. `redis.reachable: UNKNOWN`) does not contaminate or block a clean, verified decision in the target domain (e.g. `restart_nginx` with `NGINX_SERVICE_DOWN` fully verified).
- An allowed situation is blocked due to ambiguity if and only if *its own* signature evidence contains `UNKNOWN` values.

### 23.2 Complete Fallback Invariant
When a provider execution fails or is denied by capability policy, fallback `UNKNOWN` observations must be generated for all evidence items required by situation signatures in the active catalog, ensuring situational policies always receive explicit evidence rather than missing entries. Absence of evidence always resolves to `UNKNOWN`, never to an unverified assumption.

---

## 24. OpenTelemetry Mode B Outbound Tracing Contract (V1.0.3 Contract)

### 24.1 Architecture & Trace Topology
EvidenceTool produces distributed OpenTelemetry traces mapping its internal operational reasoning pipeline. Each execution generates a W3C TraceContext compliant trace consisting of hierarchical spans:
- `evidencetool.diagnosis` (Root span): Encompasses total diagnostic run.
  - `evidencetool.provider.<namespace>`: Measures individual provider collection latency, observation counts, and error/capability denials.
  - `evidencetool.evaluation`: Measures evaluation latency and breakdown of PASS / FAIL / UNKNOWN evidence.
  - `evidencetool.correlation`: Measures multi-signal situation signature matching and unresolved evidence tracking.
  - `evidencetool.causality`: Measures causal tree reconstruction, identifying root causes, propagation chains, and precluded outage hypotheses.
  - `evidencetool.decision`: Records the definitive governance verdict (`ALLOW`, `BLOCK`, `HUMAN_REVIEW`), blocking evidence, and policy action.

### 24.2 Semantic Attributes Specification
| Attribute | Scope | Type | Description |
|:---|:---|:---|:---|
| `evidencetool.target` | Root | String | Diagnosed operational target (e.g. `nginx`, `network`). |
| `evidencetool.policy.action` | Root / Decision | String | Governed remediation action. |
| `evidencetool.decision.status` | Root / Decision | String | `ALLOW`, `BLOCK`, or `HUMAN_REVIEW`. |
| `evidencetool.decision.reason` | Root / Decision | String | Deterministic human-readable explanation. |
| `evidencetool.decision.blocking_evidence` | Root / Decision | Array[String] | IDs of evidence items triggering rejection. |
| `evidencetool.authority.caller_id` | Root | String | Identity of caller or AI agent requesting diagnosis. |
| `evidencetool.authority.caller_type` | Root | String | `AI_AGENT`, `HUMAN_OPERATOR`, `CI_PIPELINE`, `CONTROLLER`. |
| `evidencetool.authority.session_id` | Root | String | Agent or workflow session identifier. |
| `evidencetool.causality.status` | Causality | String | `ROOT_CAUSE_IDENTIFIED`, `ROOT_CAUSE_CONSTRAINED`, `ROOT_CAUSE_UNKNOWN`. |
| `evidencetool.causality.primary_root_cause` | Causality | String | Primary root cause situation ID. |
| `evidencetool.causality.chain` | Causality | Array[String] | Sequence of causal propagation steps. |
| `evidencetool.causality.precluded` | Causality | Array[String] | Outage hypotheses formally refuted by healthy signals. |

### 24.3 Zero-Dependency & Export Invariants
1. **Zero Hard-Dependency**: Core EvidenceTool operates with pure standard library Python. It does not require `opentelemetry` to be installed to generate W3C trace IDs, record spans, or export OTLP/JSON.
2. **OTLP/HTTP & File Export**: Traces can be exported directly via OTLP/HTTP JSON to OpenTelemetry Collectors (Jaeger, Tempo, Datadog) or saved locally as JSON files.
3. **Resilient Export**: Network or exporter failures when transmitting traces never abort or corrupt the primary diagnostic evaluation. Export errors are caught and logged without side effects.

### 24.4 Core Architectural Invariants
1. **Observability Independence Invariant**: OpenTelemetry is strictly an observability integration layer. It **MUST NOT** influence EvidenceTool's deterministic diagnostic, causal, policy, or authority decisions. Spans describe operational reasoning; they never alter or determine it.
2. **Host TracerProvider Non-Interference Invariant**: When running inside an already instrumented host application (e.g. AI agent mesh, LangChain, web service), EvidenceTool **MUST** use the host application's OpenTelemetry context via `trace.get_tracer("evidencetool", ...)` and **MUST NOT** replace, mutate, or re-initialize the host application's global `TracerProvider`. The host's span processors and active parent contexts remain completely untouched.

### 24.5 Trace Context Non-Authentication Invariant
1. **Correlation Only**: A W3C `traceparent` (passed via `AgentDiagnosisRequest.traceparent`, CLI `--traceparent`, or `TRACEPARENT` environment variable) is strictly a telemetry correlation identifier. It carries zero authentication, authorization, or capability semantics.
2. **Authority Decoupling**: Receipt of a valid or invalid `traceparent` from an AI agent or upstream caller **MUST NEVER**:
   - Bypass, loosen, or modify the caller's `CapabilitySet`.
   - Substitute or spoof the caller's cryptographic `policy_fingerprint`.
   - Reset, extend, or bypass the per-session `ProbeTracker` budget.
   - Authorize any provider or transport not explicitly allowed by the active capability policy.
3. **Fail-Safe Robustness**: Malformed or unparseable `traceparent` headers are handled strictly fail-safe: they log a warning and fall back to the active host OpenTelemetry span context (if present) or generate a new independent root trace ID. Malformed trace context **NEVER** raises an unhandled exception or aborts diagnostic evaluation.

### 24.6 Span Status Semantics Invariant
1. **Operational Decisions are Not Errors**: Operational verdicts (`BLOCK`, `HUMAN_REVIEW`, `ALLOW`) reflect successful policy evaluation and are recorded exclusively as semantic attributes (`evidencetool.decision.status`).
2. **Error Status Exclusivity**: An OpenTelemetry span status of `StatusCode.ERROR` is strictly reserved for genuine execution or integrity failures:
   - Diagnostic integrity violation (`metrics.success == False` from `validate_decision_integrity`).
   - Uncaught crash or capability denial.
3. **No False APM Alarms**: A legitimate `BLOCK` decision resulting from healthy verification (e.g. preventing a service restart because the TLS certificate is missing) MUST produce an OpenTelemetry span status of `StatusCode.OK` to prevent false positive error rate spikes or APM alert fatigue.

### 24.7 Dual Exporter Hierarchy
1. **Host-Managed Exporter**: When running inside an already instrumented host application, EvidenceTool spans route through the host's existing `TracerProvider` pipeline.
2. **Official OTLP Exporter in Standalone Mode**: When executed standalone (CLI or isolated script with `--otel-endpoint`) and `opentelemetry-exporter-otlp-proto-http` is installed, EvidenceTool initializes an internal `TracerProvider` with `OTLPSpanExporter` transmitting standard binary Protobuf over HTTP (`application/x-protobuf`) without mutating the global host provider.
3. **Pure-Python Zero-Dependency Fallback**: If the OpenTelemetry SDK/exporter packages are absent, EvidenceTool falls back to transmitting standard OTLP JSON (`application/json`) via pure Python standard library HTTP requests.

---

## 25. OpenTelemetry Mode A Inbound Telemetry Contract (V1.0.4 Contract)

### 25.1 Telemetry Observation Invariant
1. **External Observation Only**: Telemetry backends (Prometheus, Tempo, Jaeger, OTel Collector) are treated strictly as external observation sources (`Telemetry -> Evidence`).
2. **Authority Decoupling**: Inbound telemetry brings additional evidence, but **MUST NEVER** confer or extend authority to any caller, model, or diagnostic entity. It does not alter capability budgets, bypass policies, or substitute cryptographic identity.
3. **Backend Disambiguation**: EvidenceTool interacts with telemetry interfaces (Prometheus HTTP `/api/v1/query`, Tempo/Jaeger HTTP `/api/traces`), not proprietary or direct OpenTelemetry SDK internals.

### 25.2 Deterministic Interpretation Invariant
1. **Observation vs. Evaluation**: Telemetry providers are strictly limited to collecting and normalizing raw observed values (e.g. error rate `0.073`, latency `842.0ms`, error spans `17`). Providers **MUST NOT** evaluate diagnostic business thresholds or decide whether a value constitutes an incident.
2. **Evaluation Layer Responsibility**: Verification of thresholds against service SLAs is exclusively executed by the `Evidence Evaluator` using policy declarations (`threshold`, `comparator`) and situational signatures.
3. **Technical Status Exclusivity**: Direct technical status (`PASS` / `UNKNOWN`) in observations is strictly reserved for transport availability (`otel.metrics_reachable`, `otel.traces_reachable`).

### 25.3 Telemetry Capability & SSRF Invariant
1. **Pre-connect Authorization**: Every remote telemetry query MUST be pre-authorized via `NetworkCapability` under the `"otel_query"` operation, matching authorized target hosts and ports before any network socket is opened.
2. **Strict No-Redirect Policy**: Telemetry HTTP clients **MUST NOT** follow HTTP 3xx redirects. Any redirect status code is treated as an unexpected redirect and rejected as `UNKNOWN` / `CapabilityDenied` to prevent SSRF bypass attacks (e.g. redirection to `169.254.169.254` or internal subnets).
3. **Centralized Sanitization**: All credentials, tokens, and sensitive query parameters in URLs, logs, traces, and error messages MUST be systematically redacted as `[REDACTED]`.

### 25.4 Telemetry Uncertainty Invariant
1. **Separation of Availability and Health**: Monitoring backend unavailability (`TELEMETRY_METRICS_UNAVAILABLE`) MUST be strictly separated from service health situations (`SERVICE_ERROR_RATE_EXCEEDED`).
2. **UNKNOWN is Not FAIL**: If a metrics or traces backend times out, is unreachable, or returns a transport failure, the affected observations evaluate to `UNKNOWN` (`transport_status="failed"`). Telemetry uncertainty **NEVER** implicitly converts to `FAIL`, preventing false positive alerts or misattributed service blame.

### 25.5 Telemetry Resource-Bound Invariant
1. **Multi-Dimensional Budget**: Telemetry collection is governed by a strict `TelemetryBudget`:
   - `max_requests`: limits total HTTP queries per collection pass (default 5-10).
   - `max_response_bytes`: bounds stream reading to 1MB.
   - `connect_timeout` & `read_timeout`: bounded network socket timeouts.
   - `max_query_length`: bounds query string length (default 1024 characters).
   - `max_lookback_seconds`: bounds trace search time window.
2. **Pre-Deserialization Stream Bounding**: Socket streams MUST be bounded during read (`read(limit + 1)`). If the payload exceeds the budget, the stream is aborted immediately before invoking JSON deserialization (`json.loads()`).

### 25.6 Hybrid Causality Invariant (Mode C)
1. **Surface Symptoms vs. Physical Root Causes**: Inbound telemetry signals (e.g. `otel.http_error_rate`, `otel.p99_latency_ms`) are modeled in the causal engine as surface symptoms (`is_surface_symptom: true`), not as physical root causes.
2. **Deterministic Root-Cause Reconstruction**: When surface telemetry symptoms correlate with native physical probes (e.g. `postgres.pool_exhaustion: FAIL`, `redis.memory_pressure: FAIL`), the causal engine constructs a causal propagation chain attributing the root cause to the physical failure (`relation: PROPAGATES_TO`).
3. **Hypothesis Preclusion**: Nominal telemetry (`SERVICE_TELEMETRY_NOMINAL`) formally refutes and precludes active outage hypotheses (`relation: PRECLUDES`), preventing unnecessary service restarts or destructive automated rollbacks.