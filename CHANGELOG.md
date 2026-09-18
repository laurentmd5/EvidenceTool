# Changelog

All notable changes to this project will be documented in this file.

## [1.0.6] - 2026-09-18
### Mode C Hybrid Causal Reasoning Adversarial Hardening
- **Pre-Arbitration Graph Validation & Cycle Detection (`C7`)**:
  - Implemented `_detect_cycles()` performing deterministic cycle finding prior to root candidate arbitration.
  - Enforced the invariant: *Causal graph validation MUST happen before causal arbitration*.
  - Fixed `ValueError` in `_arbitrate_candidates` when all confirmed nodes form a directed cycle ($A \longrightarrow B \longrightarrow A$).
  - In the presence of a cycle, the engine gracefully avoids crashing, sets `primary_root_cause = None`, preserves candidates with `state = POSSIBLE`, and reports detected cycle paths in `cycles_detected`.
- **Topological Chain Preservation & Strict Ordering (`C8`)**:
  - Enforced strict deterministic node ordering in `_find_causal_path` and `_build_causal_chain` via sorted neighbor traversal.
  - Long multi-hop chains ($A \longrightarrow B \longrightarrow C \longrightarrow D \longrightarrow S$) retain all intermediate nodes in strictly ordered topological sequence ($[A, B, C, D, S]$).
- **Priority Disambiguation & Priority Tie Invariant (`C9`, `C9b`)**:
  - Explicit integer `priority: <int>` deterministically elects the highest-priority root candidate.
  - Added Priority Tie Invariant: if multiple roots share the exact same maximum priority, no dictionary or file insertion order tie-breaking is permitted $\to$ `ROOT_CAUSE_CONSTRAINED` with all candidates preserved as `POSSIBLE`.
- **Indispensable Prerequisite Semantics (`C11`, `C12`)**:
  - Formalized tripartite behavior of `REQUIRES`:
    - $B = \text{PASS} \implies A$ may be confirmed.
    - $B = \text{UNKNOWN} \implies A$ transitions to `UNRESOLVED` (recorded in `unresolved_hypotheses` with `missing_evidence: [B]`).
    - $B = \text{FAIL} \implies A$ is formally refuted / precluded by prerequisite failure and added to `precluded_hypotheses`.
- **Zero Implicit Causality Enforced (`C13`)**:
  - Verified that concurrent failures without declared causal rules in catalogs produce zero causal inference (`primary_root_cause = None`, `causal_chain = []`, `status = ROOT_CAUSE_UNKNOWN`).
- **Comprehensive Adversarial Verification Suite**:
  - Added `tests/test_causality_mode_c_adversarial.py` containing 11 tests verifying scenarios C7 to C13.
  - Test suite expanded from 275 to 286 tests passing 100% with strict type safety (`mypy`), linting (`ruff`), and security scanning (`bandit`).

## [1.0.5] - 2026-09-18
### Mode C Hybrid Causal Reasoning Engine (Phase 2)
- **Deterministic Causal Graph Engine Refactoring**:
  - Removed all hardcoded indicators and hardcoded preclusions from Python code in favor of 100% declarative YAML rules.
  - Implemented formal support for 3 fundamental causal relations: `PROPAGATES_TO` ($A \longrightarrow B$), `PRECLUDES` ($A \mathrel{\rlap{\quad\not}\longrightarrow} B$), and `REQUIRES` ($A \xleftarrow{\text{req}} B$).
  - Implemented Subgraph Uncertainty Isolation: an `UNKNOWN` observation affects only hypotheses directly dependent on it, preserving complete immunity for disjoint probe subgraphs.
- **Deterministic Multi-Candidate Arbitration**:
  - Eliminated arbitrary tie-breaking: when multiple independent root causes are confirmed concurrently without priority or hierarchy, all candidates are preserved as `POSSIBLE` with `status = ROOT_CAUSE_CONSTRAINED` and `primary_root_cause = None`.
  - Deterministic resolution enabled exclusively via multi-hop causal graph hierarchy or explicit catalog rule `priority: <int>`.
  - Zero implicit causality: multiple failing situations without declared causal propagation rules evaluate to `status = ROOT_CAUSE_UNKNOWN` and `causal_chain = []`.
- **Causal Domain Models & Schema Alignment**:
  - Extended domain models with `CausalCandidateState` (`CONFIRMED`, `POSSIBLE`, `UNRESOLVED`), `CausalCandidate` dataclass, and `unresolved_hypotheses`.
  - Updated `schemas/diagnosis-result.schema.json` to support both string identifiers and structured candidate objects backward-compatibly.
- **Formal Verification Suite (Scenarios C1 to C6)**:
  - Added dedicated test suite `tests/test_causality_mode_c.py` verifying scenarios C1–C6 and the `REQUIRES` causal relation.
  - Test suite expanded to 275 tests passing 100% with strict type safety (`mypy`), linting (`ruff`), and security scanning (`bandit`).
- **Product Contract Formalization**:
  - Added Section 26 to `PRODUCT_CONTRACT.md` detailing the 6 core invariants of Mode C Hybrid Causal Reasoning.

## [1.0.4] - 2026-09-18
### OpenTelemetry Mode A Inbound Telemetry & Mode C Hybrid Correlation
- **Inbound Telemetry Provider (`otel`)**:
  - Implemented `OTelProvider` (`@provider("otel", trust=ProviderTrust.BUILTIN)`), enabling non-intrusive ingestion of application metrics and distributed trace error counts from Prometheus and Tempo/Jaeger backends.
  - Built-in provider count increased from 12 to 13 modules, protected against runtime tampering or authority extension.
- **Provider Responsibility Separation & Pipeline Alignment**:
  - Provider is strictly limited to observation and normalization of raw values (e.g. error rate `0.073`, latency `842.0ms`, error spans `17`).
  - Business SLA threshold evaluation (`PASS` / `FAIL`) is executed deterministically by the `Evidence Evaluator` according to `EvidenceRequirement(threshold, comparator)` declared in the policy.
  - Trace error searches include explicit time-window metadata (`lookback="5m"`).
- **Centralized `TelemetryHTTPClient` & SSRF Protection**:
  - Strict No-Redirect Policy: HTTP 3xx responses are immediately rejected (`RedirectDenied` / `UNKNOWN`) to prevent SSRF rebound attacks.
  - Pre-connect validation via `NetworkCapability` (`operation="otel_query"`), with automated blocking of cloud metadata endpoints (`169.254.169.254`).
  - Multi-dimensional `TelemetryBudget`: request limits (5 max), bounded stream reading (1MB ceiling) before JSON deserialization, and query length limits.
  - Centralized credential and token redaction across URLs, headers, logs, traces, and error messages (`[REDACTED]`).
- **Separation of Telemetry Availability from Service Health (Local Uncertainty)**:
  - Technical reachability (`otel.metrics_reachable`, `otel.traces_reachable`) evaluates transport availability (`PASS` / `UNKNOWN`).
  - Monitoring backend failure maps to `TELEMETRY_METRICS_UNAVAILABLE` without producing false positive service errors (`UNKNOWN ≠ FAIL`).
- **Mode C Hybrid Causal Correlation**:
  - Declarative catalogs `catalogs/telemetry.yaml` and `causality/telemetry.yaml` linking high-level surface telemetry symptoms to native physical root causes (e.g. PostgreSQL connection pool exhaustion or Redis memory pressure).
  - Nominal telemetry (`SERVICE_TELEMETRY_NOMINAL`) formally refutes and precludes active outage hypotheses.
- **Product Contract Formalization**:
  - Added Section 25 to `PRODUCT_CONTRACT.md` detailing the 6 core invariants.
- **Test Suite Expansion**:
  - Added 14 new tests (`tests/test_otel_provider.py`, `tests/test_diagnose_telemetry.py`), bringing the test suite to 266 tests passing 100%.

## [1.0.3] - 2026-09-18
### OpenTelemetry Mode B Outbound Tracing (Production-Ready)
- **Host TracerProvider Non-Interference (`Étape 1`)**:
  - Leverages host application's OpenTelemetry runtime via `trace.get_tracer("evidencetool", "1.0.3")` without mutating, reinitializing, or replacing global `TracerProvider`.
  - Zero hard-dependency fallback: collects in-memory spans and exports standard OTLP/JSON via pure standard library Python when OpenTelemetry SDK is absent.
  - Added `opentelemetry-exporter-otlp-proto-http>=1.20.0` to `[project.optional-dependencies] otel`.
- **W3C Distributed Context Propagation (`Étape 2`)**:
  - Implemented 4-tier precedence hierarchy: Tier 1 (explicit arg) > Tier 2 (`TRACEPARENT` env var) > Tier 3 (host active span) > Tier 4 (new independent root trace).
  - Added strict W3C `traceparent` RFC 00 parser with fail-safe fallback: invalid traceparents never raise exceptions and fall back to the active host span if present.
  - Exposed `traceparent` parameter in `AgentDiagnosisRequest`, `AgentSafetyGate.evaluate()`, `diagnose()`, and CLI option `--traceparent`.
  - Enforced *Trace Context Non-Authentication Invariant* (Section 24.5): traceparent correlation never grants authority or bypasses capability/probe budgets.
- **Production Hardening & Quality Gate Alignment**:
  - **Span Status Semantics Invariant (Section 24.6)**: `BLOCK` and `HUMAN_REVIEW` decisions are successful governance outcomes with span status `StatusCode.OK`. Span status `StatusCode.ERROR` is strictly reserved for genuine execution or integrity failures (`metrics.success == False`), eliminating false APM alerts.
  - **Official OTLP Exporter Integration (Section 24.7)**: Standalone diagnoses use official `OTLPSpanExporter` (Protobuf over HTTP) with fallback to native JSON HTTP exporter when optional dependencies are omitted.
  - **CI Installation & Reproducibility**: Updated `.github/workflows/ci.yml` to install `.[test,otel]` across all matrix runs, with `pytest.importorskip` for optional dependencies and pure-Python fallback verification.
  - **Dependency Locking**: Pinned OpenTelemetry runtime dependencies in `requirements-lock.txt`.
  - **Real Jaeger E2E in CI**: Added `otel-collector-e2e` job running a live Jaeger container, testing wire export and asserting trace indexing via Jaeger Query API.
  - **21 Dedicated Tracing Tests**: 252 total tests in test suite passing 100%.

## [1.0.2] - 2026-09-18
### Decision Correctness & Network Robustness Hardening
- **Local Uncertainty Invariant (`P0 / HIGH-02`)**: Replaced global boolean ambiguity with per-situation `SituationEvaluation`. Unresolved evidence in unrelated domains (e.g. Redis) no longer contaminates clean, verified decisions in the target domain (e.g. Nginx).
- **Comprehensive V2 Fallback UNKNOWN (`P0 / HIGH-01`)**: Provider failure and `CapabilityDenied` exceptions now generate fallback `UNKNOWN` observations for all evidence required by catalog situation signatures, ensuring situational policies always receive explicit evidence rather than missing entries.
- **Bounded Redis RESP Parser (`P1 / CRIT-01`)**: Enforced `MAX_RESP_BULK_SIZE` (16 MB) and `MAX_RESP_LINE_LENGTH` (64 KB) to protect against memory exhaustion from malformed or adversarial endpoints.
- **Bounded MySQL Handshake (`P1 / CRIT-02`)**: Enforced `MAX_MYSQL_HANDSHAKE_SIZE` (64 KB) on handshake payload reading.
- **SSH ConnectTimeout (`P1 / HIGH-03`)**: Added explicit `ConnectTimeout` to SSH command arguments to prevent 2+ minute TCP hangs on unreachable hosts.
- **Dependency curl Max-Time (`P2 / MED-02`)**: Added `-m` (max-time) flag to remote curl invocations in `DependencyProvider`.
- **Integrity Duplicate Check Optimization (`P2 / MED-05`)**: Replaced $O(N^2)$ `.count()` with $O(N)$ `Counter` in `validate_decision_integrity`.
- **Adversarial & Decision Correctness Test Suite**: Added `tests/test_decision_correctness.py` with 13 exhaustive scenarios validating local uncertainty, provider crashes, and network bounds (223 tests passing 100%).

## [1.0.1] - 2026-08-26
### Security & Authority Hardening
- **Strict TLS Verification by Default (`SEC-01`)**: Dependency HTTPS probes validate certificates and hostnames (`CERT_REQUIRED`). `allow_insecure_tls` is strictly governed by `NetworkCapability`.
- **Static Provider Trust Boundary (`SEC-02`)**: Replaced filesystem dynamic discovery with explicit static registration of the 12 built-in providers; external plugins strictly require pre-import SHA-256 validation.
- **Agent Policy Immutability & Action Matching (`SEC-03`)**: Gate policies are authoritative; enforced strict matching between `policy.action` and `request.action`.
- **Semantic Policy Conflict Validation (`SEC-04`)**: Added load-time checks ensuring `allow` and `blocked_by` are strictly disjoint.
- **Per-Evaluation Probe Budget Isolation (`DES-01`)**: Isolated `ProbeTracker` per evaluation request (`clone_isolated()`).
- **Transport Failure Distinction (`DES-03`)**: Reclassified Kubernetes transport/auth errors (`403 Forbidden`, timeouts) as `UNKNOWN` with `transport_status="failed"`, reserving `FAIL` for verified pod defects.
- **Clock Skew & Future Timestamp Protection (`SEC-06`)**: Requalified future-dated observations (`age < -5s`) as `UNKNOWN`.
- **Version Truth Alignment (`DES-05`)**: Synchronized version `1.0.1` in `pyproject.toml` and `SECURITY.md`.

## [1.0.0] - 2026-08-26
### Added
- **Deterministic Causal Reasoning Engine (`evidencetool.causality`)**: Reconstructs verifiable causal propagation chains from observed facts without guessing or probabilistic hallucinations.
- **Tri-State Causal Evaluation (`CausalityStatus`)**: Explicit distinction between `ROOT_CAUSE_IDENTIFIED`, `ROOT_CAUSE_CONSTRAINED`, and `ROOT_CAUSE_UNKNOWN` with strict fail-closed safety under incomplete information.
- **Declarative Causality Catalogs (`causality/`)**: Declarative rules (`causality/distributed.yaml`, `causality/kubernetes.yaml`) defining `PROPAGATES_TO` and `PRECLUDES` relations.
- **Unified Operational Incident Model (`OperationalIncident`)**: Captures observations, situations, primary root cause, causal chain, propagated symptoms, and governance decision into a single explainable record.
- **Agent SDK Causal Explainability**: Extended `AgentDiagnosisResult` and JSON output contract (`schemas/diagnosis-result.schema.json`) with `causality` metadata.
- **Canonical Causal Test Suite (`tests/test_causality.py`)**: 5 comprehensive scenarios verifying single root causes, multi-layer cascades, and fail-closed ambiguity handling (202 tests passing 100%).

## [0.9.0] - 2026-08-25
### Added
- **AI-Agent SDK & Safety Gateway (`evidencetool.agent`)**: Pure Python programmatic safety gateway providing `AgentSafetyGate`, `AgentDiagnosisRequest`, and `AgentDiagnosisResult` to evaluate autonomous AI agent actions before execution.
- **Caller Identity & Authority Tracking**: Added `CallerIdentity` and `CallerType` (`AI_AGENT`, `HUMAN`, `AUTOMATED_PIPELINE`) with session tracing.
- **Probe Budget Quotas**: Added dynamic `ProbeTracker` with strict quota enforcement (`max_probes`) to prevent denial-of-service / runaway looping from automated callers.
- **Capability Anti-Tampering**: Added SHA-256 fingerprint computation and verification for capability policy YAML files to prevent prompt-injection escalation.
- **JSON Output Contract Enrichment**: Extended `schemas/diagnosis-result.schema.json` and CLI renderers with the optional `authority` block.
- **Agent SDK Test Suite (`tests/test_agent_sdk.py`)**: 4 comprehensive scenarios verifying gate evaluation, destructive action blocking, probe budget exhaustion, and tamper detection.

## [0.8.0] - 2026-08-25
### Added
- **Distributed Diagnosis & Cross-Domain Multi-Signal Correlation**: Introduced cross-domain diagnosis correlating application symptoms with data, cache, and network transport signals.
- **Distributed Situation Catalog (`catalogs/distributed.yaml`)**: Defined 7 distributed incident signatures (`DATABASE_CONNECTIVITY_FAILURE`, `DATABASE_POOL_EXHAUSTION_CASCADE`, `CACHE_FAILURE_DATABASE_OVERLOAD`, `UPSTREAM_MICROSERVICE_OUTAGE`, `DISTRIBUTED_SPLIT_BRAIN_OR_READ_ONLY`, `TOTAL_NETWORK_PARTITION`, `DISTRIBUTED_HEALTHY`).
- **Distributed Policy (`policies/distributed.yaml`)**: Policy gating application restarts on distributed outages.
- **Multi-signal End-to-End Suite (`tests/test_distributed_diagnosis.py`)**: 7 full scenarios verifying cross-domain correlation.

## [0.7.0] - 2026-08-25
### Added
- **Kubernetes Provider (`k8s` / `kubernetes`)**: Read-only `kubectl` CLI inspection supporting `k8s.pod_phase`, `k8s.containers_ready`, `k8s.container_crashloop`, `k8s.container_oom_killed` (exit code 137), `k8s.image_pull_status`, `k8s.config_secret_status`, `k8s.pod_scheduled`, and `k8s.node_ready`.
- **Kubernetes Capability Confinement (`KubernetesCapability`)**: Strict namespace access whitelist and automated denial on system namespaces (`kube-system`, `kube-public`, `kube-node-lease`).
- **Kubernetes Situation Catalog (`catalogs/kubernetes.yaml`)**: Defined 7 Kubernetes signatures (`K8S_POD_HEALTHY`, `K8S_CRASH_LOOP_BACKOFF`, `K8S_OOM_KILLED`, `K8S_IMAGE_PULL_FAILURE`, `K8S_CONFIG_OR_SECRET_MISSING`, `K8S_INSUFFICIENT_CLUSTER_RESOURCES`, `K8S_NODE_NOT_READY_OR_PRESSURE`).
- **Kubernetes Policy (`policies/kubernetes.yaml`)**: Policy for deployment restart actions.

## [0.6.0] - 2026-08-25
### Added
- **PostgreSQL Provider (`postgres`)**: Added probes for `postgres.reachable`, `postgres.accepting_connections` (`pg_isready` and SSLRequest wire handshake), `postgres.pool_exhaustion`, `postgres.is_in_recovery` (read-only replica detection), and `postgres.latency_ms`.
- **MySQL Provider (`mysql`)**: Added probes for `mysql.reachable`, `mysql.ping` (handshake packet decoding), `mysql.max_connections` (Error 1040 detection), `mysql.read_only`, and `mysql.latency_ms`.
- **Redis Provider (`redis`)**: Pure-Python native RESP wire client (zero external dependencies) supporting `redis.reachable`, `redis.ping`, `redis.auth`, `redis.memory_pressure` (`maxmemory` OOM), `redis.role` (replication health), and `redis.latency_ms`.
- **Dependency Provider (`dependency`)**: Added probes for upstream HTTP/HTTPS API status, latency SLA budget enforcement (`latency_ms <= sla_budget_ms`), and circuit breaker / throttling detection (HTTP 503/429/504).
- **Data & Middleware Catalog (`catalogs/data.yaml`)**: 13 situations for database, cache, and upstream API degradation.
- **Data Policy (`policies/data.yaml`)**: Policy gating application restarts on data tier saturation.

## [0.5.0] - 2026-08-23
### Added
- **Network Provider (`network`)**: Added connection checks for `network.port_reachable`, `network.host_reachable`, and `network.dns_resolvable` (supporting local sockets and agentless remote execution).
- **Process Provider (`process`)**: Added process checks for `process.running` (with PID tracking) and `process.zombie` (zombie state detection).
- **Filesystem Provider Enhancement**: Added `filesystem.disk_pressure` for early disk saturation detection.
- **New Situations**: Defined `DISK_PRESSURE`, `NETWORK_UNREACHABLE`, `PROCESS_CRASHED`, and `PROCESS_HEALTHY` signatures in `catalogs/system.yaml` and `catalogs/nginx.yaml`.
- **System Catalog**: Added generic system-level catalog (`catalogs/system.yaml`).

## [0.4.0] - 2026-08-22
### Added
- **Docker Multi-environment Provider (`docker` / `container`)**: Strict read-only container inspection supporting `container.exists`, `container.running`, `container.restarting`, `container.health`, `container.exit_code`, and `container.logs`.
- **Docker Situation Catalog (`catalogs/docker.yaml`)**: Defined signatures for `CONTAINER_HEALTHY`, `CONTAINER_STOPPED`, `CONTAINER_CRASH_LOOP`, `CONTAINER_UNHEALTHY`, and `CONTAINER_NOT_FOUND`.
- **Docker Policy (`policies/docker.yaml`)**: Added default policy for container restart actions.
- **Docker E2E Test Suite (`tests/e2e/run_docker_e2e.sh`)**: Real container testing with crash loop, unhealthy healthcheck, and stopped container scenarios.
- **Contract Formalization**: Documented Docker socket privilege trade-off and read-only guardrails in Section 15 of `PRODUCT_CONTRACT.md`.

## [0.3.0] - 2026-08-22
### Added
- V2 Situational Policy Engine: Evaluates operational states based on correlated evidence forming known situations.
- Detailed JSON schema for diagnosis results (`schemas/diagnosis-result.schema.json`).
- Dynamic provider registry to load custom providers automatically.
- Enhanced Nginx and TLS providers resilient to read-only execution constraints.
- Multi-distribution CI support (Ubuntu 22.04 LTS + Debian 12).
- Agent Harness Integration Guide (`docs/integrations/agent-harness.md`).

### Changed
- Refactored `engine.py` to evaluate explicit blocking situations before concluding ambiguous states.
- Reordered `nginx.yaml` policy list to prioritize specific root causes (e.g. missing certificates) over generic errors.
- Unified decision precedence strictly to `BLOCK > HUMAN_REVIEW > ALLOW`.

## [0.2.0] - 2026-08-14
### Added
- Agentless remote execution over SSH (`--host` flag).
- `test_integrity.py` and structural invariant guarantees.

## [0.1.0] - Initial Release
### Added
- Core Evidence, Policy, and Decision models.
- V1 Legacy policy engine.
- Vertical slice for Nginx diagnostics (Scenarios A, B, C, D).
- CLI implementation.
