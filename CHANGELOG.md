# Changelog

All notable changes to this project will be documented in this file.

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
