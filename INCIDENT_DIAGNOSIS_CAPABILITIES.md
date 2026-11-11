**English** | [Français](INCIDENT_DIAGNOSIS_CAPABILITIES.fr.md)

# Analysis Report — Typology of Production Incidents Diagnosed by EvidenceTool (v1.0.6)

**Date**: September 19, 2026  
**Version**: `v1.0.6` (Branch `dev`)  
**Scope**: 13 Operational Providers (`nginx`, `tls`, `systemd`, `docker`, `filesystem`, `network`, `process`, `postgres`, `mysql`, `redis`, `dependency`, `k8s`, `otel`)  
**Catalogs**: 9 Situation Catalogs (`nginx`, `docker`, `network`, `process`, `data`, `kubernetes`, `distributed`, `system`, `telemetry`) + 3 Causal Catalogs (`distributed`, `kubernetes`, `telemetry`)  
**Policies**: Decision Policies covering 100% of defined situations without exception

---

## 1. Overview & Architectural Positioning

EvidenceTool is a read-only, policy-aware operational reasoning engine and safety gateway (*Read-Only Operational Reasoning Engine & Safety Gateway*). It never takes speculative initiatives: **it collects verifiable evidence without side effects, correlates system states into traceable situations, reconstructs deterministic causal DAGs, detects cycles prior to arbitration, isolates primary root causes, and decides whether a proposed remediation action is safe (`ALLOW`), prohibited (`BLOCK`), or requires human intervention (`HUMAN_REVIEW`)**.

```
┌────────────────────────────────────────────────────────┐
│             MULTI-LAYER DISTRIBUTED INCIDENT           │
└───────────────────────────┬────────────────────────────┘
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
[ APPLICATION LAYER ]  [ DATA LAYER ]       [ NETWORK/TRANSPORT LAYER ]
• HTTP 500 Errors      • Postgres unreachable • TCP/5432 Refused/Timeout
• Latency SLA Violated • Pool Exhausted       • DNS / Host ping PASS
• Process/Container OK • Redis PONG (Healthy) • Route OK
• K8s Pod / Node State • MySQL Max Connections• TLS Handshake
• OTel / APM Spans     • Redis MaxMemory OOM  • OTel Connect PASS
       │                    │                    │
       └────────────────────┼────────────────────┘
                            │
                            ▼
              [ COLLECTED OBSERVABLE FACTS ]
            (13 Providers, Zero Mutation Guarantee)
                            │
                            ▼
          [ V1.0.6 LOCAL SITUATION EVALUATION ]
         (Local uncertainty: SituationEvaluation)
                            │
                            ▼
           [ DETERMINISTIC CAUSAL ENGINE ]
       (DAG Graph, Precluded Hypotheses, Cycle Detection, Tri-State)
                            │
                            ▼
              [ DECISION & EXPLAINABILITY ]
               BLOCK > HUMAN_REVIEW > ALLOW
```

---

## 2. Typology of Diagnosed Incidents by Domain

### A. Web & Reverse Proxy Incidents (`nginx`, `systemd`)

| Production Incident | Observed Symptom | Technical Detection & Evidence | Decision & Safety Rule |
| :--- | :--- | :--- | :---: |
| **Configuration Syntax Error** | Nginx fails to start after modifying `nginx.conf`. | Probe `nginx.config_valid` via `nginx -t -c <path>`. Filters log permission false positives. | 🛑 **BLOCK** (`NGINX_CONFIG_INVALID`) |
| **Inactive Service Without Failure** | Nginx service stopped while entire system is nominal. | `systemd.service_active: FAIL` + `nginx.config_valid: PASS` + `tls.*: PASS`. | 🟢 **ALLOW** (`NGINX_SERVICE_DOWN`)<br>Restart permitted (`restart_nginx`). |
| **Service Missing / Not Installed** | Request to restart non-existent service unit. | `systemd.service_exists: FAIL` via `systemctl show -p LoadState`. | 🛑 **BLOCK** (`NGINX_SERVICE_NOT_INSTALLED`) |

---

### B. Cryptographic & TLS Certificate Incidents (`tls`)

| Production Incident | Observed Symptom | Technical Detection & Evidence | Decision & Safety Rule |
| :--- | :--- | :--- | :---: |
| **Expired Certificate** | SSL client errors (`SEC_ERROR_EXPIRED_CERTIFICATE`). | Probe `tls.certificate_valid` extracts validity dates via ASN.1 / OpenSSL. | 🛑 **BLOCK** (`TLS_CERTIFICATE_EXPIRED`) |
| **Key / Certificate Mismatch** | Nginx fails: `key values mismatch`. | Probe `tls.key_matches_certificate` extracts universal public keys (RSA, ECDSA, Ed25519). | 🛑 **BLOCK** (`TLS_KEY_MISMATCH`) |
| **Missing Certificate or Private Key File** | Incomplete deployment or incorrect path. | Probes `tls.certificate_exists` and `tls.private_key_exists`. | 🛑 **BLOCK** (`TLS_CERTIFICATE_MISSING`) |

---

### C. Container & Docker Orchestration Incidents (`docker`)

| Production Incident | Observed Symptom | Technical Detection & Evidence | Decision & Safety Rule |
| :--- | :--- | :--- | :---: |
| **Container CrashLoopBackOff** | Container restarts in an infinite loop. | Probe `container.restarting: FAIL` (`State.Restarting == true`) with masked logs. | 🟢 **ALLOW** (`CONTAINER_CRASH_LOOP`) |
| **Application Healthcheck Failure** | Application frozen or in an internal deadlock. | Probe `container.health: FAIL` (`State.Health.Status == 'unhealthy'`). | 🟢 **ALLOW** (`CONTAINER_UNHEALTHY`) |
| **Unexpected Stop / Exit** | Container stopped (`Exited`). | Probe `container.exists: PASS` and `container.running: FAIL`. | 🟢 **ALLOW** (`CONTAINER_STOPPED`) |
| **Non-Existent Container** | Request targeting a removed or missing container. | Probe `container.exists: FAIL`. | 🛑 **BLOCK** (`CONTAINER_NOT_FOUND`) |

---

### D. Kubernetes Orchestration Incidents (`k8s`)

| Production Incident | Observed Symptom | Technical Detection & Evidence | Decision & Safety Rule |
| :--- | :--- | :--- | :---: |
| **Pod CrashLoopBackOff** | Kubernetes pod restarting in a loop. | Probe `k8s.container_crashloop: FAIL` (`waiting.reason == 'CrashLoopBackOff'`). | 🛑 **BLOCK** (`K8S_CRASH_LOOP_BACKOFF`) |
| **Pod Killed by OOM Killer (Code 137)** | Container terminated due to memory limit breach. | Probe `k8s.container_oom_killed: FAIL` (`exitCode == 137` / `reason == 'OOMKilled'`). | 🛑 **BLOCK** (`K8S_OOM_KILLED`)<br>Requires adjusting `limits.memory`. |
| **Image Pull Failure (Registry)** | Pod stuck in `ImagePullBackOff` or `ErrImagePull`. | Probe `k8s.image_pull_status: FAIL`. | 🛑 **BLOCK** (`K8S_IMAGE_PULL_FAILURE`) |
| **Missing ConfigMap or Secret** | Error `CreateContainerConfigError`. | Probe `k8s.config_secret_status: FAIL`. | 🛑 **BLOCK** (`K8S_CONFIG_OR_SECRET_MISSING`) |
| **Insufficient Cluster Resources** | Pod stuck in `Pending` / `Unschedulable`. | Probe `k8s.pod_scheduled: FAIL` (e.g. `0/8 nodes available: Insufficient cpu`). | 🛑 **BLOCK** (`K8S_INSUFFICIENT_CLUSTER_RESOURCES`) |
| **Node Failure or Under Pressure** | Kubernetes node in `NotReady` or `MemoryPressure`. | Probe `k8s.node_ready: FAIL`. | 🛑 **BLOCK** (`K8S_NODE_NOT_READY_OR_PRESSURE`) |

---

### E. Linux Kernel, Process & Filesystem Incidents (`process`, `filesystem`)

| Production Incident | Observed Symptom | Technical Detection & Evidence | Decision & Safety Rule |
| :--- | :--- | :--- | :---: |
| **Kernel I/O Wait Deadlock (State D)** | Process frozen in uninterruptible disk I/O sleep. | Probe `process.state: FAIL` detects kernel state `D`. | 🛑 **BLOCK** (`PROCESS_IO_WAIT`) |
| **Zombie Process** | Defunct orphan process in `/proc`. | Probe `process.zombie: FAIL` (state `Z`). | ⚠️ (`PROCESS_ZOMBIE`) |
| **CPU Saturation / Memory Pressure** | Process consumes > 90% CPU or RAM. | Probes `process.cpu_usage` and `process.memory_usage` with configurable thresholds. | 🛑 **BLOCK** (`PROCESS_CPU_SATURATION`, `PROCESS_MEMORY_PRESSURE`) |
| **File Descriptor (FD) Exhaustion** | Error `Too many open files`. | Probe `process.open_files` compares `/proc/<pid>/fd` against `/proc/<pid>/limits`. | 🛑 **BLOCK** (`PROCESS_FD_EXHAUSTION`) |
| **Storage Saturation / Full Disk** | Inability to write logs or persistent data. | Probes `filesystem.disk_space_available` and `filesystem.disk_pressure`. | 🛑 **BLOCK** (`DISK_FULL`, `DISK_PRESSURE`) |

---

### F. Data, Middleware & Cache Incidents (`postgres`, `mysql`, `redis`)

| Production Incident | Observed Symptom | Technical Detection & Evidence | Decision & Safety Rule |
| :--- | :--- | :--- | :---: |
| **PostgreSQL Pool Saturation** | `FATAL: remaining connection slots are reserved` / `too many clients`. | Probe `postgres.pool_exhaustion: FAIL` via `pg_isready` or SSLRequest probe. | 🛑 **BLOCK** (`POSTGRES_POOL_EXHAUSTED`) |
| **Split-Brain / Read-Only Replica** | Application write errors on database. | Probe `postgres.is_in_recovery: FAIL` (standby node when primary expected). | 🛑 **BLOCK** (`POSTGRES_READ_ONLY_REPLICA`) |
| **MySQL Connection Saturation** | Error `1040 (HY000): Too many connections`. | Probe `mysql.max_connections: FAIL` via handshake packet decoding. | 🛑 **BLOCK** (`MYSQL_TOO_MANY_CONNECTIONS`) |
| **Redis Memory Saturation (OOM)** | Writes rejected (`OOM command not allowed`). | Probe `redis.memory_pressure: FAIL` via RESP analysis of `INFO memory`. | 🛑 **BLOCK** (`REDIS_OOM_MAXMEMORY`) |
| **Broken Redis Replication Link** | Replica disconnected from master. | Probe `redis.role: FAIL` (`master_link_status: down`). | 🛑 **BLOCK** (`REDIS_REPLICATION_BROKEN`) |
| **Redis Authentication Failure** | Error `NOAUTH` or `WRONGPASS`. | Probe `redis.auth: FAIL`. | 🛑 **BLOCK** (`REDIS_AUTH_FAILURE`) |

---

### G. Microservice Dependencies, Telemetry & SLA Latency Incidents (`dependency`, `otel`)

| Production Incident | Observed Symptom | Technical Detection & Evidence | Decision & Safety Rule |
| :--- | :--- | :--- | :---: |
| **Latency Degradation / SLA Breach** | Response time exceeds SLA budget (e.g. > 250ms). | Probe `dependency.sla_budget: FAIL` (`latency_ms > sla_budget_ms`). | 🛑 **BLOCK** (`UPSTREAM_LATENCY_DEGRADATION`) |
| **Circuit Breaker / Throttling** | Upstream API returns HTTP 503, 429, or 504. | Probe `dependency.circuit_breaker: FAIL`. | 🛑 **BLOCK** (`UPSTREAM_DEPENDENCY_DOWN`) |
| **High HTTP Error Rate (Mode A)** | Upstream 5xx error rate exceeds configured threshold. | Probe `otel.http_error_rate_high: FAIL` via Prometheus query. | 🛑 **BLOCK** (`HIGH_ERROR_RATE`) |
| **P99 Latency Spike via APM** | Latency p99 exceeds contractual budget. | Probe `otel.p99_latency_high: FAIL` via Prometheus query. | 🛑 **BLOCK** (`HIGH_LATENCY_P99`) |
| **Error Spans in Distributed Traces** | Active distributed traces returning error spans. | Probe `otel.active_traces_failing: FAIL` via Tempo/Jaeger API. | 🛑 **BLOCK** (`ACTIVE_TRACES_ERRORING`) |

---

### H. Multi-Signal Distributed Incidents & Hybrid Causal Reasoning (`distributed`, `telemetry`)

| Production Incident | Correlated Multi-Domain Signatures | Isolated Root Cause | Business Decision |
| :--- | :--- | :--- | :---: |
| **`DATABASE_CONNECTIVITY_FAILURE`** | API 500 (`dependency.http_status: FAIL`) + DB unreachable (`postgres.reachable: FAIL`) + TCP 5432 FAIL + Redis PASS. | Closed DB port or blocking SG (not a global network partition). | 🛑 **BLOCK restart_app** |
| **`DATABASE_POOL_EXHAUSTION_CASCADE`** | API latency spike + DB reachable + Pool exhausted (`postgres.pool_exhaustion: FAIL`) + Redis PASS. | Database connection exhaustion. | 🛑 **BLOCK restart_app** |
| **`CACHE_FAILURE_DATABASE_OVERLOAD`** | Redis OOM / FAIL + DB latency degraded. | Cache stampede overloading PostgreSQL. | 🛑 **BLOCK restart_app** |
| **`UPSTREAM_MICROSERVICE_OUTAGE`** | API 503 / Circuit breaker FAIL + Local DB PASS + Redis PASS. | Critical external dependency outage. | 🛑 **BLOCK restart_app** |
| **`TOTAL_NETWORK_PARTITION`** | Port 5432 FAIL + Postgres FAIL + Redis FAIL. | Global network partition / lost gateway. | 🛑 **BLOCK restart_app** |
