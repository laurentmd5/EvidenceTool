# EvidenceTool (V0.6 — Dependency-Aware Operational Evidence Engine)

> EvidenceTool does not automate actions first. It makes operational decisions explainable first.

**EvidenceTool** is a read-only, policy-aware operational evidence engine that correlates infrastructure, application, data, and dependency signals to identify probable root causes before allowing remediation.

---

## ⚠️ What EvidenceTool is NOT

> [!IMPORTANT]
> **EvidenceTool decides, it never executes.**
> A `HUMAN_REVIEW` silently treated as `ALLOW` by the calling system defeats the entire safety model.
> Do not use EvidenceTool to directly run destructive commands. It is an observer, classifier, and decision gate only.
> Autonomous agents calling EvidenceTool MUST validate decision integrity independently (see [Agent Harness Integration Guide](docs/integrations/agent-harness.md)).

---

## Supported Platforms & Environments

EvidenceTool is tested and verified on the following environments:
- **Ubuntu 22.04 LTS** (systemd + Nginx)
- **Debian 12** (systemd + Nginx)
- **Docker Environments** (container inspection, crash loops, health status)
- **Database & Middleware** (PostgreSQL 14-17, MySQL 8 / MariaDB, Redis 6-7 RESP)
- Any POSIX systemd-based Linux distribution with standard coreutils

---

## Built-in Diagnostic Providers

| Provider | Namespace | Checks / Observations | Scope |
| :--- | :--- | :--- | :--- |
| **Nginx** | `nginx` | `nginx.config_valid` | Configuration syntax, module resolution, read-only log error filtering |
| **TLS** | `tls` | `tls.certificate_exists`, `tls.certificate_valid`, `tls.private_key_exists`, `tls.key_matches_certificate` | Certificate expiration, existence, RSA/EC key modulus match |
| **Systemd** | `systemd` | `systemd.service_exists`, `systemd.service_active` | Service unit load state, daemon status |
| **Docker** | `docker` / `container` | `container.exists`, `container.running`, `container.restarting`, `container.health`, `container.exit_code`, `container.logs` | Strict read-only container inspection, health checks, OOM / crash loops |
| **Filesystem** | `filesystem` | `filesystem.disk_space_available`, `filesystem.disk_pressure` | Free disk space thresholds, storage saturation warnings |
| **Network** | `network` | `network.dns_resolvable`, `network.route_exists`, `network.host_reachable`, `network.port_reachable`, `network.tls_handshake`, `network.http_reachable` | Deterministic network evidence chain, TCP refused vs timeout |
| **Process** | `process` | `process.exists`, `process.running`, `process.state`, `process.zombie`, `process.cpu_usage`, `process.memory_usage`, `process.open_files`, `process.thread_count` | Deep Linux kernel state inspection (R/S/D/Z states, CPU, RAM, FD limits) |
| **PostgreSQL** | `postgres` | `postgres.reachable`, `postgres.accepting_connections`, `postgres.pool_exhaustion`, `postgres.is_in_recovery`, `postgres.latency_ms` | Availability, connection pool saturation, replica / read-only detection |
| **MySQL** | `mysql` | `mysql.reachable`, `mysql.ping`, `mysql.max_connections`, `mysql.read_only`, `mysql.latency_ms` | Initial handshake packet parsing, Error 1040 max connections, read-only status |
| **Redis** | `redis` | `redis.reachable`, `redis.ping`, `redis.auth`, `redis.memory_pressure`, `redis.role`, `redis.latency_ms` | Native RESP wire protocol, PING/PONG, memory saturation (OOM), replication link |
| **Dependency** | `dependency` | `dependency.http_status`, `dependency.latency_ms`, `dependency.sla_budget`, `dependency.circuit_breaker` | Upstream API SLA latency budget, HTTP 503/429/504 circuit breaking |

---

## The Flow

```
Incident
   │
   ▼
Dynamic Provider Registry (Auto-discovered plugins)
   │
   ▼
Observation Collection   (Local OR Remote via Agentless SSH)
   │
   ▼
Evidence Evaluation      (PASS / FAIL / UNKNOWN, freshness applied, errors caught)
   │
   ▼
State Correlation        (Maps evidence signatures to Situations & OperationalState)
   │
   ▼
Policy Evaluation        (V2 Situational: allowed situations & explicitly blocked_by)
   │
   ▼
Decision Engine          (BLOCK > HUMAN_REVIEW > ALLOW, fail-closed on ambiguity)
   │
   ▼
Integrity Validation     (validate_decision_integrity — invariant verification)
   │
   ▼
Recommendation           (advisory only — cannot influence Decision)
```

Nothing in this codebase modifies the system it inspects.

## Install

```bash
pip install -e ".[dev,test]"   # or use a virtualenv
```

## Usage Examples

```bash
# 1. Nginx Diagnosis (Human-readable output)
evidencetool diagnose nginx

# 2. Machine-readable JSON output (the real contract — see PRODUCT_CONTRACT.md Section 8)
evidencetool diagnose nginx --output json

# 3. Docker Container Diagnosis
evidencetool diagnose docker \
  --policy policies/docker.yaml \
  --catalog catalogs/docker.yaml \
  -a container=production_web_app

# 4. Agentless Remote SSH Diagnosis
evidencetool diagnose nginx --host prod-web-01

# 5. Explicit policy & situation catalog with Prometheus metrics
evidencetool diagnose nginx \
  --policy policies/nginx.yaml \
  --catalog catalogs/nginx.yaml \
  -a service=nginx \
  -a config_path=/etc/nginx/nginx.conf \
  -a certificate_path=/etc/letsencrypt/live/example.com/fullchain.pem \
  -a private_key_path=/etc/letsencrypt/live/example.com/privkey.pem \
  --metrics-file ./evidencetool.prom
```

Exit codes are meaningful for scripting/CI:
- `0` = ALLOW
- `1` = BLOCK
- `2` = HUMAN_REVIEW
- `3` = INTEGRITY_VIOLATION

## Example output

```
? systemd.service_active
✗ nginx.config_valid
✓ tls.certificate_exists
✓ tls.certificate_valid
✓ tls.private_key_exists
✓ tls.key_matches_certificate
? filesystem.disk_space_available

Policy:
restart_nginx

Decision:
BLOCK

Reason:
Situation 'NGINX_CONFIG_INVALID' is explicitly blocked by policy.

Blocking evidence:
- nginx.config_valid

Recommendation:
Run `nginx -t` locally to see the exact syntax error, then fix nginx.conf
before retrying.
```

## Least Privilege Setup (Production)

EvidenceTool is designed to run without `sudo` access, adhering strictly to the principle of least privilege.
However, it requires read access to sensitive files like TLS private keys (`tls.key_matches_certificate` provider).
Instead of granting `sudo`, create a dedicated system account and use Access Control Lists (ACLs):

```bash
# 1. Create a dedicated system user and group (no shell, no sudo)
sudo groupadd --system evidencetool
sudo useradd --system --gid evidencetool --shell /usr/sbin/nologin --no-create-home evidencetool

# 2. Grant read access specifically to the TLS keys via ACL
sudo apt install -y acl
sudo setfacl -m g:evidencetool:r /etc/nginx/ssl/nginx.key
sudo setfacl -m g:evidencetool:r /etc/nginx/ssl/nginx.crt

# 3. For Docker inspection, add evidencetool to docker group (see PRODUCT_CONTRACT.md Section 15 for trade-offs):
sudo usermod -aG docker evidencetool
```

## Tests & CI Verification

```bash
# Run unit tests with full coverage
pytest tests/ -v --cov=evidencetool --cov-report=term

# E2E Operational Tests (Nginx Systemd on Ubuntu + Debian, and Docker scenarios)
./tests/e2e/run.sh

# Code Quality & DevSecOps Suite
ruff check src/ tests/
mypy src/
bandit -r src/ -c pyproject.toml
pip-audit
```

## Writing a Policy

## Execution Capability Policy

Diagnostic policy and execution capabilities are separate contracts. A diagnostic policy explains how evidence
affects a decision; a capability policy controls what the caller may collect. The local CLI remains permissive by
default, while automated callers can provide an explicit capability policy:

```yaml
capabilities:
  network:
    enabled: true
    operations: [tcp_connect, dns_lookup]
    targets: [10.0.10.0/24, redis.internal.example]
    ports: [6379, 443]
    max_probes: 10
    timeout_seconds: 2
  providers:
    allowed: [network, systemd]
```

```bash
evidencetool diagnose network --capability-policy capabilities/agent.yaml \
  --target-host redis.internal.example --port 6379
```

Private and loopback targets are not blocked globally. They are available to callers whose capability policy
explicitly authorizes them. A denied capability is reported as a security/integrity violation and exits with code 3.

Provider trust is separate from provider discovery. Built-in providers are trusted by default; dynamically discovered
providers are experimental unless explicitly approved. Automated callers can require trusted providers:

```yaml
capabilities:
  providers:
    require_trusted: true
    allowed: [nginx, systemd, tls]
```

External providers can be activated through an external manifest. The source hash is verified before the module is
imported:

```yaml
plugins:
  - namespace: redis
    module: evidencetool_redis.provider
    sha256: "<64 hexadecimal characters>"
```

The legacy dynamic discovery path remains available for local extension workflows. Automated callers should use a
manifest and `providers.require_trusted: true`.

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

Decision precedence is fixed and non-configurable:
`BLOCK > HUMAN_REVIEW > ALLOW`. A blocking evidence item or blocked situation always wins,
regardless of risk level or `human_approval`.

## Known Limitations

No execution / auto-remediation (by design), no Kubernetes yet, no LLM in the decision path, no web dashboard, no aggregate 0-100 scoring. See `PRODUCT_CONTRACT.md` Section 10 for the full list and rationale.