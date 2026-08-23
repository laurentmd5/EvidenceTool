# EvidenceTool (V0.5 — Observability & Multi-Environment Decision Layer)

> EvidenceTool does not automate actions first. It makes operational decisions explainable first.

A read-only operational evidence and decision tool for diagnosing production
incidents and determining whether a proposed remediation action is
sufficiently justified by available evidence.

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
| **Network** | `network` | `network.port_reachable`, `network.host_reachable`, `network.dns_resolvable` | TCP port connectivity, ICMP ping, DNS resolution |
| **Process** | `process` | `process.running`, `process.zombie` | Process existence, PID tracking, zombie state detection |

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