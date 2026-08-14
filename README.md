# EvidenceTool (V0.2 + Agentless SSH)

> EvidenceTool does not automate actions first. It makes operational decisions explainable first.

A read-only operational evidence and decision tool for diagnosing production
incidents and determining whether a proposed remediation action is
sufficiently justified by available evidence.

This is the **second vertical slice (V0.2)**, which introduces:
1. **Dynamic Architecture**: Providers are now auto-discovered without coupling the Orchestrator.
2. **Explicit Fail-Closed**: Any provider execution error (e.g. timeout, missing binary) yields a synthetic `UNKNOWN` observation rather than crashing the tool or generating a false `FAIL`.
3. **Agentless SSH**: Run diagnostics against remote production servers via native SSH, without installing anything on the target.

## The flow

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
Policy Evaluation        (YAML policy, per-evidence on_unknown rules)
   │
   ▼
Decision Engine          (BLOCK > HUMAN_REVIEW > ALLOW)
   │
   ▼
Recommendation           (advisory only — cannot influence Decision)
```

Nothing in this codebase modifies the system it inspects.

## Install

```bash
pip install -e ".[dev,test]" --break-system-packages   # or use a virtualenv
```

## Usage

```bash
# Human-readable diagnosis, local execution
evidencetool diagnose nginx

# Agentless SSH: Diagnose a remote server (e.g. from your bastion)
evidencetool diagnose nginx --host prod-web-01

# Machine-readable output (the real contract — see PRODUCT_CONTRACT.md Section 8)
evidencetool diagnose nginx --output json

# Explicit policy file
evidencetool diagnose nginx --policy policies/nginx.yaml

# Point at specific paths and output metrics
evidencetool diagnose nginx \
  --host prod-web-01 \
  -a service=nginx \
  -a config_path=/etc/nginx/nginx.conf \
  -a certificate_path=/etc/letsencrypt/live/example.com/fullchain.pem \
  -a private_key_path=/etc/letsencrypt/live/example.com/privkey.pem \
  --metrics-file ./evidencetool.prom
```

Exit codes are meaningful for scripting/CI: `0` = ALLOW, `1` = BLOCK,
`2` = HUMAN_REVIEW, `3` = INTEGRITY_VIOLATION.

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
Required evidence nginx.config_valid is not satisfied.

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

# If using Let's Encrypt (Certbot), ensure ACLs survive renewals:
# sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy
# sudo tee /etc/letsencrypt/renewal-hooks/deploy/evidencetool-acl.sh > /dev/null << 'EOF'
# #!/bin/bash
# setfacl -m g:evidencetool:r "$RENEWED_LINEAGE/privkey.pem"
# EOF
# sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/evidencetool-acl.sh
```

## Tests

```bash
# Run tests with coverage
pytest tests/ -v --cov=evidencetool --cov-report=term

# E2E Operational Tests (Requires Docker)
# Spins up an ephemeral container with systemd, configures the least privilege
# user, and verifies real diagnostic logic against Nginx.
./tests/e2e/run.sh
```

# Code Quality & Security (DevSecOps)
ruff check src/ tests/
mypy src/
bandit -r src/ -c pyproject.toml
pip-audit
```

48 tests: the 9 contract tests from `PRODUCT_CONTRACT.md`, evaluator and policy-loading unit tests, end-to-end scenarios, V0.2 architectural validation tests (dynamic registry, context propagation), and the Agentless SSH transport tests (error classification, multiplexing). The pipeline includes full DevSecOps checks (SAST with Bandit, SCA with pip-audit, strict typing with Mypy, and linting with Ruff) maintaining 80% test coverage.

## Writing a policy

```yaml
version: "1"
action: restart_nginx
risk: LOW

required_evidence:
  - id: nginx.config_valid
    on_unknown: BLOCK        # default if omitted
  - id: filesystem.disk_space_available
    on_unknown: IGNORE       # optional evidence: UNKNOWN does not block
    max_age: 30               # seconds; stale observations become UNKNOWN

human_approval: false
```

Decision precedence is fixed and non-configurable:
`BLOCK > HUMAN_REVIEW > ALLOW`. A blocking evidence item always wins,
regardless of risk level or `human_approval`.

## Known limitations (V0.2)

No execution, no Docker/Kubernetes yet (planned), no LLM, no dashboard, no
aggregate scoring, no autonomous root-cause analysis. See
`PRODUCT_CONTRACT.md` Section 10 for the full list and rationale.
