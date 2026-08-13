# EvidenceTool (V0.1 — vertical slice)

> EvidenceTool does not automate actions first. It makes operational decisions explainable first.

A read-only operational evidence and decision tool for diagnosing production
incidents and determining whether a proposed remediation action is
sufficiently justified by available evidence.

This is the **first vertical slice**: a single flow, end to end, scoped to
one incident — an Nginx service that fails to start — and one proposed
action — `restart_nginx`. No other environment (Docker, Kubernetes), no
LLM, no execution. See `PRODUCT_CONTRACT.md` for the full functional
contract this code implements.

## The flow

```
Incident
   │
   ▼
Observation Collection   (systemd, nginx, tls, filesystem providers)
   │
   ▼
Evidence Evaluation      (PASS / FAIL / UNKNOWN, freshness applied)
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
pip install -e . --break-system-packages   # or use a virtualenv
```

## Usage

```bash
# Human-readable diagnosis, using the bundled default policy
evidencetool diagnose nginx

# Machine-readable output (the real contract — see PRODUCT_CONTRACT.md Section 8)
evidencetool diagnose nginx --output json

# Explicit policy file
evidencetool diagnose nginx --policy policies/nginx.yaml

# Point at specific paths and output metrics
evidencetool diagnose nginx \
  --service nginx \
  --config-path /etc/nginx/nginx.conf \
  --certificate-path /etc/letsencrypt/live/example.com/fullchain.pem \
  --private-key-path /etc/letsencrypt/live/example.com/privkey.pem \
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

## Tests

```bash
python -m pytest tests/ -v
```

31 tests: the 9 contract tests from `PRODUCT_CONTRACT.md` (decision
precedence, on_unknown handling, staleness, recommendation/decision
separation), evaluator and policy-loading unit tests, and end-to-end
scenarios run against real generated certificates (missing cert, expired
cert, missing key, valid cert, disk full, port conflict, permission denied, mismatched keys).

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

## Known limitations (V0.1)

No execution, no SSH, no Docker/Kubernetes, no LLM, no dashboard, no
aggregate scoring, no autonomous root-cause analysis. See
`PRODUCT_CONTRACT.md` Section 10 for the full list and rationale.
