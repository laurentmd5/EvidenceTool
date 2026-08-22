# EvidenceTool — PRODUCT_CONTRACT.md

**Version:** 3.0 (V0.3 Situational Contract)
**Status:** Locked and frozen for V0.3 release
**Scope:** This document defines the minimal functional and architectural contract that the EvidenceTool codebase must respect.

---

## 0. Founding principle

> EvidenceTool does not automate actions first. It makes operational decisions explainable first.

EvidenceTool separates **observation**, **recommendation**, **authorization**, and **execution**. It never modifies the system it inspects.

---

## 1. Scope V0.2 & V0.3

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

Freshness is derived from `observed_at` relative to evaluation time, using a default threshold:

- `FRESH`: observed less than **60 seconds** before evaluation.
- `STALE`: observed 60 seconds or more before evaluation.

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
- support Docker or Kubernetes (planned for V0.4 / V0.5);
- use an LLM anywhere in the evidence, risk, or decision path;
- expose a dashboard or web UI;
- compute a single aggregate 0–100 evidence score;
- perform probabilistic or autonomous root-cause analysis.

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