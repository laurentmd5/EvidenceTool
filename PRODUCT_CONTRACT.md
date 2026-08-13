# EvidenceTool — PRODUCT_CONTRACT.md

**Version:** 2.0 (V0.2 contract)
**Status:** Locked for V0.2 vertical slice implementation
**Scope:** This document defines the minimal functional contract that the V0.2 codebase must respect.

---

## 0. Founding principle

> EvidenceTool does not automate actions first. It makes operational decisions explainable first.

EvidenceTool separates **observation**, **recommendation**, **authorization**, and **execution**. V0.1 covers only the first two — it never modifies the system it inspects.

---

## 1. Scope V0.2

**Definition:**

> A read-only operational evidence and decision tool for diagnosing production incidents and determining whether a proposed remediation action is sufficiently justified by available evidence.

**Vertical slice — the only thing V0.2 must prove end-to-end:**

```
Nginx incident
      ↓
collect evidence
      ↓
evaluate evidence
      ↓
evaluate policy
      ↓
produce decision
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

This threshold is a V0.1 default, not yet configurable per source. It may become per-provider configurable in a later version — this is noted as a known limitation (Section 10), not solved now.

---

## 3. Evidence States

Three states only:

- **PASS** — the condition was checked and is satisfied.
- **FAIL** — the condition was checked and is not satisfied.
- **UNKNOWN** — the evidence could not be obtained, checked, or determined.

**Explicit rule:**

> `UNKNOWN ≠ FAIL`. UNKNOWN is a distinct state. Whether it blocks a decision depends on the policy's per-evidence `on_unknown` directive (Section 4), not on a universal conversion rule.

There is no implicit global mapping from `UNKNOWN` to `FAIL`. Every required evidence item must declare its own `on_unknown` behavior in the policy. If a policy omits it, the engine applies the default in Section 4.1 (fail-closed).

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

This preserves fail-closed behavior (NFR-001) as the baseline. A policy author must actively opt an evidence item into `IGNORE` — silence never grants leniency.

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

Concretely: if any required evidence resolves to a blocking state (Section 4), the decision is `BLOCK` — **regardless of risk level or `human_approval` setting**. A blocked action is never eligible for human review; there is nothing to review until the evidence itself is fixed. `HUMAN_REVIEW` only applies when all required evidence requirements are satisfied but the policy's risk/approval settings still demand a human decision.

### 5.2 Worked examples

**Case 1 — ALLOW**
```
config.valid       PASS
certificate.exists PASS
private_key.exists PASS
risk               LOW
human_approval      false
→ ALLOW
```

**Case 2 — BLOCK (evidence failure)**
```
config.valid       FAIL
certificate.exists PASS
private_key.exists PASS
→ BLOCK
```

**Case 3 — HUMAN_REVIEW**
```
config.valid       PASS
certificate.exists PASS
private_key.exists PASS
risk               CRITICAL
human_approval      true
→ HUMAN_REVIEW
```

**Case 4 — BLOCK takes precedence over HUMAN_REVIEW**
```
config.valid       FAIL
risk               CRITICAL
human_approval      true
→ BLOCK   (not HUMAN_REVIEW — precedence rule applies)
```

**Case 5 — UNKNOWN with on_unknown: BLOCK**
```
certificate.exists UNKNOWN   (on_unknown: BLOCK)
config.valid        PASS
private_key.exists  PASS
→ BLOCK
```

**Case 6 — UNKNOWN with on_unknown: IGNORE**
```
disk_io             UNKNOWN   (on_unknown: IGNORE, not in required_evidence's blocking set)
config.valid        PASS
certificate.exists  PASS
private_key.exists  PASS
→ ALLOW   (disk_io noted as unverifiable, does not block)
```

---

## 6. Risk Model

Four levels, V0.1:

```
LOW
MEDIUM
HIGH
CRITICAL
```

**Rule:** risk is declared by the policy author, never inferred or estimated by an AI component.

```yaml
action: restart_nginx
risk: LOW
```

This is a governance decision, not a computed one. No component in V0.1 (or any future version) may output a phrase like "I estimate this action to be low risk" as the source of truth for the `risk` field.

---

## 7. Policy Contract

V0.1 policies are YAML. This is a prototyping choice, not a commitment to a final policy engine (YAML vs. OPA/Rego is deferred — see Section 10).

```yaml
version: "1"

action: restart_nginx

risk: LOW

required_evidence:
  - id: nginx.config.valid
    on_unknown: BLOCK
  - id: tls.certificate.exists
    on_unknown: BLOCK
  - id: tls.private_key.exists
    on_unknown: BLOCK

human_approval: false
```

**Field reference:**

| Field | Required | Notes |
|---|---|---|
| `version` | yes | Policy schema version, string |
| `action` | yes | Identifier of the proposed action, never executed in V0.1 |
| `risk` | yes | One of the four levels in Section 6 |
| `required_evidence` | yes | List of `{id, on_unknown}` objects (Section 4) |
| `human_approval` | yes | Boolean; if `true`, forces `HUMAN_REVIEW` when no blocking evidence exists |

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
        "method": "nginx -t -c /etc/nginx/nginx.conf",
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
    },
    {
      "id": "tls.certificate_exists",
      "status": "PASS",
      "message": "Certificate found at /etc/letsencrypt/live/example.com/fullchain.pem",
      "observation": {
        "id": "tls.certificate_exists",
        "source": "tls",
        "category": "certificate",
        "collector": "tls_provider",
        "method": "file_exists(/etc/letsencrypt/live/example.com/fullchain.pem)",
        "value": {
          "status": "PASS",
          "path": "/etc/letsencrypt/live/example.com/fullchain.pem"
        },
        "message": "Certificate found at /etc/letsencrypt/live/example.com/fullchain.pem",
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
    "reason": "Required evidence failed",
    "blocking_evidence": [
      "nginx.config.valid"
    ]
  },

  "recommendation": {
    "action": "Validate nginx configuration before restart"
  }
}
```

`decision.status` is always one of `ALLOW` / `BLOCK` / `HUMAN_REVIEW` (Section 5). `decision.blocking_evidence` lists the evidence IDs that caused a `BLOCK`, resolved per the rules in Section 4 and the precedence in Section 5.1. `decision.reason` is a short, deterministic, human-readable string — no free-form LLM generation in V0.1 (per NFR-004 and Section 6).

Example CLI rendering of the same JSON:

```
✓ tls.certificate.exists
✗ nginx.config.valid

Policy:
restart_nginx

Decision:
BLOCK

Reason:
Required evidence failed.

Blocking evidence:
- nginx.config.valid
```

---

## 9. CLI Contract

V0.2 stays intentionally small — four invocation shapes:

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

No other subcommands are in scope for V0.2.

---

## 10. Known limitations

V0.2 explicitly does **not**:

- modify the system in any way;
- automatically restart or remediate anything;
- perform auto-remediation of any kind;
- support Docker or Kubernetes (planned for later versions, same evidence/decision engine);
- use an LLM anywhere in the evidence, risk, or decision path;
- expose a dashboard or web UI;
- compute a single aggregate 0–100 evidence score (deliberately rejected — see evidence model discussion);
- perform probabilistic or autonomous root-cause analysis;
- decide between a custom YAML policy engine and OPA/Rego — this choice is deferred; the policy engine is treated as swappable (`policy/local/` vs. `policy/opa/`) so the decision doesn't block V0.1;
- make freshness thresholds configurable per source (fixed at 60s for all sources in V0.1).

**Explicitly acknowledged gap:**

> `Relevance` and `Consistency` (from the five evidence dimensions: Presence, Freshness, Validity, Relevance, Consistency) are not meaningfully exercised by a single-provider (Nginx-only) vertical slice. They require correlation across multiple evidence sources (e.g. Nginx + systemd + filesystem is a start; Docker + Prometheus + Loki, or Kubernetes + Prometheus + Loki, will exercise them properly). V0.1 evidence items may carry these fields, but their evaluation logic is not considered validated until a multi-provider scenario is built and tested.

---

## 11. Definition of done for the vertical slice

The V0.1 vertical slice is considered complete when this exact flow runs end-to-end against a real (or reproducibly simulated) broken Nginx service:

```
Nginx broken
     ↓
Providers (systemd, nginx, tls, filesystem)
     ↓
Evidence (conforming to Section 2)
     ↓
Policy evaluation (conforming to Sections 4, 5, 7)
     ↓
Decision (BLOCK, per the worked examples in Section 5.2)
     ↓
JSON output (conforming to Section 8)
     ↓
CLI rendering (conforming to Section 8)
```

At minimum, the following scenarios (from validation Phase 2) must each produce the correct decision per this contract before the contract is considered proven:

1. Missing certificate
2. Expired certificate
3. Certificate/key mismatch
4. Invalid nginx configuration
5. Disk full
6. Permission problem
7. Port conflict

Any scenario that produces a decision inconsistent with this contract means either the contract or the implementation is wrong — and the contract should be revised deliberately, not silently overridden in code.

---

## 12. SLI/SLO Contract

EvidenceTool defines clear Service Level Indicators (SLIs) and Objectives (SLOs) to ensure it is observable and trustworthy.
A critical distinction in EvidenceTool is:
> **RUN SUCCESS ≠ OPERATIONAL SUCCESS**

A run that correctly diagnoses a broken system and returns `BLOCK` is a **successful run** of EvidenceTool, even though the underlying system being observed is failing.

### 12.1 SLI Families

**1. Reliability SLI**
- `evidencetool_last_run_success`: `1` if the run completed successfully and passed integrity validation, `0` otherwise.
- `evidencetool_integrity_violation`: Count of decision integrity violations.

**2. Performance SLI**
- `evidencetool_last_run_duration_seconds`: Total execution time.
- `evidencetool_provider_duration_seconds{provider="..."}`: Time spent in each provider.
- `evidencetool_evaluation_duration_seconds`: Time spent evaluating evidence.
- `evidencetool_policy_duration_seconds`: Time spent in the policy engine.
- `evidencetool_decision_duration_seconds`: Time spent in the decision engine.

**3. Decision / Operational SLI**
- `evidencetool_decision{status="ALLOW"|"BLOCK"|"HUMAN_REVIEW"}`: Counter for decisions.
- `evidencetool_evidence{status="PASS"|"FAIL"|"UNKNOWN"}`: Counter for individual evidence evaluations.

*Note: High cardinality labels (e.g., incident_id, hostname) are explicitly omitted to prevent metric explosion.*

### 12.2 SLO

**SLO — Diagnostic execution reliability**
> ≥ 99.5% of scheduled EvidenceTool runs complete successfully over a rolling 30-day window.
