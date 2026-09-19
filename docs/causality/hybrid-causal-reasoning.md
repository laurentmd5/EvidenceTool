**English** | [Français](hybrid-causal-reasoning.fr.md)

# Mode C: Hybrid Causal Reasoning & Hardening Guide

EvidenceTool includes **Mode C (Hybrid Causal Reasoning)** to bridge high-level surface telemetry with deep native physical system evidence using deterministic, declarative directed graphs (DAGs).

```
             MODE A : External Telemetry (Prometheus / Tempo)
                                   │
                                   ▼
                            Surface Symptoms
                       (e.g., HTTP_ERROR_RATE_HIGH)
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   MODE C : HYBRID CAUSAL ENGINE                        │
│                                                                        │
│   Declarative Causal Relations:                                        │
│     - PROPAGATES_TO :  A ──> B (Causal propagation)                    │
│     - PRECLUDES     :  A ──/──> B (Mutual exclusion / refutation)      │
│     - REQUIRES      :  A <──req── B (Prerequisite condition)           │
│                                                                        │
│   Cycle Detection & Validation (Precedes Arbitration)                  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   ▲
                                   │
             Native Physical Probes (Sockets, DB, Linux Kernel)
                     (e.g., POSTGRES_POOL_EXHAUSTED)
                                   │
                                   ▼
                   Primary Root Cause & Action Gate
                     (BLOCK > HUMAN_REVIEW > ALLOW)
```

---

## 1. Architectural Philosophy & The Three Pillars

EvidenceTool enforces strict segregation between three architectural pillars:
1. **Evidence (Observation)**: What is observed? (Pure facts collected with zero mutations).
2. **Causality (Explanation)**: What can explain what? (Deterministic graph navigation based on explicit declarative catalog rules).
3. **Authority (Governance)**: What is the system allowed to do? (Policies determining `ALLOW`, `BLOCK`, or `HUMAN_REVIEW`).

> [!IMPORTANT]
> **Core Invariant**: *"More observations. More evidence. Never more authority."*  
> Telemetry reveals the surface symptom; physical evidence confirms or refutes candidate root causes.  
> **No causality is implicit. No guesses are made. Ambiguity is preserved.**

---

## 2. Declarative Causal Graph Primitives

All causal relations are defined in declarative YAML catalogs (e.g. `causality/distributed.yaml`, `causality/telemetry.yaml`), never hardcoded in Python code.

### Relation Types

| Relation | Notation | Semantics |
|:---|:---|:---|
| `PROPAGATES_TO` | `A -> B` | Incident condition `A` causes or manifests as downstream symptom `B`. |
| `PRECLUDES` | `A --/--> B` | Physical evidence confirming `A` explicitly refutes and eliminates hypothesis `B`. |
| `REQUIRES` | `A <-req- B` | Hypothesis `A` cannot be confirmed unless prerequisite condition `B` evaluates to `PASS`. |

### Prerequisite Semantics (`REQUIRES`)

```
REQUIRES(Prerequisite B)
     │
     ├── B = PASS     ──> Hypothesis A can be evaluated normally
     ├── B = UNKNOWN  ──> Hypothesis A becomes UNRESOLVED (lack of evidence)
     └── B = FAIL     ──> Hypothesis A becomes PRECLUDED (explicitly refuted)
```

---

## 3. Causal Candidate States

Every evaluated causal candidate is categorized into a deterministic state:

- **`CONFIRMED`**: Proven by positive physical evidence signatures without refuting preclusions.
- **`POSSIBLE`**: Competing plausible hypothesis when multiple root causes coexist without a declared priority hierarchy.
- **`UNRESOLVED`**: Candidate matches symptoms but cannot be confirmed due to missing or `UNKNOWN` prerequisite evidence.
- **`PRECLUDED`**: Candidate explicitly eliminated due to active refutation rules or failed prerequisites.

---

## 4. Hardened Invariants (C1 to C13)

The causal engine enforces 13 formal behavioral invariants verified by automated adversarial tests:

### C1 — Confirmed Single Root Cause
When physical evidence confirms a unique root cause $A$ propagating to symptom $S$, $A$ is identified as `primary_root_cause` (`ROOT_CAUSE_IDENTIFIED`), and the full causal chain $[A, \dots, S]$ is reconstructed.

### C2 — Unresolved Unknown Root Cause
When evidence for potential root cause $A$ evaluates to `UNKNOWN`, $A$ is marked `UNRESOLVED`. The system reports `primary_root_cause = None` (`ROOT_CAUSE_UNKNOWN`).

### C3 — Multiple Concurrent Confirmed Causes
When multiple independent root causes are confirmed concurrently without a declared priority ranking, zero arbitrary choice is made. Status degrades to `ROOT_CAUSE_CONSTRAINED`, and all candidates are preserved as `POSSIBLE`.

### C4 — Precluded Hypothesis
When an active preclusion rule refutes candidate $A$, $A$ is placed in `precluded_hypotheses` and removed from the active candidate pool.

### C5 — Subgraph Uncertainty Isolation
Uncertainty (`UNKNOWN`) is strictly confined to its causal subgraph. Missing evidence on an unrelated component (e.g. TLS probe) never contaminates an independently confirmed cause (e.g. PostgreSQL pool exhaustion).

### C6 — Zero Undeclared Causality
In the absence of an explicit rule relating two components, zero causal relationship is inferred, regardless of whether both components are in failure.

### C7 — Cycle Detection Preceding Arbitration
Causal graph validation **MUST precede** causal arbitration.  
If rules contain circular dependencies ($A \to B \to A$), the engine detects all cycles, records them in `cycles_detected`, and safely falls back to `ROOT_CAUSE_CONSTRAINED` without throwing unhandled exceptions.

### C8 — Long Causal Chain Completeness & Order
For deep propagation chains ($A \to B \to C \to D \to S$), the reconstructed chain preserves 100% completeness and strict topological order $[A, B, C, D, S]$.

### C9 — Explicit Priority Arbitration
When multiple roots are confirmed, explicit declarative integer priorities (`priority: 20 > priority: 10`) resolve disambiguation deterministically.

### C9b — Priority Tie Invariant
When competing root causes share the exact same maximum priority, **zero arbitrary tie-breaking** (alphabetical, memory address, or dictionary order) is permitted. Status falls back to `ROOT_CAUSE_CONSTRAINED`, and all tied candidates remain `POSSIBLE`.

### C10 — Unranked Ambiguity Preservation
Candidates with default unranked priority (`priority: 0`) are preserved without arbitrary pruning.

### C11 — `REQUIRES` + `UNKNOWN` $\implies$ `UNRESOLVED`
If a required prerequisite probe is unavailable or `UNKNOWN`, the dependent hypothesis is classified as `UNRESOLVED`.

### C12 — `REQUIRES` + `FAIL` $\implies$ `PRECLUDED`
If an indispensable prerequisite probe fails, the dependent hypothesis is explicitly refuted, added to `precluded_hypotheses`, and disqualified.

### C13 — Disjoint Signals Yield Zero Causality
Unconnected failing probes across separate domains produce `ROOT_CAUSE_UNKNOWN` and empty causal chains.

---

## 5. Machine-Readable JSON Contract

The output produced by the causal engine strictly complies with `schemas/diagnosis-result.schema.json`:

```json
{
  "causality": {
    "status": "ROOT_CAUSE_IDENTIFIED",
    "primary_root_cause": "POSTGRES_POOL_EXHAUSTED",
    "target_situation": "SERVICE_ERROR_RATE_EXCEEDED",
    "causal_chain": [
      "POSTGRES_POOL_EXHAUSTED",
      "DATABASE_QUERY_DEADLOCK",
      "SERVICE_ERROR_RATE_EXCEEDED"
    ],
    "candidate_causes": [
      {
        "id": "POSTGRES_POOL_EXHAUSTED",
        "state": "CONFIRMED",
        "causal_path": ["POSTGRES_POOL_EXHAUSTED", "SERVICE_ERROR_RATE_EXCEEDED"],
        "missing_evidence": [],
        "description": "PostgreSQL connection pool is exhausted"
      }
    ],
    "precluded_hypotheses": [
      {
        "id": "APPLICATION_DATABASE_QUERY_DEADLOCK",
        "reason": "Required prerequisite network.database_port_reachable evaluated to FAIL"
      }
    ],
    "unresolved_hypotheses": [],
    "cycles_detected": []
  }
}
```

---

## 6. Catalog Authoring Example

```yaml
version: "1.0"
namespace: distributed_causality

rules:
  - from: POSTGRES_POOL_EXHAUSTED
    to: SERVICE_ERROR_RATE_EXCEEDED
    type: PROPAGATES_TO
    priority: 20
    description: "Postgres connection exhaustion cascades into service HTTP 500 error spikes"

  - from: DATABASE_PORT_CLOSED
    to: POSTGRES_POOL_EXHAUSTED
    type: PRECLUDES
    description: "If the TCP port is closed, connection pool exhaustion is refuted"

  - from: APPLICATION_DATABASE_QUERY_DEADLOCK
    to: network.database_port_reachable
    type: REQUIRES
    description: "Deadlock diagnosis requires network reachability to evaluate to PASS"
```
