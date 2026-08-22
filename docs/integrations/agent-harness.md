# Agent Harness Integration Guide

EvidenceTool is specifically designed to be executed by autonomous agents safely. This guide defines how an agent should wrap EvidenceTool.

## 1. Freshness Rule
Agents must re-run EvidenceTool immediately before executing an action. Observations older than a configured threshold (default 60s) are considered stale and must be recollected.

An agent must NEVER execute an action based on a previous `ALLOW` decision if that decision relies on stale evidence.

## 2. validate_decision_integrity
Every JSON output produced by EvidenceTool includes a cryptographically stable representation of the decision.
Agents MUST run `validate_decision_integrity(decision, policy, evidence)` programmatically on the output.

If `is_valid` is false, the agent MUST abort the action immediately. This ensures that the agent cannot be tricked by malicious prompt injection into hallucinating a fake `ALLOW` decision.

```python
from evidencetool.decision.integrity import validate_decision_integrity

# If integrating programmatically in an agent's harness:
integrity = validate_decision_integrity(result.decision, policy, result.evidence)
if not integrity.is_valid:
    raise SecurityViolation("Decision integrity compromised")
```

## 3. HUMAN_REVIEW
If the engine returns `HUMAN_REVIEW`, the agent MUST pause execution and request explicit permission from a human operator. Treating `HUMAN_REVIEW` as a silent `ALLOW` violates the core safety invariants of the product contract.
