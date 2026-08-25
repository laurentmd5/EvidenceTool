# Agent Harness Integration Guide

EvidenceTool is specifically designed to be executed by autonomous agents safely. This guide defines how an agent should wrap EvidenceTool.

## 1. Freshness Rule
Agents must re-run EvidenceTool immediately before executing an action. Observations older than the policy's configured `max_age` are considered stale and must be recollected. Policies that require a 60-second freshness window must declare `max_age: 60` explicitly.

An agent must NEVER execute an action based on a previous `ALLOW` decision if that decision relies on stale evidence.

For automated execution, the harness should provide an explicit capability policy. It may restrict network
operations, targets, ports, probe count, and provider trust without changing the diagnostic policy that interprets
the resulting evidence. Capability denial or an unapproved provider is an integrity failure and must abort the action.

External providers used by an automated harness should be listed in an external manifest and verified by SHA-256
before activation. Do not treat discovery alone as approval.

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
