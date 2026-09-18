"""
EvidenceTool — Quickstart & Live Safety Gateway Demonstration.

Demonstrates how an autonomous AI Agent queries EvidenceTool's AgentSafetyGate
to evaluate a planned infrastructure action before executing it.
"""

from __future__ import annotations

import json

from evidencetool.agent.gate import AgentSafetyGate
from evidencetool.agent.models import AgentDiagnosisRequest
from evidencetool.capability.models import CapabilitySet, NetworkCapability


def main() -> None:
    print("=" * 70)
    print("  EVIDENCETOOL (v1.0.5) — ZERO-TRUST AI-AGENT SAFETY GATEWAY DEMO")
    print("=" * 70)

    # 1. Initialize the Gateway with policies, catalogs, and capability boundaries
    # Confinement: Only localhost/loopback target inspection permitted
    capabilities = CapabilitySet(
        network=NetworkCapability(
            targets=("127.0.0.1", "localhost"),
            max_probes=10,
        )
    )

    gate = AgentSafetyGate(
        capability_policy=capabilities,
        catalog="catalogs/distributed.yaml",
        default_policy="policies/distributed.yaml",
        causality_catalog="causality/distributed.yaml",
    )

    # 2. Simulate an Autonomous AI Agent proposing to restart a degraded backend service
    print("\n[1] AI Agent submits diagnosis request for action: 'restart_application'")
    request = AgentDiagnosisRequest(
        agent_id="remediation-agent-007",
        action="restart_application",
        target="distributed-service",
        context={
            "url": "http://127.0.0.1:8080/api/checkout",
            "db_host": "127.0.0.1",
            "db_port": "5432",
            "redis_host": "127.0.0.1",
            "redis_port": "6379",
            "target": "127.0.0.1",
            "port": "5432",
        },
        session_id="session-demo-2026",
    )

    # 3. Evaluate Safety & Causality
    print("[2] Evaluating operational evidence, causal DAG, and safety invariants...")
    result = gate.evaluate(request)

    # 4. Display explainable result
    print("\n" + "-" * 70)
    verdict_label = "[ALLOW]" if result.is_allowed else f"[{result.status}]"
    print(f"VERDICT: {verdict_label}")
    print(f"Reason:  {result.reason}")
    print(f"Causality Status: {result.causality_status}")
    if result.primary_root_cause:
        print(f"Primary Root Cause: {result.primary_root_cause}")
    if result.causal_chain:
        print(f"Causal Chain:       {' -> '.join(result.causal_chain)}")
    if result.precluded_hypotheses:
        print(f"Precluded Hypotheses: {', '.join(result.precluded_hypotheses)}")
    print(f"Recommendation:     {result.recommendation}")
    print(f"Authority Fingerprint: {result.authority.policy_fingerprint}")
    print(f"Probes Consumed / Budget: {result.authority.probes_consumed} / {result.authority.probes_budget}")
    print("-" * 70)

    print("\n[3] Full JSON Output Contract (PRODUCT_CONTRACT.md Sec 8):")
    from evidencetool.cli.render import to_contract_dict
    print(json.dumps(to_contract_dict(result.raw_diagnosis), indent=2))


if __name__ == "__main__":
    main()
