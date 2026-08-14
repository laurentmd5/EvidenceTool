"""
Rendering — turns a DiagnosisResult into either the JSON output contract
(PRODUCT_CONTRACT.md Section 8) or a human-readable CLI rendering of that
exact same JSON. The JSON is the real contract; text is only a view over it.
"""

from __future__ import annotations

import json
import typing

from evidencetool.diagnose import DiagnosisResult
from evidencetool.models.evidence import EvidenceStatus

_STATUS_SYMBOL = {
    EvidenceStatus.PASS: "\u2713",  # check mark
    EvidenceStatus.FAIL: "\u2717",  # cross mark
    EvidenceStatus.UNKNOWN: "?",
}


def to_contract_dict(result: DiagnosisResult) -> dict[str, typing.Any]:
    return {
        "incident": {
            "id": result.incident.id,
            "type": result.incident.type,
        },
        "evidence": [e.to_dict() for e in result.evidence],
        "policy": {
            "action": result.policy.action,
            "risk": result.policy.risk.value,
        },
        "decision": result.decision.to_dict(),
        "recommendation": {
            "action": result.recommendation,
        },
    }


def to_json(result: DiagnosisResult) -> str:
    return json.dumps(to_contract_dict(result), indent=2)


def to_text(result: DiagnosisResult) -> str:
    lines = []
    for e in result.evidence:
        symbol = _STATUS_SYMBOL[e.status]
        lines.append(f"{symbol} {e.id}")

    lines.append("")
    lines.append(f"Policy:\n{result.policy.action}")
    lines.append("")
    lines.append(f"Decision:\n{result.decision.status.value}")
    lines.append("")
    lines.append(f"Reason:\n{result.decision.reason}")

    if result.decision.blocking_evidence:
        lines.append("")
        lines.append("Blocking evidence:")
        for evidence_id in result.decision.blocking_evidence:
            lines.append(f"- {evidence_id}")

    lines.append("")
    lines.append(f"Recommendation:\n{result.recommendation}")

    return "\n".join(lines)
