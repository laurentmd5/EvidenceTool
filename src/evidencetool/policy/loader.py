"""
Policy loader — parses YAML policy files into the Policy model.

Per PRODUCT_CONTRACT.md Section 7. The YAML engine is one interchangeable
implementation; nothing here assumes it is the final policy engine
(OPA/Rego remains an open, deferred option — see Known limitations).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from evidencetool.models.policy import (
    DEFAULT_ON_UNKNOWN,
    EvidenceRequirement,
    OnUnknown,
    Policy,
    RiskLevel,
)


def load_policy(path: str | Path) -> Policy:
    text = Path(path).read_text()
    return load_policy_from_string(text)


def load_policy_from_string(text: str) -> Policy:
    raw = yaml.safe_load(text)

    required_evidence = []
    for item in raw.get("required_evidence", []):
        if isinstance(item, str):
            # Shorthand: bare evidence id string -> default on_unknown.
            required_evidence.append(
                EvidenceRequirement(id=item, on_unknown=DEFAULT_ON_UNKNOWN)
            )
        else:
            required_evidence.append(
                EvidenceRequirement(
                    id=item["id"],
                    on_unknown=OnUnknown(item.get("on_unknown", DEFAULT_ON_UNKNOWN.value)),
                    max_age=item.get("max_age"),
                )
            )

    return Policy(
        version=str(raw["version"]),
        action=raw["action"],
        risk=RiskLevel(raw["risk"]),
        required_evidence=required_evidence,
        allow=raw.get("allow", []),
        blocked_by=raw.get("blocked_by", []),
        human_approval=bool(raw.get("human_approval", False)),
    )
