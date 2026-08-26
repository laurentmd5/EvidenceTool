"""
Policy loader — parses YAML policy files into the Policy model.

Per PRODUCT_CONTRACT.md Section 7. The YAML engine is one interchangeable
implementation; nothing here assumes it is the final policy engine
(OPA/Rego remains an open, deferred option — see Known limitations).
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import yaml

from evidencetool.models.policy import (
    DEFAULT_ON_UNKNOWN,
    EvidenceRequirement,
    OnUnknown,
    Policy,
    PolicySchema,
    RiskLevel,
)


def load_policy(path: str | Path) -> Policy:
    text = Path(path).read_text()
    return load_policy_from_string(text)


def _parse_evidence_requirement(item: object, index: int) -> EvidenceRequirement:
    if isinstance(item, str):
        return EvidenceRequirement(id=item, on_unknown=DEFAULT_ON_UNKNOWN)
    if not isinstance(item, dict):
        raise ValueError(f"Invalid policy: required_evidence[{index}] must be a string or mapping.")

    evidence_id = item.get("id")
    if not isinstance(evidence_id, str) or not evidence_id:
        raise ValueError(f"Invalid policy: required_evidence[{index}] needs a non-empty 'id'.")
    try:
        on_unknown = OnUnknown(item.get("on_unknown", DEFAULT_ON_UNKNOWN.value))
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Invalid policy: required_evidence[{index}].on_unknown must be BLOCK or IGNORE."
        ) from exc
    max_age = item.get("max_age")
    if max_age is not None and (
        isinstance(max_age, bool)
        or not isinstance(max_age, (int, float))
        or not math.isfinite(max_age)
        or max_age < 0
    ):
        raise ValueError(f"Invalid policy: required_evidence[{index}].max_age must be a non-negative number.")
    return EvidenceRequirement(id=evidence_id, on_unknown=on_unknown, max_age=max_age)


def _validate_situational_lists(raw: dict[str, Any]) -> tuple[list[str], list[str]]:
    allow_list = raw.get("allow", [])
    blocked_by_list = raw.get("blocked_by", [])

    for field, lst in [("allow", allow_list), ("blocked_by", blocked_by_list)]:
        if not isinstance(lst, list):
            raise ValueError(f"Invalid policy: '{field}' must be a list.")
        if any(not isinstance(s, str) or not s.strip() for s in lst):
            raise ValueError(f"Invalid policy: '{field}' entries must be non-empty strings.")

    # Semantic validation: Ensure allow and blocked_by are strictly disjoint (SEC-04)
    conflicts = set(allow_list).intersection(set(blocked_by_list))
    if conflicts:
        raise ValueError(
            f"Semantic Policy Conflict: situations cannot be simultaneously allowed and blocked: {sorted(conflicts)}"
        )

    return allow_list, blocked_by_list


def load_policy_from_string(text: str) -> Policy:
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise ValueError("Invalid policy format: expected a YAML mapping.")

    for field in ("version", "action", "risk"):
        if field not in raw:
            raise ValueError(f"Invalid policy: missing required field '{field}'.")

    required_evidence_raw = raw.get("required_evidence", [])
    if not isinstance(required_evidence_raw, list):
        raise ValueError("Invalid policy: 'required_evidence' must be a list.")

    required_evidence = [
        _parse_evidence_requirement(item, index)
        for index, item in enumerate(required_evidence_raw)
    ]

    schema_val = raw.get("schema", PolicySchema.V1_LEGACY.value)
    try:
        schema = PolicySchema(schema_val)
        risk = RiskLevel(raw["risk"])
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid policy: 'schema' or 'risk' has an unsupported value.") from exc

    allow_list, blocked_by_list = _validate_situational_lists(raw)

    human_approval = raw.get("human_approval", False)
    if not isinstance(human_approval, bool):
        raise ValueError("Invalid policy: 'human_approval' must be a boolean.")

    return Policy(
        version=str(raw["version"]),
        action=raw["action"],
        risk=risk,
        schema=schema,
        required_evidence=required_evidence,
        allow=allow_list,
        blocked_by=blocked_by_list,
        human_approval=human_approval,
    )
