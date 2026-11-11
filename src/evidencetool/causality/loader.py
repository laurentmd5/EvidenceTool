"""
Causality Catalog Loader — V1.0

Loads declarative causal rules from YAML files (e.g. causality/distributed.yaml).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from evidencetool.causality.models import CausalRelationType, CausalRule
from evidencetool.models.evidence import EvidenceStatus


def _parse_dict_conditions(
    cond_dict: dict[object, object], rule_id: str, valid_statuses: set[str]
) -> dict[str, str]:
    conditions: dict[str, str] = {}
    for k, v in cond_dict.items():
        if not isinstance(k, str) or not k.strip():
            raise ValueError(
                f"Invalid condition key '{k}' in rule '{rule_id}': must be a non-empty string."
            )
        if not isinstance(v, (str, EvidenceStatus)):
            raise ValueError(
                f"Invalid condition status '{v}' for '{k}' in rule '{rule_id}': must be one of {sorted(valid_statuses)}."
            )
        v_str = v.value if isinstance(v, EvidenceStatus) else str(v).strip().upper()
        if v_str not in valid_statuses:
            raise ValueError(
                f"Invalid condition status '{v_str}' for '{k}' in rule '{rule_id}': must be one of {sorted(valid_statuses)}."
            )
        conditions[k.strip()] = v_str
    return conditions


def _parse_list_conditions(
    cond_list: list[object], rule_id: str, valid_statuses: set[str]
) -> dict[str, str]:
    conditions: dict[str, str] = {}
    for c in cond_list:
        if not isinstance(c, str):
            raise ValueError(
                f"Invalid condition item '{c}' in rule '{rule_id}': must be a string format 'key=STATUS'."
            )
        if "=" not in c:
            raise ValueError(
                f"Invalid condition item '{c}' in rule '{rule_id}': missing '=' delimiter (format: 'key=STATUS')."
            )
        k, v = c.split("=", 1)
        k_clean = k.strip()
        v_clean = v.strip().upper()
        if not k_clean:
            raise ValueError(
                f"Invalid condition item '{c}' in rule '{rule_id}': key cannot be empty."
            )
        if v_clean not in valid_statuses:
            raise ValueError(
                f"Invalid condition status '{v_clean}' in '{c}' for rule '{rule_id}': must be one of {sorted(valid_statuses)}."
            )
        conditions[k_clean] = v_clean
    return conditions


def _parse_conditions(cond_raw: object, rule_id: str) -> dict[str, str]:
    if cond_raw is None or cond_raw == {}:
        return {}

    valid_statuses = {e.value for e in EvidenceStatus}
    if isinstance(cond_raw, dict):
        return _parse_dict_conditions(cond_raw, rule_id, valid_statuses)
    if isinstance(cond_raw, list):
        return _parse_list_conditions(cond_raw, rule_id, valid_statuses)

    raise ValueError(
        f"Invalid conditions format in rule '{rule_id}': must be a dictionary or list, got {type(cond_raw).__name__}."
    )


def _parse_rule(item: dict[str, object]) -> CausalRule:
    rule_id = str(item.get("id", "")).strip()
    if not rule_id:
        raise ValueError("Invalid causal rule: 'id' is mandatory and cannot be empty.")

    source = str(item.get("source", "")).strip()
    if not source:
        raise ValueError(f"Invalid causal rule '{rule_id}': 'source' is mandatory and cannot be empty.")

    target = str(item.get("target", "")).strip()
    if not target:
        raise ValueError(f"Invalid causal rule '{rule_id}': 'target' is mandatory and cannot be empty.")

    rel_raw = item.get("relation")
    if not rel_raw:
        raise ValueError(f"Invalid causal rule '{rule_id}': 'relation' is mandatory and cannot be empty.")

    rel_str = str(rel_raw).strip().upper()
    try:
        relation = CausalRelationType(rel_str)
    except ValueError:
        valid_rels = [r.value for r in CausalRelationType]
        raise ValueError(
            f"Invalid causal relation '{rel_str}' in rule '{rule_id}'. Valid relations are: {valid_rels}"
        )

    conditions = _parse_conditions(item.get("conditions", {}), rule_id)

    prio_raw = item.get("priority", 0)
    if not isinstance(prio_raw, int) or isinstance(prio_raw, bool):
        raise ValueError(
            f"Invalid priority '{prio_raw}' in rule '{rule_id}': must be an integer, got {type(prio_raw).__name__}."
        )
    priority = prio_raw

    root_cand_raw = item.get("is_root_cause_candidate", True)
    if not isinstance(root_cand_raw, bool):
        raise ValueError(
            f"Invalid is_root_cause_candidate '{root_cand_raw}' in rule '{rule_id}': must be a boolean."
        )
    is_root_cause_candidate = root_cand_raw

    surf_symp_raw = item.get("is_surface_symptom", False)
    if not isinstance(surf_symp_raw, bool):
        raise ValueError(
            f"Invalid is_surface_symptom '{surf_symp_raw}' in rule '{rule_id}': must be a boolean."
        )
    is_surface_symptom = surf_symp_raw

    desc_raw = item.get("description", "")
    if not isinstance(desc_raw, str):
        raise ValueError(f"Invalid description in rule '{rule_id}': must be a string.")
    description = desc_raw

    return CausalRule(
        id=rule_id,
        source=source,
        target=target,
        relation=relation,
        conditions=conditions,
        description=description,
        is_root_cause_candidate=is_root_cause_candidate,
        is_surface_symptom=is_surface_symptom,
        priority=priority,
    )


def load_causal_catalog(path: str | Path) -> list[CausalRule]:
    """Loads a list of CausalRules from a YAML file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Causality catalog file not found: {path}")

    content = p.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    if not isinstance(data, dict):
        raise ValueError("Invalid causality catalog: root must be a dictionary.")

    rules_raw = data.get("causal_rules") or data.get("rules") or []
    if not isinstance(rules_raw, list):
        raise ValueError("Invalid causality catalog: 'causal_rules' must be a list.")

    parsed_rules: list[CausalRule] = []
    for idx, item in enumerate(rules_raw):
        if not isinstance(item, dict):
            raise ValueError(
                f"Invalid causal rule at index {idx}: expected dictionary, got {type(item).__name__}."
            )
        parsed_rules.append(_parse_rule(item))

    return parsed_rules
