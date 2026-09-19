"""
Causality Catalog Loader — V1.0

Loads declarative causal rules from YAML files (e.g. causality/distributed.yaml).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from evidencetool.causality.models import CausalRelationType, CausalRule


def _parse_conditions(cond_raw: object) -> dict[str, str]:
    conditions: dict[str, str] = {}
    if isinstance(cond_raw, dict):
        conditions = {str(k): str(v) for k, v in cond_raw.items()}
    elif isinstance(cond_raw, list):
        for c in cond_raw:
            if isinstance(c, str) and "=" in c:
                k, v = c.split("=", 1)
                conditions[k.strip()] = v.strip()
    return conditions


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

    conditions = _parse_conditions(item.get("conditions", {}))

    try:
        priority = int(str(item.get("priority", 0)))
    except (ValueError, TypeError):
        priority = 0

    return CausalRule(
        id=rule_id,
        source=source,
        target=target,
        relation=relation,
        conditions=conditions,
        description=str(item.get("description", "")),
        is_root_cause_candidate=bool(item.get("is_root_cause_candidate", True)),
        is_surface_symptom=bool(item.get("is_surface_symptom", False)),
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

    return [_parse_rule(item) for item in rules_raw if isinstance(item, dict)]
