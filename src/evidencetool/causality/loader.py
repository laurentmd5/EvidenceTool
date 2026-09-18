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
    rule_id = str(item.get("id", ""))
    source = str(item.get("source", ""))
    target = str(item.get("target", ""))
    rel_str = str(item.get("relation", "PROPAGATES_TO")).upper()

    try:
        relation = CausalRelationType(rel_str)
    except ValueError:
        relation = CausalRelationType.PROPAGATES_TO

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
