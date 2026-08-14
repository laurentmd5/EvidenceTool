"""
Diagnostic Catalog Loader.

Loads Situation definitions from a YAML catalog.
"""

from __future__ import annotations

import yaml
from pathlib import Path

from evidencetool.models.correlation import Situation
from evidencetool.models.evidence import EvidenceStatus


def load_catalog(path: str) -> list[Situation]:
    """
    Loads a catalog of Situations from a YAML file.
    
    Expected format:
    situations:
      SITUATION_ID:
        description: "..."
        signature:
          evidence.id: PASS
          other.id: FAIL
    """
    content = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    
    if not isinstance(data, dict) or "situations" not in data:
        raise ValueError(f"Invalid catalog format in {path}: missing 'situations' key.")
        
    situations_data = data["situations"]
    if not isinstance(situations_data, dict):
        raise ValueError(f"Invalid catalog format in {path}: 'situations' must be a dictionary.")
        
    situations = []
    for sit_id, sit_data in situations_data.items():
        if not isinstance(sit_data, dict):
            raise ValueError(f"Invalid situation data for {sit_id}")
            
        description = sit_data.get("description", "")
        signature_raw = sit_data.get("signature", {})
        
        signature = {}
        for ev_id, status_str in signature_raw.items():
            try:
                status = EvidenceStatus(status_str)
            except ValueError:
                raise ValueError(
                    f"Invalid status '{status_str}' for evidence '{ev_id}' in situation '{sit_id}'. "
                    "Must be PASS or FAIL."
                )
            if status == EvidenceStatus.UNKNOWN:
                raise ValueError(
                    f"UNKNOWN cannot be used in a situation signature (situation: {sit_id}, evidence: {ev_id})."
                )
            signature[ev_id] = status
            
        situations.append(
            Situation(
                id=sit_id,
                description=description,
                signature=signature
            )
        )
        
    return situations
