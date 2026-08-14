"""
State Correlation Engine — V0.3

Responsible for mapping a list of Evidence into a composite OperationalState
using a catalog of known Situations (deterministic signatures).
"""

from __future__ import annotations

from evidencetool.models.correlation import OperationalState, Situation
from evidencetool.models.evidence import Evidence, EvidenceStatus


def correlate_state(evidence_list: list[Evidence], catalog: list[Situation]) -> OperationalState:
    """
    Evaluates evidence against a catalog of known situations.
    
    Returns an OperationalState containing all matched situations.
    Marks the state as ambiguous if any provided evidence is UNKNOWN.
    """
    evidence_by_id = {e.id: e for e in evidence_list}
    
    matched_situations = []
    for situation in catalog:
        match = True
        for ev_id, expected_status in situation.signature.items():
            ev = evidence_by_id.get(ev_id)
            if not ev or ev.status != expected_status:
                match = False
                break
        
        if match:
            matched_situations.append(situation)
            
    unresolved = [
        e.id for e in evidence_list 
        if e.status == EvidenceStatus.UNKNOWN
    ]
    
    ambiguous = len(unresolved) > 0
    
    return OperationalState(
        situations=matched_situations,
        unresolved_evidence=unresolved,
        ambiguous=ambiguous
    )
