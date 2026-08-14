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
    Marks the state as ambiguous if any provided evidence is UNKNOWN
    and its ID is part of at least one catalog signature.
    """
    evidence_by_id = {e.id: e for e in evidence_list}

    matched_situations = []
    discrepancies = {}
    catalog_evidence_ids = set()

    for situation in catalog:
        catalog_evidence_ids.update(situation.signature.keys())
        match = True
        situation_discrepancies = []
        for ev_id, expected_status in situation.signature.items():
            ev = evidence_by_id.get(ev_id)
            if not ev or ev.status != expected_status:
                match = False
                situation_discrepancies.append(ev_id)

        if match:
            matched_situations.append(situation)
            discrepancies[situation.id] = []
        else:
            discrepancies[situation.id] = situation_discrepancies

    unresolved = [
        e.id for e in evidence_list
        if e.status == EvidenceStatus.UNKNOWN and e.id in catalog_evidence_ids
    ]

    ambiguous = len(unresolved) > 0

    return OperationalState(
        situations=matched_situations,
        unresolved_evidence=unresolved,
        ambiguous=ambiguous,
        discrepancies=discrepancies
    )
