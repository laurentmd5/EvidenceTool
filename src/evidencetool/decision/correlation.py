"""
State Correlation Engine — V1.0.2

Responsible for mapping a list of Evidence into a composite OperationalState
using a catalog of known Situations (deterministic signatures).

V1.0.2: Produces per-situation SituationEvaluation objects.
The invariant is: uncertainty must be local to the hypothesis it affects.
"""

from __future__ import annotations

from evidencetool.models.correlation import OperationalState, Situation, SituationEvaluation
from evidencetool.models.evidence import Evidence, EvidenceStatus


def correlate_state(evidence_list: list[Evidence], catalog: list[Situation]) -> OperationalState:
    """
    Evaluates evidence against a catalog of known situations.

    Returns an OperationalState containing all matched situations and
    per-situation evaluations with local ambiguity tracking.

    V1.0.2: Ambiguity is no longer a global boolean. Each situation
    carries its own unresolved/missing/discrepant evidence lists.
    """
    evidence_by_id = {e.id: e for e in evidence_list}

    matched_situations: list[Situation] = []
    evaluations: list[SituationEvaluation] = []
    discrepancies: dict[str, list[str]] = {}
    catalog_evidence_ids: set[str] = set()

    for situation in catalog:
        catalog_evidence_ids.update(situation.signature.keys())

        unresolved: list[str] = []
        missing: list[str] = []
        discrepant: list[str] = []
        match = True

        for ev_id, expected_status in situation.signature.items():
            ev = evidence_by_id.get(ev_id)
            if ev is None:
                match = False
                missing.append(ev_id)
            elif ev.status == EvidenceStatus.UNKNOWN:
                match = False
                unresolved.append(ev_id)
            elif ev.status != expected_status:
                match = False
                discrepant.append(ev_id)

        evaluation = SituationEvaluation(
            situation=situation,
            matched=match,
            unresolved_evidence=unresolved,
            missing_evidence=missing,
            discrepant_evidence=discrepant,
        )
        evaluations.append(evaluation)

        if match:
            matched_situations.append(situation)
            discrepancies[situation.id] = []
        else:
            discrepancies[situation.id] = missing + unresolved + discrepant

    # Global unresolved list for backward compatibility
    all_unresolved = sorted({
        e.id for e in evidence_list
        if e.status == EvidenceStatus.UNKNOWN and e.id in catalog_evidence_ids
    })

    return OperationalState(
        situations=matched_situations,
        evaluations=evaluations,
        unresolved_evidence=all_unresolved,
        discrepancies=discrepancies,
    )
