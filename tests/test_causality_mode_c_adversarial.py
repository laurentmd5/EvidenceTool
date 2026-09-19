"""
Adversarial Verification Test Suite for Mode C Hybrid Causal Hardening (v1.0.6).

Verifies strict mathematical and architectural invariants under complex/adversarial topologies:
- C7: Causal cycles (A -> B -> A) detected without infinite loops or crashes; constrained arbitration
- C7b: Cycle connected to an external upstream node
- C7c: Cycle with partial uncertainty (UNKNOWN evidence)
- C7d: Cycle broken by PRECLUDES rule
- C8: Long multi-hop causal chains (A -> B -> C -> D -> S) preserving node completeness and exact topological order
- C9: Explicit priority disambiguation (priority(B) > priority(A) -> B)
- C9b: Priority tie (priority(A) == priority(B) == max -> ROOT_CAUSE_CONSTRAINED, zero dictionary tie-breaking)
- C10: Competing causes without priority -> ROOT_CAUSE_CONSTRAINED
- C11: Indispensable REQUIRES with UNKNOWN prerequisite -> UNRESOLVED
- C12: Indispensable REQUIRES with FAIL prerequisite -> PRECLUDED
- C13: Unrelated simultaneous failures with no declared causal rule -> zero causality inferred
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from evidencetool.causality.engine import reconstruct_causality
from evidencetool.causality.loader import load_causal_catalog
from evidencetool.causality.models import (
    CausalCandidateState,
    CausalityStatus,
    CausalRelationType,
    CausalRule,
)
from evidencetool.decision.correlation import correlate_state
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.models.correlation import Situation
from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.observation import Observation


def _make_evidence(obs_id: str, status: EvidenceStatus, value: dict | None = None) -> Evidence:
    obs = Observation(
        id=obs_id,
        source=obs_id.split(".")[0],
        category="adversarial",
        collector="test",
        method="test",
        value=value or {"status": status.value},
        message=f"{obs_id} is {status.value}",
        observed_at=datetime.now(timezone.utc),
    )
    return evaluate_observation(obs)


# ============================================================================
# C7: Causal Cycles
# ============================================================================

def test_c7_causal_cycle_detected_and_constrained() -> None:
    """
    C7: A -> B -> A (both confirmed).
    Cycle must be detected, no empty roots crash (ValueError: max() arg is empty),
    primary_root_cause is None, status is ROOT_CAUSE_CONSTRAINED, candidates POSSIBLE.
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="CAUSE_B", description="Cause B", signature={"probe.b": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R1", source="CAUSE_A", target="CAUSE_B", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R2", source="CAUSE_B", target="CAUSE_A", relation=CausalRelationType.PROPAGATES_TO),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert explanation.primary_root_cause is None
    assert explanation.status == CausalityStatus.ROOT_CAUSE_CONSTRAINED
    assert len(explanation.cycles_detected) >= 1
    cycle_nodes = set(explanation.cycles_detected[0])
    assert "CAUSE_A" in cycle_nodes and "CAUSE_B" in cycle_nodes

    cand_states = {c.id: c.state for c in explanation.candidate_causes}
    assert cand_states["CAUSE_A"] == CausalCandidateState.POSSIBLE
    assert cand_states["CAUSE_B"] == CausalCandidateState.POSSIBLE


def test_c7_cycle_with_unrelated_upstream_node() -> None:
    """
    C7b: C -> A -> B -> A -> S.
    Node C is an acyclic upstream cause propagating into cycle A <-> B.
    Engine must execute without infinite loop and record detected cycles.
    """
    situations = [
        Situation(id="CAUSE_C", description="Cause C", signature={"probe.c": EvidenceStatus.FAIL}),
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="CAUSE_B", description="Cause B", signature={"probe.b": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S", description="Symptom S", signature={"probe.s": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R_C_A", source="CAUSE_C", target="CAUSE_A", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_A_B", source="CAUSE_A", target="CAUSE_B", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_B_A", source="CAUSE_B", target="CAUSE_A", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_A_S", source="CAUSE_A", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO, is_surface_symptom=True),
    ]
    evidence = [
        _make_evidence("probe.c", EvidenceStatus.FAIL),
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),
        _make_evidence("probe.s", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert len(explanation.cycles_detected) >= 1
    # CAUSE_C has in_degree == 0 among confirmed nodes and reaches the graph
    assert explanation.primary_root_cause == "CAUSE_C"
    assert explanation.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED
    assert "CAUSE_C" in explanation.causal_chain


def test_c7_cycle_with_unknown_evidence() -> None:
    """
    C7c: A -> B -> A. Evidence for A is FAIL, but B has UNKNOWN evidence.
    B cannot be confirmed (becomes UNRESOLVED), breaking the cycle of confirmed nodes.
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="CAUSE_B", description="Cause B", signature={"probe.b": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R1", source="CAUSE_A", target="CAUSE_B", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R2", source="CAUSE_B", target="CAUSE_A", relation=CausalRelationType.PROPAGATES_TO),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.UNKNOWN),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    # Candidate A is confirmed, B is unresolved
    cand_dict = {c.id: c.state for c in explanation.candidate_causes}
    assert cand_dict.get("CAUSE_A") == CausalCandidateState.CONFIRMED
    assert cand_dict.get("CAUSE_B") == CausalCandidateState.UNRESOLVED
    assert explanation.primary_root_cause == "CAUSE_A"
    assert explanation.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED


def test_c7_cycle_broken_by_precludes() -> None:
    """
    C7d: A -> B -> A. Nominal evidence precludes B.
    B is removed from active candidates, cleanly breaking the cycle.
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="CAUSE_B", description="Cause B", signature={"probe.b": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R1", source="CAUSE_A", target="CAUSE_B", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R2", source="CAUSE_B", target="CAUSE_A", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_PREC", source="probe.healthy", target="CAUSE_B", relation=CausalRelationType.PRECLUDES),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),
        _make_evidence("probe.healthy", EvidenceStatus.PASS),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert "CAUSE_B" in explanation.precluded_hypotheses
    assert explanation.primary_root_cause == "CAUSE_A"
    assert explanation.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED


# ============================================================================
# C8: Long Multi-Hop Causal Chains
# ============================================================================

def test_c8_long_chain_completeness_and_order() -> None:
    """
    C8: A -> B -> C -> D -> S.
    A is confirmed. The causal chain must preserve all 5 nodes in exact topological order:
    [A, B, C, D, S].
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="HOP_B", description="Hop B", signature={"probe.b": EvidenceStatus.FAIL}),
        Situation(id="HOP_C", description="Hop C", signature={"probe.c": EvidenceStatus.FAIL}),
        Situation(id="HOP_D", description="Hop D", signature={"probe.d": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S", description="Symptom S", signature={"probe.s": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R_AB", source="CAUSE_A", target="HOP_B", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_BC", source="HOP_B", target="HOP_C", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_CD", source="HOP_C", target="HOP_D", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_DS", source="HOP_D", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO, is_surface_symptom=True),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),
        _make_evidence("probe.c", EvidenceStatus.FAIL),
        _make_evidence("probe.d", EvidenceStatus.FAIL),
        _make_evidence("probe.s", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert explanation.primary_root_cause == "CAUSE_A"
    assert explanation.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED
    # Completeness: all 5 nodes present
    assert len(explanation.causal_chain) == 5
    # Strict topological ordering
    assert explanation.causal_chain == ["CAUSE_A", "HOP_B", "HOP_C", "HOP_D", "SYMPTOM_S"]


# ============================================================================
# C9 & C9b: Priority Disambiguation & Priority Ties
# ============================================================================

def test_c9_explicit_priority_disambiguation() -> None:
    """
    C9: Two competing confirmed causes A -> S and B -> S.
    priority(A) = 10, priority(B) = 20.
    Cause B must be deterministically elected as primary_root_cause.
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="CAUSE_B", description="Cause B", signature={"probe.b": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S", description="Symptom S", signature={"probe.s": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R_A", source="CAUSE_A", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO, priority=10),
        CausalRule(id="R_B", source="CAUSE_B", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO, priority=20),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),
        _make_evidence("probe.s", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert explanation.primary_root_cause == "CAUSE_B"
    assert explanation.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED


def test_c9b_priority_tie_prevents_arbitrary_resolution() -> None:
    """
    C9b: Two competing confirmed causes A -> S and B -> S with the EXACT same priority.
    priority(A) = 20, priority(B) = 20.
    The engine MUST NOT tie-break via insertion order or sorting!
    Result must be ROOT_CAUSE_CONSTRAINED, primary_root_cause = None, both POSSIBLE.
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="CAUSE_B", description="Cause B", signature={"probe.b": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S", description="Symptom S", signature={"probe.s": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R_A", source="CAUSE_A", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO, priority=20),
        CausalRule(id="R_B", source="CAUSE_B", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO, priority=20),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),
        _make_evidence("probe.s", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert explanation.primary_root_cause is None
    assert explanation.status == CausalityStatus.ROOT_CAUSE_CONSTRAINED
    cand_states = {c.id: c.state for c in explanation.candidate_causes}
    assert cand_states["CAUSE_A"] == CausalCandidateState.POSSIBLE
    assert cand_states["CAUSE_B"] == CausalCandidateState.POSSIBLE


# ============================================================================
# C10: Competing Causes Without Priority
# ============================================================================

def test_c10_unranked_competing_causes_constrained() -> None:
    """
    C10: Two competing confirmed causes A -> S and B -> S without priority.
    Result must be ROOT_CAUSE_CONSTRAINED with all candidates preserved as POSSIBLE.
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="CAUSE_B", description="Cause B", signature={"probe.b": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S", description="Symptom S", signature={"probe.s": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R_A", source="CAUSE_A", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO, priority=0),
        CausalRule(id="R_B", source="CAUSE_B", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO, priority=0),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),
        _make_evidence("probe.s", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert explanation.primary_root_cause is None
    assert explanation.status == CausalityStatus.ROOT_CAUSE_CONSTRAINED
    for cand in explanation.candidate_causes:
        assert cand.state == CausalCandidateState.POSSIBLE


# ============================================================================
# C11 & C12: REQUIRES Semantics (UNKNOWN vs FAIL)
# ============================================================================

def test_c11_requires_unknown_results_in_unresolved() -> None:
    """
    C11: A REQUIRES B. Prerequisite B is UNKNOWN.
    A transitions to UNRESOLVED with missing_evidence: ['probe.b'].
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S", description="Symptom S", signature={"probe.s": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R_A", source="CAUSE_A", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_REQ", source="CAUSE_A", target="probe.b", relation=CausalRelationType.REQUIRES),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.UNKNOWN),
        _make_evidence("probe.s", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert "CAUSE_A" in explanation.unresolved_hypotheses
    cand = next(c for c in explanation.candidate_causes if c.id == "CAUSE_A")
    assert cand.state == CausalCandidateState.UNRESOLVED
    assert "probe.b" in cand.missing_evidence


def test_c12_requires_fail_results_in_precluded() -> None:
    """
    C12: A REQUIRES B. Indispensable prerequisite B evaluated to FAIL.
    Prerequisite failed -> hypothesis A is formally refuted and PRECLUDED.
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S", description="Symptom S", signature={"probe.s": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R_A", source="CAUSE_A", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_REQ", source="CAUSE_A", target="probe.b", relation=CausalRelationType.REQUIRES),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),  # Prerequisite failed!
        _make_evidence("probe.s", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    # Hypothesis A is refuted because prerequisite failed
    assert "CAUSE_A" in explanation.precluded_hypotheses
    # A is not confirmed as a candidate root cause
    assert not any(c.id == "CAUSE_A" and c.state == CausalCandidateState.CONFIRMED for c in explanation.candidate_causes)


# ============================================================================
# C13: Absence of Declared Relation
# ============================================================================

def test_c13_no_declared_relation_yields_zero_causality() -> None:
    """
    C13: Two failures occur simultaneously: A = FAIL, B = FAIL.
    No causal rule declares A -> B or B -> A.
    Result must be zero causal inference: primary_root_cause = None, causal_chain = [], ROOT_CAUSE_UNKNOWN.
    """
    situations = [
        Situation(id="SITUATION_A", description="Situation A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="SITUATION_B", description="Situation B", signature={"probe.b": EvidenceStatus.FAIL}),
    ]
    # Rules exist for completely different components, but zero relation between A and B
    rules = [
        CausalRule(id="R_XY", source="OTHER_X", target="OTHER_Y", relation=CausalRelationType.PROPAGATES_TO),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert explanation.primary_root_cause is None
    assert explanation.causal_chain == []
    assert explanation.status == CausalityStatus.ROOT_CAUSE_UNKNOWN


# ============================================================================
# C14: Disjoint Causal Components (H1 Isolation)
# ============================================================================

def test_c14_disjoint_causal_components() -> None:
    """
    C14: Graph contains two disjoint causal branches:
      A -> S1
      B -> S2
    Evidence: A = FAIL, S1 = FAIL, B = PASS, S2 = FAIL.
    Root cause A is identified.
    Invariance: S2 and B MUST NEVER leak into A's causal chain.
    causal_chain must strictly equal ['CAUSE_A', 'SYMPTOM_S1'].
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S1", description="Symptom S1", signature={"probe.s1": EvidenceStatus.FAIL}),
        Situation(id="CAUSE_B", description="Cause B", signature={"probe.b": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S2", description="Symptom S2", signature={"probe.s2": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R_A_S1", source="CAUSE_A", target="SYMPTOM_S1", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_B_S2", source="CAUSE_B", target="SYMPTOM_S2", relation=CausalRelationType.PROPAGATES_TO),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.s1", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.PASS),
        _make_evidence("probe.s2", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert explanation.primary_root_cause == "CAUSE_A"
    assert explanation.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED
    # Strict causal isolation: S2 must NEVER be in A's causal chain
    assert explanation.causal_chain == ["CAUSE_A", "SYMPTOM_S1"]
    assert "SYMPTOM_S2" not in explanation.causal_chain
    assert "CAUSE_B" not in explanation.causal_chain
    # Propagated symptoms must also isolate to the reachable subgraph
    assert "SYMPTOM_S1" in explanation.propagated_symptoms
    assert "SYMPTOM_S2" not in explanation.propagated_symptoms


# ============================================================================
# C15: Branching Causal Graph (H2 Causal Chain Semantics)
# ============================================================================

def test_c15_branching_causal_graph() -> None:
    """
    C15: Graph branches:
      A -> B -> S
      A -> C -> S
    Evidence confirms A, B, C, and S.
    Invariance: causal_chain must represent a valid, contiguous directed path.
    It must NEVER be [A, B, C, S] because B -> C does not exist.
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="HOP_B", description="Hop B", signature={"probe.b": EvidenceStatus.FAIL}),
        Situation(id="HOP_C", description="Hop C", signature={"probe.c": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S", description="Symptom S", signature={"probe.s": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R_AB", source="CAUSE_A", target="HOP_B", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_BS", source="HOP_B", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_AC", source="CAUSE_A", target="HOP_C", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_CS", source="HOP_C", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),
        _make_evidence("probe.c", EvidenceStatus.FAIL),
        _make_evidence("probe.s", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert explanation.primary_root_cause == "CAUSE_A"
    assert explanation.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED

    # Length must be 3 (valid path from A through one branch to S), NOT 4 ([A, B, C, S])
    assert len(explanation.causal_chain) == 3
    assert explanation.causal_chain[0] == "CAUSE_A"
    assert explanation.causal_chain[-1] == "SYMPTOM_S"
    # Deterministic tie-breaker selects lexicographically smallest path [A, B, S]
    assert explanation.causal_chain == ["CAUSE_A", "HOP_B", "SYMPTOM_S"]

    # Verify every adjacent pair in causal_chain is an actual directed edge in rules
    declared_edges = {(r.source, r.target) for r in rules}
    for i in range(len(explanation.causal_chain) - 1):
        edge = (explanation.causal_chain[i], explanation.causal_chain[i + 1])
        assert edge in declared_edges, f"Adjacent pair {edge} in causal_chain is not a declared edge!"


# ============================================================================
# C16: Multiple Rules from Same Source (H3 Multi-Rule Handling)
# ============================================================================

def test_c16_multiple_rules_from_same_source() -> None:
    """
    C16: Source CAUSE_A declares two distinct propagation rules:
      A -> B (priority 10, description: "A causes B")
      A -> C (priority 20, description: "A causes C")
      C -> S
      B -> S
    Neither rule must be overwritten.
    Because A -> C has higher priority (20 > 10), the path via C must be selected.
    Candidate description must reflect the active branch rule.
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="HOP_B", description="Hop B", signature={"probe.b": EvidenceStatus.FAIL}),
        Situation(id="HOP_C", description="Hop C", signature={"probe.c": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S", description="Symptom S", signature={"probe.s": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R_AB", source="CAUSE_A", target="HOP_B", relation=CausalRelationType.PROPAGATES_TO, priority=10, description="A causes B"),
        CausalRule(id="R_AC", source="CAUSE_A", target="HOP_C", relation=CausalRelationType.PROPAGATES_TO, priority=20, description="A causes C"),
        CausalRule(id="R_BS", source="HOP_B", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_CS", source="HOP_C", target="SYMPTOM_S", relation=CausalRelationType.PROPAGATES_TO),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),
        _make_evidence("probe.c", EvidenceStatus.FAIL),
        _make_evidence("probe.s", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert explanation.primary_root_cause == "CAUSE_A"
    # Priority 20 on A -> C over priority 10 on A -> B directs the chain through C
    assert explanation.causal_chain == ["CAUSE_A", "HOP_C", "SYMPTOM_S"]

    # Check candidate cause description reflects active rule
    cand_a = next(c for c in explanation.candidate_causes if c.id == "CAUSE_A")
    assert cand_a.description == "A causes C"


# ============================================================================
# C17: Invalid Causal Relation Fails Closed (H4 Catalog Validation)
# ============================================================================

def test_c17_invalid_causal_relation_fails_closed(tmp_path: Path) -> None:
    """
    C17: A YAML catalog with a typo in the relation (e.g. PROPAGATSE_TO)
    must fail closed with a ValueError during loading.
    Silent fallback to PROPAGATES_TO is strictly prohibited.
    """
    bad_catalog = tmp_path / "corrupted_relation.yaml"
    bad_catalog.write_text("""
causal_rules:
  - id: R_BAD
    source: CAUSE_A
    target: SYMPTOM_S
    relation: PROPAGATSE_TO
""", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid causal relation"):
        load_causal_catalog(bad_catalog)


# ============================================================================
# C18: Missing Source or Target Fails Closed (H4 Catalog Validation)
# ============================================================================

def test_c18_missing_source_or_target_fails_closed(tmp_path: Path) -> None:
    """
    C18: A YAML rule with missing or empty source, target, or id
    must fail closed with a ValueError.
    """
    # Missing source
    bad_source = tmp_path / "missing_source.yaml"
    bad_source.write_text("""
causal_rules:
  - id: R1
    target: SYMPTOM_S
    relation: PROPAGATES_TO
""", encoding="utf-8")
    with pytest.raises(ValueError, match="source.*mandatory"):
        load_causal_catalog(bad_source)

    # Missing target
    bad_target = tmp_path / "missing_target.yaml"
    bad_target.write_text("""
causal_rules:
  - id: R2
    source: CAUSE_A
    relation: PROPAGATES_TO
""", encoding="utf-8")
    with pytest.raises(ValueError, match="target.*mandatory"):
        load_causal_catalog(bad_target)

    # Missing id
    bad_id = tmp_path / "missing_id.yaml"
    bad_id.write_text("""
causal_rules:
  - source: CAUSE_A
    target: SYMPTOM_S
    relation: PROPAGATES_TO
""", encoding="utf-8")
    with pytest.raises(ValueError, match="id.*mandatory"):
        load_causal_catalog(bad_id)


# ============================================================================
# C19: Branching Graph with Unrelated Symptom (H1 + H2 Combined)
# ============================================================================

def test_c19_branching_plus_unrelated_symptom() -> None:
    """
    C19: Combines branching topology with an unrelated external symptom:
      A -> B -> S1
      A -> C -> S1
      D -> S2 (completely disjoint failure)
    Evidence: A = FAIL, B = FAIL, C = FAIL, S1 = FAIL, D = PASS, S2 = FAIL.
    Root: CAUSE_A.
    causal_chain must be a valid path to S1, and neither D nor S2 can ever appear.
    """
    situations = [
        Situation(id="CAUSE_A", description="Cause A", signature={"probe.a": EvidenceStatus.FAIL}),
        Situation(id="HOP_B", description="Hop B", signature={"probe.b": EvidenceStatus.FAIL}),
        Situation(id="HOP_C", description="Hop C", signature={"probe.c": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S1", description="Symptom S1", signature={"probe.s1": EvidenceStatus.FAIL}),
        Situation(id="CAUSE_D", description="Cause D", signature={"probe.d": EvidenceStatus.FAIL}),
        Situation(id="SYMPTOM_S2", description="Symptom S2", signature={"probe.s2": EvidenceStatus.FAIL}),
    ]
    rules = [
        CausalRule(id="R_AB", source="CAUSE_A", target="HOP_B", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_BS1", source="HOP_B", target="SYMPTOM_S1", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_AC", source="CAUSE_A", target="HOP_C", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_CS1", source="HOP_C", target="SYMPTOM_S1", relation=CausalRelationType.PROPAGATES_TO),
        CausalRule(id="R_DS2", source="CAUSE_D", target="SYMPTOM_S2", relation=CausalRelationType.PROPAGATES_TO),
    ]
    evidence = [
        _make_evidence("probe.a", EvidenceStatus.FAIL),
        _make_evidence("probe.b", EvidenceStatus.FAIL),
        _make_evidence("probe.c", EvidenceStatus.FAIL),
        _make_evidence("probe.s1", EvidenceStatus.FAIL),
        _make_evidence("probe.d", EvidenceStatus.PASS),
        _make_evidence("probe.s2", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, situations)

    explanation = reconstruct_causality(evidence, state, rules)

    assert explanation.primary_root_cause == "CAUSE_A"
    assert explanation.status == CausalityStatus.ROOT_CAUSE_IDENTIFIED

    # Chain must be a valid path of length 3: [CAUSE_A, HOP_B, SYMPTOM_S1]
    assert explanation.causal_chain == ["CAUSE_A", "HOP_B", "SYMPTOM_S1"]
    # Strict isolation
    assert "CAUSE_D" not in explanation.causal_chain
    assert "SYMPTOM_S2" not in explanation.causal_chain
    assert "HOP_C" not in explanation.causal_chain
    assert "SYMPTOM_S2" not in explanation.propagated_symptoms

