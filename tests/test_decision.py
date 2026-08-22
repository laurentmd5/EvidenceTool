"""
The 9 contract tests from PRODUCT_CONTRACT.md.

These are the executable form of the decision contract locked at the end
of the design conversation. If the implementation ever disagrees with one
of these, the contract wins -- fix the code, or deliberately revise the
contract in writing, never silently override it here.
"""

from evidencetool.decision.engine import decide
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.models.decision import DecisionStatus


def _evidence_list(observation_factory, items):
    """items: list of (id, status, age_seconds) tuples -> list[Evidence]."""
    return [
        evaluate_observation(observation_factory(id_, status, age_seconds=age))
        for id_, status, age in items
    ]


# TEST 01 -- Required evidence PASS -> ALLOW
def test_01_required_evidence_pass_allows(observation_factory, policy_factory):
    policy = policy_factory(required_evidence=["nginx.config.valid"])
    evidence = _evidence_list(observation_factory, [("nginx.config.valid", "PASS", 0)])
    decision = decide(evidence, policy)
    assert decision.status == DecisionStatus.ALLOW


# TEST 02 -- Required evidence FAIL -> BLOCK
def test_02_required_evidence_fail_blocks(observation_factory, policy_factory):
    policy = policy_factory(required_evidence=["nginx.config.valid"])
    evidence = _evidence_list(observation_factory, [("nginx.config.valid", "FAIL", 0)])
    decision = decide(evidence, policy)
    assert decision.status == DecisionStatus.BLOCK
    assert "nginx.config.valid" in decision.blocking_evidence


# TEST 03 -- Required evidence UNKNOWN (on_unknown: BLOCK, the default) -> BLOCK
def test_03_required_evidence_unknown_blocks_by_default(observation_factory, policy_factory):
    policy = policy_factory(
        required_evidence=[{"id": "tls.certificate.exists", "on_unknown": "BLOCK"}]
    )
    evidence = _evidence_list(observation_factory, [("tls.certificate.exists", "UNKNOWN", 0)])
    decision = decide(evidence, policy)
    assert decision.status == DecisionStatus.BLOCK
    assert "tls.certificate.exists" in decision.blocking_evidence


# TEST 04 -- Optional evidence UNKNOWN (on_unknown: IGNORE) -> decision still possible (ALLOW)
def test_04_optional_evidence_unknown_does_not_block(observation_factory, policy_factory):
    policy = policy_factory(
        required_evidence=[
            {"id": "nginx.config.valid", "on_unknown": "BLOCK"},
            {"id": "filesystem.disk_io", "on_unknown": "IGNORE"},
        ]
    )
    evidence = _evidence_list(
        observation_factory,
        [
            ("nginx.config.valid", "PASS", 0),
            ("filesystem.disk_io", "UNKNOWN", 0),
        ],
    )
    decision = decide(evidence, policy)
    assert decision.status == DecisionStatus.ALLOW
    assert decision.blocking_evidence == []


# TEST 05 -- Evidence too old -> policy determines outcome (default on_unknown: BLOCK)
def test_05_stale_evidence_blocks_via_default_on_unknown(observation_factory, policy_factory):
    policy = policy_factory(
        required_evidence=[{"id": "nginx.config.valid", "on_unknown": "BLOCK", "max_age": 30}]
    )
    # Provider said PASS, but the observation is 120s old against a 30s max_age.
    evidence = [
        evaluate_observation(
            observation_factory("nginx.config.valid", "PASS", age_seconds=120), max_age=30
        )
    ]
    decision = decide(evidence, policy)
    assert decision.status == DecisionStatus.BLOCK
    assert "nginx.config.valid" in decision.blocking_evidence


def test_05b_stale_evidence_with_on_unknown_ignore_does_not_block(
    observation_factory, policy_factory
):
    """Staleness still routes through on_unknown -- an explicitly
    IGNOREd evidence item does not block even when stale."""
    policy = policy_factory(
        required_evidence=[
            {"id": "filesystem.disk_io", "on_unknown": "IGNORE", "max_age": 30}
        ]
    )
    evidence = [
        evaluate_observation(
            observation_factory("filesystem.disk_io", "PASS", age_seconds=120), max_age=30
        )
    ]
    decision = decide(evidence, policy)
    assert decision.status == DecisionStatus.ALLOW


# TEST 06 -- Recommendation changes -> Decision unchanged
def test_06_recommendation_never_influences_decision(observation_factory, policy_factory):
    """Decision is produced strictly from Evidence + Policy. The `decide`
    function does not even accept a recommendation argument -- this test
    documents that invariant structurally: calling it twice with identical
    evidence/policy always yields an identical decision, and nothing in
    the recommendation layer (built later, in cli/render.py) can feed
    back into it."""
    policy = policy_factory(required_evidence=["nginx.config.valid"])
    evidence = _evidence_list(observation_factory, [("nginx.config.valid", "FAIL", 0)])

    decision_a = decide(evidence, policy)
    decision_b = decide(evidence, policy)  # simulate a second run with a
    # different recommendation string generated downstream -- irrelevant
    # here since `decide` never sees recommendation text at all.

    assert decision_a.status == decision_b.status == DecisionStatus.BLOCK


# TEST 07 -- Normal policy evaluation with multiple mixed evidence -> correct decision
def test_07_multiple_evidence_all_satisfied_allows(observation_factory, policy_factory):
    policy = policy_factory(
        required_evidence=[
            "nginx.config.valid",
            "tls.certificate.exists",
            "tls.private_key.exists",
        ]
    )
    evidence = _evidence_list(
        observation_factory,
        [
            ("nginx.config.valid", "PASS", 0),
            ("tls.certificate.exists", "PASS", 0),
            ("tls.private_key.exists", "PASS", 0),
        ],
    )
    decision = decide(evidence, policy)
    assert decision.status == DecisionStatus.ALLOW


# TEST 08 -- Required evidence PASS, risk CRITICAL, human_approval=True -> HUMAN_REVIEW
def test_08_all_pass_with_human_approval_required_escalates_to_human_review(
    observation_factory, policy_factory
):
    policy = policy_factory(
        required_evidence=["nginx.config.valid"],
        risk="CRITICAL",
        human_approval=True,
    )
    evidence = _evidence_list(observation_factory, [("nginx.config.valid", "PASS", 0)])
    decision = decide(evidence, policy)
    assert decision.status == DecisionStatus.HUMAN_REVIEW


# TEST 09 -- Required evidence FAIL, risk CRITICAL, human_approval=True -> BLOCK
# (precedence invariant: BLOCK > HUMAN_REVIEW, always)
def test_09_blocking_evidence_wins_over_human_approval(observation_factory, policy_factory):
    policy = policy_factory(
        required_evidence=["nginx.config.valid"],
        risk="CRITICAL",
        human_approval=True,
    )
    evidence = _evidence_list(observation_factory, [("nginx.config.valid", "FAIL", 0)])
    decision = decide(evidence, policy)
    assert decision.status == DecisionStatus.BLOCK, (
        "A human approval requirement can escalate ALLOW to HUMAN_REVIEW, "
        "but it can never turn BLOCK into HUMAN_REVIEW."
    )


def test_precedence_invariant_block_beats_human_review_beats_allow(
    observation_factory, policy_factory
):
    """The precedence invariant, tested directly rather than as an
    implementation detail: across a matrix of evidence/human_approval
    combinations, BLOCK always wins, then HUMAN_REVIEW, then ALLOW."""
    # All pass, no approval required -> ALLOW
    p1 = policy_factory(required_evidence=["e1"], human_approval=False)
    ev_pass = _evidence_list(observation_factory, [("e1", "PASS", 0)])
    assert decide(ev_pass, p1).status == DecisionStatus.ALLOW

    # All pass, approval required -> HUMAN_REVIEW
    p2 = policy_factory(required_evidence=["e1"], human_approval=True)
    assert decide(ev_pass, p2).status == DecisionStatus.HUMAN_REVIEW

    # Fail, approval required -> BLOCK (not HUMAN_REVIEW)
    ev_fail = _evidence_list(observation_factory, [("e1", "FAIL", 0)])
    assert decide(ev_fail, p2).status == DecisionStatus.BLOCK

    # Fail, no approval required -> still BLOCK
    assert decide(ev_fail, p1).status == DecisionStatus.BLOCK


# --- Decision Integrity Tests ---
# DO NOT WEAKEN — see PRODUCT_CONTRACT.md Section 13 (Decision Integrity Contract)

def test_10_integrity_allow_with_fail(observation_factory, policy_factory):
    from evidencetool.decision.integrity import validate_decision_integrity
    from evidencetool.models.decision import Decision

    policy = policy_factory(required_evidence=["e1"])
    evidence = _evidence_list(observation_factory, [("e1", "FAIL", 0)])

    # Inject fake ALLOW
    fake_decision = Decision(status=DecisionStatus.ALLOW, blocking_evidence=[], reason="test")

    result = validate_decision_integrity(fake_decision, policy, evidence)
    assert not result.is_valid
    assert "Decision is ALLOW but required evidence e1 is FAIL." in result.violations[0]


def test_11_integrity_review_without_approval(observation_factory, policy_factory):
    from evidencetool.decision.integrity import validate_decision_integrity
    from evidencetool.models.decision import Decision

    # Policy does NOT require human approval
    policy = policy_factory(required_evidence=["e1"], human_approval=False)
    evidence = _evidence_list(observation_factory, [("e1", "PASS", 0)])

    # Inject fake HUMAN_REVIEW
    fake_decision = Decision(status=DecisionStatus.HUMAN_REVIEW, blocking_evidence=[], reason="test")

    result = validate_decision_integrity(fake_decision, policy, evidence)
    assert not result.is_valid
    assert "Decision is HUMAN_REVIEW but policy.human_approval is false." in result.violations[0]


def test_12_integrity_block_without_evidence(observation_factory, policy_factory):
    from evidencetool.decision.integrity import validate_decision_integrity
    from evidencetool.models.decision import Decision

    policy = policy_factory(required_evidence=["e1"])
    evidence = _evidence_list(observation_factory, [("e1", "PASS", 0)])

    # Inject fake BLOCK with empty blocking evidence
    fake_decision = Decision(status=DecisionStatus.BLOCK, blocking_evidence=[], reason="test")

    result = validate_decision_integrity(fake_decision, policy, evidence)
    assert not result.is_valid
    assert "Decision is BLOCK but blocking_evidence is empty (required for legacy policies)." in result.violations[0]


def test_13_integrity_precedence(observation_factory, policy_factory):
    from evidencetool.decision.integrity import validate_decision_integrity
    from evidencetool.models.decision import Decision

    # Policy requires human approval AND evidence fails -> correct is BLOCK
    policy = policy_factory(required_evidence=["e1"], human_approval=True)
    evidence = _evidence_list(observation_factory, [("e1", "FAIL", 0)])

    fake_allow = Decision(status=DecisionStatus.ALLOW, blocking_evidence=[], reason="test")
    assert not validate_decision_integrity(fake_allow, policy, evidence).is_valid

    fake_review = Decision(status=DecisionStatus.HUMAN_REVIEW, blocking_evidence=["e1"], reason="test")
    assert not validate_decision_integrity(fake_review, policy, evidence).is_valid

    # review without review flag
    assert not validate_decision_integrity(fake_review, policy, evidence).is_valid

def test_legacy_decision_missing_observation():
    from evidencetool.decision.engine import decide
    from evidencetool.models.policy import EvidenceRequirement, OnUnknown, Policy, PolicySchema, RiskLevel

    policy = Policy(
        version="1",
        action="test",
        schema=PolicySchema.V1_LEGACY,
        risk=RiskLevel.LOW,
        required_evidence=[
            EvidenceRequirement(id="missing.evidence", on_unknown=OnUnknown.BLOCK)
        ]
    )
    decision = decide([], policy)
    assert decision.status.value == "BLOCK"
    assert "missing.evidence" in decision.blocking_evidence

def test_decide_type_error_legacy():
    import pytest

    from evidencetool.decision.engine import decide
    from evidencetool.models.policy import Policy, PolicySchema, RiskLevel
    policy = Policy(version="1", action="test", schema=PolicySchema.V1_LEGACY, risk=RiskLevel.LOW, required_evidence=[])
    with pytest.raises(TypeError):
        decide("invalid_type", policy)

def test_decide_type_error_situational():
    import pytest

    from evidencetool.decision.engine import decide
    from evidencetool.models.policy import Policy, PolicySchema, RiskLevel
    policy = Policy(version="1", action="test", schema=PolicySchema.V2_SITUATIONAL, risk=RiskLevel.LOW, required_evidence=[])
    with pytest.raises(TypeError):
        decide([], policy)

def test_decide_unknown_schema():
    import pytest

    from evidencetool.decision.engine import decide
    from evidencetool.models.policy import Policy, RiskLevel
    policy = Policy(version="1", action="test", schema="FAKE_SCHEMA", risk=RiskLevel.LOW, required_evidence=[])
    with pytest.raises(ValueError):
        decide([], policy)
