"""
Tests for the Evidence Evaluator (Observation -> Evidence).

Covers TEST 04 and TEST 05 from PRODUCT_CONTRACT.md.
"""

from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.models.evidence import EvidenceStatus


def test_pass_observation_evaluates_to_pass(observation_factory):
    obs = observation_factory("nginx.config.valid", "PASS")
    evidence = evaluate_observation(obs)
    assert evidence.status == EvidenceStatus.PASS
    assert evidence.is_stale is False


def test_fail_observation_evaluates_to_fail(observation_factory):
    obs = observation_factory("nginx.config.valid", "FAIL")
    evidence = evaluate_observation(obs)
    assert evidence.status == EvidenceStatus.FAIL


def test_missing_or_malformed_status_evaluates_to_unknown(observation_factory):
    obs = observation_factory("tls.certificate.valid", "SOMETHING_ELSE")
    evidence = evaluate_observation(obs)
    assert evidence.status == EvidenceStatus.UNKNOWN


def test_04_optional_evidence_unknown_does_not_block_evaluation(observation_factory):
    """TEST 04 -- Optional evidence UNKNOWN: evidence evaluation itself
    still succeeds; whether it blocks the *decision* is a policy concern
    (tested separately in test_decision.py), not an evaluator concern."""
    obs = observation_factory("filesystem.disk_io", "UNKNOWN")
    evidence = evaluate_observation(obs)
    assert evidence.status == EvidenceStatus.UNKNOWN
    # Evaluation always produces a usable Evidence object -- it never raises.
    assert evidence.id == "filesystem.disk_io"


def test_05_evidence_too_old_becomes_effectively_unknown(observation_factory):
    """TEST 05 -- Evidence too old: staleness (observed_at vs max_age)
    converts the effective status to UNKNOWN, regardless of what the
    provider originally reported. The policy's on_unknown rule then
    determines the final decision outcome (tested in test_decision.py)."""
    obs = observation_factory("nginx.config.valid", "PASS", age_seconds=120)
    evidence = evaluate_observation(obs, max_age=30)
    assert evidence.status == EvidenceStatus.UNKNOWN
    assert evidence.is_stale is True
    assert "stale" in evidence.message.lower()


def test_fresh_evidence_within_max_age_is_not_marked_stale(observation_factory):
    obs = observation_factory("nginx.config.valid", "PASS", age_seconds=5)
    evidence = evaluate_observation(obs, max_age=30)
    assert evidence.status == EvidenceStatus.PASS
    assert evidence.is_stale is False


def test_no_max_age_constraint_never_marks_stale(observation_factory):
    obs = observation_factory("nginx.config.valid", "PASS", age_seconds=99999)
    evidence = evaluate_observation(obs, max_age=None)
    assert evidence.status == EvidenceStatus.PASS
    assert evidence.is_stale is False
