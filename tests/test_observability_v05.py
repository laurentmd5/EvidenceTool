"""
Unit tests for V0.5 Observability Expansion and Situations (DISK_PRESSURE, NETWORK_UNREACHABLE).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from evidencetool.decision.correlation import correlate_state
from evidencetool.decision.engine import decide
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.models.decision import DecisionStatus
from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.observation import Observation
from evidencetool.models.policy import Policy, PolicySchema, RiskLevel
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.filesystem import FilesystemProvider


def _build_ev(ev_id: str, status: EvidenceStatus) -> Evidence:
    obs = Observation(
        id=ev_id,
        source="test",
        category="system",
        collector="test",
        method="mock",
        value={},
        message="mock obs",
        observed_at=datetime.now(timezone.utc),
    )
    return Evidence(observation=obs, status=status, message="test")


def test_filesystem_disk_pressure_detection(monkeypatch):
    provider = FilesystemProvider()

    # Simulate only 10MB free space (threshold 100MB)
    monkeypatch.setattr("evidencetool.providers.filesystem.get_free_disk_space", lambda path, host=None: 10 * 1024 * 1024)

    obs = provider.collect(ProviderContext({"path": "/var"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["filesystem.disk_space_available"].value["status"] == "FAIL"
    assert obs_map["filesystem.disk_pressure"].value["status"] == "FAIL"
    assert "Disk pressure detected" in obs_map["filesystem.disk_pressure"].message


def test_situation_disk_pressure_blocks_policy():
    catalog_path = Path(__file__).resolve().parents[1] / "catalogs" / "system.yaml"
    catalog = load_catalog(str(catalog_path))

    policy = Policy(
        version="1.0",
        action="start_heavy_job",
        risk=RiskLevel.MEDIUM,
        schema=PolicySchema.V2_SITUATIONAL,
        allow=["PROCESS_HEALTHY"],
        blocked_by=["DISK_PRESSURE", "NETWORK_UNREACHABLE", "PROCESS_CRASHED"],
    )

    evidence = [
        _build_ev("filesystem.disk_pressure", EvidenceStatus.FAIL),
        _build_ev("network.host_reachable", EvidenceStatus.PASS),
    ]

    state = correlate_state(evidence, catalog)
    assert any(s.id == "DISK_PRESSURE" for s in state.situations)

    decision = decide(state, policy)
    assert decision.status == DecisionStatus.BLOCK
    assert "DISK_PRESSURE" in decision.reason


def test_situation_network_unreachable_blocks_policy():
    catalog_path = Path(__file__).resolve().parents[1] / "catalogs" / "system.yaml"
    catalog = load_catalog(str(catalog_path))

    policy = Policy(
        version="1.0",
        action="sync_remote_data",
        risk=RiskLevel.LOW,
        schema=PolicySchema.V2_SITUATIONAL,
        allow=["PROCESS_HEALTHY"],
        blocked_by=["DISK_PRESSURE", "NETWORK_UNREACHABLE"],
    )

    evidence = [
        _build_ev("filesystem.disk_pressure", EvidenceStatus.PASS),
        _build_ev("network.host_reachable", EvidenceStatus.FAIL),
    ]

    state = correlate_state(evidence, catalog)
    assert any(s.id == "NETWORK_UNREACHABLE" for s in state.situations)

    decision = decide(state, policy)
    assert decision.status == DecisionStatus.BLOCK
    assert "NETWORK_UNREACHABLE" in decision.reason
