from pathlib import Path

import pytest

from evidencetool.capability.loader import load_capability_policy
from evidencetool.capability.models import CapabilityDenied


def test_load_restricted_capability_policy(tmp_path: Path):
    policy_path = tmp_path / "capabilities.yaml"
    policy_path.write_text(
        """
capabilities:
  network:
    enabled: true
    operations: [tcp_connect]
    targets: [10.0.10.0/24]
    ports: [6379]
    max_probes: 2
    timeout_seconds: 1.5
  providers:
    allowed: [network]
""",
        encoding="utf-8",
    )

    capabilities = load_capability_policy(policy_path)
    capabilities.require_network("tcp_connect", "10.0.10.12", 6379)
    assert capabilities.network.max_probes == 2
    assert capabilities.network.timeout_seconds == 1.5
    assert capabilities.allows_provider("network")
    assert not capabilities.allows_provider("docker")


def test_capability_policy_rejects_invalid_port(tmp_path: Path):
    policy_path = tmp_path / "capabilities.yaml"
    policy_path.write_text("capabilities:\n  network:\n    ports: [70000]\n", encoding="utf-8")

    with pytest.raises(ValueError, match="ports"):
        load_capability_policy(policy_path)


def test_capability_policy_rejects_unauthorized_target(tmp_path: Path):
    policy_path = tmp_path / "capabilities.yaml"
    policy_path.write_text("capabilities:\n  network:\n    targets: [10.0.10.0/24]\n", encoding="utf-8")

    capabilities = load_capability_policy(policy_path)
    with pytest.raises(CapabilityDenied, match="not authorized"):
        capabilities.require_network("tcp_connect", "10.0.20.12", 6379)
