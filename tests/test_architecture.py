from datetime import datetime, timezone

import pytest

from evidencetool.diagnose import diagnose
from evidencetool.models.decision import DecisionStatus
from evidencetool.models.observation import Observation
from evidencetool.models.policy import EvidenceRequirement, OnUnknown, Policy, RiskLevel
from evidencetool.providers.base import Provider, ProviderContext
from evidencetool.providers.registry import get_provider, provider, register_provider


@pytest.fixture
def base_policy():
    return Policy(
        version="1",
        action="dummy_action",
        risk=RiskLevel.LOW,
        required_evidence=[],
        human_approval=False,
    )


# --- TEST A & B: Provider Registration & Generic Orchestration ---

class DummyProvider(Provider):
    def collect(self, context: ProviderContext) -> list[Observation]:
        return [
            Observation(
                id="dummy.is_ok",
                source="dummy",
                category="test",
                collector="dummy_provider",
                method="test",
                value={"status": "PASS"},
                message="Dummy is OK",
                observed_at=datetime.now(timezone.utc)
            )
        ]

def test_A_and_B_provider_registration_and_generic_orchestration(base_policy):
    # Test A: Provider registration
    register_provider("dummy", DummyProvider)

    provider_instance = get_provider("dummy")
    assert isinstance(provider_instance, DummyProvider)

    # Test B: Generic orchestration
    policy = Policy(
        version="1",
        action="dummy_action",
        risk=RiskLevel.LOW,
        required_evidence=[
            EvidenceRequirement(id="dummy.is_ok", on_unknown=OnUnknown.BLOCK)
        ],
        human_approval=False,
    )

    result = diagnose("dummy_target", policy, {})
    assert result.decision.status == DecisionStatus.ALLOW
    assert len(result.evidence) == 1
    assert result.evidence[0].id == "dummy.is_ok"
    assert result.evidence[0].status == "PASS"


# --- TEST C1: Unknown Provider ---

def test_C1_unknown_provider(base_policy):
    policy = Policy(
        version="1",
        action="dummy_action",
        risk=RiskLevel.LOW,
        required_evidence=[
            EvidenceRequirement(id="unknown.config_valid", on_unknown=OnUnknown.BLOCK)
        ],
        human_approval=False,
    )

    result = diagnose("unknown_target", policy, {})

    # The provider does not exist, so it should emit a synthetic UNKNOWN observation
    assert result.decision.status == DecisionStatus.BLOCK
    assert "unknown.config_valid" in result.decision.blocking_evidence

    # Verify the synthetic observation has the correct error message
    obs = [e.observation for e in result.evidence if e.id == "unknown.config_valid"][0]
    assert "No provider registered for namespace: 'unknown'" in obs.message


# --- TEST C2: Evidence Unknown ---

@provider("failing_dummy")
class FailingDummyProvider(Provider):
    def collect(self, context: ProviderContext) -> list[Observation]:
        return [
            Observation(
                id="failing_dummy.something",
                source="failing_dummy",
                category="test",
                collector="failing_dummy_provider",
                method="test",
                value={"status": "UNKNOWN"},
                message="Cannot determine something",
                observed_at=datetime.now(timezone.utc)
            )
        ]

def test_C2_evidence_unknown():
    policy = Policy(
        version="1",
        action="dummy_action",
        risk=RiskLevel.LOW,
        required_evidence=[
            EvidenceRequirement(id="failing_dummy.something", on_unknown=OnUnknown.BLOCK)
        ],
        human_approval=False,
    )

    result = diagnose("dummy_target", policy, {})

    # The provider ran successfully but returned UNKNOWN
    assert result.decision.status == DecisionStatus.BLOCK
    assert "failing_dummy.something" in result.decision.blocking_evidence

    obs = [e.observation for e in result.evidence if e.id == "failing_dummy.something"][0]
    assert obs.message == "Cannot determine something"


# --- TEST D: Missing Provider Context ---

def test_D_missing_provider_context():
    # systemd provider requires "service" in context
    policy = Policy(
        version="1",
        action="restart_nginx",
        risk=RiskLevel.LOW,
        required_evidence=[
            EvidenceRequirement(id="systemd.service_active", on_unknown=OnUnknown.BLOCK)
        ],
        human_approval=False,
    )

    # We call diagnose without passing "service" in context
    result = diagnose("nginx", policy, {})

    # The provider should raise a ValueError ("Missing required context variable: service")
    # diagnose() should catch it, emit a synthetic UNKNOWN observation, and block.
    assert result.decision.status == DecisionStatus.BLOCK
    assert "systemd.service_active" in result.decision.blocking_evidence

    obs = [e.observation for e in result.evidence if e.id == "systemd.service_active"][0]
    assert "Missing required context variable: service" in obs.message


# --- TEST E: True Dynamic File Discovery ---

def test_E_dynamic_file_discovery():
    """
    Proves that merely dropping a file in the providers directory makes it available.
    """
    import importlib
    from pathlib import Path

    from evidencetool.providers.registry import load_all_providers

    provider_dir = Path(__file__).parent.parent / "src" / "evidencetool" / "providers"
    dummy_file = provider_dir / "dummy_dynamic.py"

    code = """
from evidencetool.providers.registry import provider
from evidencetool.providers.base import Provider, ProviderContext
from evidencetool.models.observation import Observation

@provider("dummy_dynamic")
class DummyDynamicProvider(Provider):
    def collect(self, context: ProviderContext) -> list[Observation]:
        return []
"""
    try:
        dummy_file.write_text(code)

        # Invalidate import caches to ensure pkgutil sees the new file
        importlib.invalidate_caches()

        load_all_providers()

        provider_instance = get_provider("dummy_dynamic")
        assert provider_instance.__class__.__name__ == "DummyDynamicProvider"
    finally:
        if dummy_file.exists():
            dummy_file.unlink()

        # Clean up the .pyc file/pycache if it exists
        pycache = provider_dir / "__pycache__"
        if pycache.exists():
            for pyc in pycache.glob("dummy_dynamic.*.pyc"):
                pyc.unlink()


# --- TEST F: Provider Namespace Collision ---

def test_F_provider_namespace_collision():
    from evidencetool.providers.registry import register_provider

    # Attempting to register a provider with an existing namespace should raise ValueError
    with pytest.raises(ValueError, match="Provider namespace 'dummy' is already registered"):
        register_provider("dummy", DummyProvider)


# --- TEST G: Provider Import Failure ---

def test_G_provider_import_failure():
    """
    Proves that a broken provider module logs an error and records a ProviderLoadError,
    but does not crash the registry or prevent other providers from loading.
    """
    import importlib
    from pathlib import Path

    from evidencetool.providers.registry import _FAILED_PROVIDERS, get_provider, load_all_providers

    provider_dir = Path(__file__).parent.parent / "src" / "evidencetool" / "providers"
    broken_file = provider_dir / "broken_dynamic.py"

    # Introduce a syntax error or import error
    code = """
from does_not_exist import nothing
"""
    try:
        broken_file.write_text(code)

        # Invalidate caches
        importlib.invalidate_caches()

        # Load providers. This should not raise an exception.
        load_all_providers()

        # The broken provider should be in _FAILED_PROVIDERS
        assert "broken_dynamic" in _FAILED_PROVIDERS
        error_info = _FAILED_PROVIDERS["broken_dynamic"]
        assert error_info.namespace == "broken_dynamic"
        assert "No module named 'does_not_exist'" in error_info.error

        # Existing providers should still be accessible
        provider_instance = get_provider("dummy")
        assert isinstance(provider_instance, DummyProvider)

    finally:
        if broken_file.exists():
            broken_file.unlink()

        pycache = provider_dir / "__pycache__"
        if pycache.exists():
            for pyc in pycache.glob("broken_dynamic.*.pyc"):
                pyc.unlink()

def test_H_structural_no_decision_imports_in_providers():
    """
    Ensures that no provider module imports policy, decision, or correlation directly.
    This guarantees the unidirectional architecture: Providers only know about Observation.
    """
    import ast
    from pathlib import Path

    provider_dir = Path(__file__).parent.parent / "src" / "evidencetool" / "providers"

    banned_imports = {
        "evidencetool.policy",
        "evidencetool.decision",
        "evidencetool.models.policy",
        "evidencetool.models.decision",
        "evidencetool.models.correlation"
    }

    for py_file in provider_dir.glob("*.py"):
        if py_file.name == "__init__.py":
            continue

        tree = ast.parse(py_file.read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not any(alias.name.startswith(banned) for banned in banned_imports), \
                        f"Provider {py_file.name} illegally imports {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert not any(node.module.startswith(banned) for banned in banned_imports), \
                        f"Provider {py_file.name} illegally imports from {node.module}"
