import hashlib
import importlib
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidencetool.providers.registry import (
    ProviderTrust,
    get_provider_trust,
    load_approved_plugins,
)


def _plugin_source() -> str:
    return '''
from evidencetool.providers.registry import provider
from evidencetool.providers.base import Provider

@provider("approved_dummy")
class ApprovedDummyProvider:
    def collect(self, context):
        return []
'''


def test_approved_plugin_requires_matching_hash(tmp_path: Path, monkeypatch):
    module_path = tmp_path / "approved_plugin.py"
    module_path.write_text(_plugin_source(), encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()

    digest = hashlib.sha256(module_path.read_bytes()).hexdigest()
    manifest = tmp_path / "providers.yaml"
    manifest.write_text(
        f"plugins:\n  - namespace: approved_dummy\n    module: approved_plugin\n    sha256: {digest}\n",
        encoding="utf-8",
    )

    load_approved_plugins(manifest)
    assert get_provider_trust("approved_dummy") == ProviderTrust.APPROVED
    sys.modules.pop("approved_plugin", None)


def test_approved_plugin_rejects_wrong_hash(tmp_path: Path, monkeypatch):
    module_path = tmp_path / "rejected_plugin.py"
    module_path.write_text(_plugin_source().replace("approved_dummy", "rejected_dummy"), encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    manifest = tmp_path / "providers.yaml"
    manifest.write_text(
        "plugins:\n  - namespace: rejected_dummy\n    module: rejected_plugin\n    sha256: '" + "0" * 64 + "'\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="SHA-256 verification"):
        load_approved_plugins(manifest)
    assert "rejected_plugin" not in sys.modules


def test_load_all_providers_does_not_auto_import_unknown_filesystem_modules(monkeypatch):
    from evidencetool.providers.registry import load_all_providers

    imported = []

    def mock_import(name):
        imported.append(name)
        if name.startswith("evidencetool.providers."):
            return Mock()
        raise ImportError(f"Unknown module {name}")

    monkeypatch.setattr("importlib.import_module", mock_import)

    load_all_providers()

    # Verify only the 13 verified built-in modules are imported
    assert len(imported) == 13
    assert "evidencetool.providers.malicious_unapproved" not in imported
    assert "evidencetool.providers.nginx" in imported
    assert "evidencetool.providers.redis" in imported
    assert "evidencetool.providers.otel" in imported


def test_otel_provider_authority_confinement():
    """Verify OTel provider cannot register providers or alter capabilities."""
    import evidencetool.providers.otel  # noqa: F401
    from evidencetool.providers.registry import ProviderTrust, get_provider, get_provider_trust

    p = get_provider("otel")
    assert get_provider_trust("otel") == ProviderTrust.BUILTIN
    # Provider cannot modify registry or capabilities
    assert not hasattr(p, "register_provider")
    assert not hasattr(p, "grant_capability")
