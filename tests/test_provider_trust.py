import hashlib
import importlib
import sys
from pathlib import Path

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
