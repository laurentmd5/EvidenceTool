"""
Exhaustive case-by-case unit tests for Filesystem Provider.
"""

from __future__ import annotations

from evidencetool.providers.base import ProviderContext
from evidencetool.providers.filesystem import FilesystemProvider
from evidencetool.providers.registry import get_provider


def test_filesystem_provider_registration():
    p = get_provider("filesystem")
    assert isinstance(p, FilesystemProvider)


def test_filesystem_space_available(monkeypatch):
    provider = FilesystemProvider()

    # 500MB free, threshold 100MB
    monkeypatch.setattr("evidencetool.providers.filesystem.get_free_disk_space", lambda path, host=None: 500 * 1024 * 1024)

    obs = provider.collect(ProviderContext({"path": "/var/log", "min_free_bytes": str(100 * 1024 * 1024)}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["filesystem.disk_space_available"].value["status"] == "PASS"
    assert "500MB free" in obs_map["filesystem.disk_space_available"].message
    assert obs_map["filesystem.disk_pressure"].value["status"] == "PASS"
    assert obs_map["filesystem.disk_pressure"].value["pressure"] is False


def test_filesystem_space_low(monkeypatch):
    provider = FilesystemProvider()

    # 50MB free, threshold 100MB
    monkeypatch.setattr("evidencetool.providers.filesystem.get_free_disk_space", lambda path, host=None: 50 * 1024 * 1024)

    obs = provider.collect(ProviderContext({"path": "/var/log", "min_free_bytes": str(100 * 1024 * 1024)}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["filesystem.disk_space_available"].value["status"] == "FAIL"
    assert "below threshold" in obs_map["filesystem.disk_space_available"].message
    assert obs_map["filesystem.disk_pressure"].value["status"] == "FAIL"
    assert obs_map["filesystem.disk_pressure"].value["pressure"] is True


def test_filesystem_read_error(monkeypatch):
    provider = FilesystemProvider()

    monkeypatch.setattr("evidencetool.providers.filesystem.get_free_disk_space", lambda path, host=None: None)

    obs = provider.collect(ProviderContext({"path": "/nonexistent_mount"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["filesystem.disk_space_available"].value["status"] == "UNKNOWN"
    assert obs_map["filesystem.disk_pressure"].value["status"] == "UNKNOWN"


def test_filesystem_remote_host(monkeypatch):
    provider = FilesystemProvider()

    captured_host = []
    def mock_get_free(path, host=None):
        captured_host.append(host)
        return 1024 * 1024 * 1024

    monkeypatch.setattr("evidencetool.providers.filesystem.get_free_disk_space", mock_get_free)

    obs = provider.collect(ProviderContext({"path": "/", "host": "storage-node-01"}))
    assert all(h == "storage-node-01" for h in captured_host)
    assert obs[0].host == "storage-node-01"
