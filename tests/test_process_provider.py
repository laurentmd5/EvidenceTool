"""
Unit tests for Process provider.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from evidencetool.providers.base import ProviderContext
from evidencetool.providers.process import ProcessProvider
from evidencetool.providers.registry import get_provider


def test_process_provider_registration():
    p = get_provider("process")
    assert isinstance(p, ProcessProvider)


def test_process_missing_context():
    p = ProcessProvider()
    with pytest.raises(ValueError, match="Missing required context variable: process"):
        p.collect(ProviderContext({}))


def test_process_running_pgrep_success(monkeypatch):
    p = ProcessProvider()

    def mock_run_command(args, **kwargs):
        if "pgrep" in args:
            return Mock(ran=True, returncode=0, stdout="1234\n5678", stderr="")
        if "ps" in args:
            return Mock(ran=True, returncode=0, stdout="S nginx\nS nginx", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.process.run_command", mock_run_command)

    obs = p.collect(ProviderContext({"process": "nginx"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["process.running"].value["status"] == "PASS"
    assert obs_map["process.running"].value["pids"] == ["1234", "5678"]
    assert obs_map["process.zombie"].value["status"] == "PASS"


def test_process_not_running(monkeypatch):
    p = ProcessProvider()

    def mock_run_command(args, **kwargs):
        if "pgrep" in args:
            return Mock(ran=True, returncode=1, stdout="", stderr="")
        if "ps" in args:
            return Mock(ran=True, returncode=0, stdout="S init\nS bash", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.process.run_command", mock_run_command)

    obs = p.collect(ProviderContext({"process": "my_daemon"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["process.running"].value["status"] == "FAIL"


def test_process_zombie_detected(monkeypatch):
    p = ProcessProvider()

    def mock_run_command(args, **kwargs):
        if "pgrep" in args:
            return Mock(ran=True, returncode=0, stdout="9999", stderr="")
        if "ps" in args:
            return Mock(ran=True, returncode=0, stdout="Z+ worker_process\nS master", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.process.run_command", mock_run_command)

    obs = p.collect(ProviderContext({"process": "worker_process"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["process.zombie"].value["status"] == "FAIL"
    assert "zombie" in obs_map["process.zombie"].message
