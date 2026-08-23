"""
Exhaustive case-by-case unit tests for Systemd Provider.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import get_provider
from evidencetool.providers.systemd import SystemdProvider


def test_systemd_provider_registration():
    p = get_provider("systemd")
    assert isinstance(p, SystemdProvider)


def test_systemd_missing_context():
    provider = SystemdProvider()
    with pytest.raises(ValueError, match="Missing required context variable: service"):
        provider.collect(ProviderContext({}))


def test_systemd_service_exists_loaded(monkeypatch):
    provider = SystemdProvider()

    def mock_run_command(args, **kwargs):
        if "LoadState" in args:
            return Mock(ran=True, returncode=0, stdout="LoadState=loaded\n", stderr="")
        if "is-active" in args:
            return Mock(ran=True, returncode=0, stdout="active\n", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.systemd.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"service": "nginx"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["systemd.service_exists"].value["status"] == "PASS"
    assert "loaded" in obs_map["systemd.service_exists"].message
    assert obs_map["systemd.service_active"].value["status"] == "PASS"
    assert "is active" in obs_map["systemd.service_active"].message


def test_systemd_service_not_found(monkeypatch):
    provider = SystemdProvider()

    def mock_run_command(args, **kwargs):
        if "LoadState" in args:
            return Mock(ran=True, returncode=0, stdout="LoadState=not-found\n", stderr="")
        if "is-active" in args:
            return Mock(ran=True, returncode=3, stdout="inactive\n", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.systemd.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"service": "unknown_svc"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["systemd.service_exists"].value["status"] == "FAIL"
    assert "not found" in obs_map["systemd.service_exists"].message
    assert obs_map["systemd.service_active"].value["status"] == "FAIL"


def test_systemd_unexpected_load_state(monkeypatch):
    provider = SystemdProvider()

    def mock_run_command(args, **kwargs):
        if "LoadState" in args:
            return Mock(ran=True, returncode=0, stdout="LoadState=masked\n", stderr="")
        if "is-active" in args:
            return Mock(ran=True, returncode=0, stdout="custom_state\n", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.systemd.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"service": "masked_svc"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["systemd.service_exists"].value["status"] == "UNKNOWN"
    assert "Unexpected LoadState" in obs_map["systemd.service_exists"].message
    assert obs_map["systemd.service_active"].value["status"] == "UNKNOWN"


def test_systemd_command_not_ran(monkeypatch):
    provider = SystemdProvider()

    def mock_run_command(args, **kwargs):
        return Mock(ran=False, returncode=None, stdout="", stderr="", error="systemctl binary not found")

    monkeypatch.setattr("evidencetool.providers.systemd.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"service": "nginx"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["systemd.service_exists"].value["status"] == "UNKNOWN"
    assert "Could not query systemd" in obs_map["systemd.service_exists"].message
    assert obs_map["systemd.service_active"].value["status"] == "UNKNOWN"


def test_systemd_command_error_returncode(monkeypatch):
    provider = SystemdProvider()

    def mock_run_command(args, **kwargs):
        return Mock(ran=True, returncode=1, stdout="", stderr="Failed to connect to bus")

    monkeypatch.setattr("evidencetool.providers.systemd.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"service": "nginx"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["systemd.service_exists"].value["status"] == "UNKNOWN"
    assert "systemctl exited 1" in obs_map["systemd.service_exists"].message


def test_systemd_remote_host(monkeypatch):
    provider = SystemdProvider()

    captured_host = []
    def mock_run_command(args, host=None, **kwargs):
        captured_host.append(host)
        return Mock(ran=True, returncode=0, stdout="LoadState=loaded\n", stderr="")

    monkeypatch.setattr("evidencetool.providers.systemd.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"service": "nginx", "host": "web-node-01"}))
    assert all(h == "web-node-01" for h in captured_host)
    assert obs[0].host == "web-node-01"
