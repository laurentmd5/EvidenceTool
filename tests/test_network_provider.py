"""
Unit tests for Network provider.
"""

from __future__ import annotations

from unittest.mock import Mock

from evidencetool.providers.base import ProviderContext
from evidencetool.providers.network import NetworkProvider
from evidencetool.providers.registry import get_provider


def test_network_provider_registration():
    p = get_provider("network")
    assert isinstance(p, NetworkProvider)


def test_network_local_host_reachable_ping_success(monkeypatch):
    provider = NetworkProvider()

    def mock_run_command(args, **kwargs):
        if "ping" in args:
            return Mock(ran=True, returncode=0, stdout="1 packets transmitted, 1 received", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.network.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"target_host": "127.0.0.1"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["network.host_reachable"].value["status"] == "PASS"


def test_network_host_unreachable(monkeypatch):
    provider = NetworkProvider()

    def mock_run_command(args, **kwargs):
        if "ping" in args:
            return Mock(ran=True, returncode=1, stdout="", stderr="Destination Host Unreachable")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.network.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"target_host": "192.0.2.1"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["network.host_reachable"].value["status"] == "FAIL"


def test_network_port_reachable_remote_nc(monkeypatch):
    provider = NetworkProvider()

    def mock_run_command(args, **kwargs):
        if "nc" in args:
            return Mock(ran=True, returncode=0, stdout="", stderr="")
        if "ping" in args:
            return Mock(ran=True, returncode=0, stdout="", stderr="")
        if "getent" in args:
            return Mock(ran=True, returncode=0, stdout="127.0.0.1 localhost", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.network.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"target_host": "127.0.0.1", "port": "8080", "host": "remote-node"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["network.port_reachable"].value["status"] == "PASS"
    assert obs_map["network.dns_resolvable"].value["status"] == "PASS"


def test_network_dns_resolvable_failure(monkeypatch):
    provider = NetworkProvider()

    def mock_run_command(args, **kwargs):
        if "getent" in args:
            return Mock(ran=True, returncode=2, stdout="", stderr="Unknown host")
        if "ping" in args:
            return Mock(ran=True, returncode=1, stdout="", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.network.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"target_host": "invalid.nonexistent.domain.xyz", "host": "remote-node"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["network.dns_resolvable"].value["status"] == "FAIL"
