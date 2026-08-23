"""
Exhaustive case-by-case unit tests for Nginx Provider.
"""

from __future__ import annotations

from unittest.mock import Mock

from evidencetool.providers.base import ProviderContext
from evidencetool.providers.nginx import NginxProvider
from evidencetool.providers.registry import get_provider


def test_nginx_provider_registration():
    p = get_provider("nginx")
    assert isinstance(p, NginxProvider)


def test_nginx_config_exists_and_valid(monkeypatch):
    provider = NginxProvider()

    monkeypatch.setattr("evidencetool.providers.nginx.file_exists", lambda path, host=None: True)

    def mock_run_command(args, **kwargs):
        return Mock(ran=True, returncode=0, stdout="", stderr="nginx: configuration file /etc/nginx/nginx.conf test is successful")

    monkeypatch.setattr("evidencetool.providers.nginx.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"config_path": "/etc/nginx/nginx.conf"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["nginx.config_exists"].value["status"] == "PASS"
    assert obs_map["nginx.config_valid"].value["status"] == "PASS"


def test_nginx_config_missing(monkeypatch):
    provider = NginxProvider()

    monkeypatch.setattr("evidencetool.providers.nginx.file_exists", lambda path, host=None: False)

    obs = provider.collect(ProviderContext({"config_path": "/missing/nginx.conf"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["nginx.config_exists"].value["status"] == "FAIL"
    assert obs_map["nginx.config_valid"].value["status"] == "UNKNOWN"
    assert "configuration file does not exist" in obs_map["nginx.config_valid"].message


def test_nginx_config_syntax_error(monkeypatch):
    provider = NginxProvider()

    monkeypatch.setattr("evidencetool.providers.nginx.file_exists", lambda path, host=None: True)

    def mock_run_command(args, **kwargs):
        stderr = "nginx: [emerg] unknown directive \"invalid_directive\" in /etc/nginx/nginx.conf:10\nnginx: configuration file test failed"
        return Mock(ran=True, returncode=1, stdout="", stderr=stderr)

    monkeypatch.setattr("evidencetool.providers.nginx.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"config_path": "/etc/nginx/nginx.conf"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["nginx.config_valid"].value["status"] == "FAIL"
    assert "nginx: configuration file test failed" in obs_map["nginx.config_valid"].message


def test_nginx_config_readonly_benign_errors_ignored(monkeypatch):
    provider = NginxProvider()

    monkeypatch.setattr("evidencetool.providers.nginx.file_exists", lambda path, host=None: True)

    def mock_run_command(args, **kwargs):
        stderr = (
            "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"
            "2026/08/23 00:00:00 [emerg] 1234#1234: open() \"/var/log/nginx/access.log\" failed (13: Permission denied)\n"
            "nginx: configuration file /etc/nginx/nginx.conf test failed\n"
        )
        return Mock(ran=True, returncode=1, stdout="", stderr=stderr)

    monkeypatch.setattr("evidencetool.providers.nginx.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"config_path": "/etc/nginx/nginx.conf"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["nginx.config_valid"].value["status"] == "PASS"
    assert "ignoring read-only permission errors" in obs_map["nginx.config_valid"].message


def test_nginx_config_operational_real_error_after_syntax_ok(monkeypatch):
    provider = NginxProvider()

    monkeypatch.setattr("evidencetool.providers.nginx.file_exists", lambda path, host=None: True)

    def mock_run_command(args, **kwargs):
        stderr = (
            "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"
            "nginx: [emerg] cannot load certificate \"/etc/nginx/ssl/missing.crt\": BIO_new_file failed\n"
            "nginx: configuration file /etc/nginx/nginx.conf test failed\n"
        )
        return Mock(ran=True, returncode=1, stdout="", stderr=stderr)

    monkeypatch.setattr("evidencetool.providers.nginx.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"config_path": "/etc/nginx/nginx.conf"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["nginx.config_valid"].value["status"] == "FAIL"
    assert "cannot load certificate" in obs_map["nginx.config_valid"].message


def test_nginx_command_not_ran(monkeypatch):
    provider = NginxProvider()

    monkeypatch.setattr("evidencetool.providers.nginx.file_exists", lambda path, host=None: True)

    def mock_run_command(args, **kwargs):
        return Mock(ran=False, returncode=None, stdout="", stderr="", error="nginx executable not found")

    monkeypatch.setattr("evidencetool.providers.nginx.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"config_path": "/etc/nginx/nginx.conf"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["nginx.config_valid"].value["status"] == "UNKNOWN"
    assert "Could not run nginx" in obs_map["nginx.config_valid"].message
