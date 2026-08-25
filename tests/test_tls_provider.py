"""
Exhaustive case-by-case unit tests for TLS Provider.
"""

from __future__ import annotations

from unittest.mock import Mock

from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import get_provider
from evidencetool.providers.tls import TLSProvider


def test_tls_provider_registration():
    p = get_provider("tls")
    assert isinstance(p, TLSProvider)


def test_tls_all_pass(monkeypatch):
    provider = TLSProvider()

    monkeypatch.setattr("evidencetool.providers.tls.file_exists", lambda path, host=None: True)

    def mock_run_command(args, **kwargs):
        if "-checkend" in args:
            return Mock(ran=True, returncode=0, stdout="", stderr="")
        if "-pubout" in args or "-pubkey" in args:
            return Mock(ran=True, returncode=0, stdout="PUBLIC_KEY\n", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.tls.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"certificate_path": "/tmp/cert.pem", "private_key_path": "/tmp/key.pem"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["tls.certificate_exists"].value["status"] == "PASS"
    assert obs_map["tls.certificate_valid"].value["status"] == "PASS"
    assert obs_map["tls.private_key_exists"].value["status"] == "PASS"
    assert obs_map["tls.key_matches_certificate"].value["status"] == "PASS"


def test_tls_files_missing(monkeypatch):
    provider = TLSProvider()

    monkeypatch.setattr("evidencetool.providers.tls.file_exists", lambda path, host=None: False)

    obs = provider.collect(ProviderContext({"certificate_path": "/tmp/cert.pem", "private_key_path": "/tmp/key.pem"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["tls.certificate_exists"].value["status"] == "FAIL"
    assert obs_map["tls.certificate_valid"].value["status"] == "UNKNOWN"
    assert obs_map["tls.private_key_exists"].value["status"] == "FAIL"
    assert obs_map["tls.key_matches_certificate"].value["status"] == "UNKNOWN"


def test_tls_certificate_expired(monkeypatch):
    provider = TLSProvider()

    monkeypatch.setattr("evidencetool.providers.tls.file_exists", lambda path, host=None: True)

    def mock_run_command(args, **kwargs):
        if "-checkend" in args:
            return Mock(ran=True, returncode=1, stdout="", stderr="Certificate will expire")
        if "-modulus" in args:
            return Mock(ran=True, returncode=0, stdout="Modulus=MATCH\n", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.tls.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"certificate_path": "/tmp/cert.pem", "private_key_path": "/tmp/key.pem"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["tls.certificate_exists"].value["status"] == "PASS"
    assert obs_map["tls.certificate_valid"].value["status"] == "FAIL"
    assert "expired" in obs_map["tls.certificate_valid"].message


def test_tls_key_mismatch(monkeypatch):
    provider = TLSProvider()

    monkeypatch.setattr("evidencetool.providers.tls.file_exists", lambda path, host=None: True)

    def mock_run_command(args, **kwargs):
        if "-checkend" in args:
            return Mock(ran=True, returncode=0, stdout="", stderr="")
        if "x509" in args and "-pubkey" in args:
            return Mock(ran=True, returncode=0, stdout="CERT_PUBLIC_KEY\n", stderr="")
        if "pkey" in args and "-pubout" in args:
            return Mock(ran=True, returncode=0, stdout="KEY_PUBLIC_KEY\n", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.tls.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"certificate_path": "/tmp/cert.pem", "private_key_path": "/tmp/key.pem"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["tls.key_matches_certificate"].value["status"] == "FAIL"
    assert "mismatch" in obs_map["tls.key_matches_certificate"].message


def test_tls_openssl_command_failure(monkeypatch):
    provider = TLSProvider()

    monkeypatch.setattr("evidencetool.providers.tls.file_exists", lambda path, host=None: True)

    def mock_run_command(args, **kwargs):
        return Mock(ran=False, returncode=None, stdout="", stderr="", error="openssl missing")

    monkeypatch.setattr("evidencetool.providers.tls.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"certificate_path": "/tmp/cert.pem", "private_key_path": "/tmp/key.pem"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["tls.certificate_valid"].value["status"] == "UNKNOWN"
    assert obs_map["tls.key_matches_certificate"].value["status"] == "UNKNOWN"
