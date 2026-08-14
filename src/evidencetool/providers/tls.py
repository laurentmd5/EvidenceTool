"""
TLS Provider.

Produces evidence about TLS certificates and keys.

- tls.certificate_exists
- tls.certificate_valid
- tls.private_key_exists
- tls.key_matches_certificate
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from evidencetool.models.observation import Observation
from evidencetool.providers._shell import run_command, file_exists
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider

COLLECTOR = "tls_provider"
DEFAULT_CERT_PATH = "/etc/letsencrypt/live/example.com/fullchain.pem"
DEFAULT_KEY_PATH = "/etc/letsencrypt/live/example.com/privkey.pem"


def _now():
    return datetime.now(timezone.utc)


@provider("tls")
class TLSProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        certificate_path = context.get("certificate_path", DEFAULT_CERT_PATH)
        private_key_path = context.get("private_key_path", DEFAULT_KEY_PATH)
        host = context.get("host", None)
        return [
            self._certificate_exists(certificate_path, host),
            self._certificate_valid(certificate_path, host),
            self._private_key_exists(private_key_path, host),
            self._key_matches_certificate(certificate_path, private_key_path, host),
        ]

    def _certificate_exists(self, certificate_path: str, host: str | None) -> Observation:
        method = f"file_exists({certificate_path})"
        exists = file_exists(certificate_path, host=host)
        status = "PASS" if exists else "FAIL"
        message = (
            f"Certificate found at {certificate_path}"
            if exists
            else f"Certificate not found at {certificate_path}"
        )
        return Observation(
            id="tls.certificate_exists",
            source="tls",
            category="certificate",
            collector=COLLECTOR,
            method=method,
            value={"status": status, "path": certificate_path},
            message=message,
            observed_at=_now(),
            host=host,
        )

    def _certificate_valid(self, certificate_path: str, host: str | None) -> Observation:
        method = f"openssl x509 -in {certificate_path} -noout -checkend 0"

        if not file_exists(certificate_path, host=host):
            return Observation(
                id="tls.certificate_valid",
                source="tls",
                category="certificate",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN"},
                message="Cannot check validity: certificate file does not exist",
                observed_at=_now(),
                host=host,
            )

        result = run_command(
            ["openssl", "x509", "-in", certificate_path, "-noout", "-checkend", "0"],
            host=host
        )

        if not result.ran:
            status, message = "UNKNOWN", f"Could not run openssl: {result.error}"
        elif result.returncode == 0:
            status, message = "PASS", "Certificate is valid and not expired"
        elif result.returncode == 1:
            status, message = "FAIL", "Certificate is expired or invalid"
        else:
            status, message = "UNKNOWN", f"openssl exited {result.returncode}: {result.stderr}"

        return Observation(
            id="tls.certificate_valid",
            source="tls",
            category="certificate",
            collector=COLLECTOR,
            method=method,
            value={"status": status},
            message=message,
            observed_at=_now(),
            host=host,
        )

    def _private_key_exists(self, private_key_path: str, host: str | None) -> Observation:
        method = f"file_exists({private_key_path})"
        exists = file_exists(private_key_path, host=host)
        status = "PASS" if exists else "FAIL"
        message = (
            f"Private key found at {private_key_path}"
            if exists
            else f"Private key not found at {private_key_path}"
        )
        return Observation(
            id="tls.private_key_exists",
            source="tls",
            category="certificate",
            collector=COLLECTOR,
            method=method,
            value={"status": status, "path": private_key_path},
            message=message,
            observed_at=_now(),
            host=host,
        )

    def _key_matches_certificate(self, certificate_path: str, private_key_path: str, host: str | None) -> Observation:
        method = "openssl x509/rsa -modulus"

        if not file_exists(certificate_path, host=host) or not file_exists(private_key_path, host=host):
            return Observation(
                id="tls.key_matches_certificate",
                source="tls",
                category="certificate",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN"},
                message="Cannot verify match: certificate or key file is missing",
                observed_at=_now(),
                host=host,
            )

        cert_result = run_command(["openssl", "x509", "-noout", "-modulus", "-in", certificate_path], host=host)
        key_result = run_command(["openssl", "rsa", "-noout", "-modulus", "-in", private_key_path], host=host)

        if not cert_result.ran or not key_result.ran:
            error_msg = cert_result.error if not cert_result.ran else key_result.error
            status, message = "UNKNOWN", f"Could not run openssl to extract moduli: {error_msg}"
        elif cert_result.returncode != 0 or key_result.returncode != 0:
            status, message = "UNKNOWN", "Failed to extract modulus from certificate or key"
        else:
            cert_modulus = cert_result.stdout.strip()
            key_modulus = key_result.stdout.strip()
            
            if cert_modulus == key_modulus:
                status, message = "PASS", "Certificate and private key moduli match"
            else:
                status, message = "FAIL", "Certificate and private key mismatch: moduli are different"

        return Observation(
            id="tls.key_matches_certificate",
            source="tls",
            category="certificate",
            collector=COLLECTOR,
            method=method,
            value={"status": status},
            message=message,
            observed_at=_now(),
            host=host,
        )
