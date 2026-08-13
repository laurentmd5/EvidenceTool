"""
TLS provider.

Checks:
  - tls.certificate_exists
  - tls.certificate_valid   (not expired, parseable)
  - tls.private_key_exists
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from evidencetool.models.observation import Observation
from evidencetool.providers._shell import run_command

COLLECTOR = "tls_provider"


def _now():
    return datetime.now(timezone.utc)


class TLSProvider:
    def collect(self, certificate_path: str, private_key_path: str) -> list[Observation]:
        return [
            self._certificate_exists(certificate_path),
            self._certificate_valid(certificate_path),
            self._private_key_exists(private_key_path),
            self._key_matches_certificate(certificate_path, private_key_path),
        ]

    def _certificate_exists(self, certificate_path: str) -> Observation:
        method = f"os.path.exists({certificate_path})"
        exists = os.path.exists(certificate_path)
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
        )

    def _certificate_valid(self, certificate_path: str) -> Observation:
        method = f"openssl x509 -in {certificate_path} -noout -checkend 0"

        if not os.path.exists(certificate_path):
            return Observation(
                id="tls.certificate_valid",
                source="tls",
                category="certificate",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN"},
                message="Cannot check validity: certificate file does not exist",
                observed_at=_now(),
            )

        result = run_command(
            ["openssl", "x509", "-in", certificate_path, "-noout", "-checkend", "0"]
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
        )

    def _private_key_exists(self, private_key_path: str) -> Observation:
        method = f"os.path.exists({private_key_path})"
        exists = os.path.exists(private_key_path)
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
        )

    def _key_matches_certificate(self, certificate_path: str, private_key_path: str) -> Observation:
        method = "openssl x509/rsa -modulus"

        if not os.path.exists(certificate_path) or not os.path.exists(private_key_path):
            return Observation(
                id="tls.key_matches_certificate",
                source="tls",
                category="certificate",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN"},
                message="Cannot verify match: certificate or key file is missing",
                observed_at=_now(),
            )

        cert_result = run_command(["openssl", "x509", "-noout", "-modulus", "-in", certificate_path])
        key_result = run_command(["openssl", "rsa", "-noout", "-modulus", "-in", private_key_path])

        if not cert_result.ran or not key_result.ran:
            status, message = "UNKNOWN", "Could not run openssl to extract moduli"
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
        )
