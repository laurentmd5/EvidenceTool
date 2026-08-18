"""
Nginx provider.

Checks:
  - nginx.config_exists
  - nginx.config_valid
"""

from __future__ import annotations

from datetime import datetime, timezone

from evidencetool.models.observation import Observation
from evidencetool.providers._shell import file_exists, run_command
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider

COLLECTOR = "nginx_provider"
DEFAULT_CONFIG_PATH = "/etc/nginx/nginx.conf"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@provider("nginx")
class NginxProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        config_path = context.get("config_path", DEFAULT_CONFIG_PATH)
        host = context.get("host", "")
        return [
            self._config_exists(config_path, host),
            self._config_valid(config_path, host),
        ]

    def _config_exists(self, config_path: str, host: str | None) -> Observation:
        method = f"file_exists({config_path})"
        exists = file_exists(config_path, host=host)
        status = "PASS" if exists else "FAIL"
        message = (
            f"Configuration file found at {config_path}"
            if exists
            else f"Configuration file not found at {config_path}"
        )
        return Observation(
            id="nginx.config_exists",
            source="nginx",
            category="configuration",
            collector=COLLECTOR,
            method=method,
            value={"status": status, "path": config_path},
            message=message,
            observed_at=_now(),
            host=host,
        )

    def _config_valid(self, config_path: str, host: str | None) -> Observation:
        method = f"nginx -t -c {config_path}"

        if not file_exists(config_path, host=host):
            return Observation(
                id="nginx.config_valid",
                source="nginx",
                category="configuration",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN"},
                message="Cannot check validity: configuration file does not exist",
                observed_at=_now(),
                host=host,
            )

        args = ["nginx", "-t", "-c", config_path]
        result = run_command(args, host=host)

        if not result.ran:
            status, message = "UNKNOWN", f"Could not run nginx: {result.error}"
        else:
            output = result.stderr or ""
            if result.returncode == 0:
                status, message = "PASS", "nginx -t reports configuration is valid"
            elif "syntax is ok" in output:
                # Nginx parsed the syntax successfully, but failed later.
                # Since EvidenceTool runs as a read-only user (NFR-002), we expect permission
                # denied errors when Nginx tries to open log/pid files for writing.
                # We must filter these out, but FAIL on any other operational [emerg].
                real_errors = []
                for line in output.splitlines():
                    is_error = "[emerg]" in line or "[alert]" in line or "[crit]" in line
                    is_benign = "Permission denied" in line and ("open()" in line or "mkdir()" in line)
                    if is_error and not is_benign:
                        real_errors.append(line.strip())

                if not real_errors:
                    status = "PASS"
                    message = "nginx -t reports syntax is ok (ignoring read-only permission errors on logs/pid)"
                else:
                    status = "FAIL"
                    message = f"nginx -t failed operationally: {real_errors[0]}"
            else:
                # Syntax error or other fatal error before 'syntax is ok'
                last_line = output.strip().splitlines()[-1] if output.strip() else ""
                status = "FAIL"
                message = f"nginx -t failed: {last_line}"

        return Observation(
            id="nginx.config_valid",
            source="nginx",
            category="configuration",
            collector=COLLECTOR,
            method=method,
            value={"status": status, "stderr": result.stderr},
            message=message,
            observed_at=_now(),
            host=host,
        )
