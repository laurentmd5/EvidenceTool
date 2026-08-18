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
        import os
        config_dir = os.path.dirname(config_path) or "/etc/nginx"

        override = (
            "pid /tmp/evidencetool-nginx-test.pid; "
            "error_log /tmp/evidencetool-nginx-test-error.log;"
        )

        # We use a temporary config file stripped of 'pid' and 'error_log'
        # to avoid "duplicate directive" errors when passing -g.
        # NFR-005: To prevent shell injection via config_path, dynamic values
        # are passed safely as positional arguments to sh -c, rather than interpolated.
        script = (
            "tmp=$(mktemp) && "
            "sed -e '/^[[:space:]]*pid[[:space:]]/d' -e '/^[[:space:]]*error_log[[:space:]]/d' \"$1\" > \"$tmp\" && "
            "nginx -t -c \"$tmp\" -p \"$2\" -g \"$3\"; "
            "code=$?; rm -f \"$tmp\"; exit $code"
        )
        method = f"nginx -t -c {config_path} (filtered read-only)"

        args = ["sh", "-c", script, "sh", config_path, config_dir, override]
        result = run_command(args, host=host)

        if not result.ran:
            status, message = "UNKNOWN", f"Could not run nginx: {result.error}"
        elif result.returncode == 0:
            status, message = "PASS", "nginx -t reports configuration is valid"
        else:
            status, message = "FAIL", f"nginx -t failed: {result.stderr or result.stdout}"

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
