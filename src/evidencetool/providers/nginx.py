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
        # nginx -t writes transiently to the pid file and error log paths
        # declared in the config it's testing. EvidenceTool is read-only by
        # design (NFR-002) — it must never depend on write access to the
        # real production paths (/run/nginx.pid, /var/log/nginx/error.log)
        # just to run a syntax check. Override both to a scratch location
        # nobody else depends on.
        override = (
            "pid /tmp/evidencetool-nginx-test.pid; "
            "error_log /tmp/evidencetool-nginx-test-error.log;"
        )
        method = f"nginx -t -c {config_path} -g '{override}'"
        result = run_command(
            ["nginx", "-t", "-c", config_path, "-g", override], host=host
        )

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
