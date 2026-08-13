"""
Nginx provider.

Checks:
  - nginx.config_exists
  - nginx.config_valid
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from evidencetool.models.observation import Observation
from evidencetool.providers._shell import run_command, file_exists
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider

COLLECTOR = "nginx_provider"
DEFAULT_CONFIG_PATH = "/etc/nginx/nginx.conf"


def _now():
    return datetime.now(timezone.utc)


@provider("nginx")
class NginxProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        config_path = context.get("config_path", DEFAULT_CONFIG_PATH)
        host = context.get("host", None)
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
        result = run_command(["nginx", "-t", "-c", config_path], host=host)

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
