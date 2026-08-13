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
from evidencetool.providers._shell import run_command

COLLECTOR = "nginx_provider"
DEFAULT_CONFIG_PATH = "/etc/nginx/nginx.conf"


def _now():
    return datetime.now(timezone.utc)


class NginxProvider:
    def collect(self, config_path: str = DEFAULT_CONFIG_PATH) -> list[Observation]:
        return [
            self._config_exists(config_path),
            self._config_valid(config_path),
        ]

    def _config_exists(self, config_path: str) -> Observation:
        method = f"os.path.exists({config_path})"
        exists = os.path.exists(config_path)
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
        )

    def _config_valid(self, config_path: str) -> Observation:
        method = f"nginx -t -c {config_path}"
        result = run_command(["nginx", "-t", "-c", config_path])

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
        )
