"""
Systemd provider.

Checks:
  - systemd.service_exists
  - systemd.service_active
"""

from __future__ import annotations

from datetime import datetime, timezone

from evidencetool.models.observation import Observation
from evidencetool.providers._shell import run_command
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider

COLLECTOR = "systemd_provider"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@provider("systemd")
class SystemdProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        service = context.require("service")
        host = context.get("host", "")
        return [
            self._service_exists(service, host),
            self._service_active(service, host),
        ]

    def _service_exists(self, service: str, host: str | None) -> Observation:
        method = f"systemctl show {service}.service -p LoadState"
        result = run_command(["systemctl", "show", f"{service}.service", "-p", "LoadState"], host=host)

        if not result.ran:
            status, message = "UNKNOWN", f"Could not query systemd: {result.error}"
        elif result.returncode != 0:
            status, message = "UNKNOWN", f"systemctl exited {result.returncode}: {result.stderr}"
        else:
            load_state = result.stdout.replace("LoadState=", "").strip()
            if load_state == "loaded":
                status, message = "PASS", f"Unit {service}.service is loaded"
            elif load_state in ("not-found", ""):
                status, message = "FAIL", f"Unit {service}.service not found"
            else:
                status, message = "UNKNOWN", f"Unexpected LoadState: {load_state}"

        return Observation(
            id="systemd.service_exists",
            source="systemd",
            category="service",
            collector=COLLECTOR,
            method=method,
            value={"status": status, "raw": result.stdout},
            message=message,
            observed_at=_now(),
            host=host,
        )

    def _service_active(self, service: str, host: str | None) -> Observation:
        method = f"systemctl is-active {service}"
        result = run_command(["systemctl", "is-active", service], host=host)

        if not result.ran:
            status, message = "UNKNOWN", f"Could not query systemd: {result.error}"
        else:
            state = result.stdout.strip()
            if state == "active":
                status, message = "PASS", f"{service} is active"
            elif state in ("inactive", "failed", "activating", "deactivating", "unknown"):
                status, message = "FAIL", f"{service} is {state}"
            else:
                status, message = "UNKNOWN", f"Unexpected systemctl state: {state}"

        return Observation(
            id="systemd.service_active",
            source="systemd",
            category="service",
            collector=COLLECTOR,
            method=method,
            value={"status": status, "raw": result.stdout},
            message=message,
            observed_at=_now(),
            host=host,
        )
