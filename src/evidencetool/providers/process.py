"""
Process provider — per PRODUCT_CONTRACT.md (V0.5 Observability Expansion).

Checks:
  - process.running
  - process.zombie
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from evidencetool.models.observation import Observation
from evidencetool.providers._shell import run_command
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider

COLLECTOR = "process_provider"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@provider("process")
class ProcessProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        process_name = context.get("process") or context.get("process_name")
        if not process_name:
            process_name = context.require("process")
        host = context.get("host", "")

        return [
            self._check_running(process_name, host),
            self._check_zombie(process_name, host),
        ]

    def _check_running(self, process_name: str, host: str | None) -> Observation:
        method = f"pgrep -x {process_name}"
        res = run_command(["pgrep", "-x", process_name], host=host)

        if not res.ran:
            # Fallback to ps -C if pgrep missing
            ps_res = run_command(["ps", "-C", process_name, "-o", "pid="], host=host)
            if not ps_res.ran:
                msg = f"Could not inspect processes: {res.error}"
                val: dict[str, Any] = {"status": "UNKNOWN"}
            elif ps_res.returncode == 0 and ps_res.stdout.strip():
                pids = ps_res.stdout.strip().split()
                msg = f"Process '{process_name}' is running (PIDs: {', '.join(pids)})"
                val = {"status": "PASS", "running": True, "pids": pids}
            else:
                msg = f"Process '{process_name}' is not running"
                val = {"status": "FAIL", "running": False}
        elif res.returncode == 0 and res.stdout.strip():
            pids = res.stdout.strip().split()
            msg = f"Process '{process_name}' is running (PIDs: {', '.join(pids)})"
            val = {"status": "PASS", "running": True, "pids": pids}
        else:
            msg = f"Process '{process_name}' is not running"
            val = {"status": "FAIL", "running": False}

        return Observation(
            id="process.running",
            source="process",
            category="system",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_zombie(self, process_name: str, host: str | None) -> Observation:
        method = "ps -eo state,comm"
        res = run_command(["ps", "-eo", "state,comm"], host=host)

        if not res.ran:
            msg = f"Could not inspect process states: {res.error}"
            val: dict[str, Any] = {"status": "UNKNOWN"}
        elif res.returncode != 0:
            msg = f"ps command failed with code {res.returncode}: {res.stderr}"
            val = {"status": "UNKNOWN", "returncode": res.returncode}
        else:
            zombies = []
            for line in res.stdout.splitlines():
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2:
                    st, comm = parts[0], parts[1]
                    if st.upper().startswith("Z") and process_name in comm:
                        zombies.append(comm)

            if zombies:
                msg = f"Found {len(zombies)} zombie process(es) matching '{process_name}'"
                val = {"status": "FAIL", "zombies": zombies}
            else:
                msg = f"No zombie processes detected for '{process_name}'"
                val = {"status": "PASS", "zombies": []}

        return Observation(
            id="process.zombie",
            source="process",
            category="system",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )
