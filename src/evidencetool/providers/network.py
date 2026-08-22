"""
Network provider — per PRODUCT_CONTRACT.md (V0.5 Observability Expansion).

Checks:
  - network.port_reachable
  - network.host_reachable
  - network.dns_resolvable
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any

from evidencetool.models.observation import Observation
from evidencetool.providers._shell import run_command
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider

COLLECTOR = "network_provider"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@provider("network")
class NetworkProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        host = context.get("host", "")
        target_host = context.get("target_host") or context.get("domain") or "127.0.0.1"
        port_str = context.get("port")
        port = int(port_str) if port_str and port_str.isdigit() else 80

        observations: list[Observation] = []

        if context.get("port") or context.get("target_host"):
            observations.append(self._check_port_reachable(target_host, port, host))

        observations.append(self._check_host_reachable(target_host, host))
        observations.append(self._check_dns_resolvable(target_host, host))

        return observations

    def _check_port_reachable(self, target_host: str, port: int, host: str | None) -> Observation:
        method = f"tcp_connect({target_host}:{port})"
        if host:
            # Remote agentless check via nc
            res = run_command(["nc", "-z", "-w", "2", target_host, str(port)], host=host)
            if not res.ran:
                msg = f"Could not check remote port: {res.error}"
                val: dict[str, Any] = {"status": "UNKNOWN"}
            elif res.returncode == 0:
                msg = f"Port {port} on {target_host} is reachable"
                val = {"status": "PASS", "target_host": target_host, "port": port}
            else:
                msg = f"Port {port} on {target_host} is unreachable / connection refused"
                val = {"status": "FAIL", "target_host": target_host, "port": port, "returncode": res.returncode}
        else:
            try:
                sock = socket.create_connection((target_host, port), timeout=2.0)
                sock.close()
                msg = f"Port {port} on {target_host} is reachable"
                val = {"status": "PASS", "target_host": target_host, "port": port}
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                msg = f"Port {port} on {target_host} is unreachable: {e}"
                val = {"status": "FAIL", "target_host": target_host, "port": port, "error": str(e)}

        return Observation(
            id="network.port_reachable",
            source="network",
            category="connectivity",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_host_reachable(self, target_host: str, host: str | None) -> Observation:
        method = f"ping -c 1 -W 2 {target_host}"
        res = run_command(["ping", "-c", "1", "-W", "2", target_host], host=host)
        if not res.ran:
            # Degrade to socket test if ping binary is missing / not permitted
            try:
                socket.getaddrinfo(target_host, None)
                msg = f"Host {target_host} is resolvable and addressable"
                val: dict[str, Any] = {"status": "PASS", "target_host": target_host}
            except Exception as e:
                msg = f"Host {target_host} is unreachable: {e}"
                val = {"status": "FAIL", "target_host": target_host, "error": str(e)}
        elif res.returncode == 0:
            msg = f"Host {target_host} responds to ping"
            val = {"status": "PASS", "target_host": target_host}
        else:
            msg = f"Host {target_host} did not respond to ping"
            val = {"status": "FAIL", "target_host": target_host, "returncode": res.returncode}

        return Observation(
            id="network.host_reachable",
            source="network",
            category="connectivity",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_dns_resolvable(self, target_host: str, host: str | None) -> Observation:
        method = f"dns_lookup({target_host})"
        if host:
            res = run_command(["getent", "hosts", target_host], host=host)
            if not res.ran:
                msg = f"Could not perform remote DNS lookup: {res.error}"
                val: dict[str, Any] = {"status": "UNKNOWN"}
            elif res.returncode == 0:
                msg = f"DNS lookup succeeded for {target_host}"
                val = {"status": "PASS", "resolved": True, "raw": res.stdout}
            else:
                msg = f"DNS resolution failed for {target_host}"
                val = {"status": "FAIL", "resolved": False}
        else:
            try:
                results = socket.getaddrinfo(target_host, None)
                ip = results[0][4][0] if results else "resolved"
                msg = f"DNS lookup succeeded for {target_host} ({ip})"
                val = {"status": "PASS", "resolved": True, "ip": ip}
            except (socket.gaierror, OSError) as e:
                msg = f"DNS lookup failed for {target_host}: {e}"
                val = {"status": "FAIL", "resolved": False, "error": str(e)}

        return Observation(
            id="network.dns_resolvable",
            source="network",
            category="connectivity",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )
