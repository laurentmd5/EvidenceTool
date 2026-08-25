"""
Network provider — per PRODUCT_CONTRACT.md (V0.5 Observability Expansion).

Checks:
  - network.port_reachable
  - network.host_reachable
  - network.dns_resolvable
"""

from __future__ import annotations

import math
import socket
from datetime import datetime, timezone
from typing import Any

from evidencetool.capability.models import CapabilityDenied
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
        self._capabilities = context.execution.capabilities
        self._probe_count = 0
        host = context.get("host", "")
        target_host = context.get("target_host") or context.get("domain") or "127.0.0.1"
        port_str = context.get("port")
        if port_str:
            try:
                port = int(port_str)
            except ValueError as exc:
                raise ValueError("port must be an integer between 1 and 65535") from exc
            if not 1 <= port <= 65535:
                raise ValueError("port must be an integer between 1 and 65535")
        else:
            port = 80

        observations: list[Observation] = []

        if context.get("port") or context.get("target_host"):
            observations.append(self._check_port_reachable(target_host, port, host))

        observations.append(self._check_host_reachable(target_host, host))
        observations.append(self._check_dns_resolvable(target_host, host))

        return observations

    def _check_port_reachable(self, target_host: str, port: int, host: str | None) -> Observation:
        method = f"tcp_connect({target_host}:{port})"
        try:
            self._require_network("tcp_connect", target_host, port, host)
        except CapabilityDenied as exc:
            return self._unknown_observation(
                "network.port_reachable", method, target_host, "tcp_connect", host, str(exc)
            )
        if host:
            # Remote agentless check via nc
            timeout = self._probe_timeout()
            res = run_command(["nc", "-z", "-w", str(timeout), target_host, str(port)], timeout=timeout + 1, host=host)
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
                sock = socket.create_connection((target_host, port), timeout=self._probe_timeout())
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
            execution_scope="remote" if host else "local",
            target=target_host,
            capability="tcp_connect",
            transport_status="executed",
        )

    def _check_host_reachable(self, target_host: str, host: str | None) -> Observation:
        timeout = self._probe_timeout()
        method = f"ping -c 1 -W {timeout} {target_host}"
        try:
            self._require_network("icmp_echo", target_host, None, host)
        except CapabilityDenied as exc:
            return self._unknown_observation(
                "network.host_reachable", method, target_host, "icmp_echo", host, str(exc)
            )
        res = run_command(["ping", "-c", "1", "-W", str(timeout), target_host], timeout=timeout + 1, host=host)
        if not res.ran:
            if host:
                return self._unknown_observation(
                    "network.host_reachable", method, target_host, "icmp_echo", host,
                    f"Could not execute remote ping: {res.error}", capability_denied=False,
                )
            # Degrade to address resolution only for local collection.
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
            execution_scope="remote" if host else "local",
            target=target_host,
            capability="icmp_echo",
            transport_status="executed",
        )

    def _check_dns_resolvable(self, target_host: str, host: str | None) -> Observation:
        method = f"dns_lookup({target_host})"
        try:
            self._require_network("dns_lookup", target_host, None, host)
        except CapabilityDenied as exc:
            return self._unknown_observation(
                "network.dns_resolvable", method, target_host, "dns_lookup", host, str(exc)
            )
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
            execution_scope="remote" if host else "local",
            target=target_host,
            capability="dns_lookup",
            transport_status="executed",
        )

    def _require_network(self, operation: str, target: str, port: int | None, host: str | None) -> None:
        del host
        self._capabilities.require_network(operation, target, port)
        max_probes = self._capabilities.network.max_probes
        if max_probes is not None and self._probe_count >= max_probes:
            raise CapabilityDenied("Network probe limit has been reached.")
        self._probe_count += 1

    def _probe_timeout(self) -> float:
        return max(1, math.ceil(self._capabilities.network.timeout_seconds))

    def _unknown_observation(
        self,
        evidence_id: str,
        method: str,
        target: str,
        capability: str,
        host: str | None,
        reason: str,
        capability_denied: bool = True,
    ) -> Observation:
        return Observation(
            id=evidence_id,
            source="network",
            category="connectivity",
            collector=COLLECTOR,
            method=method,
            value={"status": "UNKNOWN", "capability_denied": capability_denied},
            message=(
                f"Network capability denied: {reason}"
                if capability_denied
                else reason
            ),
            observed_at=_now(),
            host=host,
            execution_scope="remote" if host else "local",
            target=target,
            capability=capability,
            transport_status="capability_denied",
        )
