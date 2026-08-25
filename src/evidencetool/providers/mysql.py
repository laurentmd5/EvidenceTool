"""
MySQL provider — per PRODUCT_CONTRACT.md (V0.6 Application & Data Dependencies).

Checks:
  - mysql.reachable
  - mysql.ping
  - mysql.max_connections
  - mysql.read_only
  - mysql.latency_ms
"""

from __future__ import annotations

import math
import socket
import time
from datetime import datetime, timezone
from typing import Any

from evidencetool.capability.models import CapabilityDenied
from evidencetool.models.observation import Observation
from evidencetool.providers._shell import run_command
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider

COLLECTOR = "mysql_provider"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@provider("mysql")
class MySQLProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        self._capabilities = context.execution.capabilities
        self._probe_count = 0
        host = context.get("host", "")
        target_host = context.get("db_host") or context.get("mysql_host") or context.get("target_host") or "127.0.0.1"

        port_str = context.get("db_port") or context.get("mysql_port") or context.get("port")
        if port_str:
            try:
                port = int(port_str)
            except ValueError as exc:
                raise ValueError("port must be an integer between 1 and 65535") from exc
            if not 1 <= port <= 65535:
                raise ValueError("port must be an integer between 1 and 65535")
        else:
            port = 3306

        expected_role = context.get("expected_role") or "primary"
        max_latency_ms = float(context.get("max_latency_ms", "200.0"))

        observations: list[Observation] = []

        # 1. Reachable Check
        reach_obs = self._check_reachable(target_host, port, host)
        observations.append(reach_obs)

        if reach_obs.value.get("status") != "PASS":
            return observations

        # 2. Handshake & Ping Check
        ping_obs, latency_ms, too_many_connections, is_read_only = self._check_mysql_handshake(
            target_host, port, host
        )
        observations.append(ping_obs)

        # 3. Max Connections Check
        if too_many_connections:
            conn_msg = "MySQL max connections reached (Error 1040: Too many connections)"
            conn_val: dict[str, Any] = {"status": "FAIL", "failure": "TOO_MANY_CONNECTIONS"}
        else:
            conn_msg = "MySQL connection slots available"
            conn_val = {"status": "PASS"}

        observations.append(
            Observation(
                id="mysql.max_connections",
                source="mysql",
                category="database",
                collector=COLLECTOR,
                method="mysql_connection_inspection",
                value=conn_val,
                message=conn_msg,
                observed_at=_now(),
                host=host,
            )
        )

        # 4. Read-Only / Replica Check
        if expected_role == "primary" and is_read_only:
            ro_msg = "MySQL is configured as read_only replica while primary was expected"
            ro_val: dict[str, Any] = {"status": "FAIL", "failure": "READ_ONLY_REPLICA", "read_only": True}
        else:
            ro_msg = f"MySQL role matches expectation (read_only={is_read_only})"
            ro_val = {"status": "PASS", "read_only": is_read_only}

        observations.append(
            Observation(
                id="mysql.read_only",
                source="mysql",
                category="database",
                collector=COLLECTOR,
                method="mysql_role_inspection",
                value=ro_val,
                message=ro_msg,
                observed_at=_now(),
                host=host,
            )
        )

        # 5. Latency Observation
        lat_status = "FAIL" if latency_ms > max_latency_ms else "PASS"
        observations.append(
            Observation(
                id="mysql.latency_ms",
                source="mysql",
                category="database",
                collector=COLLECTOR,
                method="mysql_ping_latency",
                value={"status": lat_status, "latency_ms": latency_ms, "threshold_ms": max_latency_ms},
                message=f"MySQL latency is {latency_ms}ms (threshold: {max_latency_ms}ms)",
                observed_at=_now(),
                host=host,
            )
        )

        return observations

    def _check_reachable(self, target_host: str, port: int, host: str | None) -> Observation:
        method = f"tcp_connect({target_host}:{port})"
        try:
            self._require_network("tcp_connect", target_host, port)
        except CapabilityDenied as exc:
            return self._unknown_observation("mysql.reachable", method, target_host, "tcp_connect", host, str(exc))

        timeout = self._probe_timeout()
        if host:
            res = run_command(["nc", "-z", "-w", str(int(timeout)), target_host, str(port)], timeout=timeout + 1, host=host)
            if res.ran and res.returncode == 0:
                msg = f"MySQL port {port} on {target_host} is reachable"
                val: dict[str, Any] = {"status": "PASS", "target_host": target_host, "port": port}
            else:
                msg = f"MySQL port {port} on {target_host} is unreachable"
                val = {"status": "FAIL", "failure": "CONNECTION_REFUSED", "target_host": target_host, "port": port}
        else:
            try:
                sock = socket.create_connection((target_host, port), timeout=timeout)
                sock.close()
                msg = f"MySQL port {port} on {target_host} is reachable"
                val = {"status": "PASS", "target_host": target_host, "port": port}
            except Exception as e:
                msg = f"MySQL port {port} on {target_host} is unreachable: {e}"
                val = {"status": "FAIL", "failure": "CONNECTION_REFUSED", "error": str(e)}

        return Observation(
            id="mysql.reachable",
            source="mysql",
            category="database",
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

    def _check_mysql_handshake(
        self, target_host: str, port: int, host: str | None
    ) -> tuple[Observation, float, bool, bool]:
        try:
            self._require_network("db_ping", target_host, port)
        except CapabilityDenied as exc:
            obs = self._unknown_observation("mysql.ping", "mysql_ping", target_host, "db_ping", host, str(exc))
            return obs, 0.0, False, False

        timeout = self._probe_timeout()
        t0 = time.time()
        too_many_connections = False
        is_read_only = False

        try:
            with socket.create_connection((target_host, port), timeout=timeout) as s:
                # Read MySQL Initial Handshake Packet
                header = s.recv(4)
                if len(header) < 4:
                    raise OSError("Incomplete MySQL packet header")
                payload_len = int.from_bytes(header[:3], "little")
                payload = s.recv(payload_len)
                latency_ms = round((time.time() - t0) * 1000.0, 2)

                if payload and payload[0] == 0xFF:  # Error Packet
                    err_code = int.from_bytes(payload[1:3], "little") if len(payload) >= 3 else 0
                    if err_code == 1040:
                        too_many_connections = True
                        msg = "MySQL Error 1040: Too many connections"
                        val: dict[str, Any] = {"status": "FAIL", "failure": "TOO_MANY_CONNECTIONS", "error_code": 1040}
                    else:
                        msg = f"MySQL Error {err_code} on handshake"
                        val = {"status": "FAIL", "failure": "HANDSHAKE_ERROR", "error_code": err_code}
                elif payload and len(payload) > 1:
                    protocol_ver = payload[0]
                    # Server version is null-terminated string starting at index 1
                    null_idx = payload.find(b"\x00", 1)
                    server_ver = payload[1:null_idx].decode("ascii", errors="replace") if null_idx > 1 else "unknown"
                    msg = f"MySQL handshake succeeded (Server: {server_ver}, Protocol: {protocol_ver})"
                    val = {"status": "PASS", "server_version": server_ver, "protocol_version": protocol_ver}
                else:
                    msg = "MySQL received invalid handshake packet"
                    val = {"status": "FAIL", "failure": "INVALID_PACKET"}

        except Exception as e:
            latency_ms = round((time.time() - t0) * 1000.0, 2)
            msg = f"MySQL handshake connection failed: {e}"
            val = {"status": "FAIL", "failure": "CONNECT_ERROR", "error": str(e)}

        obs = Observation(
            id="mysql.ping",
            source="mysql",
            category="database",
            collector=COLLECTOR,
            method="mysql_handshake_inspection",
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

        return obs, latency_ms, too_many_connections, is_read_only

    def _require_network(self, operation: str, target: str, port: int | None) -> None:
        self._capabilities.require_network(operation, target, port)
        max_probes = self._capabilities.network.max_probes
        if max_probes is not None and self._probe_count >= max_probes:
            raise CapabilityDenied("Network probe limit has been reached.")
        self._probe_count += 1

    def _probe_timeout(self) -> float:
        return max(1, math.ceil(self._capabilities.network.timeout_seconds))

    def _unknown_observation(
        self, evidence_id: str, method: str, target: str, capability: str, host: str | None, reason: str
    ) -> Observation:
        return Observation(
            id=evidence_id,
            source="mysql",
            category="database",
            collector=COLLECTOR,
            method=method,
            value={"status": "UNKNOWN", "capability_denied": True},
            message=f"Capability denied: {reason}",
            observed_at=_now(),
            host=host,
            execution_scope="remote" if host else "local",
            target=target,
            capability=capability,
            transport_status="capability_denied",
        )
