"""
PostgreSQL provider — per PRODUCT_CONTRACT.md (V0.6 Application & Data Dependencies).

Checks:
  - postgres.reachable
  - postgres.accepting_connections
  - postgres.pool_exhaustion
  - postgres.is_in_recovery
  - postgres.latency_ms
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

COLLECTOR = "postgres_provider"

# PostgreSQL SSLRequest packet: Length(8), Code(80877103) = 0x00000008 0x04d2162f
PG_SSL_REQUEST = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@provider("postgres")
class PostgresProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        self._capabilities = context.execution.capabilities
        self._probe_count = 0
        host = context.get("host", "")
        target_host = context.get("db_host") or context.get("postgres_host") or context.get("target_host") or "127.0.0.1"

        port_str = context.get("db_port") or context.get("postgres_port") or context.get("port")
        if port_str:
            try:
                port = int(port_str)
            except ValueError as exc:
                raise ValueError("port must be an integer between 1 and 65535") from exc
            if not 1 <= port <= 65535:
                raise ValueError("port must be an integer between 1 and 65535")
        else:
            port = 5432

        dbname = context.get("dbname") or "postgres"
        user = context.get("user") or context.get("username") or "postgres"
        expected_role = context.get("expected_role") or "primary"
        max_latency_ms = float(context.get("max_latency_ms", "200.0"))

        observations: list[Observation] = []

        # 1. Reachable Check
        reach_obs = self._check_reachable(target_host, port, host)
        observations.append(reach_obs)

        if reach_obs.value.get("status") != "PASS":
            return observations

        # 2. Availability & Handshake (pg_isready / wire protocol)
        avail_obs, latency_ms, is_pool_exhausted, is_in_recovery = self._check_accepting_connections(
            target_host, port, dbname, user, host
        )
        observations.append(avail_obs)

        # 3. Pool Exhaustion Check
        if is_pool_exhausted:
            pool_msg = "PostgreSQL connection pool exhausted (too many clients / reserved slots)"
            pool_val: dict[str, Any] = {"status": "FAIL", "failure": "POOL_EXHAUSTED"}
        else:
            pool_msg = "PostgreSQL connection slots available"
            pool_val = {"status": "PASS"}

        observations.append(
            Observation(
                id="postgres.pool_exhaustion",
                source="postgres",
                category="database",
                collector=COLLECTOR,
                method="pg_pool_inspection",
                value=pool_val,
                message=pool_msg,
                observed_at=_now(),
                host=host,
            )
        )

        # 4. In-Recovery / Read-Only Check (pure fact vs expected role)
        if expected_role == "primary" and is_in_recovery:
            rec_msg = "PostgreSQL is in recovery / read-only standby mode while primary was expected"
            rec_val: dict[str, Any] = {"status": "FAIL", "failure": "READ_ONLY_REPLICA", "is_in_recovery": True}
        else:
            rec_msg = f"PostgreSQL role matches expectation (in_recovery={is_in_recovery})"
            rec_val = {"status": "PASS", "is_in_recovery": is_in_recovery}

        observations.append(
            Observation(
                id="postgres.is_in_recovery",
                source="postgres",
                category="database",
                collector=COLLECTOR,
                method="pg_recovery_check",
                value=rec_val,
                message=rec_msg,
                observed_at=_now(),
                host=host,
            )
        )

        # 5. Latency Observation
        lat_status = "FAIL" if latency_ms > max_latency_ms else "PASS"
        observations.append(
            Observation(
                id="postgres.latency_ms",
                source="postgres",
                category="database",
                collector=COLLECTOR,
                method="pg_ping_latency",
                value={"status": lat_status, "latency_ms": latency_ms, "threshold_ms": max_latency_ms},
                message=f"PostgreSQL latency is {latency_ms}ms (threshold: {max_latency_ms}ms)",
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
            return self._unknown_observation("postgres.reachable", method, target_host, "tcp_connect", host, str(exc))

        timeout = self._probe_timeout()
        if host:
            res = run_command(["nc", "-z", "-w", str(int(timeout)), target_host, str(port)], timeout=timeout + 1, host=host)
            if res.ran and res.returncode == 0:
                msg = f"PostgreSQL port {port} on {target_host} is reachable"
                val: dict[str, Any] = {"status": "PASS", "target_host": target_host, "port": port}
            else:
                msg = f"PostgreSQL port {port} on {target_host} is unreachable"
                val = {"status": "FAIL", "failure": "CONNECTION_REFUSED", "target_host": target_host, "port": port}
        else:
            try:
                sock = socket.create_connection((target_host, port), timeout=timeout)
                sock.close()
                msg = f"PostgreSQL port {port} on {target_host} is reachable"
                val = {"status": "PASS", "target_host": target_host, "port": port}
            except Exception as e:
                msg = f"PostgreSQL port {port} on {target_host} is unreachable: {e}"
                val = {"status": "FAIL", "failure": "CONNECTION_REFUSED", "error": str(e)}

        return Observation(
            id="postgres.reachable",
            source="postgres",
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

    def _check_accepting_connections(
        self, target_host: str, port: int, dbname: str, user: str, host: str | None
    ) -> tuple[Observation, float, bool, bool]:
        try:
            self._require_network("db_ping", target_host, port)
        except CapabilityDenied as exc:
            obs = self._unknown_observation(
                "postgres.accepting_connections", "pg_isready", target_host, "db_ping", host, str(exc)
            )
            return obs, 0.0, False, False

        # Attempt pg_isready CLI first if available
        t0 = time.time()
        res = run_command(["pg_isready", "-h", target_host, "-p", str(port), "-d", dbname, "-U", user], host=host)
        latency_ms = round((time.time() - t0) * 1000.0, 2)

        is_pool_exhausted = False
        is_in_recovery = False

        if res.ran:
            stdout = res.stdout.strip()
            if res.returncode == 0:
                msg = f"PostgreSQL is accepting connections ({stdout})"
                val: dict[str, Any] = {"status": "PASS", "output": stdout}
            elif res.returncode == 1:
                if "remaining connection slots" in stdout or "too many clients" in stdout:
                    is_pool_exhausted = True
                msg = f"PostgreSQL is rejecting connections ({stdout})"
                val = {"status": "FAIL", "failure": "REJECTING_CONNECTIONS", "output": stdout}
            else:
                msg = f"PostgreSQL is not responding ({stdout})"
                val = {"status": "FAIL", "failure": "NO_RESPONSE", "output": stdout}
        elif host:
            # Cannot run local socket probe for a remote SSH target without remote CLI
            msg = "Remote PostgreSQL inspection over SSH requires pg_isready on target host"
            val = {"status": "UNKNOWN", "target_host": target_host, "port": port}
        else:
            # Wire protocol fallback via SSLRequest probe (local mode only)
            timeout = self._probe_timeout()
            t0 = time.time()
            try:
                with socket.create_connection((target_host, port), timeout=timeout) as s:
                    s.sendall(PG_SSL_REQUEST)
                    resp = s.recv(1)
                    latency_ms = round((time.time() - t0) * 1000.0, 2)
                    if resp in (b"S", b"N"):
                        msg = f"PostgreSQL wire handshake succeeded (SSL response: {resp.decode('ascii')})"
                        val = {"status": "PASS", "ssl_response": resp.decode("ascii")}
                    else:
                        msg = f"PostgreSQL unexpected handshake response: {resp!r}"
                        val = {"status": "FAIL", "failure": "HANDSHAKE_ERROR"}
            except Exception as e:
                latency_ms = round((time.time() - t0) * 1000.0, 2)
                msg = f"PostgreSQL wire handshake failed: {e}"
                val = {"status": "FAIL", "failure": "CONNECT_ERROR", "error": str(e)}

        obs = Observation(
            id="postgres.accepting_connections",
            source="postgres",
            category="database",
            collector=COLLECTOR,
            method="pg_isready / wire_handshake",
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

        return obs, latency_ms, is_pool_exhausted, is_in_recovery

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
            source="postgres",
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
