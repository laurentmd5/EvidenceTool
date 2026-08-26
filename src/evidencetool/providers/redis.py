"""
Redis provider — per PRODUCT_CONTRACT.md (V0.6 Application & Data Dependencies).

Checks:
  - redis.reachable
  - redis.ping
  - redis.auth
  - redis.memory_pressure
  - redis.role
  - redis.latency_ms
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

COLLECTOR = "redis_provider"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _encode_resp_command(*args: str) -> bytes:
    """Encodes a list of string arguments into a RESP array command."""
    parts = [f"*{len(args)}\r\n".encode("utf-8")]
    for arg in args:
        arg_bytes = arg.encode("utf-8")
        parts.append(f"${len(arg_bytes)}\r\n".encode("utf-8") + arg_bytes + b"\r\n")
    return b"".join(parts)


def _read_resp_line(sock: socket.socket) -> str:
    """Reads a single line terminated by CRLF from a socket."""
    buf = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) >= 2 and buf[-2:] == b"\r\n":
            return buf[:-2].decode("utf-8", errors="replace")
    return buf.decode("utf-8", errors="replace")


def _read_resp_response(sock: socket.socket) -> tuple[str, str]:
    """
    Reads a standard RESP response.
    Returns (type_char, payload).
    """
    line = _read_resp_line(sock)
    if not line:
        return "", ""
    resp_type = line[0]
    content = line[1:]

    if resp_type == "$":
        try:
            length = int(content)
        except ValueError:
            return "$", content
        if length == -1:
            return "$", ""
        data = bytearray()
        while len(data) < length:
            chunk = sock.recv(min(4096, length - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        _read_resp_line(sock)
        return "$", data.decode("utf-8", errors="replace")

    return resp_type, content


@provider("redis")
class RedisProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        self._capabilities = context.execution.capabilities
        self._probe_count = 0
        host = context.get("host", "")
        target_host = context.get("redis_host") or context.get("target_host") or "127.0.0.1"

        port_str = context.get("redis_port") or context.get("port")
        if port_str:
            try:
                port = int(port_str)
            except ValueError as exc:
                raise ValueError("port must be an integer between 1 and 65535") from exc
            if not 1 <= port <= 65535:
                raise ValueError("port must be an integer between 1 and 65535")
        else:
            port = 6379

        password = context.get("password") or context.get("redis_password") or ""
        username = context.get("username") or context.get("redis_username") or ""
        expected_role = context.get("expected_role") or "master"
        max_mem_ratio = float(context.get("max_mem_ratio", "0.9"))
        max_latency_ms = float(context.get("max_latency_ms", "100.0"))

        observations: list[Observation] = []

        # 1. Reachable & TCP Connect
        reach_obs = self._check_reachable(target_host, port, host)
        observations.append(reach_obs)

        if reach_obs.value.get("status") != "PASS":
            return observations

        # 2. Redis RESP Session & Probes
        probes = self._execute_redis_probes(
            target_host=target_host,
            port=port,
            password=password,
            username=username,
            expected_role=expected_role,
            max_mem_ratio=max_mem_ratio,
            max_latency_ms=max_latency_ms,
            host=host,
        )
        observations.extend(probes)

        return observations

    def _check_reachable(self, target_host: str, port: int, host: str | None) -> Observation:
        method = f"tcp_connect({target_host}:{port})"
        try:
            self._require_network("tcp_connect", target_host, port)
        except CapabilityDenied as exc:
            return self._unknown_observation("redis.reachable", method, target_host, "tcp_connect", host, str(exc))

        timeout = self._probe_timeout()
        if host:
            res = run_command(["nc", "-z", "-w", str(int(timeout)), target_host, str(port)], timeout=timeout + 1, host=host)
            if res.ran and res.returncode == 0:
                msg = f"Redis instance on {target_host}:{port} is reachable"
                val: dict[str, Any] = {"status": "PASS", "target_host": target_host, "port": port}
            else:
                msg = f"Redis instance on {target_host}:{port} is unreachable"
                val = {"status": "FAIL", "failure": "CONNECTION_REFUSED", "target_host": target_host, "port": port}
        else:
            try:
                sock = socket.create_connection((target_host, port), timeout=timeout)
                sock.close()
                msg = f"Redis instance on {target_host}:{port} is reachable"
                val = {"status": "PASS", "target_host": target_host, "port": port}
            except Exception as e:
                msg = f"Redis instance on {target_host}:{port} is unreachable: {e}"
                val = {"status": "FAIL", "failure": "CONNECTION_REFUSED", "error": str(e)}

        return Observation(
            id="redis.reachable",
            source="redis",
            category="datastore",
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

    def _probe_auth(self, sock: socket.socket, password: str, username: str, host: str | None) -> tuple[bool, Observation | None]:
        if not password:
            return True, None
        if username:
            sock.sendall(_encode_resp_command("AUTH", username, password))
        else:
            sock.sendall(_encode_resp_command("AUTH", password))
        rtype, rval = _read_resp_response(sock)
        if rtype == "+":
            return True, Observation(
                id="redis.auth",
                source="redis",
                category="datastore",
                collector=COLLECTOR,
                method="AUTH",
                value={"status": "PASS"},
                message="Redis authentication succeeded",
                observed_at=_now(),
                host=host,
            )
        failure = "WRONGPASS" if "WRONGPASS" in rval or "invalid password" in rval else "AUTH_FAILED"
        return False, Observation(
            id="redis.auth",
            source="redis",
            category="datastore",
            collector=COLLECTOR,
            method="AUTH",
            value={"status": "FAIL", "failure": failure, "error": rval},
            message=f"Redis authentication failed: {rval}",
            observed_at=_now(),
            host=host,
        )

    def _probe_ping(
        self, sock: socket.socket, max_latency_ms: float, host: str | None
    ) -> tuple[bool, list[Observation]]:
        t0 = time.time()
        sock.sendall(_encode_resp_command("PING"))
        rtype, rval = _read_resp_response(sock)
        latency_ms = round((time.time() - t0) * 1000.0, 2)

        obs: list[Observation] = []
        is_ok = False

        if rtype == "+" and rval == "PONG":
            is_ok = True
            obs.append(
                Observation(
                    id="redis.ping",
                    source="redis",
                    category="datastore",
                    collector=COLLECTOR,
                    method="PING",
                    value={"status": "PASS", "latency_ms": latency_ms},
                    message=f"Redis PING succeeded (PONG, {latency_ms}ms)",
                    observed_at=_now(),
                    host=host,
                )
            )
        elif "NOAUTH" in rval:
            obs.append(
                Observation(
                    id="redis.auth",
                    source="redis",
                    category="datastore",
                    collector=COLLECTOR,
                    method="AUTH",
                    value={"status": "FAIL", "failure": "NOAUTH"},
                    message="Authentication required (NOAUTH)",
                    observed_at=_now(),
                    host=host,
                )
            )
            obs.append(
                Observation(
                    id="redis.ping",
                    source="redis",
                    category="datastore",
                    collector=COLLECTOR,
                    method="PING",
                    value={"status": "FAIL", "failure": "NOAUTH", "error": rval},
                    message="Redis PING rejected: Authentication required (NOAUTH)",
                    observed_at=_now(),
                    host=host,
                )
            )
        else:
            obs.append(
                Observation(
                    id="redis.ping",
                    source="redis",
                    category="datastore",
                    collector=COLLECTOR,
                    method="PING",
                    value={"status": "FAIL", "failure": "PING_FAILED", "error": rval},
                    message=f"Redis PING failed: {rval}",
                    observed_at=_now(),
                    host=host,
                )
            )

        lat_status = "FAIL" if latency_ms > max_latency_ms else "PASS"
        obs.append(
            Observation(
                id="redis.latency_ms",
                source="redis",
                category="datastore",
                collector=COLLECTOR,
                method="PING_LATENCY",
                value={"status": lat_status, "latency_ms": latency_ms, "threshold_ms": max_latency_ms},
                message=f"Redis latency is {latency_ms}ms (threshold: {max_latency_ms}ms)",
                observed_at=_now(),
                host=host,
            )
        )

        return is_ok, obs

    def _probe_info(
        self, sock: socket.socket, expected_role: str, max_mem_ratio: float, host: str | None
    ) -> list[Observation]:
        sock.sendall(_encode_resp_command("INFO"))
        _, info_raw = _read_resp_response(sock)
        info_dict = self._parse_info(info_raw)

        obs: list[Observation] = []

        # Memory Check
        used_mem = int(info_dict.get("used_memory", 0))
        max_mem = int(info_dict.get("maxmemory", 0))
        used_mem_mb = round(used_mem / (1024.0 * 1024.0), 2)
        max_mem_mb = round(max_mem / (1024.0 * 1024.0), 2)

        if max_mem > 0:
            mem_ratio = round(used_mem / max_mem, 4)
            if mem_ratio >= max_mem_ratio:
                mem_val: dict[str, Any] = {
                    "status": "FAIL",
                    "failure": "OOM_MAXMEMORY",
                    "used_memory_mb": used_mem_mb,
                    "maxmemory_mb": max_mem_mb,
                    "ratio": mem_ratio,
                }
                mem_msg = f"Redis memory saturation: {used_mem_mb}MB / {max_mem_mb}MB ({round(mem_ratio*100, 1)}%)"
            else:
                mem_val = {"status": "PASS", "used_memory_mb": used_mem_mb, "maxmemory_mb": max_mem_mb, "ratio": mem_ratio}
                mem_msg = f"Redis memory usage: {used_mem_mb}MB / {max_mem_mb}MB ({round(mem_ratio*100, 1)}%)"
        else:
            mem_val = {"status": "PASS", "used_memory_mb": used_mem_mb, "maxmemory_mb": 0}
            mem_msg = f"Redis memory usage: {used_mem_mb}MB (no maxmemory configured)"

        obs.append(
            Observation(
                id="redis.memory_pressure",
                source="redis",
                category="datastore",
                collector=COLLECTOR,
                method="INFO memory",
                value=mem_val,
                message=mem_msg,
                observed_at=_now(),
                host=host,
            )
        )

        # Role Check
        actual_role = info_dict.get("role", "master")
        link_status = info_dict.get("master_link_status", "up")

        if actual_role == "slave" and link_status == "down":
            role_val: dict[str, Any] = {"status": "FAIL", "failure": "REPLICATION_BROKEN", "role": actual_role, "link_status": link_status}
            role_msg = "Redis replica disconnected from master (master_link_status: down)"
        elif expected_role and actual_role != expected_role:
            role_val = {"status": "FAIL", "failure": "ROLE_MISMATCH", "role": actual_role, "expected_role": expected_role}
            role_msg = f"Redis role is '{actual_role}' but '{expected_role}' was expected"
        else:
            role_val = {"status": "PASS", "role": actual_role, "link_status": link_status}
            role_msg = f"Redis role is {actual_role} (nominal)"

        obs.append(
            Observation(
                id="redis.role",
                source="redis",
                category="datastore",
                collector=COLLECTOR,
                method="INFO replication",
                value=role_val,
                message=role_msg,
                observed_at=_now(),
                host=host,
            )
        )

        return obs

    def _execute_redis_remote(
        self, target_host: str, port: int, password: str, host: str, timeout: float
    ) -> list[Observation]:
        base_cmd = ["redis-cli", "-h", target_host, "-p", str(port), "--no-auth-warning"]
        if password:
            return self._remote_auth_required_observations(target_host, port, host)

        start = time.perf_counter()
        ping_res = run_command(base_cmd + ["ping"], host=host, timeout=timeout + 1)
        latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
        info_memory_res = run_command(base_cmd + ["info", "memory"], host=host, timeout=timeout + 1)
        info_replication_res = run_command(base_cmd + ["info", "replication"], host=host, timeout=timeout + 1)

        observations: list[Observation] = []
        ping_error = ping_res.stderr.strip() or ping_res.stdout.strip() or ping_res.error or "remote command failed"
        if ping_res.ran and ping_res.returncode == 0 and "PONG" in ping_res.stdout:
            ping_value: dict[str, Any] = {"status": "PASS", "response": ping_res.stdout.strip()}
            ping_message = f"Redis PING succeeded over SSH ({ping_res.stdout.strip()})"
        elif not ping_res.ran:
            ping_value = {"status": "UNKNOWN", "failure": "PROBE_ERROR"}
            ping_message = f"Could not execute remote Redis PING: {ping_error}"
        else:
            ping_value = {"status": "FAIL", "failure": "PING_FAILED", "error": ping_error}
            ping_message = f"Redis PING failed over SSH: {ping_error}"
        observations.append(self._remote_observation("redis.ping", "PING", ping_value, ping_message, host))

        latency_status = "PASS" if ping_res.ran else "UNKNOWN"
        observations.append(
            self._remote_observation(
                "redis.latency_ms",
                "PING_LATENCY",
                {"status": latency_status, "latency_ms": latency_ms},
                f"Remote Redis PING latency is {latency_ms}ms",
                host,
            )
        )

        observations.extend(self._remote_info_observations(info_memory_res, info_replication_res, target_host, port, host))
        return observations

    def _remote_auth_required_observations(self, target_host: str, port: int, host: str) -> list[Observation]:
        message = "Remote Redis probes requiring authentication are unavailable without exposing the password in a command argument"
        return [
            self._remote_observation(
                "redis.auth", "AUTH", {"status": "UNKNOWN", "failure": "SECURE_AUTH_UNAVAILABLE"}, message, host
            ),
            self._remote_observation(
                "redis.ping", "PING", {"status": "UNKNOWN", "failure": "AUTH_REQUIRED"}, message, host
            ),
            self._remote_observation(
                "redis.latency_ms", "PING_LATENCY", {"status": "UNKNOWN"}, message, host
            ),
            self._remote_observation(
                "redis.memory_pressure", "INFO memory", {"status": "UNKNOWN", "failure": "AUTH_REQUIRED"}, message, host
            ),
            self._remote_observation(
                "redis.role", "INFO replication", {"status": "UNKNOWN", "failure": "AUTH_REQUIRED"}, message, host
            ),
        ]

    def _remote_info_observations(
        self, memory_result: Any, replication_result: Any, target_host: str, port: int, host: str
    ) -> list[Observation]:
        if not memory_result.ran or memory_result.returncode != 0:
            memory_value: dict[str, Any] = {"status": "UNKNOWN", "failure": "INFO_UNAVAILABLE"}
            memory_message = "Remote Redis memory information is unavailable"
        else:
            info = self._parse_info(memory_result.stdout)
            used_mem = int(info.get("used_memory", 0))
            max_mem = int(info.get("maxmemory", 0))
            memory_value = {"status": "PASS", "used_memory_mb": round(used_mem / (1024.0 * 1024.0), 2), "maxmemory_mb": round(max_mem / (1024.0 * 1024.0), 2)}
            memory_message = "Remote Redis memory information collected over SSH"

        if not replication_result.ran or replication_result.returncode != 0:
            role_value: dict[str, Any] = {"status": "UNKNOWN", "failure": "INFO_UNAVAILABLE"}
            role_message = "Remote Redis replication information is unavailable"
        else:
            info = self._parse_info(replication_result.stdout)
            role_value = {"status": "PASS", "role": info.get("role", "unknown"), "link_status": info.get("master_link_status", "unknown")}
            role_message = "Remote Redis replication information collected over SSH"

        return [
            self._remote_observation("redis.memory_pressure", "INFO memory", memory_value, memory_message, host),
            self._remote_observation("redis.role", "INFO replication", role_value, role_message, host),
        ]

    def _remote_observation(
        self, evidence_id: str, method: str, value: dict[str, Any], message: str, host: str
    ) -> Observation:
        return Observation(
            id=evidence_id,
            source="redis",
            category="datastore",
            collector=COLLECTOR,
            method=method,
            value=value,
            message=message,
            observed_at=_now(),
            host=host,
            execution_scope="remote",
            transport_status="executed",
        )

    def _execute_redis_local(
        self,
        target_host: str,
        port: int,
        password: str,
        username: str,
        expected_role: str,
        max_mem_ratio: float,
        max_latency_ms: float,
        timeout: float,
    ) -> list[Observation]:
        try:
            sock = socket.create_connection((target_host, port), timeout=timeout)
        except Exception as e:
            return [
                Observation(
                    id="redis.ping",
                    source="redis",
                    category="datastore",
                    collector=COLLECTOR,
                    method="PING",
                    value={"status": "FAIL", "failure": "CONNECT_FAILED", "error": str(e)},
                    message=f"Could not connect to Redis: {e}",
                    observed_at=_now(),
                    host=None,
                )
            ]

        observations: list[Observation] = []
        try:
            auth_ok, auth_obs = self._probe_auth(sock, password, username, None)
            if auth_obs:
                observations.append(auth_obs)

            ping_ok, ping_obs_list = self._probe_ping(sock, max_latency_ms, None)
            observations.extend(ping_obs_list)

            if auth_ok and ping_ok:
                info_obs_list = self._probe_info(sock, expected_role, max_mem_ratio, None)
                observations.extend(info_obs_list)

            sock.close()
        except Exception as e:
            if not any(o.id == "redis.ping" for o in observations):
                observations.append(
                    Observation(
                        id="redis.ping",
                        source="redis",
                        category="datastore",
                        collector=COLLECTOR,
                        method="RESP_SESSION",
                        value={"status": "FAIL", "failure": "SESSION_ERROR", "error": str(e)},
                        message=f"Redis session error: {e}",
                        observed_at=_now(),
                        host=None,
                    )
                )

        return observations

    def _execute_redis_probes(
        self,
        target_host: str,
        port: int,
        password: str,
        username: str,
        expected_role: str,
        max_mem_ratio: float,
        max_latency_ms: float,
        host: str | None,
    ) -> list[Observation]:
        try:
            self._require_network("redis_ping", target_host, port)
        except CapabilityDenied as exc:
            return [self._unknown_observation("redis.ping", "redis_ping", target_host, "redis_ping", host, str(exc))]

        timeout = self._probe_timeout()
        if host:
            return self._execute_redis_remote(target_host, port, password, host, timeout)

        return self._execute_redis_local(
            target_host, port, password, username, expected_role, max_mem_ratio, max_latency_ms, timeout
        )

    def _parse_info(self, raw_info: str) -> dict[str, str]:
        info: dict[str, str] = {}
        for line in raw_info.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and ":" in line:
                key, val = line.split(":", 1)
                info[key.strip()] = val.strip()
        return info

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
            source="redis",
            category="datastore",
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
