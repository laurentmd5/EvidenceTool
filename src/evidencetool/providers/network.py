"""
Network provider — per PRODUCT_CONTRACT.md (Deterministic Network Evidence Chain).

Checks:
  - network.dns_resolvable
  - network.route_exists
  - network.host_reachable
  - network.port_reachable
  - network.tls_handshake
  - network.http_reachable
"""

from __future__ import annotations

import errno
import http.client
import math
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

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

        target_raw = context.get("target_host") or context.get("domain") or context.get("target") or "127.0.0.1"
        if "://" in target_raw:
            parsed = urlparse(target_raw)
            target_host = parsed.hostname or "127.0.0.1"
            default_port = 443 if parsed.scheme == "https" else 80
            port_val = parsed.port or default_port
            http_path = parsed.path or "/"
            use_tls = parsed.scheme == "https"
        else:
            target_host = target_raw
            port_val = 80
            http_path = context.get("http_path") or context.get("path") or "/"
            use_tls = False

        port_str = context.get("port")
        if port_str:
            try:
                port = int(port_str)
            except ValueError as exc:
                raise ValueError("port must be an integer between 1 and 65535") from exc
            if not 1 <= port <= 65535:
                raise ValueError("port must be an integer between 1 and 65535")
        else:
            port = port_val

        if context.get("use_tls") is not None:
            use_tls = context.get("use_tls").lower() in ("true", "1", "yes")
        elif port in (443, 8443):
            use_tls = True

        observations: list[Observation] = []

        # 1. DNS Resolution
        dns_obs = self._check_dns_resolvable(target_host, host)
        observations.append(dns_obs)

        # 2. Route Check
        route_obs = self._check_route_exists(target_host, host)
        observations.append(route_obs)

        # 3. Host Reachability (ICMP / IP)
        host_obs = self._check_host_reachable(target_host, host)
        observations.append(host_obs)

        # 4. TCP Port Reachability
        tcp_obs = self._check_port_reachable(target_host, port, host)
        observations.append(tcp_obs)

        # 5. TLS Handshake
        if use_tls or context.get("check_tls") in ("true", "1", "yes"):
            tls_obs = self._check_tls_handshake(target_host, port, host, tcp_status=tcp_obs.value.get("status"))
            observations.append(tls_obs)

        # 6. HTTP Reachability
        if (
            context.get("check_http") in ("true", "1", "yes")
            or context.get("http_path")
            or port in (80, 443, 8080, 8443)
        ):
            http_obs = self._check_http_reachable(
                target_host, port, http_path, use_tls, host, tcp_status=tcp_obs.value.get("status")
            )
            observations.append(http_obs)

        return observations

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
                val: dict[str, Any] = {"status": "UNKNOWN", "failure": "PROBE_ERROR"}
            elif res.returncode == 0:
                ip = res.stdout.split()[0] if res.stdout.split() else "resolved"
                msg = f"DNS lookup succeeded for {target_host} ({ip})"
                val = {"status": "PASS", "resolved": True, "ip": ip, "raw": res.stdout}
            else:
                msg = f"DNS resolution failed for {target_host}: NXDOMAIN or resolution error"
                val = {"status": "FAIL", "resolved": False, "failure": "NXDOMAIN"}
        else:
            try:
                results = socket.getaddrinfo(target_host, None)
                ip = str(results[0][4][0]) if results else "resolved"
                msg = f"DNS lookup succeeded for {target_host} ({ip})"
                val = {"status": "PASS", "resolved": True, "ip": ip}
            except (socket.gaierror, OSError) as e:
                msg = f"DNS lookup failed for {target_host}: {e}"
                val = {"status": "FAIL", "resolved": False, "failure": "NXDOMAIN", "error": str(e)}

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

    def _check_route_exists(self, target_host: str, host: str | None) -> Observation:
        method = f"route_get({target_host})"
        try:
            self._require_network("route_check", target_host, None, host)
        except CapabilityDenied as exc:
            return self._unknown_observation(
                "network.route_exists", method, target_host, "route_check", host, str(exc)
            )

        if host:
            res = run_command(["ip", "route", "get", target_host], host=host)
            if not res.ran:
                msg = f"Could not perform remote route check: {res.error}"
                val: dict[str, Any] = {"status": "UNKNOWN", "failure": "PROBE_ERROR"}
            elif res.returncode == 0:
                msg = f"Route to {target_host} exists: {res.stdout.strip()}"
                val = {"status": "PASS", "route": res.stdout.strip()}
            else:
                msg = f"No route to {target_host}: {res.stderr.strip()}"
                val = {"status": "FAIL", "failure": "NO_ROUTE_TO_HOST", "error": res.stderr.strip()}
        else:
            res = run_command(["ip", "route", "get", target_host], host=None)
            if res.ran and res.returncode == 0:
                msg = f"Route to {target_host} exists: {res.stdout.strip()}"
                val = {"status": "PASS", "route": res.stdout.strip()}
            elif res.ran and res.returncode != 0 and "RTNETLINK" in res.stderr:
                msg = f"No route to {target_host}: {res.stderr.strip()}"
                val = {"status": "FAIL", "failure": "NO_ROUTE_TO_HOST", "error": res.stderr.strip()}
            else:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect((target_host if target_host != "localhost" else "127.0.0.1", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                    msg = f"Route to {target_host} via interface {local_ip}"
                    val = {"status": "PASS", "interface_ip": local_ip}
                except OSError as e:
                    if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
                        msg = f"No route to host {target_host}: {e}"
                        val = {"status": "FAIL", "failure": "NO_ROUTE_TO_HOST", "error": str(e)}
                    else:
                        msg = f"Route lookup for {target_host}: {e}"
                        val = {"status": "PASS", "info": str(e)}

        return Observation(
            id="network.route_exists",
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
            capability="route_check",
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

        if sys.platform == "win32" and not host:
            ping_cmd = ["ping", "-n", "1", "-w", str(max(1, int(timeout * 1000))), target_host]
        else:
            ping_cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), target_host]
        res = run_command(ping_cmd, timeout=timeout + 1, host=host)
        if not res.ran:
            if host:
                return self._unknown_observation(
                    "network.host_reachable",
                    method,
                    target_host,
                    "icmp_echo",
                    host,
                    f"Could not execute remote ping: {res.error}",
                    capability_denied=False,
                )
            try:
                socket.getaddrinfo(target_host, None)
                msg = f"Host {target_host} is addressable"
                val: dict[str, Any] = {"status": "PASS", "target_host": target_host}
            except Exception as e:
                msg = f"Host {target_host} is unreachable: {e}"
                val = {"status": "FAIL", "failure": "HOST_UNREACHABLE", "target_host": target_host, "error": str(e)}
        elif res.returncode == 0:
            msg = f"Host {target_host} responds to ping"
            val = {"status": "PASS", "target_host": target_host}
        else:
            msg = f"Host {target_host} did not respond to ping"
            val = {
                "status": "FAIL",
                "failure": "HOST_UNREACHABLE",
                "target_host": target_host,
                "returncode": res.returncode,
            }

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

    def _check_port_remote(self, target_host: str, port: int, host: str, timeout: float) -> tuple[str, dict[str, Any]]:
        res = run_command(["nc", "-z", "-w", str(timeout), target_host, str(port)], timeout=timeout + 1, host=host)
        if not res.ran:
            return f"Could not check remote port: {res.error}", {"status": "UNKNOWN", "failure": "PROBE_ERROR"}
        if res.returncode == 0:
            return f"Port {port} on {target_host} is reachable", {
                "status": "PASS",
                "target_host": target_host,
                "port": port,
            }
        return f"Port {port} on {target_host} is unreachable / connection refused", {
            "status": "FAIL",
            "failure": "CONNECTION_REFUSED",
            "target_host": target_host,
            "port": port,
        }

    def _check_port_local(self, target_host: str, port: int, timeout: float) -> tuple[str, dict[str, Any]]:
        try:
            sock = socket.create_connection((target_host, port), timeout=timeout)
            sock.close()
            return f"Port {port} on {target_host} is reachable", {
                "status": "PASS",
                "target_host": target_host,
                "port": port,
            }
        except ConnectionRefusedError as e:
            return f"Connection refused on port {port} on {target_host}", {
                "status": "FAIL",
                "failure": "CONNECTION_REFUSED",
                "target_host": target_host,
                "port": port,
                "error": str(e),
            }
        except socket.timeout as e:
            return f"Connection timed out on port {port} on {target_host}", {
                "status": "FAIL",
                "failure": "TIMEOUT",
                "target_host": target_host,
                "port": port,
                "error": str(e),
            }
        except OSError as e:
            if e.errno == errno.ECONNREFUSED:
                failure = "CONNECTION_REFUSED"
            elif e.errno in (errno.ETIMEDOUT, 10060):
                failure = "TIMEOUT"
            elif e.errno in (errno.EHOSTUNREACH, 10065):
                failure = "HOST_UNREACHABLE"
            elif e.errno in (errno.ENETUNREACH, 10051):
                failure = "NETWORK_UNREACHABLE"
            else:
                failure = "CONNECTION_FAILED"
            return f"Port {port} on {target_host} is unreachable ({failure}): {e}", {
                "status": "FAIL",
                "failure": failure,
                "target_host": target_host,
                "port": port,
                "error": str(e),
            }

    def _check_port_reachable(self, target_host: str, port: int, host: str | None) -> Observation:
        method = f"tcp_connect({target_host}:{port})"
        try:
            self._require_network("tcp_connect", target_host, port, host)
        except CapabilityDenied as exc:
            return self._unknown_observation(
                "network.port_reachable", method, target_host, "tcp_connect", host, str(exc)
            )

        timeout = self._probe_timeout()
        if host:
            msg, val = self._check_port_remote(target_host, port, host, timeout)
        else:
            msg, val = self._check_port_local(target_host, port, timeout)

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

    def _check_tls_handshake(
        self, target_host: str, port: int, host: str | None, tcp_status: str | None
    ) -> Observation:
        method = f"tls_handshake({target_host}:{port})"
        try:
            self._require_network("tls_handshake", target_host, port, host)
        except CapabilityDenied as exc:
            return self._unknown_observation(
                "network.tls_handshake", method, target_host, "tls_handshake", host, str(exc)
            )

        if tcp_status == "FAIL":
            return Observation(
                id="network.tls_handshake",
                source="network",
                category="connectivity",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN", "failure": "TCP_UNREACHABLE", "skipped": True},
                message=f"TLS handshake skipped because TCP port {port} on {target_host} is unreachable",
                observed_at=_now(),
                host=host,
                execution_scope="remote" if host else "local",
                target=target_host,
                capability="tls_handshake",
                transport_status="skipped",
            )

        timeout = self._probe_timeout()
        if host:
            res = run_command(
                ["openssl", "s_client", "-connect", f"{target_host}:{port}", "-servername", target_host, "-brief"],
                timeout=timeout + 2,
                host=host,
            )
            if not res.ran:
                msg = f"Could not execute remote openssl s_client: {res.error}"
                val: dict[str, Any] = {"status": "UNKNOWN", "failure": "PROBE_ERROR"}
            elif res.returncode == 0:
                msg = f"TLS handshake succeeded with {target_host}:{port}"
                val = {"status": "PASS", "target_host": target_host, "port": port}
            else:
                msg = f"TLS handshake failed with {target_host}:{port}: {res.stderr.strip() or res.stdout.strip()}"
                val = {"status": "FAIL", "failure": "TLS_HANDSHAKE_ERROR", "target_host": target_host, "port": port}
        else:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((target_host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                        version = ssock.version() or "TLS"
                        cipher = ssock.cipher()
                        cipher_name = cipher[0] if cipher else "unknown"
                        msg = f"TLS handshake succeeded ({version}, {cipher_name})"
                        val = {"status": "PASS", "tls_version": version, "cipher": cipher_name}
            except ssl.SSLError as e:
                msg = f"TLS handshake failed for {target_host}:{port}: {e}"
                val = {"status": "FAIL", "failure": "TLS_HANDSHAKE_ERROR", "error": str(e)}
            except socket.timeout as e:
                msg = f"TLS handshake timed out for {target_host}:{port}: {e}"
                val = {"status": "FAIL", "failure": "TIMEOUT", "error": str(e)}
            except OSError as e:
                msg = f"TLS connection error for {target_host}:{port}: {e}"
                val = {"status": "FAIL", "failure": "CONNECTION_FAILED", "error": str(e)}

        return Observation(
            id="network.tls_handshake",
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
            capability="tls_handshake",
            transport_status="executed",
        )

    def _check_http_remote(
        self, scheme: str, target_host: str, port: int, http_path: str, host: str, timeout: float
    ) -> tuple[str, dict[str, Any]]:
        url = f"{scheme}://{target_host}:{port}{http_path}"
        res = run_command(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}:%{time_total}",
                "--connect-timeout",
                str(int(timeout)),
                "-k",
                url,
            ],
            timeout=timeout + 2,
            host=host,
        )
        if not res.ran:
            return f"Could not execute remote curl probe: {res.error}", {
                "status": "UNKNOWN",
                "failure": "PROBE_ERROR",
            }
        if res.returncode == 0 and ":" in res.stdout:
            code_str, latency_str = res.stdout.strip().split(":", 1)
            code = int(code_str) if code_str.isdigit() else 0
            latency_ms = int(float(latency_str) * 1000) if latency_str else 0
            if 200 <= code < 400:
                return f"HTTP probe succeeded: status {code} ({latency_ms}ms)", {
                    "status": "PASS",
                    "status_code": code,
                    "latency_ms": latency_ms,
                }
            if code >= 500:
                return f"HTTP probe returned server error: status {code} ({latency_ms}ms)", {
                    "status": "FAIL",
                    "failure": "HTTP_5XX",
                    "status_code": code,
                    "latency_ms": latency_ms,
                }
            return f"HTTP probe returned status {code} ({latency_ms}ms)", {
                "status": "FAIL",
                "failure": f"HTTP_{code}",
                "status_code": code,
                "latency_ms": latency_ms,
            }
        return f"HTTP probe failed for {url}", {"status": "FAIL", "failure": "HTTP_UNAVAILABLE", "error": res.stderr.strip()}

    def _check_http_local(
        self, target_host: str, port: int, http_path: str, use_tls: bool, timeout: float
    ) -> tuple[str, dict[str, Any]]:
        start_t = time.time()
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                    target_host, port=port, timeout=timeout, context=ctx
                )
            else:
                conn = http.client.HTTPConnection(target_host, port=port, timeout=timeout)

            conn.request("GET", http_path, headers={"User-Agent": "EvidenceTool/0.5.0"})
            resp = conn.getresponse()
            code = resp.status
            latency_ms = int((time.time() - start_t) * 1000)
            conn.close()

            if 200 <= code < 400:
                return f"HTTP GET {http_path} returned status {code} ({latency_ms}ms)", {
                    "status": "PASS",
                    "status_code": code,
                    "latency_ms": latency_ms,
                }
            if code >= 500:
                return f"HTTP GET {http_path} returned server error: status {code} ({latency_ms}ms)", {
                    "status": "FAIL",
                    "failure": "HTTP_5XX",
                    "status_code": code,
                    "latency_ms": latency_ms,
                }
            return f"HTTP GET {http_path} returned status {code} ({latency_ms}ms)", {
                "status": "FAIL",
                "failure": f"HTTP_{code}",
                "status_code": code,
                "latency_ms": latency_ms,
            }
        except (socket.timeout, TimeoutError) as e:
            return f"HTTP request timed out for {target_host}:{port}{http_path}: {e}", {
                "status": "FAIL",
                "failure": "HTTP_TIMEOUT",
                "error": str(e),
            }
        except Exception as e:
            return f"HTTP request failed for {target_host}:{port}{http_path}: {e}", {
                "status": "FAIL",
                "failure": "HTTP_UNAVAILABLE",
                "error": str(e),
            }

    def _check_http_reachable(
        self,
        target_host: str,
        port: int,
        http_path: str,
        use_tls: bool,
        host: str | None,
        tcp_status: str | None,
    ) -> Observation:
        scheme = "https" if use_tls else "http"
        method = f"http_get({scheme}://{target_host}:{port}{http_path})"
        try:
            self._require_network("http_probe", target_host, port, host)
        except CapabilityDenied as exc:
            return self._unknown_observation(
                "network.http_reachable", method, target_host, "http_probe", host, str(exc)
            )

        if tcp_status == "FAIL":
            return Observation(
                id="network.http_reachable",
                source="network",
                category="connectivity",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN", "failure": "TCP_UNREACHABLE", "skipped": True},
                message=f"HTTP probe skipped because TCP port {port} on {target_host} is unreachable",
                observed_at=_now(),
                host=host,
                execution_scope="remote" if host else "local",
                target=target_host,
                capability="http_probe",
                transport_status="skipped",
            )

        timeout = self._probe_timeout()
        if host:
            msg, val = self._check_http_remote(scheme, target_host, port, http_path, host, timeout)
        else:
            msg, val = self._check_http_local(target_host, port, http_path, use_tls, timeout)

        return Observation(
            id="network.http_reachable",
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
            capability="http_probe",
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
