"""
Dependency provider — per PRODUCT_CONTRACT.md (V0.6 Application & Data Dependencies).

Checks:
  - dependency.http_status
  - dependency.latency_ms
  - dependency.sla_budget
  - dependency.circuit_breaker
"""

from __future__ import annotations

import http.client
import math
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from evidencetool.capability.models import CapabilityDenied
from evidencetool.models.observation import Observation
from evidencetool.providers._shell import run_command
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider

COLLECTOR = "dependency_provider"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sanitize_url(raw_url: str) -> str:
    """Removes user:password credentials and redacts sensitive query parameters."""
    try:
        parsed = urlparse(raw_url)
        # Redact credentials in netloc
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        # Redact sensitive query parameters
        if parsed.query:
            queries = parse_qsl(parsed.query, keep_blank_values=True)
            sanitized_query = []
            sensitive_keywords = (
                "token",
                "key",
                "secret",
                "auth",
                "password",
                "pass",
                "bearer",
                "sig",
                "signature",
                "api_key",
                "apikey",
            )
            for k, v in queries:
                if any(kw in k.lower() for kw in sensitive_keywords):
                    sanitized_query.append((k, "[REDACTED]"))
                else:
                    sanitized_query.append((k, v))
            query_str = urlencode(sanitized_query)
        else:
            query_str = ""

        return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, query_str, parsed.fragment))
    except Exception:
        return raw_url


@provider("dependency")
class DependencyProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        self._capabilities = context.execution.capabilities
        self._probe_count = 0
        host = context.get("host", "")

        url = context.get("url") or context.get("target_url") or context.get("endpoint") or "http://127.0.0.1:80/health"
        parsed = urlparse(url)
        target_host = parsed.hostname or "127.0.0.1"
        scheme = parsed.scheme or "http"
        default_port = 443 if scheme == "https" else 80
        port = parsed.port or default_port
        http_path = parsed.path or "/health"
        if parsed.query:
            http_path += f"?{parsed.query}"

        sla_budget_ms = float(context.get("sla_budget_ms", "250.0"))

        observations: list[Observation] = []

        # Probe upstream dependency
        status_obs, latency_obs, sla_obs, cb_obs = self._probe_endpoint(
            url=url,
            scheme=scheme,
            target_host=target_host,
            port=port,
            http_path=http_path,
            sla_budget_ms=sla_budget_ms,
            host=host,
        )

        observations.append(status_obs)
        observations.append(latency_obs)
        observations.append(sla_obs)
        observations.append(cb_obs)

        return observations

    def _probe_remote(
        self, url: str, host: str, timeout: float, sla_budget_ms: float
    ) -> tuple[Observation, Observation, Observation, Observation]:
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

        if res.ran and res.returncode == 0 and ":" in res.stdout:
            code_str, latency_str = res.stdout.strip().split(":", 1)
            code = int(code_str) if code_str.isdigit() else 0
            raw_latency_ms = float(latency_str) * 1000.0 if latency_str else 0.0
            error = None
        else:
            code = 0
            raw_latency_ms = 0.0
            error = res.stderr.strip() if res.ran else res.error

        return self._build_observations(url, code, raw_latency_ms, sla_budget_ms, host, error)

    def _probe_local(
        self, scheme: str, target_host: str, port: int, http_path: str, url: str, timeout: float, sla_budget_ms: float
    ) -> tuple[Observation, Observation, Observation, Observation]:
        start_t = time.perf_counter()
        error = None
        code = 0

        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                    target_host, port=port, timeout=timeout, context=ctx
                )
            else:
                conn = http.client.HTTPConnection(target_host, port=port, timeout=timeout)

            conn.request("GET", http_path, headers={"User-Agent": "EvidenceTool/0.6.0-DependencyProbe"})
            resp = conn.getresponse()
            code = resp.status
            raw_latency_ms = (time.perf_counter() - start_t) * 1000.0
            conn.close()
        except Exception as e:
            raw_latency_ms = (time.perf_counter() - start_t) * 1000.0
            error = str(e)

        return self._build_observations(url, code, raw_latency_ms, sla_budget_ms, None, error)

    def _probe_endpoint(
        self,
        url: str,
        scheme: str,
        target_host: str,
        port: int,
        http_path: str,
        sla_budget_ms: float,
        host: str | None,
    ) -> tuple[Observation, Observation, Observation, Observation]:
        sanitized_url = _sanitize_url(url)
        method = f"http_get({sanitized_url})"
        try:
            self._require_network("http_probe", target_host, port)
        except CapabilityDenied as exc:
            obs = self._unknown_observation("dependency.http_status", method, target_host, "http_probe", host, str(exc))
            obs_lat = self._unknown_observation("dependency.latency_ms", method, target_host, "http_probe", host, str(exc))
            obs_sla = self._unknown_observation("dependency.sla_budget", method, target_host, "http_probe", host, str(exc))
            obs_cb = self._unknown_observation("dependency.circuit_breaker", method, target_host, "http_probe", host, str(exc))
            return obs, obs_lat, obs_sla, obs_cb

        timeout = self._probe_timeout()
        if host:
            return self._probe_remote(url, host, timeout, sla_budget_ms)
        return self._probe_local(scheme, target_host, port, http_path, url, timeout, sla_budget_ms)

    def _build_observations(
        self, raw_url: str, code: int, raw_latency_ms: float, sla_budget_ms: float, host: str | None, error: str | None
    ) -> tuple[Observation, Observation, Observation, Observation]:
        sanitized_url = _sanitize_url(raw_url)
        display_latency_ms = round(raw_latency_ms, 2)

        # 1. HTTP Status Observation
        if 200 <= code < 400:
            status_val: dict[str, Any] = {"status": "PASS", "status_code": code, "url": sanitized_url}
            status_msg = f"Upstream dependency returned HTTP {code}"
        elif code >= 500:
            status_val = {"status": "FAIL", "failure": "HTTP_5XX", "status_code": code, "url": sanitized_url}
            status_msg = f"Upstream dependency returned server error HTTP {code}"
        elif code == 429:
            status_val = {"status": "FAIL", "failure": "HTTP_429", "status_code": code, "url": sanitized_url}
            status_msg = "Upstream dependency returned rate limit HTTP 429"
        elif error:
            status_val = {"status": "FAIL", "failure": "CONNECT_FAILED", "error": error, "url": sanitized_url}
            status_msg = f"Could not reach upstream dependency: {error}"
        else:
            status_val = {"status": "FAIL", "failure": f"HTTP_{code}", "status_code": code, "url": sanitized_url}
            status_msg = f"Upstream dependency returned HTTP {code}"

        obs_status = Observation(
            id="dependency.http_status",
            source="dependency",
            category="dependency",
            collector=COLLECTOR,
            method=f"http_get({sanitized_url})",
            value=status_val,
            message=status_msg,
            observed_at=_now(),
            host=host,
        )

        # 2. Latency Observation
        obs_latency = Observation(
            id="dependency.latency_ms",
            source="dependency",
            category="dependency",
            collector=COLLECTOR,
            method=f"latency({sanitized_url})",
            value={"status": "PASS" if error is None else "FAIL", "latency_ms": display_latency_ms, "url": sanitized_url},
            message=f"Upstream dependency response latency: {display_latency_ms}ms",
            observed_at=_now(),
            host=host,
        )

        # 3. SLA Budget Observation (compare exact raw_latency_ms)
        if error is None and raw_latency_ms <= sla_budget_ms:
            sla_msg = f"Latency {display_latency_ms}ms respects SLA budget ({sla_budget_ms}ms)"
            sla_val: dict[str, Any] = {
                "status": "PASS",
                "latency_ms": display_latency_ms,
                "sla_budget_ms": sla_budget_ms,
            }
        else:
            sla_msg = f"Latency {display_latency_ms}ms violates SLA budget ({sla_budget_ms}ms)"
            sla_val = {
                "status": "FAIL",
                "failure": "SLA_VIOLATED",
                "latency_ms": display_latency_ms,
                "sla_budget_ms": sla_budget_ms,
            }

        obs_sla = Observation(
            id="dependency.sla_budget",
            source="dependency",
            category="dependency",
            collector=COLLECTOR,
            method=f"sla_check({sanitized_url})",
            value=sla_val,
            message=sla_msg,
            observed_at=_now(),
            host=host,
        )

        # 4. Circuit Breaker / Throttling Observation
        if code in (503, 429, 504):
            cb_msg = f"Upstream circuit breaker / throttling triggered (HTTP {code})"
            cb_val: dict[str, Any] = {"status": "FAIL", "failure": f"HTTP_{code}", "status_code": code}
        else:
            cb_msg = "No upstream circuit breaking or throttling detected"
            cb_val = {"status": "PASS"}

        obs_cb = Observation(
            id="dependency.circuit_breaker",
            source="dependency",
            category="dependency",
            collector=COLLECTOR,
            method=f"circuit_breaker({sanitized_url})",
            value=cb_val,
            message=cb_msg,
            observed_at=_now(),
            host=host,
        )

        return obs_status, obs_latency, obs_sla, obs_cb

    def _require_network(self, operation: str, target: str, port: int | None) -> None:
        self._capabilities.require_network(operation, target, port)
        max_probes = self._capabilities.network.max_probes
        if max_probes is not None and self._probe_count >= max_probes:
            raise CapabilityDenied("Network probe limit has been reached.")
        self._probe_count += 1

    def _probe_timeout(self) -> float:
        timeout = self._capabilities.network.timeout_seconds
        if not math.isfinite(timeout) or timeout <= 0:
            return 2.0
        return timeout

    def _unknown_observation(
        self,
        obs_id: str,
        method: str,
        target_host: str,
        operation: str,
        host: str | None,
        msg: str,
    ) -> Observation:
        return Observation(
            id=obs_id,
            source="dependency",
            category="dependency",
            collector=COLLECTOR,
            method=method,
            value={"status": "UNKNOWN", "target": target_host, "operation": operation},
            message=msg,
            observed_at=_now(),
            host=host,
        )
