"""
Centralized Telemetry HTTP Client & Resource Budget (Mode A).

Guarantees:
- Capability Confinement & Pre-connect SSRF Validation
- Strict No-Redirect Policy (3xx forbidden to prevent SSRF rebound)
- Multi-dimensional TelemetryBudget (requests count, response bytes, query length)
- Bounded stream reading before deserialization (Anti-DoS)
- Centralized credential and URL sanitization
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import ssl
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from evidencetool.capability.models import CapabilityDenied, CapabilitySet

logger = logging.getLogger(__name__)


class RedirectDenied(PermissionError):
    """Raised when an HTTP redirect (3xx) is encountered."""


@dataclass(frozen=True)
class TelemetryBudget:
    """Multi-dimensional resource budget governing inbound telemetry consumption."""
    max_requests: int = 5
    max_response_bytes: int = 1 * 1024 * 1024  # 1 MB
    connect_timeout: float = 2.0
    read_timeout: float = 3.0
    max_query_length: int = 1024
    max_lookback_seconds: int = 3600  # 1 hour
    max_result_items: int = 100
    max_traces: int = 50
    max_spans_per_trace: int = 500


HARD_BUDGET_CEILINGS: dict[str, int | float] = {
    "max_requests": 20,
    "max_response_bytes": 5 * 1024 * 1024,  # 5 MB
    "connect_timeout": 10.0,
    "read_timeout": 10.0,
    "max_query_length": 2048,
    "max_lookback_seconds": 86400,  # 24h
    "max_result_items": 1000,
    "max_traces": 200,
    "max_spans_per_trace": 1000,
}


def _clamp_int_budget(val: object, default: int, ceiling: int) -> int:
    if val is None:
        return default
    try:
        int_val = int(str(val))
        if int_val <= 0:
            return default
        return min(int_val, ceiling)
    except (ValueError, TypeError):
        return default


def _clamp_float_budget(val: object, default: float, ceiling: float) -> float:
    if val is None:
        return default
    try:
        flt_val = float(str(val))
        if flt_val <= 0:
            return default
        return min(flt_val, ceiling)
    except (ValueError, TypeError):
        return default


def build_clamped_telemetry_budget(
    max_requests: object = None,
    max_response_bytes: object = None,
    connect_timeout: object = None,
    read_timeout: object = None,
    max_query_length: object = None,
    max_lookback_seconds: object = None,
    max_result_items: object = None,
    max_traces: object = None,
    max_spans_per_trace: object = None,
) -> TelemetryBudget:
    """
    Builds a TelemetryBudget clamping all requested values against strict internal hard ceilings.
    Prevents configuration-based budget evasion.
    """
    return TelemetryBudget(
        max_requests=_clamp_int_budget(max_requests, 5, int(HARD_BUDGET_CEILINGS["max_requests"])),
        max_response_bytes=_clamp_int_budget(max_response_bytes, 1024 * 1024, int(HARD_BUDGET_CEILINGS["max_response_bytes"])),
        connect_timeout=_clamp_float_budget(connect_timeout, 2.0, float(HARD_BUDGET_CEILINGS["connect_timeout"])),
        read_timeout=_clamp_float_budget(read_timeout, 3.0, float(HARD_BUDGET_CEILINGS["read_timeout"])),
        max_query_length=_clamp_int_budget(max_query_length, 1024, int(HARD_BUDGET_CEILINGS["max_query_length"])),
        max_lookback_seconds=_clamp_int_budget(max_lookback_seconds, 3600, int(HARD_BUDGET_CEILINGS["max_lookback_seconds"])),
        max_result_items=_clamp_int_budget(max_result_items, 100, int(HARD_BUDGET_CEILINGS["max_result_items"])),
        max_traces=_clamp_int_budget(max_traces, 50, int(HARD_BUDGET_CEILINGS["max_traces"])),
        max_spans_per_trace=_clamp_int_budget(max_spans_per_trace, 500, int(HARD_BUDGET_CEILINGS["max_spans_per_trace"])),
    )


def sanitize_url(raw_url: str) -> str:
    """Removes user:password credentials and redacts sensitive query parameters."""
    try:
        parsed = urlparse(raw_url)
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        if parsed.query:
            queries = parse_qsl(parsed.query, keep_blank_values=True)
            sanitized_query = []
            sensitive_keywords = (
                "token",
                "key",
                "secret",
                "auth",
                "password",
                "bearer",
                "api_key",
                "apikey",
            )
            for k, v in queries:
                if any(kw in k.lower() for kw in sensitive_keywords):
                    sanitized_query.append((k, "[REDACTED]"))
                else:
                    sanitized_query.append((k, v))
            query_str = urlencode(sanitized_query, safe="[]")
        else:
            query_str = ""

        return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, query_str, parsed.fragment))
    except Exception:
        return raw_url


def sanitize_error(error: str | None, raw_url: str) -> str | None:
    """Sanitizes sensitive information from error messages."""
    if error is None:
        return None
    return error.replace(raw_url, sanitize_url(raw_url))


def _create_http_connection(
    scheme: str,
    target_host: str,
    port: int,
    timeout: float,
    allow_insecure_tls: bool,
) -> http.client.HTTPConnection:
    if scheme == "https":
        ctx = ssl.create_default_context()
        if allow_insecure_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        return http.client.HTTPSConnection(target_host, port=port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(target_host, port=port, timeout=timeout)


class TelemetryHTTPClient:
    """
    Hardened HTTP client for inbound telemetry backends (Prometheus, Tempo, Jaeger).
    Enforces capabilities, SSRF guards, redirect prohibition, and bounded streaming.
    """

    def __init__(
        self,
        capabilities: CapabilitySet | None = None,
        budget: TelemetryBudget | None = None,
    ) -> None:
        self.capabilities = capabilities
        self.budget = budget or TelemetryBudget()
        self.consumed_requests = 0

    def validate_target(self, endpoint_url: str) -> tuple[str, str, int, str]:
        """
        Validates URL scheme, port, capability authorization, and SSRF rules.
        Returns (scheme, host, port, path).
        """
        parsed = urlparse(endpoint_url)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise CapabilityDenied(f"Unsupported telemetry URL scheme: '{scheme}'. Only http and https are allowed.")

        target_host = parsed.hostname or "127.0.0.1"
        default_port = 443 if scheme == "https" else 80
        port = parsed.port or default_port
        base_path = parsed.path.rstrip("/")

        # Defense-in-depth: check against cloud metadata endpoint SSRF (169.254.169.254)
        try:
            ip = ipaddress.ip_address(target_host)
            if ip.is_link_local:
                # Link-local / metadata addresses require explicit non-wildcard target permission
                if not self.capabilities or "*" in self.capabilities.network.targets:
                    raise CapabilityDenied(
                        f"Target address '{target_host}' is link-local/cloud-metadata and is blocked for SSRF prevention."
                    )
        except ValueError:
            pass

        if self.capabilities:
            self.capabilities.require_network("otel_query", target_host, port)

        return scheme, target_host, port, base_path

    def get(self, endpoint_url: str, path_with_query: str) -> tuple[int, bytes, str | None]:
        """
        Performs a bounded HTTP GET without following redirects.
        Returns (status_code, body_bytes, error_message).
        """
        if self.consumed_requests >= self.budget.max_requests:
            return (
                0,
                b"",
                f"Telemetry request budget exceeded: limit of {self.budget.max_requests} requests reached.",
            )

        try:
            scheme, target_host, port, base_path = self.validate_target(endpoint_url)
        except CapabilityDenied as exc:
            return 0, b"", str(exc)

        if len(path_with_query) > self.budget.max_query_length:
            return (
                0,
                b"",
                f"Telemetry query length ({len(path_with_query)}) exceeds maximum limit of {self.budget.max_query_length} characters.",
            )

        full_path = base_path + path_with_query
        self.consumed_requests += 1

        timeout = self.budget.connect_timeout
        if self.capabilities:
            timeout = min(timeout, self.capabilities.network.timeout_seconds)

        allow_insecure_tls = bool(self.capabilities and self.capabilities.network.allow_insecure_tls)

        try:
            conn = _create_http_connection(scheme, target_host, port, timeout, allow_insecure_tls)

            conn.request(
                "GET",
                full_path,
                headers={
                    "User-Agent": "EvidenceTool/1.0.4-TelemetryClient",
                    "Accept": "application/json",
                },
            )

            # Active Read Timeout Enforcement (A1)
            sock = getattr(conn, "sock", None)
            if sock is not None:
                effective_read_timeout = self.budget.read_timeout
                if self.capabilities:
                    effective_read_timeout = min(effective_read_timeout, self.capabilities.network.timeout_seconds)
                conn.sock.settimeout(effective_read_timeout)

            resp = conn.getresponse()
            status_code = resp.status

            # Strict No-Redirect Policy: HTTP 3xx is forbidden
            if 300 <= status_code < 400:
                conn.close()
                return (
                    status_code,
                    b"",
                    f"HTTP redirect ({status_code}) rejected by security policy (redirects forbidden to prevent SSRF).",
                )

            # Bounded Stream Reading (Anti-DoS before JSON deserialization)
            body = resp.read(self.budget.max_response_bytes + 1)
            conn.close()

            if len(body) > self.budget.max_response_bytes:
                return (
                    status_code,
                    b"",
                    f"Response size exceeded safety budget of {self.budget.max_response_bytes} bytes.",
                )

            return status_code, body, None

        except Exception as exc:
            sanitized_err = sanitize_error(str(exc), endpoint_url)
            return 0, b"", sanitized_err
