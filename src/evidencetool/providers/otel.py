"""
OpenTelemetry Inbound Telemetry Provider (Mode A).

Observes and normalizes live application metrics, latency percentiles, and distributed
trace error spans from Prometheus-compatible and Tempo/Jaeger-compatible backends.

Adheres strictly to the 6 Section 25 Invariants:
- 25.1 Telemetry Observation Invariant (raw normalized observations, no authority extension)
- 25.2 Deterministic Interpretation Invariant (provider observes, policy/evaluator judges thresholds)
- 25.3 Telemetry Capability Invariant (SSRF guards, pre-connect validation, strict no-redirect)
- 25.4 Telemetry Uncertainty Invariant (transport/reachability failures resolve to UNKNOWN)
- 25.5 Telemetry Resource-Bound Invariant (TelemetryBudget multi-dimensional limits, bounded streams)
- 25.6 Hybrid Causality Invariant (surface telemetry symptoms distinct from native root causes)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from urllib.parse import quote_plus

from evidencetool.models.observation import Observation
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import ProviderTrust, provider
from evidencetool.providers.telemetry_client import (
    TelemetryBudget,
    TelemetryHTTPClient,
    sanitize_error,
    sanitize_url,
)

logger = logging.getLogger(__name__)

COLLECTOR = "otel_provider"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@provider("otel", trust=ProviderTrust.BUILTIN)
class OTelProvider:
    """
    Inbound Telemetry Provider.
    Queries metrics and distributed tracing backends to emit normalized observations
    without embedding diagnostic threshold judgements.
    """

    def collect(self, context: ProviderContext) -> list[Observation]:
        capabilities = context.execution.capabilities
        host = context.get("host", "")

        budget = TelemetryBudget(
            max_requests=int(context.get("max_telemetry_requests", "10")),
            connect_timeout=capabilities.network.timeout_seconds if capabilities else 2.0,
        )
        client = TelemetryHTTPClient(capabilities=capabilities, budget=budget)

        metrics_endpoint = (
            context.get("metrics_endpoint")
            or context.get("otel_metrics_endpoint")
            or context.get("prometheus_endpoint")
            or "http://127.0.0.1:9090"
        )
        traces_endpoint = (
            context.get("traces_endpoint")
            or context.get("otel_traces_endpoint")
            or context.get("jaeger_endpoint")
            or context.get("tempo_endpoint")
            or "http://127.0.0.1:3200"
        )
        service_name = context.get("service_name") or context.get("service") or context.get("target") or "default"
        lookback = context.get("lookback", "5m")

        metric_query = context.get("metric_query", "")

        observations: list[Observation] = []

        # 1. Probe Metrics Backend Availability (Technical Reachability)
        reach_metrics_obs = self._probe_metrics_availability(client, metrics_endpoint, host)
        observations.append(reach_metrics_obs)

        # 2. Probe Traces Backend Availability (Technical Reachability)
        reach_traces_obs = self._probe_traces_availability(client, traces_endpoint, host)
        observations.append(reach_traces_obs)

        # 3. Observe HTTP Error Rate (Raw Ratio Observation)
        err_obs = self._observe_http_error_rate(
            client=client,
            metrics_endpoint=metrics_endpoint,
            service_name=service_name,
            host=host,
            custom_promql=context.get("http_error_rate_query", ""),
        )
        observations.append(err_obs)

        # 4. Observe P99 Latency (Raw Milliseconds Observation)
        lat_obs = self._observe_p99_latency(
            client=client,
            metrics_endpoint=metrics_endpoint,
            service_name=service_name,
            host=host,
            custom_promql=context.get("p99_latency_query", ""),
        )
        observations.append(lat_obs)

        # 5. Observe Error Spans Count (Time-Windowed Trace Search)
        trace_obs = self._observe_error_spans(
            client=client,
            traces_endpoint=traces_endpoint,
            service_name=service_name,
            lookback=lookback,
            host=host,
        )
        observations.append(trace_obs)

        # 6. Optional Custom PromQL Query (Raw Numerical Observation)
        if metric_query:
            custom_obs = self._observe_custom_query(
                client=client,
                metrics_endpoint=metrics_endpoint,
                query=metric_query,
                host=host,
            )
            observations.append(custom_obs)

        return observations

    def _probe_metrics_availability(
        self, client: TelemetryHTTPClient, metrics_endpoint: str, host: str | None
    ) -> Observation:
        sanitized = sanitize_url(metrics_endpoint)
        method = f"telemetry_ping({sanitized})"
        status_code, _, error = client.get(metrics_endpoint, "/api/v1/query?query=up")

        if error or status_code != 200:
            err_msg = sanitize_error(error or f"HTTP {status_code}", metrics_endpoint)
            return Observation(
                id="otel.metrics_reachable",
                source="otel",
                category="sla",
                collector=COLLECTOR,
                method=method,
                value={"status": "FAIL", "endpoint": sanitized, "error": err_msg},
                message=f"Metrics backend at {sanitized} is unreachable: {err_msg}",
                observed_at=_now(),
                host=host,
                transport_status="failed",
            )

        return Observation(
            id="otel.metrics_reachable",
            source="otel",
            category="sla",
            collector=COLLECTOR,
            method=method,
            value={"status": "PASS", "endpoint": sanitized, "http_status": status_code},
            message=f"Metrics backend at {sanitized} is responsive (HTTP {status_code})",
            observed_at=_now(),
            host=host,
            transport_status="connected",
        )

    def _probe_traces_availability(
        self, client: TelemetryHTTPClient, traces_endpoint: str, host: str | None
    ) -> Observation:
        sanitized = sanitize_url(traces_endpoint)
        method = f"telemetry_ping({sanitized})"
        status_code, _, error = client.get(traces_endpoint, "/api/traces?limit=1")

        if error or status_code >= 400:
            err_msg = sanitize_error(error or f"HTTP {status_code}", traces_endpoint)
            return Observation(
                id="otel.traces_reachable",
                source="otel",
                category="sla",
                collector=COLLECTOR,
                method=method,
                value={"status": "FAIL", "endpoint": sanitized, "error": err_msg},
                message=f"Traces backend at {sanitized} is unreachable: {err_msg}",
                observed_at=_now(),
                host=host,
                transport_status="failed",
            )

        return Observation(
            id="otel.traces_reachable",
            source="otel",
            category="sla",
            collector=COLLECTOR,
            method=method,
            value={"status": "PASS", "endpoint": sanitized, "http_status": status_code},
            message=f"Traces backend at {sanitized} is responsive (HTTP {status_code})",
            observed_at=_now(),
            host=host,
            transport_status="connected",
        )

    def _query_prometheus_number(
        self, client: TelemetryHTTPClient, metrics_endpoint: str, promql: str
    ) -> tuple[float | None, str | None]:
        path = f"/api/v1/query?query={quote_plus(promql)}"
        status_code, body, error = client.get(metrics_endpoint, path)
        if error:
            return None, error
        if status_code != 200:
            return None, f"Prometheus query returned HTTP {status_code}"

        try:
            data = json.loads(body.decode("utf-8"))
            if data.get("status") != "success":
                return None, f"Prometheus query failed: {data.get('error', 'unknown error')}"
            results = data.get("data", {}).get("result", [])
            if not results:
                return None, "No data returned for metric query"
            raw_val = results[0].get("value", [None, None])[1]
            if raw_val is None:
                return None, "Metric result missing value"
            return float(raw_val), None
        except Exception as exc:
            return None, f"Failed to parse Prometheus response: {exc}"

    def _observe_http_error_rate(
        self,
        client: TelemetryHTTPClient,
        metrics_endpoint: str,
        service_name: str,
        host: str | None,
        custom_promql: str = "",
    ) -> Observation:
        promql = custom_promql or (
            f'sum(rate(http_requests_total{{status=~"5..",service="{service_name}"}}[5m])) / '
            f'sum(rate(http_requests_total{{service="{service_name}"}}[5m]))'
        )
        method = f"promql_query({promql})"
        val, err = self._query_prometheus_number(client, metrics_endpoint, promql)

        if err is not None or val is None:
            err_msg = err or "No data returned for error rate metric"
            return Observation(
                id="otel.http_error_rate",
                source="otel",
                category="metric",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN", "service": service_name, "error": err_msg},
                message=f"HTTP error rate observation inconclusive for '{service_name}': {err_msg}",
                observed_at=_now(),
                host=host,
                transport_status="failed",
            )

        pct = round(val * 100.0, 2)
        return Observation(
            id="otel.http_error_rate",
            source="otel",
            category="metric",
            collector=COLLECTOR,
            method=method,
            value={
                "value": val,
                "error_rate_pct": pct,
                "unit": "ratio",
                "service": service_name,
                "window": "5m",
            },
            message=f"Service '{service_name}' HTTP error rate observed at {pct}% over 5m window",
            observed_at=_now(),
            host=host,
        )

    def _observe_p99_latency(
        self,
        client: TelemetryHTTPClient,
        metrics_endpoint: str,
        service_name: str,
        host: str | None,
        custom_promql: str = "",
    ) -> Observation:
        promql = custom_promql or (
            f'histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket{{service="{service_name}"}}[5m])) by (le)) * 1000'
        )
        method = f"promql_query({promql})"
        val, err = self._query_prometheus_number(client, metrics_endpoint, promql)

        if err is not None or val is None:
            err_msg = err or "No data returned for P99 latency metric"
            return Observation(
                id="otel.p99_latency_ms",
                source="otel",
                category="metric",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN", "service": service_name, "error": err_msg},
                message=f"P99 latency observation inconclusive for '{service_name}': {err_msg}",
                observed_at=_now(),
                host=host,
                transport_status="failed",
            )

        lat_ms = round(val, 2)
        return Observation(
            id="otel.p99_latency_ms",
            source="otel",
            category="metric",
            collector=COLLECTOR,
            method=method,
            value={
                "value": lat_ms,
                "unit": "ms",
                "service": service_name,
                "window": "5m",
            },
            message=f"Service '{service_name}' P99 latency observed at {lat_ms}ms over 5m window",
            observed_at=_now(),
            host=host,
        )

    def _observe_error_spans(
        self,
        client: TelemetryHTTPClient,
        traces_endpoint: str,
        service_name: str,
        lookback: str,
        host: str | None,
    ) -> Observation:
        sanitized = sanitize_url(traces_endpoint)
        method = f"traces_search({sanitized}, service={service_name}, lookback={lookback}, error=true)"
        error_tag_param = quote_plus('{"error":"true"}')
        path = f"/api/traces?service={quote_plus(service_name)}&tags={error_tag_param}&limit={client.budget.max_traces}&lookback={quote_plus(lookback)}"

        status_code, body, error = client.get(traces_endpoint, path)

        if error or status_code != 200:
            err_msg = sanitize_error(error or f"HTTP {status_code}", traces_endpoint)
            return Observation(
                id="otel.error_spans_count",
                source="otel",
                category="trace",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN", "service": service_name, "error": err_msg},
                message=f"Traces query inconclusive for '{service_name}': {err_msg}",
                observed_at=_now(),
                host=host,
                transport_status="failed",
            )

        try:
            data = json.loads(body.decode("utf-8"))
            traces = data.get("data", [])
            if not isinstance(traces, list):
                traces = []
            error_count = sum(
                sum(1 for span in trace.get("spans", []) if any(tag.get("key") == "error" and str(tag.get("value")).lower() == "true" for tag in span.get("tags", [])))
                for trace in traces
            )

            return Observation(
                id="otel.error_spans_count",
                source="otel",
                category="trace",
                collector=COLLECTOR,
                method=method,
                value={
                    "count": error_count,
                    "unit": "count",
                    "window": lookback,
                    "service": service_name,
                    "query": "error=true",
                },
                message=f"Trace search for '{service_name}' found {error_count} error spans in last {lookback}",
                observed_at=_now(),
                host=host,
            )
        except Exception as exc:
            return Observation(
                id="otel.error_spans_count",
                source="otel",
                category="trace",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN", "service": service_name, "error": str(exc)},
                message=f"Failed to parse traces response for '{service_name}': {exc}",
                observed_at=_now(),
                host=host,
                transport_status="failed",
            )

    def _observe_custom_query(
        self,
        client: TelemetryHTTPClient,
        metrics_endpoint: str,
        query: str,
        host: str | None,
    ) -> Observation:
        method = f"promql_query({query})"
        val, err = self._query_prometheus_number(client, metrics_endpoint, query)

        if err is not None or val is None:
            err_msg = err or "No data returned for custom query"
            return Observation(
                id="otel.custom_query",
                source="otel",
                category="metric",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN", "query": query, "error": err_msg},
                message=f"Custom PromQL query failed: {err_msg}",
                observed_at=_now(),
                host=host,
                transport_status="failed",
            )

        return Observation(
            id="otel.custom_query",
            source="otel",
            category="metric",
            collector=COLLECTOR,
            method=method,
            value={"value": val, "query": query},
            message=f"Custom PromQL query evaluated to {val}",
            observed_at=_now(),
            host=host,
        )
