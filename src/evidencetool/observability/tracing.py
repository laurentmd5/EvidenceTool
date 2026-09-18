"""
OpenTelemetry Tracing Module — Mode B (Outbound Tracing).

Provides structured tracing and explainability export for EvidenceTool diagnoses.
Captures the entire operational pipeline as standard OpenTelemetry spans:
- evidencetool.diagnosis (root span)
  - evidencetool.provider.<namespace>
  - evidencetool.evaluation
  - evidencetool.correlation
  - evidencetool.causality
  - evidencetool.decision

Zero-dependency design:
- If `opentelemetry` is installed, leverages the standard OpenTelemetry SDK / Tracer.
- If `opentelemetry` is not installed, collects in-memory spans and supports OTLP/JSON
  export (HTTP and file) natively with pure Python.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from opentelemetry import trace as otel_trace
    from opentelemetry.trace import Status as OtelStatus
    from opentelemetry.trace import StatusCode as OtelStatusCode
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

    _HAS_OTEL = True
except ImportError:
    otel_trace = None  # type: ignore
    OtelStatus = None  # type: ignore
    OtelStatusCode = None  # type: ignore
    TraceContextTextMapPropagator = None  # type: ignore
    _HAS_OTEL = False

try:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource as OtelResource
    from opentelemetry.sdk.trace import TracerProvider as OtelTracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor as OtelSimpleSpanProcessor

    _HAS_OTEL_EXPORTER = True
except ImportError:
    OTLPSpanExporter = None  # type: ignore
    OtelResource = None  # type: ignore
    OtelTracerProvider = None  # type: ignore
    OtelSimpleSpanProcessor = None  # type: ignore
    _HAS_OTEL_EXPORTER = False

logger = logging.getLogger(__name__)


def _random_hex(num_bytes: int) -> str:
    return uuid.uuid4().hex[: num_bytes * 2]


@dataclass(frozen=True)
class W3CTraceContext:
    """Parsed W3C Trace Context representation."""

    version: str
    trace_id: str
    parent_id: str
    flags: str
    raw: str


_W3C_TRACEPARENT_RE = re.compile(
    r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$",
    re.IGNORECASE,
)


def parse_w3c_traceparent(raw: str | None) -> W3CTraceContext | None:
    """
    Parses a W3C Traceparent header string into its components.

    Complies with W3C Trace Context recommendation (version 00):
    - Format: version-trace_id-parent_id-flags
    - version '00' must be exactly 55 characters
    - version 'ff' is explicitly invalid
    - trace_id must not be all zeros
    - parent_id must not be all zeros
    Returns W3CTraceContext if valid, or None if invalid.
    """
    if not raw or not isinstance(raw, str):
        return None

    cleaned = raw.strip()
    match = _W3C_TRACEPARENT_RE.match(cleaned)
    if not match:
        return None

    version, trace_id, parent_id, flags = match.groups()
    version_lower = version.lower()
    trace_id_lower = trace_id.lower()
    parent_id_lower = parent_id.lower()
    flags_lower = flags.lower()

    if version_lower == "ff":
        return None

    if version_lower == "00" and len(cleaned) != 55:
        return None

    if trace_id_lower == "0" * 32:
        return None
    if parent_id_lower == "0" * 16:
        return None

    return W3CTraceContext(
        version=version_lower,
        trace_id=trace_id_lower,
        parent_id=parent_id_lower,
        flags=flags_lower,
        raw=cleaned,
    )


def has_active_trace_context() -> bool:
    """Returns True if the host OpenTelemetry runtime has an active valid span."""
    if not _HAS_OTEL or otel_trace is None:
        return False
    curr = otel_trace.get_current_span()
    if curr is None or not hasattr(curr, "get_span_context"):
        return False
    ctx = curr.get_span_context()
    return bool(ctx and getattr(ctx, "is_valid", False))



@dataclass
class SpanRecord:
    """A single span in the diagnostic trace."""

    name: str
    span_id: str
    parent_span_id: str | None
    trace_id: str
    start_time_unix_nano: int
    end_time_unix_nano: int | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    status: str = "OK"
    status_description: str | None = None

    def end(self, status: str = "OK", description: str | None = None) -> None:
        self.end_time_unix_nano = time.time_ns()
        self.status = status
        if description:
            self.status_description = description

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "start_time_unix_nano": self.start_time_unix_nano,
            "end_time_unix_nano": self.end_time_unix_nano,
            "duration_ms": round(((self.end_time_unix_nano or time.time_ns()) - self.start_time_unix_nano) / 1e6, 3),
            "status": self.status,
            "status_description": self.status_description,
            "attributes": self.attributes,
        }


@dataclass
class TraceRecord:
    """The full trace containing all spans for an EvidenceTool diagnosis."""

    trace_id: str
    root_span: SpanRecord
    spans: list[SpanRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "root_span": self.root_span.to_dict(),
            "spans": [s.to_dict() for s in self.spans],
        }

    def to_otlp_json(self, service_name: str = "evidencetool") -> dict[str, Any]:
        """Convert trace to standard OTLP/JSON ResourceSpans format."""
        all_spans = [self.root_span] + self.spans
        otlp_spans = []
        for s in all_spans:
            attributes_list = []
            for k, v in s.attributes.items():
                val_obj: dict[str, Any]
                if isinstance(v, bool):
                    val_obj = {"boolValue": v}
                elif isinstance(v, int):
                    val_obj = {"intValue": str(v)}
                elif isinstance(v, float):
                    val_obj = {"doubleValue": v}
                elif isinstance(v, list):
                    val_obj = {"arrayValue": {"values": [{"stringValue": str(item)} for item in v]}}
                else:
                    val_obj = {"stringValue": str(v)}
                attributes_list.append({"key": k, "value": val_obj})

            span_dict: dict[str, Any] = {
                "traceId": s.trace_id,
                "spanId": s.span_id,
                "name": s.name,
                "kind": 1,  # SPAN_KIND_INTERNAL
                "startTimeUnixNano": str(s.start_time_unix_nano),
                "endTimeUnixNano": str(s.end_time_unix_nano or s.start_time_unix_nano),
                "attributes": attributes_list,
                "status": {
                    "code": 1 if s.status == "OK" else 2,
                    "message": s.status_description or "",
                },
            }
            if s.parent_span_id:
                span_dict["parentSpanId"] = s.parent_span_id
            otlp_spans.append(span_dict)

        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": service_name}},
                            {"key": "service.version", "value": {"stringValue": "1.0.3"}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "evidencetool", "version": "1.0.3"},
                            "spans": otlp_spans,
                        }
                    ],
                }
            ]
        }


class DiagnosisTracer:
    """
    Orchestrates OpenTelemetry Mode B tracing during an EvidenceTool diagnosis.

    Host TracerProvider Non-Interference Invariant:
    - EvidenceTool NEVER installs, mutates, or replaces the host application's global TracerProvider.
    - If `opentelemetry` is available, EvidenceTool calls `trace.get_tracer("evidencetool", "1.0.3")`
      and integrates cleanly into the host's active span hierarchy and exporter pipeline.
    - If `opentelemetry` is not installed or no active span exists, EvidenceTool uses its pure-Python
      in-memory collector and native OTLP/file export.
    """

    def __init__(
        self,
        service_name: str | None = None,
        endpoint: str | None = None,
        trace_file: str | None = None,
        traceparent: str | None = None,
    ) -> None:
        self.service_name = service_name or os.getenv("OTEL_SERVICE_NAME", "evidencetool")
        self.endpoint = endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        self.trace_file = trace_file
        self.root_span: SpanRecord | None = None
        self.spans: list[SpanRecord] = []
        self._active_spans: dict[str, SpanRecord] = {}

        # Host OpenTelemetry Tracer integration (strictly read-only, never mutates host provider)
        self._otel_tracer: Any = None
        self._active_otel_spans: dict[str, Any] = {}
        self._host_parent_span_id: str | None = None
        self._extracted_otel_context: Any = None

        self._standalone_provider: Any = None

        if (
            self.endpoint
            and _HAS_OTEL_EXPORTER
            and OtelTracerProvider is not None
            and OTLPSpanExporter is not None
            and OtelResource is not None
        ):
            # Standalone exporter mode using official OTLPSpanExporter:
            # We initialize a standalone TracerProvider without mutating the global host provider.
            try:
                res = OtelResource.create({"service.name": self.service_name or "evidencetool", "service.version": "1.0.3"})
                provider = OtelTracerProvider(resource=res)
                provider.add_span_processor(OtelSimpleSpanProcessor(OTLPSpanExporter(endpoint=self.endpoint)))
                self._standalone_provider = provider
                self._otel_tracer = provider.get_tracer("evidencetool", "1.0.3")
            except Exception as exc:
                logger.warning(
                    f"Could not initialize official OTLPSpanExporter: {exc}; falling back to native HTTP exporter."
                )
                self._standalone_provider = None
        elif _HAS_OTEL and otel_trace is not None:
            self._otel_tracer = otel_trace.get_tracer("evidencetool", "1.0.3")

        # 4-Tier Precedence Hierarchy:
        # Tier 1: Explicit traceparent argument
        # Tier 2: TRACEPARENT environment variable
        # Tier 3: Active host OpenTelemetry span context
        # Tier 4: Generate new independent root trace
        raw_traceparent = traceparent or os.getenv("TRACEPARENT")
        parsed_w3c = parse_w3c_traceparent(raw_traceparent) if raw_traceparent else None

        if raw_traceparent and parsed_w3c is None:
            logger.warning(
                f"Malformed W3C traceparent '{raw_traceparent}'; falling back to active host context or new root trace."
            )

        if parsed_w3c is not None:
            self.trace_id = parsed_w3c.trace_id
            self._host_parent_span_id = parsed_w3c.parent_id
            if _HAS_OTEL and TraceContextTextMapPropagator is not None:
                self._extracted_otel_context = TraceContextTextMapPropagator().extract(
                    carrier={"traceparent": parsed_w3c.raw}
                )
        elif _HAS_OTEL and otel_trace is not None:
            curr = otel_trace.get_current_span()
            if curr is not None and hasattr(curr, "get_span_context"):
                ctx = curr.get_span_context()
                if ctx and getattr(ctx, "is_valid", False):
                    self.trace_id = f"{ctx.trace_id:032x}"
                    self._host_parent_span_id = f"{ctx.span_id:016x}"
                else:
                    self.trace_id = _random_hex(16)
            else:
                self.trace_id = _random_hex(16)
        else:
            self.trace_id = _random_hex(16)

    def start_root_span(self, target: str, policy_action: str) -> SpanRecord:
        """Starts the root evidencetool.diagnosis span."""
        span_id = _random_hex(8)
        parent_id = self._host_parent_span_id

        if self._otel_tracer is not None:
            otel_span = self._otel_tracer.start_span(
                name="evidencetool.diagnosis",
                context=self._extracted_otel_context,
                attributes={
                    "evidencetool.target": target,
                    "evidencetool.policy.action": policy_action,
                    "service.name": self.service_name,
                },
            )
            self._active_otel_spans["evidencetool.diagnosis"] = otel_span
            ctx = otel_span.get_span_context()
            if ctx and getattr(ctx, "is_valid", False):
                self.trace_id = f"{ctx.trace_id:032x}"
                span_id = f"{ctx.span_id:016x}"

        self.root_span = SpanRecord(
            name="evidencetool.diagnosis",
            span_id=span_id,
            parent_span_id=parent_id,
            trace_id=self.trace_id,
            start_time_unix_nano=time.time_ns(),
            attributes={
                "evidencetool.target": target,
                "evidencetool.policy.action": policy_action,
                "service.name": self.service_name,
            },
        )
        return self.root_span

    def start_span(self, name: str, parent: SpanRecord | None = None) -> SpanRecord:
        """Starts a child span under the root span (or specified parent)."""
        parent_span = parent or self.root_span
        parent_id = parent_span.span_id if parent_span else None
        span_id = _random_hex(8)

        if self._otel_tracer is not None and otel_trace is not None:
            parent_name = parent_span.name if parent_span else "evidencetool.diagnosis"
            parent_otel = self._active_otel_spans.get(parent_name)
            context = None
            if parent_otel is not None:
                context = otel_trace.set_span_in_context(parent_otel)

            otel_span = self._otel_tracer.start_span(
                name=name,
                context=context,
            )
            self._active_otel_spans[name] = otel_span
            ctx = otel_span.get_span_context()
            if ctx and getattr(ctx, "is_valid", False):
                span_id = f"{ctx.span_id:016x}"

        span = SpanRecord(
            name=name,
            span_id=span_id,
            parent_span_id=parent_id,
            trace_id=self.trace_id,
            start_time_unix_nano=time.time_ns(),
        )
        self._active_spans[name] = span
        return span

    def end_span(
        self,
        name: str,
        status: str = "OK",
        description: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> SpanRecord | None:
        """Ends an active span by name and records it."""
        otel_span = self._active_otel_spans.pop(name, None)
        if otel_span is not None:
            if attributes:
                for k, v in attributes.items():
                    otel_span.set_attribute(k, v)
            if OtelStatus is not None and OtelStatusCode is not None:
                code = OtelStatusCode.OK if status == "OK" else OtelStatusCode.ERROR
                desc = (description or "") if code == OtelStatusCode.ERROR else ""
                otel_span.set_status(OtelStatus(code, description=desc))
            otel_span.end()

        span = self._active_spans.pop(name, None)
        if span:
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, v)
            span.end(status=status, description=description)
            self.spans.append(span)
        return span

    def record_decision(
        self,
        status: str,
        reason: str,
        blocking_evidence: list[str],
        action: str,
    ) -> None:
        """Enriches the root span and creates the evidencetool.decision span."""
        if self.root_span:
            self.root_span.set_attribute("evidencetool.decision.status", status)
            self.root_span.set_attribute("evidencetool.decision.reason", reason)
            self.root_span.set_attribute("evidencetool.decision.blocking_evidence", blocking_evidence)
            self.root_span.set_attribute("evidencetool.decision.action", action)

        root_otel = self._active_otel_spans.get("evidencetool.diagnosis")
        if root_otel is not None:
            root_otel.set_attribute("evidencetool.decision.status", status)
            root_otel.set_attribute("evidencetool.decision.reason", reason)
            root_otel.set_attribute("evidencetool.decision.blocking_evidence", blocking_evidence)
            root_otel.set_attribute("evidencetool.decision.action", action)

        self.start_span("evidencetool.decision")
        self.end_span(
            "evidencetool.decision",
            status="OK",
            description=reason,
            attributes={
                "evidencetool.decision.status": status,
                "evidencetool.decision.reason": reason,
                "evidencetool.decision.blocking_evidence": blocking_evidence,
            },
        )

    def record_causality(
        self,
        causality_status: str,
        primary_root_cause: str | None,
        causal_chain: list[str],
        precluded_hypotheses: list[str],
    ) -> None:
        """Enriches root span and records evidencetool.causality span."""
        if self.root_span:
            self.root_span.set_attribute("evidencetool.causality.status", causality_status)
            if primary_root_cause:
                self.root_span.set_attribute("evidencetool.causality.primary_root_cause", primary_root_cause)

        root_otel = self._active_otel_spans.get("evidencetool.diagnosis")
        if root_otel is not None:
            root_otel.set_attribute("evidencetool.causality.status", causality_status)
            if primary_root_cause:
                root_otel.set_attribute("evidencetool.causality.primary_root_cause", primary_root_cause)

        self.end_span(
            "evidencetool.causality",
            status="OK",
            attributes={
                "evidencetool.causality.status": causality_status,
                "evidencetool.causality.primary_root_cause": primary_root_cause or "",
                "evidencetool.causality.chain": causal_chain,
                "evidencetool.causality.precluded": precluded_hypotheses,
            },
        )

    def finish(self, status: str = "OK", description: str | None = None) -> TraceRecord:
        """Finalizes the root span and exports the trace if configured."""
        root_otel = self._active_otel_spans.pop("evidencetool.diagnosis", None)
        if root_otel is not None:
            if OtelStatus is not None and OtelStatusCode is not None:
                code = OtelStatusCode.OK if status == "OK" else OtelStatusCode.ERROR
                desc = (description or "") if code == OtelStatusCode.ERROR else ""
                root_otel.set_status(OtelStatus(code, description=desc))
            root_otel.end()

        for leftover in list(self._active_otel_spans.values()):
            leftover.end()
        self._active_otel_spans.clear()

        if self.root_span:
            self.root_span.end(status=status, description=description)
        else:
            self.root_span = SpanRecord(
                name="evidencetool.diagnosis",
                span_id=_random_hex(8),
                parent_span_id=self._host_parent_span_id,
                trace_id=self.trace_id,
                start_time_unix_nano=time.time_ns(),
                end_time_unix_nano=time.time_ns(),
                status=status,
            )

        trace = TraceRecord(trace_id=self.trace_id, root_span=self.root_span, spans=self.spans)

        # Standalone export if explicitly configured
        if self.trace_file:
            self.export_to_file(trace, self.trace_file)

        if self._standalone_provider is not None:
            try:
                self._standalone_provider.force_flush()
            except Exception as exc:
                logger.warning(f"Failed to flush standalone OTLP exporter: {exc}")
        elif self.endpoint:
            self.export_to_otlp(trace, self.endpoint)

        return trace

    def export_to_file(self, trace: TraceRecord, filepath: str) -> None:
        """Exports the trace in human-friendly JSON and OTLP structure."""
        path = Path(filepath)
        if path.parent and str(path.parent) != ".":
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(trace.to_dict(), indent=2), encoding="utf-8")

    def export_to_otlp(self, trace: TraceRecord, endpoint: str) -> bool:
        """Exports the trace to an OTLP/HTTP collector endpoint."""
        url = endpoint
        if not (url.startswith("http://") or url.startswith("https://")):
            logger.warning(f"Invalid OTLP endpoint scheme: {url}")
            return False

        if not url.endswith("/v1/traces") and not url.endswith("/"):
            url = f"{url}/v1/traces"
        elif url.endswith("/"):
            url = f"{url}v1/traces"

        payload = json.dumps(trace.to_otlp_json(self.service_name or "evidencetool")).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
                return resp.status in (200, 202)
        except Exception as exc:
            logger.warning(f"Failed to export trace to OTLP endpoint {url}: {exc}")
            return False

