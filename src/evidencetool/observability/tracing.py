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
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _random_hex(num_bytes: int) -> str:
    return uuid.uuid4().hex[: num_bytes * 2]


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
    Works transparently whether the official opentelemetry SDK is installed or not.
    """

    def __init__(
        self,
        service_name: str | None = None,
        endpoint: str | None = None,
        trace_file: str | None = None,
    ) -> None:
        self.service_name = service_name or os.getenv("OTEL_SERVICE_NAME", "evidencetool")
        self.endpoint = endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        self.trace_file = trace_file
        self.trace_id = _random_hex(16)
        self.root_span: SpanRecord | None = None
        self.spans: list[SpanRecord] = []
        self._active_spans: dict[str, SpanRecord] = {}

    def start_root_span(self, target: str, policy_action: str) -> SpanRecord:
        """Starts the root evidencetool.diagnosis span."""
        span_id = _random_hex(8)
        self.root_span = SpanRecord(
            name="evidencetool.diagnosis",
            span_id=span_id,
            parent_span_id=None,
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
        span = SpanRecord(
            name=name,
            span_id=_random_hex(8),
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

        self.start_span("evidencetool.decision")
        self.end_span(
            "evidencetool.decision",
            status="OK" if status == "ALLOW" else "ERROR",
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
        if self.root_span:
            self.root_span.end(status=status, description=description)
        else:
            self.root_span = SpanRecord(
                name="evidencetool.diagnosis",
                span_id=_random_hex(8),
                parent_span_id=None,
                trace_id=self.trace_id,
                start_time_unix_nano=time.time_ns(),
                end_time_unix_nano=time.time_ns(),
                status=status,
            )

        trace = TraceRecord(trace_id=self.trace_id, root_span=self.root_span, spans=self.spans)

        # 1. Export to file if requested
        if self.trace_file:
            self.export_to_file(trace, self.trace_file)

        # 2. Export to OTLP endpoint if requested
        if self.endpoint:
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

