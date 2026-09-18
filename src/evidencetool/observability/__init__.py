"""
Observability package for EvidenceTool.

Provides Prometheus metrics generation and OpenTelemetry tracing (Mode B).
"""

from __future__ import annotations

from evidencetool.observability.metrics import MetricsData, write_metrics
from evidencetool.observability.tracing import DiagnosisTracer, SpanRecord, TraceRecord

__all__ = ["MetricsData", "write_metrics", "DiagnosisTracer", "SpanRecord", "TraceRecord"]
