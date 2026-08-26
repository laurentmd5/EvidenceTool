"""
Observation — the raw fact collected by a provider.

Per PRODUCT_CONTRACT.md V1.1: Observation is deliberately separate from
Evidence (the evaluated PASS/FAIL/UNKNOWN judgement). The Observation is
what was actually seen on the system; it is kept verbatim for audit
purposes, independent of how it gets evaluated later.

Observation also carries provenance: which collector produced it, and by
what method (e.g. a shell command), so that a Decision can always be
traced back to the concrete check that produced it.
"""

from __future__ import annotations

import re
import typing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_SENSITIVE_KEY_PATTERN = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie)")
_SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie)(\s*[:=]\s*)([^\s,;]+)"
)


def _redact(value: Any, key: str | None = None) -> Any:
    if key and _SENSITIVE_KEY_PATTERN.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact(item) for item in value)
    if isinstance(value, str):
        return _SENSITIVE_VALUE_PATTERN.sub(r"\1\2[REDACTED]", value)
    return value


@dataclass(frozen=True)
class Observation:
    id: str  # dotted namespace: "<source>.<category>.<check>"
    source: str  # e.g. "nginx", "tls", "systemd", "filesystem"
    category: str  # e.g. "certificate", "configuration"
    collector: str  # name of the provider/collector that produced this
    method: str  # concrete command/API used, e.g. "nginx -t"
    value: Any  # raw observed value, provider-specific shape
    message: str  # human-readable description of what was observed
    observed_at: datetime  # when the underlying fact was true
    collected_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )  # when EvidenceTool actually ran the collector
    host: str | None = None  # the target host the observation was collected from (None = local)
    execution_scope: str | None = None
    target: str | None = None
    capability: str | None = None
    transport_status: str | None = None

    def age_seconds(self, now: datetime | None = None) -> float:
        """Age of the observation relative to `now` (defaults to current time)."""
        reference = now or datetime.now(timezone.utc)
        return (reference - self.observed_at).total_seconds()

    def to_dict(self) -> dict[str, typing.Any]:
        return {
            "id": self.id,
            "source": self.source,
            "category": self.category,
            "collector": self.collector,
            "method": _redact(self.method),
            "value": _redact(self.value),
            "message": _redact(self.message),
            "observed_at": self.observed_at.isoformat(),
            "collected_at": self.collected_at.isoformat(),
            "host": self.host,
            "execution_scope": self.execution_scope,
            "target": self.target,
            "capability": self.capability,
            "transport_status": self.transport_status,
        }
