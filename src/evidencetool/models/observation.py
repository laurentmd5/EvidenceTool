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

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


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

    def age_seconds(self, now: datetime | None = None) -> float:
        """Age of the observation relative to `now` (defaults to current time)."""
        reference = now or datetime.now(timezone.utc)
        return (reference - self.observed_at).total_seconds()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "category": self.category,
            "collector": self.collector,
            "method": self.method,
            "value": self.value,
            "message": self.message,
            "observed_at": self.observed_at.isoformat(),
            "collected_at": self.collected_at.isoformat(),
        }
