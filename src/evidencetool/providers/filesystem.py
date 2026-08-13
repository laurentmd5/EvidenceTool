"""
Filesystem provider.

Checks:
  - filesystem.disk_space_available
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from evidencetool.models.observation import Observation
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider
from evidencetool.providers._shell import get_free_disk_space

COLLECTOR = "filesystem_provider"
DEFAULT_MIN_FREE_BYTES = 100 * 1024 * 1024  # 100 MB


def _now():
    return datetime.now(timezone.utc)


@provider("filesystem")
class FilesystemProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        path = context.get("path", "/")
        min_free_bytes = int(context.get("min_free_bytes", str(DEFAULT_MIN_FREE_BYTES)))
        host = context.get("host", None)
        return [self._disk_space_available(path, min_free_bytes, host)]

    def _disk_space_available(self, path: str, min_free_bytes: int, host: str | None) -> Observation:
        method = f"get_free_disk_space({path})"
        free_bytes = get_free_disk_space(path, host=host)
        
        if free_bytes is None:
            return Observation(
                id="filesystem.disk_space_available",
                source="filesystem",
                category="disk",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN"},
                message=f"Could not read disk usage for {path}",
                observed_at=_now(),
                host=host,
            )

        status = "PASS" if free_bytes >= min_free_bytes else "FAIL"
        free_mb = free_bytes / (1024 * 1024)
        threshold_mb = min_free_bytes / (1024 * 1024)
        message = (
            f"{free_mb:.0f}MB free (threshold {threshold_mb:.0f}MB)"
            if status == "PASS"
            else f"Only {free_mb:.0f}MB free, below threshold of {threshold_mb:.0f}MB"
        )

        return Observation(
            id="filesystem.disk_space_available",
            source="filesystem",
            category="disk",
            collector=COLLECTOR,
            method=method,
            value={"status": status, "free_bytes": free_bytes},
            message=message,
            observed_at=_now(),
            host=host,
        )
