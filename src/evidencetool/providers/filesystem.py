"""
Filesystem provider.

Checks:
  - filesystem.disk_space_available
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone

from evidencetool.models.observation import Observation

COLLECTOR = "filesystem_provider"
DEFAULT_MIN_FREE_BYTES = 100 * 1024 * 1024  # 100 MB


def _now():
    return datetime.now(timezone.utc)


class FilesystemProvider:
    def collect(
        self, path: str = "/", min_free_bytes: int = DEFAULT_MIN_FREE_BYTES
    ) -> list[Observation]:
        return [self._disk_space_available(path, min_free_bytes)]

    def _disk_space_available(self, path: str, min_free_bytes: int) -> Observation:
        method = f"shutil.disk_usage({path})"
        try:
            usage = shutil.disk_usage(path)
        except OSError as exc:
            return Observation(
                id="filesystem.disk_space_available",
                source="filesystem",
                category="disk",
                collector=COLLECTOR,
                method=method,
                value={"status": "UNKNOWN"},
                message=f"Could not read disk usage for {path}: {exc}",
                observed_at=_now(),
            )

        status = "PASS" if usage.free >= min_free_bytes else "FAIL"
        free_mb = usage.free / (1024 * 1024)
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
            value={"status": status, "free_bytes": usage.free},
            message=message,
            observed_at=_now(),
        )
