"""
Prometheus textfile metrics writer.

This writes EvidenceTool execution metrics to a text file for Node Exporter
to scrape, rather than exposing an HTTP server.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from evidencetool.models.decision import DecisionStatus
from evidencetool.models.evidence import EvidenceStatus


@dataclass
class MetricsData:
    start_time: float = field(default_factory=time.time)
    provider_durations: dict[str, float] = field(default_factory=dict)
    evaluation_duration: float = 0.0
    decision_duration: float = 0.0
    total_duration: float = 0.0
    success: bool = False
    integrity_violation: int = 0
    decision_status: DecisionStatus | None = None
    evidence_status_counts: dict[EvidenceStatus, int] = field(
        default_factory=lambda: {
            EvidenceStatus.PASS: 0,
            EvidenceStatus.FAIL: 0,
            EvidenceStatus.UNKNOWN: 0,
        }
    )


def write_metrics(metrics: MetricsData, output_path: str = "./evidencetool.prom"):
    lines = []
    
    lines.append("# HELP evidencetool_last_run_success 1 if the run completed successfully and passed integrity validation.")
    lines.append("# TYPE evidencetool_last_run_success gauge")
    lines.append(f"evidencetool_last_run_success {1 if metrics.success else 0}")
    
    lines.append("# HELP evidencetool_integrity_violation 1 if there was a decision integrity violation in the last run, 0 otherwise.")
    lines.append("# TYPE evidencetool_integrity_violation gauge")
    lines.append(f"evidencetool_integrity_violation {metrics.integrity_violation}")

    lines.append("# HELP evidencetool_last_run_duration_seconds Total execution time.")
    lines.append("# TYPE evidencetool_last_run_duration_seconds gauge")
    lines.append(f"evidencetool_last_run_duration_seconds {metrics.total_duration:.4f}")

    lines.append("# HELP evidencetool_provider_duration_seconds Time spent in each provider.")
    lines.append("# TYPE evidencetool_provider_duration_seconds gauge")
    for provider, duration in metrics.provider_durations.items():
        lines.append(f"evidencetool_provider_duration_seconds{{provider=\"{provider}\"}} {duration:.4f}")

    lines.append("# HELP evidencetool_evaluation_duration_seconds Time spent evaluating evidence.")
    lines.append("# TYPE evidencetool_evaluation_duration_seconds gauge")
    lines.append(f"evidencetool_evaluation_duration_seconds {metrics.evaluation_duration:.4f}")

    lines.append("# HELP evidencetool_decision_duration_seconds Time spent in the decision engine.")
    lines.append("# TYPE evidencetool_decision_duration_seconds gauge")
    lines.append(f"evidencetool_decision_duration_seconds {metrics.decision_duration:.4f}")

    lines.append("# HELP evidencetool_decision Decision status of the last run.")
    lines.append("# TYPE evidencetool_decision gauge")
    for status in DecisionStatus:
        val = 1 if metrics.decision_status == status else 0
        lines.append(f"evidencetool_decision{{status=\"{status.value}\"}} {val}")

    lines.append("# HELP evidencetool_evidence Evidence status counts for the last run.")
    lines.append("# TYPE evidencetool_evidence gauge")
    for status, count in metrics.evidence_status_counts.items():
        lines.append(f"evidencetool_evidence{{status=\"{status.value}\"}} {count}")

    lines.append("")  # Ensure trailing newline

    content = "\n".join(lines)
    
    path = Path(output_path)
    if path.parent and str(path.parent) != ".":
        path.parent.mkdir(parents=True, exist_ok=True)
        
    path.write_text(content, encoding="utf-8")
