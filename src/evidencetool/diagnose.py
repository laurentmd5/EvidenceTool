"""
Diagnose orchestration for the "nginx" vertical slice.

This is the only place in the codebase that wires providers, the
evaluator, the policy engine, the decision engine, and the recommendation
module together. Providers themselves know nothing about policy or
decision (per the architectural principle locked in the design phase):

    Nginx Provider
          |
          v
     Observation
          |
          v
    Evidence Evaluator
          |
          v
     Policy Engine
          |
          v
    Decision Engine
          |
          v
     Recommendation   (advisory only, cannot influence Decision)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from evidencetool.decision.engine import decide
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.models.decision import Decision
from evidencetool.models.evidence import Evidence
from evidencetool.models.incident import Incident
from evidencetool.models.policy import Policy
from evidencetool.providers.filesystem import FilesystemProvider
from evidencetool.providers.nginx import NginxProvider
from evidencetool.providers.systemd import SystemdProvider
from evidencetool.providers.tls import TLSProvider
from evidencetool.recommendation import recommend

from evidencetool.observability.metrics import MetricsData
from evidencetool.decision.integrity import validate_decision_integrity
import time
import logging

logger = logging.getLogger(__name__)

DEFAULT_SERVICE = "nginx"
DEFAULT_NGINX_CONFIG = "/etc/nginx/nginx.conf"
DEFAULT_CERT_PATH = "/etc/letsencrypt/live/example.com/fullchain.pem"
DEFAULT_KEY_PATH = "/etc/letsencrypt/live/example.com/privkey.pem"


@dataclass(frozen=True)
class DiagnosisResult:
    incident: Incident
    evidence: list[Evidence]
    policy: Policy
    decision: Decision
    recommendation: str
    metrics: MetricsData


def diagnose_nginx(
    policy: Policy,
    *,
    service: str = DEFAULT_SERVICE,
    config_path: str = DEFAULT_NGINX_CONFIG,
    certificate_path: str = DEFAULT_CERT_PATH,
    private_key_path: str = DEFAULT_KEY_PATH,
) -> DiagnosisResult:
    m = MetricsData()
    start_total = time.time()
    
    incident = Incident(id=f"inc_{uuid.uuid4().hex[:8]}", type="nginx_start_failure")

    observations = []
    
    t0 = time.time()
    observations += SystemdProvider().collect(service)
    m.provider_durations["systemd"] = time.time() - t0
    
    t0 = time.time()
    observations += NginxProvider().collect(config_path)
    m.provider_durations["nginx"] = time.time() - t0
    
    t0 = time.time()
    observations += TLSProvider().collect(certificate_path, private_key_path)
    m.provider_durations["tls"] = time.time() - t0
    
    t0 = time.time()
    observations += FilesystemProvider().collect()
    m.provider_durations["filesystem"] = time.time() - t0

    t0 = time.time()
    max_ages = {
        req.id: req.max_age for req in policy.required_evidence if req.max_age is not None
    }
    evidence = [evaluate_observation(obs, max_age=max_ages.get(obs.id)) for obs in observations]
    m.evaluation_duration = time.time() - t0

    for e in evidence:
        m.evidence_status_counts[e.status] += 1

    t0 = time.time()
    decision = decide(evidence, policy)
    m.decision_duration = time.time() - t0
    
    m.decision_status = decision.status

    # Integrity Check
    integrity_result = validate_decision_integrity(decision, policy, evidence)
    if not integrity_result.is_valid:
        m.integrity_violation = 1
        m.success = False
    else:
        m.success = True
        
    recommendation_text = recommend(decision)

    m.total_duration = time.time() - start_total

    return DiagnosisResult(
        incident=incident,
        evidence=evidence,
        policy=policy,
        decision=decision,
        recommendation=recommendation_text,
        metrics=m,
    )

