"""
Recommendation — advisory text only.

Per PRODUCT_CONTRACT.md and the governance discussion:

    Recommendation never modifies Decision.

This module takes a Decision as INPUT (read-only) and produces advisory
text as OUTPUT. There is no path in this codebase where a Recommendation
feeds back into `evidencetool.decision.engine.decide`. In V0.1 this
mapping is a deterministic rule table -- no LLM involved (consistent with
NFR-004: deterministic policy/decision evaluation). A future LLM-backed
recommender could replace this function's body without touching its
signature or anything upstream of it.
"""

from __future__ import annotations

from evidencetool.models.decision import Decision, DecisionStatus

_KNOWN_REMEDIATIONS = {
    "nginx.config_valid": "Run `nginx -t` locally to see the exact syntax error, then fix nginx.conf before retrying.",
    "nginx.config_exists": "Restore or recreate the nginx configuration file at the expected path.",
    "tls.certificate_exists": "Provision or restore the missing TLS certificate (e.g. re-run certbot).",
    "tls.certificate_valid": "Renew the certificate — it is expired, malformed, or unparseable.",
    "tls.private_key_exists": "Restore the missing private key, or reissue the certificate/key pair.",
    "systemd.service_exists": "Verify the systemd unit file is installed and named correctly.",
    "systemd.service_active": "Inspect `journalctl -u <service>` to see why the service isn't active.",
    "filesystem.disk_space_available": "Free up disk space before attempting the action.",
}


def recommend(decision: Decision) -> str:
    if decision.status == DecisionStatus.ALLOW:
        return "Evidence and policy support proceeding with the proposed action."

    if decision.status == DecisionStatus.HUMAN_REVIEW:
        return (
            "Evidence supports the proposed action, but its risk level requires "
            "explicit human sign-off before proceeding."
        )

    # BLOCK
    tips = [
        _KNOWN_REMEDIATIONS.get(evidence_id, f"Investigate {evidence_id} before retrying.")
        for evidence_id in decision.blocking_evidence
    ]
    if not tips:
        return "Action is blocked. Investigate the reported evidence before retrying."
    if len(tips) == 1:
        return tips[0]
    return " Also: ".join(tips)
