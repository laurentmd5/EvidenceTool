"""
Deterministic Causal Reasoning Engine — V1.0

Reconstructs causal chains, disambiguates root causes, and identifies precluded hypotheses
based on verified operational evidence and declarative causal catalogs without guessing.
"""

from __future__ import annotations

from collections import defaultdict, deque

from evidencetool.causality.models import (
    CausalExplanation,
    CausalityStatus,
    CausalRelationType,
    CausalRule,
)
from evidencetool.models.correlation import OperationalState
from evidencetool.models.evidence import Evidence, EvidenceStatus


def _conditions_satisfied(rule: CausalRule, evidence_by_id: dict[str, Evidence]) -> bool:
    for ev_id, expected_status in rule.conditions.items():
        ev = evidence_by_id.get(ev_id)
        if not ev or ev.status.value != expected_status:
            return False
    return True


def _filter_active_rules(
    causal_rules: list[CausalRule],
    evidence_by_id: dict[str, Evidence],
    matched_situations: set[str],
) -> tuple[list[CausalRule], list[str]]:
    active_rules: list[CausalRule] = []
    precluded: list[str] = []

    for rule in causal_rules:
        if not _conditions_satisfied(rule, evidence_by_id):
            continue

        if rule.relation == CausalRelationType.PRECLUDES:
            precluded.append(rule.target)
            continue

        is_active_source = rule.source in matched_situations or (
            rule.source in evidence_by_id and evidence_by_id[rule.source].status == EvidenceStatus.FAIL
        )
        if is_active_source:
            active_rules.append(rule)

    return active_rules, precluded


def _build_graph(active_rules: list[CausalRule], matched_situations: set[str]) -> tuple[dict[str, list[str]], dict[str, int], set[str]]:
    graph: dict[str, list[str]] = defaultdict(list)
    in_degree: dict[str, int] = defaultdict(int)
    all_nodes: set[str] = set()

    for rule in active_rules:
        graph[rule.source].append(rule.target)
        in_degree[rule.target] += 1
        all_nodes.add(rule.source)
        all_nodes.add(rule.target)

    all_nodes.update(matched_situations)
    return graph, in_degree, all_nodes


def _find_candidate_causes(
    all_nodes: set[str],
    in_degree: dict[str, int],
    symptom_nodes: set[str],
    precluded: list[str],
    matched_situations: set[str],
) -> list[str]:
    candidates = [
        node for node in all_nodes
        if in_degree[node] == 0 and node not in symptom_nodes and node not in precluded
    ]
    if not candidates and matched_situations:
        candidates = [
            sit_id for sit_id in matched_situations
            if sit_id not in symptom_nodes and sit_id not in precluded
        ]
    return candidates


def _collect_symptoms(
    all_nodes: set[str],
    in_degree: dict[str, int],
    symptom_nodes: set[str],
    evidence_list: list[Evidence],
) -> list[str]:
    symptoms = [node for node in all_nodes if in_degree[node] > 0 or node in symptom_nodes]
    for e in evidence_list:
        if e.status == EvidenceStatus.FAIL and any(kw in e.id for kw in ("http_status", "latency", "sla")):
            if e.id not in symptoms:
                symptoms.append(e.id)
    return sorted(set(symptoms))


def reconstruct_causality(
    evidence_list: list[Evidence],
    state: OperationalState,
    causal_rules: list[CausalRule] | None = None,
) -> CausalExplanation:
    """
    Reconstructs the deterministic causal explanation for an operational state.
    """
    causal_rules = causal_rules or []
    evidence_by_id = {e.id: e for e in evidence_list}
    matched_situations = {s.id for s in state.situations}

    active_rules, precluded = _filter_active_rules(causal_rules, evidence_by_id, matched_situations)
    _add_standard_preclusions(evidence_by_id, precluded)

    graph, in_degree, all_nodes = _build_graph(active_rules, matched_situations)

    symptom_nodes = {rule.target for rule in causal_rules if rule.is_surface_symptom}
    symptom_nodes.update(rule.source for rule in causal_rules if rule.is_surface_symptom)

    candidates = _find_candidate_causes(all_nodes, in_degree, symptom_nodes, precluded, matched_situations)
    candidates = _rank_and_filter_candidates(candidates, evidence_by_id, matched_situations)
    propagated_symptoms = _collect_symptoms(all_nodes, in_degree, symptom_nodes, evidence_list)

    precluded_sorted = sorted(set(precluded))

    if state.ambiguous or len(state.unresolved_evidence) > 0:
        if not candidates:
            return CausalExplanation(
                status=CausalityStatus.ROOT_CAUSE_UNKNOWN,
                primary_root_cause=None,
                causal_chain=[],
                propagated_symptoms=propagated_symptoms,
                precluded_hypotheses=precluded_sorted,
                candidate_causes=candidates,
                confidence="INSUFFICIENT_EVIDENCE",
            )

    if len(candidates) == 1:
        primary = candidates[0]
        chain = _build_causal_chain(primary, graph, propagated_symptoms)
        status = CausalityStatus.ROOT_CAUSE_IDENTIFIED
    elif len(candidates) > 1:
        primary = None
        chain = []
        status = CausalityStatus.ROOT_CAUSE_CONSTRAINED
    else:
        primary = None
        chain = []
        status = CausalityStatus.ROOT_CAUSE_UNKNOWN

    return CausalExplanation(
        status=status,
        primary_root_cause=primary,
        causal_chain=chain,
        propagated_symptoms=propagated_symptoms,
        precluded_hypotheses=precluded_sorted,
        candidate_causes=candidates,
        confidence="DETERMINISTIC" if status == CausalityStatus.ROOT_CAUSE_IDENTIFIED else "CONSTRAINED",
    )


def _add_standard_preclusions(evidence_by_id: dict[str, Evidence], precluded: list[str]) -> None:
    net_port = evidence_by_id.get("network.port_reachable")
    pg_reach = evidence_by_id.get("postgres.reachable")
    redis_reach = evidence_by_id.get("redis.reachable")
    tls_valid = evidence_by_id.get("tls.certificate_valid")

    if (net_port and net_port.status == EvidenceStatus.PASS) or (
        redis_reach and redis_reach.status == EvidenceStatus.PASS
    ):
        precluded.append("TOTAL_NETWORK_PARTITION")

    if pg_reach and pg_reach.status == EvidenceStatus.PASS:
        precluded.append("POSTGRES_UNREACHABLE")

    if redis_reach and redis_reach.status == EvidenceStatus.PASS:
        precluded.append("REDIS_UNREACHABLE")

    if tls_valid and tls_valid.status == EvidenceStatus.PASS:
        precluded.append("TLS_FAILURE")


def _rank_and_filter_candidates(
    candidates: list[str],
    evidence_by_id: dict[str, Evidence],
    matched_situation_ids: set[str],
) -> list[str]:
    if len(candidates) <= 1:
        return candidates

    direct_indicators = {
        "REDIS_OOM_MAXMEMORY": "redis.memory_pressure",
        "POSTGRES_POOL_EXHAUSTED": "postgres.pool_exhaustion",
        "K8S_OOM_KILLED": "k8s.container_oom_killed",
        "NGINX_CONFIG_INVALID": "nginx.config_valid",
    }

    prioritized = [
        cand for cand in candidates
        if (ind := direct_indicators.get(cand)) and ind in evidence_by_id and evidence_by_id[ind].status == EvidenceStatus.FAIL
    ]
    return prioritized if prioritized else candidates


def _build_causal_chain(root: str, graph: dict[str, list[str]], symptoms: list[str]) -> list[str]:
    chain = [root]
    visited = {root}
    queue = deque([root])

    while queue:
        curr = queue.popleft()
        for nxt in graph.get(curr, []):
            if nxt not in visited:
                visited.add(nxt)
                chain.append(nxt)
                queue.append(nxt)

    for s in symptoms:
        if s not in visited and s != root:
            chain.append(s)
            visited.add(s)

    return chain
