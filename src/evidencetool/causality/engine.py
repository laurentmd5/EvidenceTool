"""
Deterministic Causal Reasoning Engine — V1.0.4 Mode C

Reconstructs causal chains, disambiguates root causes, and identifies precluded hypotheses
based on verified operational evidence and declarative causal catalogs without guessing.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from evidencetool.causality.models import (
    CausalCandidate,
    CausalCandidateState,
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


def _evaluate_preclusions(
    causal_rules: list[CausalRule],
    evidence_by_id: dict[str, Evidence],
    matched_situations: set[str],
    eval_by_sit_id: dict[str, Any],
) -> set[str]:
    """
    Evaluates all PRECLUDES rules and evidence contradictions deterministically.
    """
    precluded: set[str] = set()

    for rule in causal_rules:
        if rule.relation != CausalRelationType.PRECLUDES:
            continue

        if rule.conditions:
            if _conditions_satisfied(rule, evidence_by_id):
                precluded.add(rule.target)
        else:
            is_active_source = rule.source in matched_situations or (
                rule.source in evidence_by_id
                and evidence_by_id[rule.source].status == EvidenceStatus.PASS
            )
            if is_active_source:
                precluded.add(rule.target)

    # Physical evidence contradictions refute corresponding hypotheses
    for sit_id, ev_eval in eval_by_sit_id.items():
        for disc_id in getattr(ev_eval, "discrepant_evidence", []):
            ev = evidence_by_id.get(disc_id)
            if ev and ev.status == EvidenceStatus.PASS:
                precluded.add(sit_id)
                break

    return precluded


def _detect_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    """
    Deterministically detects directed cycles in the causal graph.
    Returns sorted list of canonical cycle paths (e.g. [['A', 'B', 'A']]).
    """
    visited: dict[str, int] = {}  # 1 = visiting, 2 = done
    path: list[str] = []
    cycles: list[list[str]] = []
    seen_cycle_tuples: set[tuple[str, ...]] = set()

    def dfs(u: str) -> None:
        visited[u] = 1
        path.append(u)
        for v in sorted(graph.get(u, [])):
            if visited.get(v) == 1:
                cycle_start = path.index(v)
                cycle = path[cycle_start:] + [v]
                nodes_in_cycle = cycle[:-1]
                min_idx = nodes_in_cycle.index(min(nodes_in_cycle))
                canonical = tuple(nodes_in_cycle[min_idx:] + nodes_in_cycle[:min_idx] + [nodes_in_cycle[min_idx]])
                if canonical not in seen_cycle_tuples:
                    seen_cycle_tuples.add(canonical)
                    cycles.append(list(canonical))
            elif visited.get(v) != 2:
                dfs(v)
        path.pop()
        visited[u] = 2

    for node in sorted(graph.keys()):
        if visited.get(node) != 2:
            dfs(node)

    return sorted(cycles, key=lambda c: (len(c), c))


def _is_reachable(start: str, target: str, graph: dict[str, list[str]]) -> bool:
    """Returns True if target is reachable from start via directed edges in graph."""
    if start == target:
        return True
    visited = {start}
    queue: deque[str] = deque([start])
    while queue:
        curr = queue.popleft()
        for nxt in graph.get(curr, []):
            if nxt == target:
                return True
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)
    return False


def _find_causal_path(
    start: str,
    target: str,
    graph: dict[str, list[str]],
    rules_by_source: dict[str, list[CausalRule]] | None = None,
) -> list[str]:
    """Finds a shortest directed path from start to target in the graph with edge-priority and deterministic tie-breaking."""
    if start == target:
        return [start]
    visited = {start}
    queue: deque[list[str]] = deque([[start]])
    while queue:
        path = queue.popleft()
        node = path[-1]

        def _neighbor_sort_key(nxt: str) -> tuple[int, str]:
            prio = 0
            if rules_by_source and node in rules_by_source:
                prio = max((r.priority for r in rules_by_source[node] if r.target == nxt), default=0)
            return (-prio, nxt)

        for neighbor in sorted(graph.get(node, []), key=_neighbor_sort_key):
            if neighbor == target:
                return path + [neighbor]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(path + [neighbor])
    return [start]


def _build_causal_chain(
    root: str,
    graph: dict[str, list[str]],
    targets: set[str] | list[str],
    rules_by_source: dict[str, list[CausalRule]] | None = None,
) -> list[str]:
    """
    Reconstructs the deterministic causal path from root to the deepest reachable target symptom.

    Guarantees:
      1. Every adjacent pair in the returned chain has an explicit directed edge in the graph.
      2. Unrelated, unreachable symptoms are strictly excluded (H1).
      3. In branching topologies, selects a single determined causal path using edge priorities and determinism (H2).
    """
    reachable_targets = [t for t in sorted(targets) if t != root and _is_reachable(root, t, graph)]
    if not reachable_targets:
        return [root]

    best_path: list[str] = []
    for t in reachable_targets:
        path = _find_causal_path(root, t, graph, rules_by_source)
        if len(path) > 1 and path[-1] == t:
            if not best_path:
                best_path = path
            else:
                # Prefer deeper paths (longer cascade)
                if len(path) > len(best_path):
                    best_path = path
                elif len(path) == len(best_path):
                    # Deterministic tie-breaker
                    if path < best_path:
                        best_path = path

    return best_path if best_path else [root]


def _build_graph(prop_rules: list[CausalRule]) -> tuple[
    dict[str, list[str]], dict[str, list[str]], dict[str, int], set[str]
]:
    graph: dict[str, list[str]] = defaultdict(list)
    reverse_graph: dict[str, list[str]] = defaultdict(list)
    in_degree: dict[str, int] = defaultdict(int)
    all_nodes: set[str] = set()

    for rule in prop_rules:
        graph[rule.source].append(rule.target)
        reverse_graph[rule.target].append(rule.source)
        in_degree[rule.target] += 1
        all_nodes.add(rule.source)
        all_nodes.add(rule.target)

    return graph, reverse_graph, in_degree, all_nodes


def _collect_symptoms(
    prop_rules: list[CausalRule],
    evidence_list: list[Evidence],
    all_nodes: set[str],
    matched_situations: set[str],
) -> tuple[set[str], list[str]]:
    symptom_nodes = {rule.target for rule in prop_rules if rule.is_surface_symptom}
    symptom_nodes.update(rule.source for rule in prop_rules if rule.is_surface_symptom)
    for e in evidence_list:
        if e.status == EvidenceStatus.FAIL and any(
            kw in e.id for kw in ("http_status", "latency", "sla", "error_rate")
        ):
            symptom_nodes.add(e.id)

    propagated_symptoms = sorted(symptom_nodes.intersection(all_nodes) | {
        sit for sit in matched_situations if any(r.target == sit for r in prop_rules)
    })
    return symptom_nodes, propagated_symptoms


def _discover_candidates(
    targets: set[str],
    reverse_graph: dict[str, list[str]],
    prop_rules: list[CausalRule],
    matched_situations: set[str],
    eval_by_sit_id: dict[str, Any],
) -> set[str]:
    candidate_node_ids: set[str] = set()
    for t in targets:
        queue = deque([t])
        visited = {t}
        while queue:
            curr = queue.popleft()
            parents = reverse_graph.get(curr, [])
            if not parents:
                candidate_node_ids.add(curr)
            else:
                for p in parents:
                    if p not in visited:
                        visited.add(p)
                        queue.append(p)

    for rule in prop_rules:
        if rule.is_root_cause_candidate and (
            rule.source in matched_situations or rule.source in eval_by_sit_id
        ):
            candidate_node_ids.add(rule.source)

    return candidate_node_ids


def _check_requires_and_conditions(
    cand_id: str,
    requires_rules: dict[str, list[CausalRule]],
    cand_rule: CausalRule | None,
    evidence_by_id: dict[str, Evidence],
) -> tuple[list[str], bool]:
    unresolved: list[str] = []

    for req_rule in requires_rules.get(cand_id, []):
        ev = evidence_by_id.get(req_rule.target)
        if ev is None or ev.status == EvidenceStatus.UNKNOWN:
            unresolved.append(req_rule.target)
        elif ev.status == EvidenceStatus.FAIL:
            return [], True

    if cand_rule and cand_rule.conditions:
        for c_id, expected in cand_rule.conditions.items():
            ev = evidence_by_id.get(c_id)
            if ev is None or ev.status == EvidenceStatus.UNKNOWN:
                unresolved.append(c_id)
            elif ev.status.value != expected:
                return [], True

    return unresolved, False


def _resolve_candidate_state(
    cand_id: str,
    matched_situations: set[str],
    direct_ev: Evidence | None,
    sit_eval: Any,
) -> tuple[CausalCandidateState | None, bool, list[str]]:
    """Resolves whether a candidate is confirmed, unresolved, refuted, or inactive."""
    if cand_id in matched_situations:
        return CausalCandidateState.CONFIRMED, False, []

    if direct_ev is not None:
        if direct_ev.status == EvidenceStatus.FAIL:
            return CausalCandidateState.CONFIRMED, False, []
        if direct_ev.status == EvidenceStatus.UNKNOWN:
            return CausalCandidateState.UNRESOLVED, False, [cand_id]
        return None, True, []

    if sit_eval is not None:
        if getattr(sit_eval, "unresolved_evidence", []):
            return CausalCandidateState.UNRESOLVED, False, list(sit_eval.unresolved_evidence)
        return None, True, []

    return None, False, []


def _evaluate_candidate(
    cand_id: str,
    targets: set[str],
    graph: dict[str, list[str]],
    precluded_set: set[str],
    requires_rules: dict[str, list[CausalRule]],
    rules_by_source: dict[str, list[CausalRule]],
    evidence_by_id: dict[str, Evidence],
    matched_situations: set[str],
    eval_by_sit_id: dict[str, Any],
) -> CausalCandidate | None:
    if cand_id in precluded_set:
        return None

    cand_rules = rules_by_source.get(cand_id, [])
    path = _build_causal_chain(cand_id, graph, targets, rules_by_source)
    if not path:
        path = [cand_id]

    active_rule: CausalRule | None = None
    if len(path) > 1:
        active_rule = next((r for r in cand_rules if r.target == path[1]), cand_rules[0] if cand_rules else None)
    elif cand_rules:
        active_rule = cand_rules[0]

    external_unresolved, is_refuted = _check_requires_and_conditions(
        cand_id, requires_rules, active_rule, evidence_by_id
    )
    if is_refuted:
        precluded_set.add(cand_id)
        return None

    sit_eval = eval_by_sit_id.get(cand_id)
    direct_ev = evidence_by_id.get(cand_id)

    cand_state, is_refuted_state, sit_unresolved = _resolve_candidate_state(
        cand_id, matched_situations, direct_ev, sit_eval
    )
    if is_refuted_state:
        precluded_set.add(cand_id)
        return None
    if cand_state is None:
        return None

    missing_all = sorted(set(external_unresolved + sit_unresolved))
    if missing_all:
        cand_state = CausalCandidateState.UNRESOLVED

    return CausalCandidate(
        id=cand_id,
        state=cand_state,
        causal_path=path,
        missing_evidence=missing_all,
        description=active_rule.description if active_rule else "",
    )


def _arbitrate_candidates(
    candidates: list[CausalCandidate],
    graph: dict[str, list[str]],
    reverse_graph: dict[str, list[str]],
    targets: set[str],
    rules_by_source: dict[str, list[CausalRule]],
) -> tuple[str | None, CausalityStatus, list[str], list[CausalCandidate]]:
    confirmed = [c for c in candidates if c.state == CausalCandidateState.CONFIRMED]

    if len(confirmed) == 1:
        primary = confirmed[0].id
        return primary, CausalityStatus.ROOT_CAUSE_IDENTIFIED, _build_causal_chain(primary, graph, targets, rules_by_source), candidates

    if len(confirmed) > 1:
        confirmed_ids = {c.id for c in confirmed}
        roots = [
            c for c in confirmed
            if not any(p in confirmed_ids for p in reverse_graph.get(c.id, []))
        ]
        if len(roots) == 1:
            primary = roots[0].id
            return primary, CausalityStatus.ROOT_CAUSE_IDENTIFIED, _build_causal_chain(primary, graph, targets, rules_by_source), candidates

        if roots:
            priorities = [
                max((r.priority for r in rules_by_source.get(c.id, [])), default=0)
                for c in roots
            ]
            max_prio = max(priorities)
            prio_cands = [
                c for c in roots
                if max((r.priority for r in rules_by_source.get(c.id, [])), default=0) == max_prio
            ]
            # C9: single highest priority candidate wins
            # C9b: if multiple candidates share the exact same max priority, do NOT tie-break!
            if max_prio > 0 and len(prio_cands) == 1:
                primary = prio_cands[0].id
                return (
                    primary,
                    CausalityStatus.ROOT_CAUSE_IDENTIFIED,
                    _build_causal_chain(primary, graph, targets, rules_by_source),
                    candidates,
                )

        # Multi-candidate ambiguity (roots is empty due to cycles, priority tie, or unranked roots):
        # All confirmed candidates are preserved with state = POSSIBLE
        updated = [
            CausalCandidate(
                id=c.id,
                state=CausalCandidateState.POSSIBLE,
                causal_path=c.causal_path,
                missing_evidence=c.missing_evidence,
                description=c.description,
            )
            if c.state == CausalCandidateState.CONFIRMED else c
            for c in candidates
        ]
        return None, CausalityStatus.ROOT_CAUSE_CONSTRAINED, [], updated

    return None, CausalityStatus.ROOT_CAUSE_UNKNOWN, [], candidates


def reconstruct_causality(
    evidence_list: list[Evidence],
    state: OperationalState,
    causal_rules: list[CausalRule] | None = None,
    target_situation: str | None = None,
) -> CausalExplanation:
    """
    Reconstructs the deterministic causal explanation for an operational state.
    """
    causal_rules = causal_rules or []
    evidence_by_id = {e.id: e for e in evidence_list}
    matched_situations = {s.id for s in state.situations}
    eval_by_sit_id = {ev.situation.id: ev for ev in (state.evaluations or [])}

    precluded_set = _evaluate_preclusions(causal_rules, evidence_by_id, matched_situations, eval_by_sit_id)

    prop_rules: list[CausalRule] = []
    requires_rules: dict[str, list[CausalRule]] = defaultdict(list)
    rules_by_source: dict[str, list[CausalRule]] = defaultdict(list)

    for rule in causal_rules:
        if rule.relation in (CausalRelationType.PROPAGATES_TO, CausalRelationType.TRIGGERS):
            prop_rules.append(rule)
            rules_by_source[rule.source].append(rule)
        elif rule.relation == CausalRelationType.REQUIRES:
            requires_rules[rule.source].append(rule)

    if not prop_rules:
        return CausalExplanation(
            status=CausalityStatus.ROOT_CAUSE_UNKNOWN,
            primary_root_cause=None,
            target_situation=target_situation,
            causal_chain=[],
            propagated_symptoms=[],
            precluded_hypotheses=sorted(precluded_set),
            unresolved_hypotheses=[],
            candidate_causes=[],
            confidence="ZERO_CAUSAL_RULES",
        )

    graph, reverse_graph, in_degree, all_nodes = _build_graph(prop_rules)
    detected_cycles = _detect_cycles(graph)

    symptom_nodes, propagated_symptoms = _collect_symptoms(
        prop_rules, evidence_list, all_nodes, matched_situations
    )

    targets: set[str] = {target_situation} if target_situation else {
        node for node in all_nodes
        if (node in matched_situations or node in symptom_nodes) and in_degree[node] > 0
    } or {node for node in all_nodes if in_degree[node] > 0}

    candidate_node_ids = _discover_candidates(
        targets, reverse_graph, prop_rules, matched_situations, eval_by_sit_id
    )

    candidates: list[CausalCandidate] = []
    unresolved_hypotheses: list[str] = []

    for cand_id in sorted(candidate_node_ids):
        cand = _evaluate_candidate(
            cand_id,
            targets,
            graph,
            precluded_set,
            requires_rules,
            rules_by_source,
            evidence_by_id,
            matched_situations,
            eval_by_sit_id,
        )
        if cand:
            candidates.append(cand)
            if cand.state == CausalCandidateState.UNRESOLVED:
                unresolved_hypotheses.append(cand.id)

    primary, status, chain, final_candidates = _arbitrate_candidates(
        candidates, graph, reverse_graph, targets, rules_by_source
    )

    if primary:
        effective_symptoms = [
            s for s in propagated_symptoms
            if s != primary and _is_reachable(primary, s, graph)
        ]
    else:
        effective_symptoms = propagated_symptoms

    return CausalExplanation(
        status=status,
        primary_root_cause=primary,
        target_situation=target_situation,
        causal_chain=chain,
        propagated_symptoms=effective_symptoms,
        precluded_hypotheses=sorted(precluded_set),
        unresolved_hypotheses=sorted(set(unresolved_hypotheses)),
        candidate_causes=final_candidates,
        confidence="DETERMINISTIC" if status == CausalityStatus.ROOT_CAUSE_IDENTIFIED else "CONSTRAINED",
        cycles_detected=detected_cycles,
    )
