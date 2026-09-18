"""Load execution capabilities from a YAML policy."""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any

import yaml

from evidencetool.capability.models import (
    CapabilityDenied,
    CapabilitySet,
    KubernetesCapability,
    NetworkCapability,
)


def _parse_ports(value: object) -> frozenset[int] | None:
    if value is None or value == "*":
        return None
    if not isinstance(value, list) or not all(isinstance(item, int) and not isinstance(item, bool) for item in value):
        raise ValueError("Invalid capability policy: network.ports must be a list of integers or '*'.")
    if not all(1 <= item <= 65535 for item in value):
        raise ValueError("Invalid capability policy: network.ports must be between 1 and 65535.")
    return frozenset(value)


def _parse_network(raw: object) -> NetworkCapability:
    if not isinstance(raw, dict):
        raise ValueError("Invalid capability policy: 'network' must be a mapping.")
    operations = raw.get(
        "operations",
        [
            "dns_lookup",
            "route_check",
            "icmp_echo",
            "tcp_connect",
            "tls_handshake",
            "http_probe",
            "redis_ping",
            "redis_info",
            "db_ping",
            "db_pool_check",
            "ssh_transport",
        ],
    )
    targets = raw.get("targets", ["*"])
    if not isinstance(operations, list) or not all(isinstance(item, str) for item in operations):
        raise ValueError("Invalid capability policy: network.operations must be a list of strings.")
    if not isinstance(targets, list) or not all(isinstance(item, str) for item in targets):
        raise ValueError("Invalid capability policy: network.targets must be a list of strings.")
    max_probes = raw.get("max_probes")
    if max_probes is not None and (isinstance(max_probes, bool) or not isinstance(max_probes, int) or max_probes < 1):
        raise ValueError("Invalid capability policy: network.max_probes must be a positive integer.")
    timeout_seconds = raw.get("timeout_seconds", 2.0)
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ValueError("Invalid capability policy: network.timeout_seconds must be a positive number.")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("Invalid capability policy: network.timeout_seconds must be a positive number.")
    return NetworkCapability(
        enabled=bool(raw.get("enabled", True)),
        operations=frozenset(operations),
        targets=tuple(targets),
        ports=_parse_ports(raw.get("ports")),
        max_probes=max_probes,
        timeout_seconds=float(timeout_seconds),
    )


def _parse_kubernetes(raw: Any) -> KubernetesCapability:
    if raw is None:
        return KubernetesCapability()
    if not isinstance(raw, dict):
        raise ValueError("Invalid capability policy: 'kubernetes' must be a mapping.")
    operations = raw.get(
        "operations",
        ["k8s_get_pod", "k8s_get_events", "k8s_get_node", "k8s_get_pvc", "k8s_get_service"],
    )
    allowed_ns = raw.get("allowed_namespaces", ["*"])
    denied_ns = raw.get("denied_namespaces", ["kube-system", "kube-public", "kube-node-lease"])
    if not isinstance(operations, list) or not all(isinstance(item, str) for item in operations):
        raise ValueError("Invalid capability policy: kubernetes.operations must be a list of strings.")
    if not isinstance(allowed_ns, list) or not all(isinstance(item, str) for item in allowed_ns):
        raise ValueError("Invalid capability policy: kubernetes.allowed_namespaces must be a list of strings.")
    if not isinstance(denied_ns, list) or not all(isinstance(item, str) for item in denied_ns):
        raise ValueError("Invalid capability policy: kubernetes.denied_namespaces must be a list of strings.")
    timeout_seconds = raw.get("timeout_seconds", 5.0)
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        raise ValueError("Invalid capability policy: kubernetes.timeout_seconds must be a positive number.")
    return KubernetesCapability(
        enabled=bool(raw.get("enabled", True)),
        operations=frozenset(operations),
        allowed_namespaces=tuple(allowed_ns),
        denied_namespaces=frozenset(denied_ns),
        timeout_seconds=float(timeout_seconds),
    )


def load_capability_policy(
    path: str | Path, expected_hash: str | None = None
) -> CapabilitySet:
    content = Path(path).read_text(encoding="utf-8")
    sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    if expected_hash and sha256_hash.lower() != expected_hash.lower():
        raise CapabilityDenied(
            f"Capability policy tamper detected: expected hash {expected_hash}, got {sha256_hash}"
        )

    raw = yaml.safe_load(content)
    if not isinstance(raw, dict):
        raise ValueError("Invalid capability policy: expected a YAML mapping.")

    capabilities = raw.get("capabilities", raw)
    if not isinstance(capabilities, dict):
        raise ValueError("Invalid capability policy: 'capabilities' must be a mapping.")

    network = _parse_network(capabilities.get("network", {}))
    kubernetes = _parse_kubernetes(capabilities.get("kubernetes", {}))
    providers_raw = capabilities.get("providers", {})
    allowed_providers_raw = providers_raw.get("allowed") if isinstance(providers_raw, dict) else None
    require_trusted = providers_raw.get("require_trusted", False) if isinstance(providers_raw, dict) else False
    if not isinstance(require_trusted, bool):
        raise ValueError("Invalid capability policy: providers.require_trusted must be a boolean.")
    if allowed_providers_raw is not None and (
        not isinstance(allowed_providers_raw, list)
        or not all(isinstance(item, str) for item in allowed_providers_raw)
    ):
        raise ValueError("Invalid capability policy: providers.allowed must be a list of strings.")

    return CapabilitySet(
        network=network,
        kubernetes=kubernetes,
        allowed_providers=frozenset(allowed_providers_raw) if allowed_providers_raw is not None else None,
        require_trusted_providers=require_trusted,
        policy_fingerprint=sha256_hash,
    )
