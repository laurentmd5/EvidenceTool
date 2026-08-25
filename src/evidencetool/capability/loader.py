"""Load execution capabilities from a YAML policy."""

from __future__ import annotations

import math
from pathlib import Path

import yaml

from evidencetool.capability.models import CapabilitySet, NetworkCapability


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
        "operations", ["dns_lookup", "route_check", "icmp_echo", "tcp_connect", "tls_handshake", "http_probe"]
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


def load_capability_policy(path: str | Path) -> CapabilitySet:
    content = Path(path).read_text(encoding="utf-8")
    raw = yaml.safe_load(content)
    if not isinstance(raw, dict):
        raise ValueError("Invalid capability policy: expected a YAML mapping.")

    capabilities = raw.get("capabilities", raw)
    if not isinstance(capabilities, dict):
        raise ValueError("Invalid capability policy: 'capabilities' must be a mapping.")

    network = _parse_network(capabilities.get("network", {}))
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
        allowed_providers=(frozenset(allowed_providers_raw) if allowed_providers_raw is not None else None),
        require_trusted_providers=require_trusted,
    )
