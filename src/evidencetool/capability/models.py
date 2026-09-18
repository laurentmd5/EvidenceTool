"""Execution capabilities, independent from diagnostic business policies."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import ip_address, ip_network
from typing import Any


class CapabilityDenied(PermissionError):
    """Raised when a caller attempts a probe outside its granted capabilities."""


class CallerType(str, Enum):
    AI_AGENT = "AI_AGENT"
    HUMAN = "HUMAN"
    AUTOMATED_PIPELINE = "AUTOMATED_PIPELINE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CallerIdentity:
    caller_id: str = "local-cli"
    caller_type: CallerType = CallerType.HUMAN
    session_id: str | None = None


class ProbeTracker:
    """Tracks dynamic probe execution count against budget limits."""

    def __init__(self, max_probes: int | None = None) -> None:
        self.max_probes = max_probes
        self.consumed = 0

    def record_probe(self) -> None:
        self.consumed += 1
        if self.max_probes is not None and self.consumed > self.max_probes:
            raise CapabilityDenied(
                f"Probe budget exceeded: limit of {self.max_probes} probes reached."
            )

    @property
    def remaining(self) -> int | None:
        if self.max_probes is None:
            return None
        return max(0, self.max_probes - self.consumed)


@dataclass(frozen=True)
class AuthorityMetadata:
    caller_id: str
    caller_type: str
    session_id: str | None = None
    policy_fingerprint: str | None = None
    probes_budget: int | None = None
    probes_consumed: int = 0
    probes_remaining: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller_id": self.caller_id,
            "caller_type": self.caller_type,
            "session_id": self.session_id,
            "policy_fingerprint": self.policy_fingerprint,
            "probes_budget": self.probes_budget,
            "probes_consumed": self.probes_consumed,
            "probes_remaining": self.probes_remaining,
        }


@dataclass(frozen=True)
class NetworkCapability:
    enabled: bool = True
    operations: frozenset[str] = frozenset(
        {
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
            "otel_query",
        }
    )
    targets: tuple[str, ...] = ("*",)
    ports: frozenset[int] | None = None
    max_probes: int | None = None
    timeout_seconds: float = 2.0
    allow_insecure_tls: bool = False

    def allows_operation(self, operation: str) -> bool:
        return self.enabled and operation in self.operations

    def allows_target(self, target: str) -> bool:
        if "*" in self.targets:
            return True
        try:
            address = ip_address(target)
        except ValueError:
            return target in self.targets
        return any(address in ip_network(item, strict=False) for item in self.targets)

    def allows_port(self, port: int) -> bool:
        return self.ports is None or port in self.ports


@dataclass(frozen=True)
class KubernetesCapability:
    enabled: bool = True
    operations: frozenset[str] = frozenset(
        {"k8s_get_pod", "k8s_get_events", "k8s_get_node", "k8s_get_pvc", "k8s_get_service"}
    )
    allowed_namespaces: tuple[str, ...] = ("*",)
    denied_namespaces: frozenset[str] = frozenset({"kube-system", "kube-public", "kube-node-lease"})
    timeout_seconds: float = 5.0

    def allows_operation(self, operation: str) -> bool:
        return self.enabled and operation in self.operations

    def allows_namespace(self, namespace: str) -> bool:
        if not self.enabled:
            return False
        if namespace in self.denied_namespaces:
            return False
        if "*" in self.allowed_namespaces:
            return True
        return namespace in self.allowed_namespaces


@dataclass(frozen=True)
class CapabilitySet:
    network: NetworkCapability = field(default_factory=NetworkCapability)
    kubernetes: KubernetesCapability = field(default_factory=KubernetesCapability)
    allowed_providers: frozenset[str] | None = None
    require_trusted_providers: bool = False
    policy_fingerprint: str | None = None
    probe_tracker: ProbeTracker = field(default_factory=ProbeTracker)

    def __post_init__(self) -> None:
        if self.network.max_probes is not None and self.probe_tracker.max_probes is None:
            self.probe_tracker.max_probes = self.network.max_probes

    def require_network(
        self, operation: str, target: str, port: int | None = None
    ) -> None:
        self.probe_tracker.record_probe()
        if not self.network.allows_operation(operation):
            raise CapabilityDenied(f"Network capability '{operation}' is not enabled.")
        if not self.network.allows_target(target):
            raise CapabilityDenied(f"Network target '{target}' is not authorized.")
        if port is not None and not self.network.allows_port(port):
            raise CapabilityDenied(f"Network port '{port}' is not authorized.")

    def require_ssh_transport(self, target: str) -> None:
        """Authorize an SSH destination using the explicit network policy."""
        self.require_network("ssh_transport", target)

    def require_kubernetes(self, operation: str, namespace: str) -> None:
        self.probe_tracker.record_probe()
        if not self.kubernetes.allows_operation(operation):
            raise CapabilityDenied(f"Kubernetes operation '{operation}' is not enabled.")
        if not self.kubernetes.allows_namespace(namespace):
            raise CapabilityDenied(f"Kubernetes namespace '{namespace}' is not authorized.")

    def allows_provider(self, namespace: str) -> bool:
        return self.allowed_providers is None or namespace in self.allowed_providers

    def clone_isolated(self) -> CapabilitySet:
        """Returns a copy of the capability set with an isolated, fresh ProbeTracker."""
        return CapabilitySet(
            network=self.network,
            kubernetes=self.kubernetes,
            allowed_providers=self.allowed_providers,
            require_trusted_providers=self.require_trusted_providers,
            policy_fingerprint=self.policy_fingerprint,
            probe_tracker=ProbeTracker(max_probes=self.network.max_probes),
        )


@dataclass(frozen=True)
class ExecutionContext:
    caller: str = "local-cli"
    identity: CallerIdentity = field(default_factory=CallerIdentity)
    transport_host: str | None = None
    capabilities: CapabilitySet = field(default_factory=CapabilitySet)
