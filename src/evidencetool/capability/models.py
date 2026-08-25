"""Execution capabilities, independent from diagnostic business policies."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network


class CapabilityDenied(PermissionError):
    """Raised when a caller attempts a probe outside its granted capabilities."""


@dataclass(frozen=True)
class NetworkCapability:
    enabled: bool = True
    operations: frozenset[str] = frozenset(
        {"dns_lookup", "route_check", "icmp_echo", "tcp_connect", "tls_handshake", "http_probe"}
    )
    targets: tuple[str, ...] = ("*",)
    ports: frozenset[int] | None = None
    max_probes: int | None = None
    timeout_seconds: float = 2.0

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
class CapabilitySet:
    network: NetworkCapability = field(default_factory=NetworkCapability)
    allowed_providers: frozenset[str] | None = None
    require_trusted_providers: bool = False

    def require_network(
        self, operation: str, target: str, port: int | None = None
    ) -> None:
        if not self.network.allows_operation(operation):
            raise CapabilityDenied(f"Network capability '{operation}' is not enabled.")
        if not self.network.allows_target(target):
            raise CapabilityDenied(f"Network target '{target}' is not authorized.")
        if port is not None and not self.network.allows_port(port):
            raise CapabilityDenied(f"Network port '{port}' is not authorized.")

    def allows_provider(self, namespace: str) -> bool:
        return self.allowed_providers is None or namespace in self.allowed_providers


@dataclass(frozen=True)
class ExecutionContext:
    caller: str = "local-cli"
    transport_host: str | None = None
    capabilities: CapabilitySet = field(default_factory=CapabilitySet)
