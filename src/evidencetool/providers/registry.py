"""
Provider Registry for EvidenceTool.
Enables dynamic discovery of providers based on their namespaces.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Type

import yaml

from evidencetool.providers.base import Provider


@dataclass(frozen=True)
class ProviderLoadError:
    namespace: str
    module: str
    error: str


@dataclass(frozen=True)
class ProviderManifest:
    namespace: str
    module: str
    sha256: str

_PROVIDERS: dict[str, Type[Provider]] = {}
_FAILED_PROVIDERS: dict[str, ProviderLoadError] = {}
_PROVIDER_TRUST: dict[str, "ProviderTrust"] = {}


class ProviderTrust(str, Enum):
    BUILTIN = "builtin"
    APPROVED = "approved"
    EXPERIMENTAL = "experimental"
    DISABLED = "disabled"


BUILTIN_NAMESPACES = frozenset({
    "container",
    "dependency",
    "docker",
    "filesystem",
    "k8s",
    "kubernetes",
    "mysql",
    "network",
    "nginx",
    "postgres",
    "process",
    "redis",
    "systemd",
    "tls",
})


def register_provider(
    namespace: str,
    provider_cls: Type[Provider],
    trust: ProviderTrust | None = None,
) -> None:
    """Register a provider class under a specific namespace."""
    if namespace in _PROVIDERS:
        raise ValueError(f"Provider namespace '{namespace}' is already registered.")
    _PROVIDERS[namespace] = provider_cls
    _PROVIDER_TRUST[namespace] = trust or (
        ProviderTrust.BUILTIN if namespace in BUILTIN_NAMESPACES else ProviderTrust.EXPERIMENTAL
    )


def provider(
    namespace: str,
    trust: ProviderTrust | None = None,
) -> Callable[[Type[Provider]], Type[Provider]]:
    """Decorator to register a provider."""
    def decorator(cls: Type[Provider]) -> Type[Provider]:
        register_provider(namespace, cls, trust=trust)
        return cls
    return decorator


def get_provider(namespace: str) -> Provider:
    """
    Instantiate and return the provider for the given namespace.
    Raises ValueError if the namespace is not registered.
    """
    if namespace not in _PROVIDERS:
        raise ValueError(f"No provider registered for namespace: '{namespace}'")

    cls = _PROVIDERS[namespace]
    return cls()


def get_provider_trust(namespace: str) -> ProviderTrust:
    if namespace not in _PROVIDERS:
        raise ValueError(f"No provider registered for namespace: '{namespace}'")
    return _PROVIDER_TRUST[namespace]


BUILTIN_MODULE_NAMES = (
    "dependency",
    "docker",
    "filesystem",
    "k8s",
    "mysql",
    "network",
    "nginx",
    "postgres",
    "process",
    "redis",
    "systemd",
    "tls",
)


def load_all_providers(include_experimental: bool = False) -> None:
    """
    Statically imports the 12 verified built-in providers.
    External providers are never auto-discovered from the filesystem and must be
    explicitly approved via load_approved_plugins() before import.
    """
    for module_name in BUILTIN_MODULE_NAMES:
        full_module_name = f"evidencetool.providers.{module_name}"
        try:
            importlib.import_module(full_module_name)
        except Exception as e:
            _FAILED_PROVIDERS[module_name] = ProviderLoadError(
                namespace=module_name,
                module=full_module_name,
                error=str(e),
            )
            import logging
            logging.getLogger(__name__).error(f"Failed to load built-in provider module {full_module_name}: {e}")


def load_approved_plugins(manifest_path: str | Path) -> None:
    """Verify external plugin source hashes before importing plugin modules."""
    raw = yaml.safe_load(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("plugins"), list):
        raise ValueError("Invalid provider manifest: 'plugins' must be a list.")

    for index, item in enumerate(raw["plugins"]):
        if not isinstance(item, dict):
            raise ValueError(f"Invalid provider manifest: plugins[{index}] must be a mapping.")
        namespace = item.get("namespace")
        module = item.get("module")
        expected_hash = item.get("sha256")
        if (
            not isinstance(namespace, str)
            or not isinstance(module, str)
            or not isinstance(expected_hash, str)
            or not namespace
            or not module
            or not expected_hash
        ):
            raise ValueError(f"Invalid provider manifest: plugins[{index}] requires namespace, module and sha256.")
        if len(expected_hash) != 64 or any(character not in "0123456789abcdefABCDEF" for character in expected_hash):
            raise ValueError(f"Invalid provider manifest: plugins[{index}].sha256 is invalid.")

        spec = importlib.util.find_spec(module)
        if spec is None or not spec.origin or spec.origin in {"built-in", "frozen"}:
            raise ValueError(f"Provider plugin module '{module}' has no verifiable source file.")
        source = Path(spec.origin).read_bytes()
        actual_hash = hashlib.sha256(source).hexdigest()
        if actual_hash.lower() != expected_hash.lower():
            raise ValueError(f"Provider plugin '{module}' failed SHA-256 verification.")

        importlib.import_module(module)
        if namespace not in _PROVIDERS:
            raise ValueError(f"Provider plugin '{module}' did not register namespace '{namespace}'.")
        _PROVIDER_TRUST[namespace] = ProviderTrust.APPROVED
