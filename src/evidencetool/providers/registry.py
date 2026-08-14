"""
Provider Registry for EvidenceTool.
Enables dynamic discovery of providers based on their namespaces.
"""

from __future__ import annotations
from typing import Callable, Type
from dataclasses import dataclass

from evidencetool.providers.base import Provider

@dataclass(frozen=True)
class ProviderLoadError:
    namespace: str
    module: str
    error: str

_PROVIDERS: dict[str, Type[Provider]] = {}
_FAILED_PROVIDERS: dict[str, ProviderLoadError] = {}


def register_provider(namespace: str, provider_cls: Type[Provider]) -> None:
    """Register a provider class under a specific namespace."""
    if namespace in _PROVIDERS:
        raise ValueError(f"Provider namespace '{namespace}' is already registered.")
    _PROVIDERS[namespace] = provider_cls


def provider(namespace: str) -> Callable[[Type[Provider]], Type[Provider]]:
    """Decorator to register a provider."""
    def decorator(cls: Type[Provider]) -> Type[Provider]:
        register_provider(namespace, cls)
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


def load_all_providers() -> None:
    """
    Dynamically discovers and imports all provider modules in the `providers` package.
    Any class decorated with `@provider` in these modules will automatically register itself.
    """
    import importlib
    import pkgutil
    import evidencetool.providers

    package = evidencetool.providers
    for _, module_name, is_pkg in pkgutil.iter_modules(package.__path__):
        if not is_pkg and not module_name.startswith("_") and module_name not in ("base", "registry"):
            full_module_name = f"{package.__name__}.{module_name}"
            try:
                importlib.import_module(full_module_name)
            except Exception as e:
                # Store the error so it can be audited
                _FAILED_PROVIDERS[module_name] = ProviderLoadError(
                    namespace=module_name,
                    module=full_module_name,
                    error=str(e)
                )
                import logging
                logging.getLogger(__name__).error(f"Failed to load provider module {full_module_name}: {e}")
