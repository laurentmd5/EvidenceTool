"""
Base interface and context for EvidenceTool Providers.
"""

from __future__ import annotations
from typing import Protocol, Mapping

from evidencetool.models.observation import Observation


class ProviderContext:
    """
    Context injected into every provider during collection.
    Provides generic access to CLI arguments and global configuration.
    """

    def __init__(self, kwargs: Mapping[str, str]):
        self._kwargs = kwargs

    def get(self, key: str, default: str = "") -> str:
        """Get a configuration value, returning `default` if not present."""
        return self._kwargs.get(key, default)
        
    def require(self, key: str) -> str:
        """Get a configuration value, raising ValueError if missing."""
        if key not in self._kwargs:
            raise ValueError(f"Missing required context variable: {key}")
        return self._kwargs[key]


class Provider(Protocol):
    """
    Standard interface for all EvidenceTool providers.
    A provider collects a list of Observations based on a given context.
    """
    def collect(self, context: ProviderContext) -> list[Observation]:
        ...
