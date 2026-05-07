#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Protocol handler registry."""

from __future__ import annotations
import importlib
import logging
import os
from typing import Any, Dict, List, Optional

from .base import ProtocolHandler


class ProtocolRegistry:
    """Registry of all available protocol handlers."""

    _PROCESSOR_MAP: dict[str, str] = {
        "ssh": "SSHKeyProcessor",
    #    "ipsec": "IPSecKeyProcessor",
        "tls": "TLSKeyProcessor",
    }

    _MODULE_MAP: dict[str, str] = {
        "ssh": ".ssh_extractor",
    #    "ipsec": ".ipsec_extractor",
        "tls": ".tls_extractor",
    }

    def __init__(self) -> None:
        self._handlers: Dict[str, ProtocolHandler] = {}
        self._logger = logging.getLogger("friTap.protocols")

    def register(self, handler: ProtocolHandler) -> None:
        self._handlers[handler.name] = handler
        self._logger.debug("Registered protocol handler: %s", handler.name)

    def get(self, protocol: str) -> Optional[ProtocolHandler]:
        return self._handlers.get(protocol)

    def get_all(self) -> List[ProtocolHandler]:
        return list(self._handlers.values())

    def auto_detect(self, detected_libraries: List[str]) -> List[ProtocolHandler]:
        """Given detected libraries, return matching protocol handlers."""
        matched = [
            handler for handler in self._handlers.values()
            if handler.matches_libraries(detected_libraries)
        ]
        if matched:
            return matched
        fallback = self._handlers.get("tls") or next(iter(self._handlers.values()))
        return [fallback]

    def list_protocols(self) -> List[str]:
        return list(self._handlers.keys())

    def get_agent_script_path(self, protocol: str, backend_name: str) -> Optional[str]:
        """Return the filesystem path to the hook script for a protocol+backend.

        Parameters
        ----------
        protocol
            Protocol name (e.g., 'ssh', 'ipsec', 'tls').
        backend_name
            Backend name (e.g., 'gdb', 'lldb').

        Returns
        -------
        str or None
            Absolute path to the script, or None if not found.
        """
        # Agent directories are siblings of the friTap package at project root
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        agent_dir = os.path.join(base_dir, f"agent_{backend_name}")
        script_path = os.path.join(agent_dir, protocol, f"{protocol}_key_extract.py")
        if os.path.isfile(script_path):
            return script_path
        return None

    def get_processor(self, protocol: str) -> Optional[Any]:
        """Return the key processor class for a protocol.

        Parameters
        ----------
        protocol
            Protocol name (e.g., 'ssh', 'ipsec', 'tls').

        Returns
        -------
        class or None
            The processor class (SSHKeyProcessor, IPSecKeyProcessor, TLSKeyProcessor).
        """
        class_name = self._PROCESSOR_MAP.get(protocol)
        if class_name is None:
            return None
        module_name = self._MODULE_MAP[protocol]
        try:
            mod = importlib.import_module(module_name, package="friTap.protocols")
            return getattr(mod, class_name)
        except (ImportError, AttributeError) as e:
            self._logger.warning("Could not load processor for '%s': %s", protocol, e)
            return None

    def get_compatibility_matrix(self) -> Dict[str, Dict[str, str]]:
        """Return the full protocol x backend support matrix.

        Returns
        -------
        dict
            Nested dict: {protocol_name: {backend_name: support_level}}.
        """
        matrix = {}
        for name, handler in self._handlers.items():
            matrix[name] = dict(handler.supported_backends)
        return matrix


def create_default_registry(protocols: Optional[List[str]] = None) -> ProtocolRegistry:
    """Create a registry with built-in protocol handlers.

    Parameters
    ----------
    protocols
        Names of protocols to register. ``None`` keeps the historical
        behaviour of registering everything available, so the no-arg
        callers (lazy discovery, tests, TUI menu) keep working.
    """
    from .tls_handler import TLSHandler
#    from .ipsec_handler import IPSecHandler # needs to be impl.
    from .ssh_handler import SSHHandler

    known = {"tls", "ssh"}
    selected = set(protocols) if protocols is not None else known
    if not selected:
        raise ValueError("create_default_registry: at least one protocol required")
    unknown = selected - known
    if unknown:
        raise ValueError(
            f"create_default_registry: unknown protocol(s): {sorted(unknown)}; "
            f"known: {sorted(known)}"
        )

    registry = ProtocolRegistry()
    if "tls" in selected:
        registry.register(TLSHandler())
#    if "ipsec" in selected:
#        registry.register(IPSecHandler()) # needs to be impl.
    if "ssh" in selected:
        registry.register(SSHHandler())
    return registry
