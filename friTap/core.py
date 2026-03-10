#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Core controller for friTap.

Provides both sync and async APIs consumed by different UIs equally. Replaces the legacy pattern of SSL_Logger
with explicit dependency injection.

Usage (sync):
    from friTap.core import CoreController
    ctrl = CoreController()
    session = ctrl.create_session(FriTapConfig(target="com.example.app"))
    session.start()
    session.wait()

Usage (async):
    ctrl = CoreController()
    session = ctrl.create_session(config)
    await session.astart()
    await session.await_done()
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Optional

from .backends import get_backend
from .backends.base import Backend
from .config import FriTapConfig
from .pipeline import create_default_pipeline
from .plugins.loader import PluginLoader

if TYPE_CHECKING:
    from .protocols.registry import ProtocolRegistry
    from .session import Session


class CoreController:
    """Central API for friTap operations.

    Uses constructor injection — no service locator, no globals.
    All frontends (CLI, TUI, Web UI, MCP) use this same interface.

    Both sync and async methods are provided:
    - Sync: ``create_session()``, ``list_devices()``
    - Async: ``acreate_session()``, ``alist_devices()``
    """

    def __init__(
        self,
        backend: Optional[Backend] = None,
        protocol_registry: Optional["ProtocolRegistry"] = None,
        plugin_loader: Optional[PluginLoader] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._backend = backend
        self._protocol_registry = protocol_registry
        self._plugin_loader = plugin_loader or PluginLoader()
        self._logger = logger or logging.getLogger("friTap.core")

    @property
    def backend(self) -> Backend:
        """Return the backend, lazily initializing if needed."""
        if self._backend is None:
            self._backend = get_backend()
        return self._backend

    @property
    def protocol_registry(self) -> "ProtocolRegistry":
        """Return the protocol registry, lazily initializing if needed."""
        if self._protocol_registry is None:
            from .protocols.registry import create_default_registry
            self._protocol_registry = create_default_registry()
        return self._protocol_registry

    def create_session(self, config: FriTapConfig) -> "Session":
        """Create a new capture session with the given configuration.

        The session is created in CREATED state. Call session.start()
        to begin the capture.
        """
        from .session import Session

        pipeline = create_default_pipeline(debug=config.debug_output)

        session = Session(
            config=config,
            backend=self.backend,
            protocol_registry=self.protocol_registry,
            plugin_loader=self._plugin_loader,
            pipeline=pipeline,
            logger=self._logger,
        )

        return session

    async def acreate_session(self, config: FriTapConfig) -> "Session":
        """Async version of create_session.

        Note: create_session() is non-blocking (no I/O), so this is a
        thin async wrapper for API consistency.
        """
        return self.create_session(config)

    def list_devices(self) -> list:
        """List available instrumentation devices."""
        return self.backend.enumerate_devices()

    async def alist_devices(self) -> list:
        """Async version of list_devices."""
        return await asyncio.to_thread(self.list_devices)

    def list_processes(self, device=None) -> list:
        """List running processes on the target device."""
        if device is None:
            device = self.backend.get_device()
        return self.backend.enumerate_processes(device)

    async def alist_processes(self, device=None) -> list:
        """Async version of list_processes."""
        return await asyncio.to_thread(self.list_processes, device)
