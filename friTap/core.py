#!/usr/bin/env python3

"""Core controller for friTap with sync and async APIs shared by all UIs.

Replaces the legacy SSL_Logger pattern with explicit dependency injection::

    ctrl = CoreController()
    session = ctrl.create_session(FriTapConfig(target="com.example.app"))
    session.start(); session.wait()          # sync
    await session.astart(); await session.await_done()   # async
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Optional

from .backends import BackendName, get_backend
from .backends.base import Backend
from .config import DeviceConfig, FriTapConfig
from .pipeline import create_default_pipeline
from .plugins.loader import PluginLoader

if TYPE_CHECKING:
    from .backends.capture import CaptureReadiness
    from .protocols.registry import ProtocolRegistry
    from .session import CaptureProducer, Session


class CoreController:
    """Central API for friTap operations (constructor injection, no globals), used by CLI, TUI, Web UI and MCP.

    Sync (``create_session``, ``list_devices``) and async (``acreate_session``, ``alist_devices``) variants.
    """

    def __init__(
        self,
        backend: Optional[Backend] = None,
        protocol_registry: Optional["ProtocolRegistry"] = None,
        plugin_loader: Optional[PluginLoader] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._backend = backend  # injected; None resolves per request
        self._protocol_registry = protocol_registry
        self._plugin_loader = plugin_loader or PluginLoader()
        self._logger = logger or logging.getLogger("friTap.core")

    @property
    def backend(self) -> Backend:
        """Return the injected backend, else the default (Frida) one."""
        return self._resolve_backend()

    def _resolve_backend(self, name: str = BackendName.FRIDA) -> Backend:
        """The injected backend wins; otherwise the cached backend named *name*."""
        return self._backend if self._backend is not None else get_backend(name)

    @property
    def protocol_registry(self) -> "ProtocolRegistry":
        """Return the protocol registry, lazily initializing if needed."""
        if self._protocol_registry is None:
            from .protocols.registry import create_default_registry
            self._protocol_registry = create_default_registry()
        return self._protocol_registry

    def create_session(
        self, config: FriTapConfig, *, producer: Optional["CaptureProducer"] = None,
        manage_capture_resources: bool = True,
    ) -> "Session":
        """Create a session in CREATED state; call ``session.start()`` to capture."""
        from .backends.capture import create_ebpf_producer
        from .session import Session

        if (self._backend is not None and config.backend_explicit
                and self._backend.name != config.backend):
            raise ValueError("Injected backend conflicts with the explicit capture backend")
        if producer is None and config.backend == "ebpf":
            producer = create_ebpf_producer(config)

        pipeline = create_default_pipeline(
            debug=config.debug_output,
            filter_infrastructure=config.output.filter_infrastructure,
            include_loopback=config.output.include_loopback,
        )

        # A producer feeds records itself; only an injected backend rides along.
        backend = self._backend if producer is not None else self._resolve_backend(config.backend)

        session = Session(
            config=config,
            backend=backend,
            protocol_registry=self.protocol_registry,
            plugin_loader=self._plugin_loader,
            pipeline=pipeline,
            logger=self._logger,
            producer=producer,
            manage_capture_resources=manage_capture_resources,
        )

        return session

    async def acreate_session(self, config: FriTapConfig) -> "Session":
        """Async wrapper (``create_session`` does no I/O)."""
        return self.create_session(config)

    def capture_readiness(
        self, backend: str, device: DeviceConfig, *, diagnostic: bool = False,
        kernel_helper: str | None = None, target: str | None = None,
    ) -> "CaptureReadiness":
        """Inspect a named backend without initializing the controller's default."""
        from .backends.capture import select_capture_backend

        selected = select_capture_backend(backend)
        if selected is None:
            raise ValueError(f"Readiness is unavailable for backend {backend!r}")
        if diagnostic or target is not None:
            return selected.diagnose(device, kernel_helper=kernel_helper, target=target)
        if kernel_helper is not None:
            raise ValueError("A kernel helper requires an explicit diagnostic")
        return selected.readiness(device)

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
