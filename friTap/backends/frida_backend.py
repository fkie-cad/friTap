#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Frida instrumentation backend.

Wraps all ``frida.*`` API calls so that the rest of friTap never
imports or references Frida directly.
"""

from __future__ import annotations
import functools
import logging
from typing import Any, Callable

import frida

from .base import (
    Backend,
    BackendInvalidArgumentError,
    BackendInvalidOperationError,
    BackendNotRunningError,
    BackendPermissionDeniedError,
    BackendProcessNotFoundError,
    BackendTimedOutError,
    BackendTransportError,
    ProcessInfo,
    ThreadInfo,
)


# Mapping from frida exception types to backend exception types
_EXCEPTION_MAP = {
    frida.ServerNotRunningError: BackendNotRunningError,
    frida.InvalidArgumentError: BackendInvalidArgumentError,
    frida.TransportError: BackendTransportError,
    frida.TimedOutError: BackendTimedOutError,
    frida.ProcessNotFoundError: BackendProcessNotFoundError,
    frida.PermissionDeniedError: BackendPermissionDeniedError,
    frida.InvalidOperationError: BackendInvalidOperationError,
}

# Pre-computed tuple of exception types for the except clause (avoids rebuilding per call)
_FRIDA_EXCEPTION_TYPES = tuple(_EXCEPTION_MAP.keys())


def _wrap_frida_errors(func):
    """Decorator that translates frida exceptions to backend exceptions."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except _FRIDA_EXCEPTION_TYPES as exc:
            backend_exc_type = _EXCEPTION_MAP[type(exc)]
            raise backend_exc_type(str(exc)) from exc
    return wrapper


class FridaBackend(Backend):
    """Concrete backend using Frida for dynamic instrumentation."""

    def __init__(self) -> None:
        self._logger = logging.getLogger("friTap.backend.frida")

    # ------------------------------------------------------------------
    # Device
    # ------------------------------------------------------------------

    @_wrap_frida_errors
    def get_device(self, mobile: bool | str = False, host: str | None = None) -> Any:
        if mobile is True:
            self._logger.debug("Attaching to the first available USB device...")
            return frida.get_usb_device()
        if mobile:
            self._logger.debug("Attaching to device with ID: %s", mobile)
            return frida.get_device(mobile)
        if host:
            return frida.get_device_manager().add_remote_device(host)
        return frida.get_local_device()

    # ------------------------------------------------------------------
    # Process attach / spawn
    # ------------------------------------------------------------------

    @_wrap_frida_errors
    def attach(self, device: Any, target: str) -> Any:
        if target.isnumeric():
            return device.attach(int(target))
        return device.attach(target)

    @_wrap_frida_errors
    def spawn(self, device: Any, target: str, env: dict | None = None) -> tuple[Any, int]:
        if env is None:
            env = {}
        try:
            pid = device.spawn(target)
        except frida.InvalidArgumentError:
            pid = device.spawn(target.split(" "), env=env)
        process = device.attach(pid)
        return process, pid

    def resume(self, device: Any, pid: int) -> None:
        device.resume(pid)

    @_wrap_frida_errors
    def spawn_raw(self, device: Any, target, env: dict | None = None) -> int:
        if env:
            return device.spawn(target, env=env)
        return device.spawn(target)

    def on_detached(self, process: Any, callback: Callable) -> None:
        process.on('detached', callback)

    # ------------------------------------------------------------------
    # Script management
    # ------------------------------------------------------------------

    def create_script(self, process: Any, script_source: str, runtime: str = "qjs") -> Any:
        return process.create_script(script_source, runtime=runtime)

    def load_script(self, script: Any) -> None:
        script.load()

    def unload_script(self, script: Any) -> None:
        try:
            script.unload()
        except Exception:
            pass

    def on_message(self, script: Any, callback: Callable) -> None:
        script.on("message", callback)

    def post_message(self, script: Any, msg_type: str, payload: Any) -> None:
        script.post({"type": msg_type, "payload": payload})

    # ------------------------------------------------------------------
    # Process lifecycle
    # ------------------------------------------------------------------

    def detach(self, process: Any) -> None:
        try:
            process.detach()
        except Exception as e:
            self._logger.debug("Detach error (may be expected): %s", e)

    def enable_child_gating(self, process: Any) -> None:
        process.enable_child_gating()

    def enable_spawn_gating(self, device: Any) -> None:
        device.enable_spawn_gating()

    def on_child_added(self, device: Any, callback: Callable) -> None:
        device.on("child_added", callback)

    def on_spawn_added(self, device: Any, callback: Callable) -> None:
        device.on("spawn_added", callback)

    # ------------------------------------------------------------------
    # Debugging
    # ------------------------------------------------------------------

    def enable_debugger(self, script: Any, port: int) -> None:
        if self.version_at_least(16):
            script.enable_debugger(port)
        else:
            self._logger.warning("Script-level debugger requires Frida >= 16")

    # ------------------------------------------------------------------
    # Thread management
    # ------------------------------------------------------------------

    def enumerate_threads(self, process: Any) -> list[ThreadInfo]:
        return [
            ThreadInfo(
                id=t.id,
                name=getattr(t, 'name', None) or f"Thread-{t.id}",
                index=getattr(t, 'index', 0),
                entrypoint=getattr(t, 'entrypoint', None),
                is_stopped=False,
            )
            for t in process.enumerate_threads()
        ]

    def suspend_thread(self, process: Any, thread_id: int) -> None:
        process.suspend(thread_id)

    def resume_thread(self, process: Any, thread_id: int) -> None:
        process.resume(thread_id)

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    @_wrap_frida_errors
    def enumerate_devices(self) -> list:
        return frida.enumerate_devices()

    @_wrap_frida_errors
    def query_system_parameters(self, device: Any) -> dict:
        return device.query_system_parameters()

    @_wrap_frida_errors
    def enumerate_processes(self, device: Any) -> list[ProcessInfo]:
        return [
            ProcessInfo(pid=p.pid, name=p.name)
            for p in device.enumerate_processes()
        ]

    def get_device_manager(self) -> Any:
        return frida.get_device_manager()

    @_wrap_frida_errors
    def get_local_device(self) -> Any:
        return frida.get_local_device()

    @_wrap_frida_errors
    def get_usb_device(self) -> Any:
        return frida.get_usb_device()

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "frida"

    @property
    def version(self) -> str:
        return frida.__version__
