#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eBPF instrumentation backend (stub).

Uses uprobes attached to TLS library functions for key/data extraction.
Linux-only, kernel >= 4.18 (x86_64/ARM64).

Advantages over Frida:
- No code injection (works on hardened processes)
- Lower overhead
- Kernel-level visibility

Limitations:
- Read-only (cannot modify traffic)
- No Java/ObjC hooking
- Linux-only
"""

from __future__ import annotations
import logging
from typing import Any, Callable

from .base import Backend


class EBPFBackend(Backend):
    """
    eBPF-based backend using uprobes for TLS function hooking.

    This is a stub implementation. Full implementation requires BCC or
    libbpf for attaching uprobes and reading perf buffers.
    """

    def __init__(self) -> None:
        self._logger = logging.getLogger("friTap.backend.ebpf")
        self._logger.info("eBPF backend initialized (stub)")

    def _not_implemented(self, method: str) -> None:
        raise NotImplementedError(
            f"eBPF backend: {method} is not yet implemented. "
            "Contributions welcome at https://github.com/fkie-cad/friTap"
        )

    def get_device(self, mobile: bool | str = False, host: str | None = None) -> Any:
        if mobile:
            raise NotImplementedError("eBPF backend does not support mobile devices")
        return "local"  # eBPF only works locally

    def attach(self, device: Any, target: str) -> Any:
        self._not_implemented("attach")

    def spawn(self, device: Any, target: str, env: dict | None = None) -> tuple[Any, int]:
        self._not_implemented("spawn")

    def spawn_raw(self, device: Any, target, env: dict | None = None) -> int:
        self._not_implemented("spawn_raw")

    def on_detached(self, process: Any, callback: Callable) -> None:
        pass  # No-op: eBPF doesn't attach to processes the same way

    def resume(self, device: Any, pid: int) -> None:
        self._not_implemented("resume")

    def create_script(self, process: Any, script_source: str, runtime: str = "qjs") -> Any:
        self._not_implemented("create_script")

    def load_script(self, script: Any) -> None:
        self._not_implemented("load_script")

    def unload_script(self, script: Any) -> None:
        pass

    def on_message(self, script: Any, callback: Callable) -> None:
        self._not_implemented("on_message")

    def post_message(self, script: Any, msg_type: str, payload: Any) -> None:
        self._not_implemented("post_message")

    def detach(self, process: Any) -> None:
        pass

    def enable_child_gating(self, process: Any) -> None:
        raise NotImplementedError("eBPF backend does not support child gating")

    def enable_spawn_gating(self, device: Any) -> None:
        raise NotImplementedError("eBPF backend does not support spawn gating")

    def on_child_added(self, device: Any, callback: Callable) -> None:
        raise NotImplementedError("eBPF backend does not support child events")

    def on_spawn_added(self, device: Any, callback: Callable) -> None:
        raise NotImplementedError("eBPF backend does not support spawn events")

    def enable_debugger(self, script: Any, port: int) -> None:
        raise NotImplementedError("eBPF backend does not support debugging")

    def enumerate_threads(self, process: Any) -> list:
        self._not_implemented("enumerate_threads")

    def suspend_thread(self, process: Any, thread_id: int) -> None:
        self._not_implemented("suspend_thread")

    def resume_thread(self, process: Any, thread_id: int) -> None:
        self._not_implemented("resume_thread")

    def enumerate_devices(self) -> list:
        raise NotImplementedError("eBPF backend does not support device enumeration")

    def get_device_manager(self) -> Any:
        raise NotImplementedError("eBPF backend does not support device manager")

    def get_local_device(self) -> Any:
        return "local"  # eBPF only works locally

    def get_usb_device(self) -> Any:
        raise NotImplementedError("eBPF backend does not support USB devices")

    @property
    def name(self) -> str:
        return "ebpf"

    @property
    def version(self) -> str:
        return "0.1.0-stub"
