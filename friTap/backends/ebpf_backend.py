#!/usr/bin/env python3

"""Legacy eBPF script interface.

The Linux plaintext capture entrypoints use the native CaptureProducer.
The script backend remains available for legacy device selection.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from .base import Backend


class EBPFBackend(Backend):
    """Compatibility backend for the legacy script interface."""

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

    def spawn_raw(self, device: Any, target, env: dict | None = None,
                  aux: dict | None = None) -> int:
        self._not_implemented("spawn_raw")

    def on_detached(self, process: Any, callback: Callable) -> None:
        pass  # No-op: eBPF doesn't attach to processes the same way

    def resume(self, device: Any, pid: int) -> None:
        self._not_implemented("resume")

    def create_script(self, process: Any, script_source: str, runtime: str = "qjs") -> Any:
        self._not_implemented("create_script")

    def load_script(self, script: Any, *, timeout: float | None = None) -> None:
        # *timeout* is ignored: this backend never reaches a blocking load.
        self._not_implemented("load_script")

    def unload_script(self, script: Any) -> None:
        pass

    def on_message(self, script: Any, callback: Callable) -> None:
        self._not_implemented("on_message")

    def post_message(self, script: Any, msg_type: str, payload: Any) -> None:
        self._not_implemented("post_message")

    def detach(self, process: Any) -> None:
        pass

    def enumerate_threads(self, process: Any) -> list:
        self._not_implemented("enumerate_threads")

    def suspend_thread(self, process: Any, thread_id: int) -> None:
        self._not_implemented("suspend_thread")

    def resume_thread(self, process: Any, thread_id: int) -> None:
        self._not_implemented("resume_thread")

    def enumerate_devices(self) -> list:
        """Legacy script-backend discovery; use CaptureBackend for readiness."""
        return []

    def get_local_device(self) -> Any:
        return "local"  # eBPF only works locally

    @property
    def name(self) -> str:
        return "ebpf"

    @property
    def version(self) -> str:
        return "0.1.0-stub"
