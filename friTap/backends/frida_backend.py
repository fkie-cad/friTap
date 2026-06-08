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
import os
import subprocess
import sys
import time
from typing import Any, Callable, Optional

import frida

from .base import (
    Backend,
    BackendError,
    BackendErrorContext,
    BackendInvalidArgumentError,
    BackendInvalidOperationError,
    BackendNotRunningError,
    BackendPermissionDeniedError,
    BackendProcessNotFoundError,
    BackendProcessNotRespondingError,
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
    frida.ProcessNotRespondingError: BackendProcessNotRespondingError,
    frida.PermissionDeniedError: BackendPermissionDeniedError,
    frida.InvalidOperationError: BackendInvalidOperationError,
}

# Pre-computed tuple of exception types for the except clause (avoids rebuilding per call)
_FRIDA_EXCEPTION_TYPES = tuple(_EXCEPTION_MAP.keys())

# Stable category tags surfaced via BackendError.category. Used by the TUI
# to render a meaningful diagnostic instead of just the message string.
_FRIDA_CATEGORY = {
    frida.ServerNotRunningError:    "frida_server_down",
    frida.InvalidArgumentError:     "frida_invalid_arg",
    frida.TransportError:           "frida_transport",
    frida.TimedOutError:            "frida_timeout",
    frida.ProcessNotFoundError:     "frida_not_found",
    frida.ProcessNotRespondingError: "frida_not_responding",
    frida.PermissionDeniedError:    "frida_denied",
    frida.InvalidOperationError:    "frida_invalid_op",
}


def _probe_hardened_runtime(path: str) -> Optional[bool]:
    """Return True if the binary at ``path`` has the hardened-runtime flag.

    ``codesign --display --verbose=2`` writes a 'flags=...(runtime)' line
    to stderr on success.
    """
    try:
        r = subprocess.run(
            ["codesign", "--display", "--verbose=2", path],
            capture_output=True, text=True, timeout=2,
        )
        return "runtime" in (r.stderr or "") + (r.stdout or "")
    except Exception:
        return None


def _probe_entitlements(path: str) -> tuple[Optional[bool], Optional[bool]]:
    """Return (library_validation_disabled, get_task_allow) for ``path``."""
    try:
        r = subprocess.run(
            ["codesign", "--display", "--entitlements", "-", "--xml", path],
            capture_output=True, text=True, timeout=2,
        )
        ent = r.stdout or ""
        if not ent:
            return None, None
        return (
            "com.apple.security.cs.disable-library-validation" in ent,
            "com.apple.security.get-task-allow" in ent,
        )
    except Exception:
        return None, None


def _macos_target_probes(pid: int, ctx: BackendErrorContext) -> None:
    """Populate ctx.target_path and codesign-derived flags for ``pid``.

    Hardened-runtime + library-validation are the prime remaining culprits
    when a macOS attach fails even with root and SIP off, so we report them
    explicitly. The two ``codesign`` calls run concurrently because each
    takes up to 2 s and they share no state beyond the target path.
    """
    try:
        r = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="],
            capture_output=True, text=True, timeout=1,
        )
        path = r.stdout.strip()
        if path:
            ctx.target_path = path
    except Exception:
        return  # without a path we can't run codesign anyway

    if not ctx.target_path:
        return

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_runtime = ex.submit(_probe_hardened_runtime, ctx.target_path)
        f_ent = ex.submit(_probe_entitlements, ctx.target_path)
        ctx.target_hardened_runtime = f_runtime.result()
        ctx.target_library_validation_disabled, ctx.target_get_task_allow = (
            f_ent.result()
        )


def _collect_context(device: Any = None, target: Any = None) -> BackendErrorContext:
    """Sample cheap diagnostic state. Runs only on the error path.

    All probes have safe fallbacks: if ``csrutil`` is missing, the target
    is a name not a PID, or frida-server is unreachable, the corresponding
    field stays ``None``. The function is intentionally non-raising.
    """
    ctx = BackendErrorContext(
        euid=os.geteuid() if hasattr(os, "geteuid") else -1,
        platform=sys.platform,
    )
    if sys.platform == "darwin":
        try:
            r = subprocess.run(
                ["csrutil", "status"],
                capture_output=True,
                text=True,
                timeout=1,
            )
            ctx.sip_enabled = "enabled" in r.stdout.lower()
        except Exception:
            pass
    pid_int: Optional[int] = None
    if target is not None:
        try:
            target_str = str(target)
            if target_str.isnumeric():
                pid_int = int(target_str)
                os.kill(pid_int, 0)            # raises if the target is gone
                ctx.target_alive = True
        except ProcessLookupError:
            ctx.target_alive = False
        except Exception:
            pass
    if pid_int is not None and sys.platform == "darwin" and ctx.target_alive:
        _macos_target_probes(pid_int, ctx)
    if device is not None:
        try:
            device.query_system_parameters()
            ctx.server_reachable = True
        except Exception:
            ctx.server_reachable = False
    return ctx


def _wrap_frida_errors(func):
    """Two-tier wrapper: translates frida.* errors with rich context, and
    re-tags any other exception as a ``backend_bug`` so the TUI can clearly
    say "this is friTap's fault, not yours".
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except _FRIDA_EXCEPTION_TYPES as exc:
            backend_exc_type = _EXCEPTION_MAP[type(exc)]
            # First positional after self is usually device, second is target;
            # this is best-effort context — we never call methods on stale args.
            device = args[0] if args else None
            target = args[1] if len(args) > 1 else None
            raise backend_exc_type(
                str(exc),
                original_exception=exc,
                category=_FRIDA_CATEGORY.get(type(exc), "frida_error"),
                context=_collect_context(device, target),
            ) from exc
        except BackendError:
            # Already enriched by an inner wrapped call; let it propagate.
            raise
        except Exception as exc:
            raise BackendError(
                f"Internal error in {self.__class__.__name__}.{func.__name__}: "
                f"{type(exc).__name__}: {exc}",
                original_exception=exc,
                category="backend_bug",
                context=_collect_context(),
            ) from exc
    return wrapper


def _is_transient_attach_error(exc: BaseException) -> bool:
    """Return True if ``exc`` is a transient Frida attach failure worth retrying.

    Covers two observed races: the agent-injection handshake stalling on a
    freshly-launched / multi-process target (ProcessNotRespondingError) and
    the transport closing mid-handshake (TransportError with an
    "unexpected early end-of-stream" message).
    """
    if isinstance(exc, frida.ProcessNotRespondingError):
        return True
    if isinstance(exc, frida.TransportError) and "unexpected early end-of-stream" in str(exc):
        return True
    return False


class FridaBackend(Backend):
    """Concrete backend using Frida for dynamic instrumentation."""

    # Frida major this friTap release was tested against. Bumped in lockstep
    # with the `frida>=N,<N+1` constraint in requirements.txt — see RELEASING.md
    # and scripts/check_compat.py (CI version-guard).
    SUPPORTED_FRIDA_MAJOR = 17

    def __init__(self) -> None:
        self._logger = logging.getLogger("friTap.backend.frida")
        self._check_frida_compat()

    def _check_frida_compat(self) -> None:
        """Warn (or fail) when the installed frida major doesn't match the
        version this friTap release was tested against.

        Suppressing the warning: leave ``FRITAP_STRICT_FRIDA`` unset and the
        message goes through the standard logger (warning level).
        Making it fatal: ``FRITAP_STRICT_FRIDA=1`` raises
        ``BackendInvalidArgumentError`` from the constructor.
        """
        try:
            major = int(frida.__version__.split(".")[0])
        except (AttributeError, ValueError):
            return
        if major == self.SUPPORTED_FRIDA_MAJOR:
            return
        msg = (
            f"friTap was tested with frida {self.SUPPORTED_FRIDA_MAJOR}.x; "
            f"you have frida {frida.__version__}. "
            f"See https://github.com/fkie-cad/friTap#frida-compatibility"
        )
        if os.environ.get("FRITAP_STRICT_FRIDA") == "1":
            raise BackendInvalidArgumentError(msg)
        self._logger.warning(msg)

    # ------------------------------------------------------------------
    # Device
    # ------------------------------------------------------------------

    @_wrap_frida_errors
    def get_device(self, mobile: bool | str = False, host: str | None = None, device_id: str | None = None) -> Any:
        if device_id:
            self._logger.debug("Attaching to pre-enumerated device with ID: %s", device_id)
            return frida.get_device(device_id)
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

    def _attach_with_retry(self, device: Any, target: Any) -> Any:
        """Call ``device.attach(target)`` with up to 3 attempts on transient frida errors.

        Backoff is 0.5s then 1.0s. Non-transient frida exceptions propagate
        immediately so the caller's wrapper can translate them.
        """
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                return device.attach(target)
            except (frida.ProcessNotRespondingError, frida.TransportError) as exc:
                if not _is_transient_attach_error(exc) or attempt == max_attempts:
                    raise
                delay = 0.5 * attempt  # 0.5s, then 1.0s
                self._logger.warning(
                    "Frida attach transient failure (attempt %d/%d): %s — retrying in %.1fs",
                    attempt, max_attempts, exc, delay,
                )
                time.sleep(delay)

    @_wrap_frida_errors
    def attach(self, device: Any, target: str) -> Any:
        if target.isnumeric():
            return self._attach_with_retry(device, int(target))
        return self._attach_with_retry(device, target)

    @_wrap_frida_errors
    def spawn(self, device: Any, target: str, env: dict | None = None) -> tuple[Any, int]:
        if env is None:
            env = {}
        try:
            pid = device.spawn(target)
        except frida.InvalidArgumentError as inner_exc:
            # Retry treating ``target`` as a tokenised command line. Preserve
            # the chain so a follow-up failure still names the original cause.
            try:
                pid = device.spawn(target.split(" "), env=env)
            except Exception as retry_exc:
                raise retry_exc from inner_exc
        process = self._attach_with_retry(device, pid)
        return process, pid

    def resume(self, device: Any, pid: int) -> None:
        device.resume(pid)

    @_wrap_frida_errors
    def spawn_raw(self, device: Any, target, env: dict | None = None,
                  aux: dict | None = None) -> int:
        # Frida routes recognized kwargs (env) to their slot and any others
        # (e.g. Android "activity") into the spawn aux dictionary.
        options = dict(aux) if aux else {}
        if env:
            options["env"] = env
        return device.spawn(target, **options)

    def on_detached(self, process: Any, callback: Callable) -> None:
        process.on('detached', callback)

    # ------------------------------------------------------------------
    # Script management
    # ------------------------------------------------------------------

    @_wrap_frida_errors
    def create_script(self, process: Any, script_source: str, runtime: str = "qjs") -> Any:
        return process.create_script(script_source, runtime=runtime)

    @_wrap_frida_errors
    def load_script(self, script: Any) -> None:
        script.load()

    def unload_script(self, script: Any) -> None:
        # Cleanup is best-effort (the process may already be gone). Log so
        # latent backend bugs are still visible instead of silently dropped.
        try:
            script.unload()
        except Exception:
            self._logger.debug("unload_script: cleanup error", exc_info=True)

    def on_message(self, script: Any, callback: Callable) -> None:
        script.on("message", callback)

    def post_message(self, script: Any, msg_type: str, payload: Any) -> None:
        script.post({"type": msg_type, "payload": payload})

    # ------------------------------------------------------------------
    # Process lifecycle
    # ------------------------------------------------------------------

    def detach(self, process: Any) -> None:
        # Detach often races with the target exiting; treat as best-effort.
        # Include the exception type so a real backend bug is still findable
        # in the debug log even though we don't propagate it.
        try:
            process.detach()
        except Exception as e:
            self._logger.debug(
                "Detach error (may be expected): %s: %s", type(e).__name__, e,
            )

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
