#!/usr/bin/env python3

"""Frida instrumentation backend; wraps all ``frida.*`` calls."""

from __future__ import annotations

import functools
import logging
import os
import subprocess
import sys
import threading
import time
import weakref
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
    BackendScriptLoadTimeout,
    BackendTimedOutError,
    BackendTransportError,
    ProcessInfo,
    ThreadInfo,
)
from .frida_chunked_loader import ChunkedLoadScript, needs_chunked_load

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

# Prebuilt once for the except clause.
_FRIDA_EXCEPTION_TYPES = tuple(_EXCEPTION_MAP.keys())

# Other frida.* errors are an ordinary "frida said no", not a friTap bug: they
# keep their message and the generic BackendError. getattr: the set differs
# between frida versions.
_OTHER_FRIDA_ERROR_CATEGORIES = {
    "ExecutableNotFoundError": "frida_executable_not_found",
    "ExecutableNotSupportedError": "frida_executable_not_supported",
    "NotSupportedError": "frida_not_supported",
    "AddressInUseError": "frida_address_in_use",
    "OperationCancelledError": "frida_cancelled",
    "ProtocolError": "frida_protocol",
}
_OTHER_FRIDA_EXCEPTION_TYPES = tuple(
    getattr(frida, name) for name in _OTHER_FRIDA_ERROR_CATEGORIES
    if isinstance(getattr(frida, name, None), type)
)

# Stable BackendError.category tags, rendered by the TUI.
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
    """True if the binary at ``path`` has the hardened-runtime flag.

    ``codesign --display --verbose=2`` prints 'flags=...(runtime)' on stderr.
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

    Hardened runtime and library validation are the prime culprits when a
    macOS attach fails despite root and SIP off. The two ``codesign`` calls
    run concurrently because each can take 2 s.
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
    """Sample cheap diagnostic state on the error path; never raises.

    A probe that cannot run leaves its field ``None``.
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
        _probe_server(device, ctx)
    return ctx


def _probe_server(device, ctx: BackendErrorContext) -> None:
    """Fill ``server_reachable``/``server_access`` from the device.

    frida 17's USB device answers ``query_system_parameters()`` with no
    frida-server running (ADB-only fallback, ``access='jailed'``), so only
    ``access == 'full'`` counts as reachable. With no ``access`` reported,
    an answer counts as reachable.
    """
    try:
        params = device.query_system_parameters()
    except Exception:
        ctx.server_reachable = False
        return
    access = params.get("access") if isinstance(params, dict) else None
    if isinstance(access, str):
        ctx.server_access = access
        ctx.server_reachable = access == "full"
    else:
        ctx.server_reachable = True


def _wrap_frida_errors(
    func: Optional[Callable] = None,
    *,
    first_arg_is_device: bool = True,
) -> Callable:
    """Translate frida.* errors with context; re-tag any other exception as ``backend_bug``.

    Usable bare or as ``@_wrap_frida_errors(first_arg_is_device=False)``.

    Device-first methods (``attach``, ``spawn``, ...) take ``(device, target)``
    and contribute device/target diagnostics. Script-first methods
    (``create_script``, ``load_script``) must pass ``False``: probing a
    Script/Session as a device would report ``server_reachable=False``, and
    ``create_script``'s second positional is the whole agent source, which
    must never be stringified into the context.
    """
    def decorate(target_func: Callable) -> Callable:
        @functools.wraps(target_func)
        def wrapper(self, *args, **kwargs):
            try:
                return target_func(self, *args, **kwargs)
            except _FRIDA_EXCEPTION_TYPES as exc:
                backend_exc_type = _EXCEPTION_MAP[type(exc)]
                if first_arg_is_device:
                    device = args[0] if args else None
                    target = args[1] if len(args) > 1 else None
                else:
                    device = target = None
                raise backend_exc_type(
                    str(exc),
                    original_exception=exc,
                    category=_FRIDA_CATEGORY.get(type(exc), "frida_error"),
                    context=_collect_context(device, target),
                ) from exc
            except BackendError:
                # Already enriched by an inner wrapped call.
                raise
            except _OTHER_FRIDA_EXCEPTION_TYPES as exc:
                raise BackendError(
                    str(exc),
                    original_exception=exc,
                    category=_OTHER_FRIDA_ERROR_CATEGORIES.get(
                        type(exc).__name__, "frida_error"),
                    context=_collect_context(),
                ) from exc
            except Exception as exc:
                raise BackendError(
                    f"Internal error in {self.__class__.__name__}."
                    f"{target_func.__name__}: {type(exc).__name__}: {exc}",
                    original_exception=exc,
                    category="backend_bug",
                    context=_collect_context(),
                ) from exc
        return wrapper

    if func is None:
        return decorate
    return decorate(func)


def _off_frida_main_loop(callback: Callable, thread_name: str) -> Callable:
    """Wrap a Frida signal handler so it runs on its own daemon thread.

    Frida delivers ``detached`` on its main-loop thread, and every synchronous
    Frida call (``query_system_parameters``, unload, ``detach``) waits on that
    same loop. A handler making such a call inline deadlocks: the target-death
    teardown (crash report, pcap finalize, tcpdump stop) never runs and friTap
    hangs until Ctrl+C.
    """
    @functools.wraps(callback)
    def handler(*args: Any) -> None:
        threading.Thread(target=callback, args=args, name=thread_name, daemon=True).start()
    return handler


def _is_transient_attach_error(exc: BaseException) -> bool:
    """True for a transient attach failure worth retrying.

    Two races: the injection handshake stalling on a fresh or multi-process
    target (ProcessNotRespondingError), and the transport closing mid-handshake
    ("unexpected early end-of-stream" TransportError).
    """
    if isinstance(exc, frida.ProcessNotRespondingError):
        return True
    if isinstance(exc, frida.TransportError) and "unexpected early end-of-stream" in str(exc):
        return True
    return False


class FridaBackend(Backend):
    """Concrete backend using Frida for dynamic instrumentation."""

    # Bumped with the `frida>=N,<N+1` pin in requirements.txt (RELEASING.md,
    # scripts/check_compat.py).
    SUPPORTED_FRIDA_MAJOR = 17

    def __init__(self) -> None:
        self._logger = logging.getLogger("friTap.backend.frida")
        # Remote (-H) sessions: large scripts are chunk-loaded there
        # (see frida_chunked_loader).
        self._remote_sessions: "weakref.WeakSet[Any]" = weakref.WeakSet()
        self._check_frida_compat()

    def _check_frida_compat(self) -> None:
        """Warn on a frida major mismatch; ``FRITAP_STRICT_FRIDA=1`` raises
        ``BackendInvalidArgumentError`` instead."""
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

    # Not device-first: the first positional is the *selector* (a bool or a
    # device id), not a device object — there is nothing to probe yet.
    @_wrap_frida_errors(first_arg_is_device=False)
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

    def _attach_with_retry(self, device: Any, target: Any) -> Any:
        """``device.attach(target)`` with up to 3 attempts (0.5 s, 1.0 s backoff).

        Non-transient errors propagate for the caller's wrapper to translate.
        """
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                session = device.attach(target)
                self._remember_remote_session(device, session)
                return session
            except (frida.ProcessNotRespondingError, frida.TransportError) as exc:
                if not _is_transient_attach_error(exc) or attempt == max_attempts:
                    raise
                delay = 0.5 * attempt  # 0.5s, then 1.0s
                self._logger.warning(
                    "Frida attach transient failure (attempt %d/%d): %s — retrying in %.1fs",
                    attempt, max_attempts, exc, delay,
                )
                time.sleep(delay)

    def _remember_remote_session(self, device: Any, session: Any) -> None:
        if getattr(device, "type", None) == "remote":
            self.__dict__.setdefault("_remote_sessions", weakref.WeakSet()).add(session)

    def _is_remote_session(self, session: Any) -> bool:
        try:
            return session in getattr(self, "_remote_sessions", ())
        except TypeError:  # not weak-referenceable: never ours
            return False

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
            # Retry with ``target`` as a tokenised command line, keeping the cause chain.
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
        process.on('detached', _off_frida_main_loop(callback, "fritap-detach"))

    def on_process_crashed(self, device: Any, callback: Callable) -> None:
        device.on('process-crashed', callback)

    def off_process_crashed(self, device: Any, callback: Callable) -> None:
        try:
            device.off('process-crashed', callback)
        except Exception:
            self._logger.debug("off_process_crashed cleanup error", exc_info=True)

    # Not device-first: (session, agent source) — probing either as a device
    # would fabricate a server_reachable=False verdict.
    @_wrap_frida_errors(first_arg_is_device=False)
    def create_script(self, process: Any, script_source: str, runtime: str = "qjs") -> Any:
        # Remote frida-server drops the connection on a message above ~128 KiB:
        # stage a large script through a bootstrap script.
        if self._is_remote_session(process) and needs_chunked_load(script_source):
            self._logger.debug(
                "remote session: chunk-loading a %d-byte script", len(script_source.encode("utf-8")),
            )
            return ChunkedLoadScript.create(process, script_source, runtime=runtime)
        return process.create_script(script_source, runtime=runtime)

    # Not device-first: the first positional is a frida Script.
    @_wrap_frida_errors(first_arg_is_device=False)
    def load_script(self, script: Any, *, timeout: float | None = None) -> None:
        if not timeout:
            # Unbounded: load inline, no thread hand-off.
            script.load()
            return

        # A wedged agent never returns from script.load(), so bound it on a
        # worker thread. Its exception is re-raised here, inside the
        # @_wrap_frida_errors frame, so frida errors still map to Backend*.
        captured: list[BaseException] = []

        def _load() -> None:
            try:
                script.load()
            except BaseException as exc:  # re-raised on the calling thread
                captured.append(exc)

        # script.load() is not cancellable: on timeout the worker is abandoned,
        # and only a daemon thread lets the process exit without joining it.
        started = time.monotonic()
        loader = threading.Thread(target=_load, daemon=True, name="fritap-script-load")
        loader.start()
        loader.join(timeout)
        elapsed = time.monotonic() - started

        if loader.is_alive():
            raise BackendScriptLoadTimeout(
                f"Agent script.load() did not return within {elapsed:.1f}s",
                elapsed_seconds=elapsed,
                bound_seconds=timeout,
            )
        if captured:
            raise captured[0]

    def unload_script(self, script: Any) -> None:
        # Best-effort (the process may be gone); logged so bugs stay findable.
        try:
            script.unload()
        except Exception:
            self._logger.debug("unload_script: cleanup error", exc_info=True)

    def on_message(self, script: Any, callback: Callable) -> None:
        script.on("message", callback)

    def post_message(self, script: Any, msg_type: str, payload: Any) -> None:
        script.post({"type": msg_type, "payload": payload})

    def detach(self, process: Any) -> None:
        process.detach()

    def enable_child_gating(self, process: Any) -> None:
        process.enable_child_gating()

    def enable_spawn_gating(self, device: Any) -> None:
        device.enable_spawn_gating()

    def disable_spawn_gating(self, device: Any) -> None:
        device.disable_spawn_gating()

    def enumerate_pending_spawn(self, device: Any) -> list:
        return list(device.enumerate_pending_spawn())

    def on_child_added(self, device: Any, callback: Callable) -> None:
        device.on("child_added", callback)

    def on_spawn_added(self, device: Any, callback: Callable) -> None:
        device.on("spawn_added", callback)

    def enable_debugger(self, script: Any, port: int) -> None:
        if self.version_at_least(16):
            script.enable_debugger(port)
        else:
            self._logger.warning("Script-level debugger requires Frida >= 16")

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

    @_wrap_frida_errors
    def process_paths(self, device: Any, pids: list[int]) -> dict[int, str]:
        # Filtered by pid and without icons: a few ms even on a remote device.
        processes = device.enumerate_processes(pids=list(pids), scope="metadata")
        return {p.pid: p.parameters["path"] for p in processes
                if isinstance(p.parameters.get("path"), str)}

    def process_name(self, device: Any, pid: int) -> str | None:
        """Resolve *pid* to a package id or process name (see Backend.process_name).

        Only ``scope="metadata"`` carries Android's ``applications`` list; in
        ``minimal`` scope an app is named by its label ("Chrome"), not its
        package id ("com.android.chrome"), which the transport classifier needs.
        """
        try:
            for process in device.enumerate_processes(pids=[pid], scope="metadata"):
                if process.pid == pid:
                    return self._package_or_process_name(process)
        except Exception as exc:  # noqa: BLE001 - fall through to /proc below
            self._logger.debug("enumerate_processes(pid=%s) failed: %s", pid, exc)
        if getattr(device, "type", None) == "local":
            return self._local_proc_comm(pid)
        return None

    @staticmethod
    def _package_or_process_name(process: Any) -> str | None:
        applications = (getattr(process, "parameters", None) or {}).get("applications")
        if isinstance(applications, list) and applications and isinstance(applications[0], str):
            return applications[0]
        return getattr(process, "name", None) or None

    @staticmethod
    def _local_proc_comm(pid: int) -> str | None:
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as comm:
                return comm.read().strip() or None
        except OSError:
            return None

    def get_device_manager(self) -> Any:
        return frida.get_device_manager()

    @_wrap_frida_errors
    def get_local_device(self) -> Any:
        return frida.get_local_device()

    @_wrap_frida_errors
    def get_usb_device(self) -> Any:
        return frida.get_usb_device()

    @property
    def name(self) -> str:
        return "frida"

    @property
    def version(self) -> str:
        return frida.__version__
