"""
Process-wide registry of live capture sessions.

:class:`SessionManager` enforces the capture policy of the calling
:class:`~friTap.agent_api.context.ToolContext` (``allow_capture``, target
allow-list), caps concurrent captures and owns the session directories
(``<root>/.fritap-sessions/<id>``). The module-level :data:`default_manager`
is stopped at interpreter exit; :func:`tap_path_for` lets read tools accept a
``session_id`` instead of a tap path.
"""

from __future__ import annotations

import atexit
import threading
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Optional

from friTap.agent_api import protocol_catalog
from friTap.agent_api.capture.runner import CaptureRequest, build_argv, validate_request
from friTap.agent_api.capture.session import CaptureSession
from friTap.agent_api.context import ToolContext
from friTap.agent_api.errors import ToolError
from friTap.agent_api.paths import resolve_under_root

SESSIONS_DIRNAME = ".fritap-sessions"
DEFAULT_MAX_SESSIONS = 4
_STOP_ALL_TIMEOUT_S = 5.0

SessionFactory = Callable[[str, CaptureRequest, list], CaptureSession]


def sessions_root(ctx: ToolContext) -> Path:
    """Directory holding every session directory of ``ctx``'s sandbox."""
    return Path(ctx.root) / SESSIONS_DIRNAME


def new_session_id() -> str:
    return "s" + uuid.uuid4().hex[:8]


class SessionManager:
    """Thread-safe ``session_id -> CaptureSession`` map with a concurrency cap."""

    def __init__(self, max_sessions: int = DEFAULT_MAX_SESSIONS,
                 command: Optional[list[str]] = None,
                 session_factory: SessionFactory = CaptureSession) -> None:
        self.max_sessions = max_sessions
        self.command = command  # None = python -m friTap.friTap
        self._factory = session_factory
        self._sessions: dict[str, CaptureSession] = {}
        self._lock = threading.Lock()

    # -- start ---------------------------------------------------------------

    def start(self, request: CaptureRequest, ctx: ToolContext) -> CaptureSession:
        """Check policy and limits, then launch ``request`` (its session_dir is ignored)."""
        check_capture_allowed(request.target, ctx)
        validate_request(request)
        request = sandbox_option_paths(request, ctx)
        with self._lock:
            self._check_capacity()
            session_id = new_session_id()
            request = _with_session_dir(request, sessions_root(ctx) / session_id)
            session = self._factory(session_id, request, build_argv(request, self.command))
            session.start()
            self._sessions[session_id] = session
        return session

    def _check_capacity(self) -> None:
        running = sum(1 for s in self._sessions.values() if s.is_running())
        if running >= self.max_sessions:
            raise ToolError(
                f"{running} captures already running (max {self.max_sessions})",
                "limit_reached", hint="stop a running session with stop_capture first")

    # -- lookup --------------------------------------------------------------

    def get(self, session_id: str) -> CaptureSession:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise ToolError(f"unknown capture session {session_id!r}", "not_found",
                            hint="call list_sessions for the known session ids")
        return session

    def sessions(self) -> list[CaptureSession]:
        with self._lock:
            return list(self._sessions.values())

    def tap_path_for(self, session_id: str) -> Path:
        """Tap file of a finished session (raises while it is still running)."""
        session = self.get(session_id)
        if session.is_running():
            raise ToolError(f"capture session {session_id!r} is still running",
                            "capture_running", hint="call stop_capture first")
        tap = session.request.tap_path
        if not tap.exists():
            raise ToolError(f"capture session {session_id!r} produced no tap file",
                            "not_found", hint="check capture_status for the error")
        return tap

    # -- stop ----------------------------------------------------------------

    def stop(self, session_id: str, timeout: Optional[float] = None) -> dict[str, Any]:
        session = self.get(session_id)
        return session.stop() if timeout is None else session.stop(timeout)

    def stop_all(self, timeout: float = _STOP_ALL_TIMEOUT_S) -> None:
        """Stop every running session (registered with atexit)."""
        for session in self.sessions():
            if session.is_running():
                session.stop(timeout)


def check_capture_allowed(target: str, ctx: ToolContext) -> None:
    """Raise ``forbidden`` unless ``ctx`` permits capturing ``target``."""
    if not ctx.allow_capture:
        raise ToolError("live capture is disabled on this server", "forbidden",
                        hint="start the server with --allow-capture")
    if not ctx.target_allowed(target):
        raise ToolError(f"target {target!r} is not in the allow-list", "forbidden",
                        hint="allowed: " + ", ".join(ctx.allow_targets))


def sandbox_option_paths(request: CaptureRequest, ctx: ToolContext) -> CaptureRequest:
    """Resolve file-path option values (``offsets``/``patterns``) under ``ctx.root``.

    Inline JSON passes through only for options that accept it (``offsets``);
    a path must exist inside the sandbox root and is replaced by its absolute
    real path (the friTap child may run elsewhere).

    Raises:
        ToolError: ``forbidden`` (outside the root) or ``not_found``, with
            ``option`` / ``param`` naming the offending option.
    """
    options = dict(request.protocol_options)
    for name in protocol_catalog.path_option_names():
        value = options.get(name)
        if isinstance(value, str) and not protocol_catalog.is_inline_value(name, value):
            options[name] = str(_resolve_option_path(name, value, ctx))
    return replace(request, protocol_options=options)


def _resolve_option_path(name: str, value: str, ctx: ToolContext) -> Path:
    try:
        return resolve_under_root(value, ctx.root, must_exist=True)
    except ToolError as error:
        raise ToolError(f"options.{name}: {error.error}", error.error_type, hint=error.hint,
                        option=name, param=f"options.{name}") from error


def _with_session_dir(request: CaptureRequest, session_dir: Path) -> CaptureRequest:
    return replace(request, session_dir=session_dir)


#: The manager shared by the agent tools of this process.
default_manager = SessionManager()
atexit.register(default_manager.stop_all)


def tap_path_for(session_id: str) -> Path:
    """Tap path of a finished session of :data:`default_manager`.

    Raises:
        ToolError: ``not_found`` (unknown session / no tap) or
            ``capture_running`` (hint: call stop_capture first).
    """
    return default_manager.tap_path_for(session_id)


__all__ = ["SessionManager", "default_manager", "tap_path_for", "check_capture_allowed",
           "sandbox_option_paths",
           "sessions_root", "SESSIONS_DIRNAME", "DEFAULT_MAX_SESSIONS"]
