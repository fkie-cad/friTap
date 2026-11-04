"""
Capture services: tool params -> :class:`SessionManager` calls -> result dicts.

Every call goes through the module attribute :data:`default_manager` (tests
monkeypatch it).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from friTap.agent_api.capture.manager import default_manager
from friTap.agent_api.capture.runner import (
    DEFAULT_CAPTURE_MODE,
    DEFAULT_DURATION_S,
    CaptureRequest,
    build_argv,
)
from friTap.agent_api.capture.session import CaptureSession
from friTap.agent_api.context import ToolContext
from friTap.agent_api.envelope import ok

START_SCHEMA = "fritap.capture_start/1"
STATUS_SCHEMA = "fritap.capture_status/1"
PHASE_SCHEMA = "fritap.capture_phase/1"
SESSIONS_SCHEMA = "fritap.capture_sessions/1"

#: argv shown to callers starts with this instead of the interpreter path.
DISPLAY_COMMAND = "fritap"


def request_from_params(params: dict[str, Any]) -> CaptureRequest:
    """Build a request from validated tool params (session_dir set by the manager)."""
    return CaptureRequest(
        target=params["target"],
        session_dir=Path("."),
        args=tuple(params.get("args") or ()),
        device=params.get("device"),
        host=params.get("host"),
        spawn=params.get("spawn", True),
        protocols=tuple(dict.fromkeys(params.get("protocols") or ())),
        protocol_options=dict(params.get("protocol_options") or {}),
        capture=params.get("capture", DEFAULT_CAPTURE_MODE),
        duration_s=params.get("duration_s", DEFAULT_DURATION_S),
        follow_exec=params.get("follow_exec", True),
    )


def start_capture(params: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    session = default_manager.start(request_from_params(params), ctx)
    return ok(START_SCHEMA, {
        "session_id": session.session_id,
        "state": session.state,
        "tap": str(session.request.tap_path),
        "session_dir": str(session.session_dir),
        "argv": display_argv(session.request),
    })


def capture_status(session_id: str) -> dict[str, Any]:
    return ok(STATUS_SCHEMA, default_manager.get(session_id).status())


def stop_capture(session_id: str) -> dict[str, Any]:
    return ok(STATUS_SCHEMA, default_manager.stop(session_id))


def mark_phase(session_id: str, label: str) -> dict[str, Any]:
    entry = default_manager.get(session_id).mark_phase(label)
    return ok(PHASE_SCHEMA, {"session_id": session_id, **entry})


def list_sessions() -> dict[str, Any]:
    rows = [_session_row(s) for s in default_manager.sessions()]
    return ok(SESSIONS_SCHEMA, {"sessions": rows})


def display_argv(request: CaptureRequest) -> list[str]:
    """The capture command line as a user would type it (``fritap ...``)."""
    return build_argv(request, command=[DISPLAY_COMMAND])


def _session_row(session: CaptureSession) -> dict[str, Any]:
    status = session.status()
    keys = ("session_id", "state", "target", "elapsed_s", "tap", "tap_bytes", "exit_code")
    return {key: status.get(key) for key in keys}


__all__ = ["request_from_params", "start_capture", "capture_status", "stop_capture",
           "mark_phase", "list_sessions", "display_argv"]
