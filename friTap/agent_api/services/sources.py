"""
Resolve a read tool's capture source (``tap`` path or capture ``session_id``) to a file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from friTap.agent_api.context import ToolContext
from friTap.agent_api.errors import ToolError
from friTap.agent_api.paths import resolve_under_root

TAP_SUFFIX = ".tap"


def resolve_tap_source(params: dict[str, Any], ctx: ToolContext) -> Path:
    """Return the ``.tap`` file named by ``params["tap"]`` or ``params["session_id"]``.

    ``tap`` must resolve inside ``ctx.root``; a ``session_id`` is looked up in
    the capture session manager (its files live in the manager's session dir).

    Raises:
        ToolError: ``bad_param`` (neither given), ``forbidden`` (sandbox
            escape), ``not_found`` (missing file / unknown session) or
            ``capture_running`` (session not stopped yet).
    """
    if params.get("tap"):
        return resolve_under_root(params["tap"], ctx.root, suffix=TAP_SUFFIX)
    if params.get("session_id"):
        return _session_tap(params["session_id"])
    raise ToolError("one of tap, session_id is required", "bad_param",
                    hint="pass tap=<file.tap> or session_id from start_capture")


def _session_tap(session_id: str) -> Path:
    from friTap.agent_api.capture.manager import tap_path_for

    return Path(tap_path_for(session_id))


__all__ = ["resolve_tap_source", "TAP_SUFFIX"]
