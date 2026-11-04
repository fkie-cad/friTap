"""
Live capture sessions for the agent API (friTap CLI run as a subprocess).

- :mod:`.runner`  -- :class:`CaptureRequest` -> argv (pure)
- :mod:`.status`  -- :class:`StatusTracker` over the JSONL event stream (pure)
- :mod:`.session` -- :class:`CaptureSession` (Popen + reader thread + stop)
- :mod:`.manager` -- :class:`SessionManager`, ``default_manager``, ``tap_path_for``
"""

from friTap.agent_api.capture.manager import (
    SessionManager,
    default_manager,
    tap_path_for,
)
from friTap.agent_api.capture.runner import CaptureRequest, build_argv
from friTap.agent_api.capture.session import CaptureSession
from friTap.agent_api.capture.status import StatusTracker

__all__ = ["CaptureRequest", "build_argv", "StatusTracker", "CaptureSession",
           "SessionManager", "default_manager", "tap_path_for"]
