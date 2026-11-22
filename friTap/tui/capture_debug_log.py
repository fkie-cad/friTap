"""Per-session debug log file for TUI captures (``--debug-output``).

``DebugLogMixin`` is mixed into ``CaptureController``; the file handle, handler
and saved log level live on the controller. Open and setup run on the worker
thread; the UI notice goes through ``app.call_from_thread``.
"""

from __future__ import annotations

import dataclasses as _dc
import os
import time


class DebugLogMixin:
    """Open, feed and close the per-session ``fritap_debug_*.log`` file."""

    def _open_debug_log_file(self) -> bool:
        """Open the per-session debug file and attach a handler to the ``friTap`` logger.

        Call before ``SSL_Logger.__init__`` so init-time records also land in
        the file. Returns True if the file is open and the handler attached.
        """
        import logging as _logging

        try:
            ts = time.strftime("%Y%m%d_%H%M%S")
            self._debug_log_path = f"fritap_debug_{ts}.log"
            self._debug_log_file = open(self._debug_log_path, "w", buffering=1)
            self._debug_log_file.write(
                f"# friTap debug log — started {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )
        except OSError:
            self._debug_log_file = None
            self._debug_log_writer = None
            return False

        # Read by frida helper subprocesses spawned after this point; the only
        # knob frida honours for GLib output.
        os.environ.setdefault("G_MESSAGES_DEBUG", "all")

        # setup_fritap_logging() leaves the logger at INFO without a debug flag;
        # DEBUG records must reach the handler for this capture.
        fritap_logger = _logging.getLogger("friTap")
        self._prior_friTap_level = fritap_logger.level
        fritap_logger.setLevel(_logging.DEBUG)
        fritap_logger.propagate = False

        from friTap.fritap_utility import _DEBUG_LOG_FORMATTER
        handler = _logging.StreamHandler(self._debug_log_file)
        handler.setLevel(_logging.DEBUG)
        handler.setFormatter(_DEBUG_LOG_FORMATTER)
        fritap_logger.addHandler(handler)
        self._debug_log_handler = handler
        return True

    def _setup_debug_log(self, event_bus):
        """Log EventBus events to the debug file opened by ``_open_debug_log_file``.

        Failures are non-fatal; debug logging never aborts the capture.
        """
        if self._debug_log_file is None:
            # Open failed or debug logging not requested.
            return

        from friTap.events import (
            ConsoleEvent,
            DatalogEvent,
            DetachEvent,
            ErrorEvent,
            KeylogEvent,
            LibraryDetectedEvent,
            OhttpEvent,
            SessionEvent,
        )
        for evt_type in (DatalogEvent, KeylogEvent, ConsoleEvent, ErrorEvent,
                         LibraryDetectedEvent, SessionEvent, DetachEvent,
                         OhttpEvent):
            event_bus.subscribe(evt_type, self._log_debug_event)

        try:
            from friTap.events import FlowEvent
            event_bus.subscribe(FlowEvent, self._log_debug_event)
        except ImportError:
            pass

        self._screen.app.call_from_thread(self._notify_debug_log_path)

    def _log_debug_event(self, event) -> None:
        """Append one event's non-empty fields to the debug file (EventBus thread)."""
        target = self._debug_log_file
        if target is None:
            return
        try:
            ts_str = time.strftime("%H:%M:%S")
            evt_name = type(event).__name__
            parts = [f"{ts_str} [{evt_name}]"]
            for f in _dc.fields(event):
                val = getattr(event, f.name, None)
                if val is None or val == "" or val == 0:
                    continue
                if isinstance(val, (bytes, bytearray)):
                    parts.append(f"  {f.name}=<{len(val)} bytes>")
                else:
                    s = str(val)
                    if len(s) > 200:
                        s = s[:200] + "..."
                    parts.append(f"  {f.name}={s}")
            target.write("\n".join(parts) + "\n\n")
        except Exception:
            pass

    def _notify_debug_log_path(self) -> None:
        """Show the debug log path in the activity log (Textual thread)."""
        log = self._screen._get_activity_log()
        if log and self._debug_log_path:
            log.log_info(f"Debug log: [bold]{self._debug_log_path}[/]")

    def _close_debug_log(self):
        """Close the per-session debug log file and detach its handler."""
        import logging as _logging

        handler = getattr(self, "_debug_log_handler", None)
        fritap_logger = _logging.getLogger("friTap")
        if handler is not None:
            try:
                fritap_logger.removeHandler(handler)
            except Exception:
                pass
            self._debug_log_handler = None

        # Later non-debug captures must not pay for DEBUG-level processing.
        prior = getattr(self, "_prior_friTap_level", None)
        if prior is not None:
            try:
                fritap_logger.setLevel(prior)
            except Exception:
                pass
            self._prior_friTap_level = None

        if self._debug_log_file is not None:
            try:
                self._debug_log_file.write(
                    f"\n# Capture session ended — {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
                self._debug_log_file.close()
            except Exception:
                pass
            self._debug_log_file = None
        self._debug_log_writer = None
