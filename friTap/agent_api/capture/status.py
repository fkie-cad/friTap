"""
Fold the ``fritap.events/1`` JSONL stream of a capture into a status summary.

:class:`StatusTracker` is pure (fed decoded record dicts, no I/O) and only
keeps counters and short strings: plaintext (``data`` records) and key
material (``keylog`` records) are counted, never stored.

Hooked is not in use: under ``--protocol auto`` (the default) friTap installs
every protocol's hooks speculatively, so e.g. the RC4 key hooks attach to any
libssl/libcrypto that exports ``RC4_set_key``. A protocol is only reported as
``active`` (and listed in ``protocols_in_use``) once it produced keys,
plaintext or session/message records; hooked-but-silent protocols are
``idle`` (listed in ``idle_hooks``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from friTap.exit_codes import EXIT_OK, EXIT_TARGET_DETACHED

STARTING, RUNNING, STOPPED, FAILED = "starting", "running", "stopped", "failed"
TERMINAL_STATES = frozenset({STOPPED, FAILED})

HOOK_ATTACHED, HOOK_NO_LIBRARY, HOOK_FAILED = "attached", "no_library_seen", "failed"

#: Per-protocol ``status``: ``active`` = traffic/keys seen, ``idle`` = hooks
#: installed but nothing seen (speculative under ``auto``), else why not hooked.
PROTOCOL_ACTIVE, PROTOCOL_IDLE = "active", "idle"
PROTOCOL_STATUS_VALUES = (PROTOCOL_ACTIVE, PROTOCOL_IDLE, HOOK_NO_LIBRARY, HOOK_FAILED)

#: Record types (besides ``keylog`` / ``data``) proving a protocol carried traffic.
ACTIVITY_RECORD_TYPES = frozenset({"session", "ohttp", "message", "flow"})

#: Why a finished session ended (``ended_by``); ``None`` while it is still active.
ENDED_BY_TARGET_EXITED = "target_exited"
ENDED_BY_DURATION = "duration"
ENDED_BY_STOPPED = "stopped"
ENDED_BY_ERROR = "error"
ENDED_BY_VALUES = (ENDED_BY_TARGET_EXITED, ENDED_BY_DURATION, ENDED_BY_STOPPED, ENDED_BY_ERROR)

#: Exit codes of a capture that ended normally (stop/duration, or the target exited).
CLEAN_EXIT_CODES = frozenset({EXIT_OK, EXIT_TARGET_DETACHED})

MAX_ERRORS_PER_PROTOCOL = 20
MAX_ERROR_CHARS = 300


@dataclass
class ProtocolStats:
    """Counters for one protocol of a capture."""

    libraries: list[str] = field(default_factory=list)
    keys: int = 0
    data_events: int = 0
    data_bytes: int = 0
    other_events: int = 0
    errors: list[str] = field(default_factory=list)

    def hooked(self) -> bool:
        return bool(self.libraries or self.active())

    def active(self) -> bool:
        """Keys, plaintext or session/message records were seen (in use)."""
        return bool(self.keys or self.data_events or self.other_events)

    def status(self) -> str:
        """``active`` | ``idle`` | ``no_library_seen`` | ``failed``."""
        if self.active():
            return PROTOCOL_ACTIVE
        if self.libraries:
            return PROTOCOL_IDLE
        return HOOK_FAILED if self.errors else HOOK_NO_LIBRARY

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status(), "libraries": list(self.libraries), "keys": self.keys,
                "data_events": self.data_events, "data_bytes": self.data_bytes,
                "other_events": self.other_events, "errors": list(self.errors),
                "hook_status": self._hook_status()}

    def _hook_status(self) -> str:
        if self.hooked():
            return HOOK_ATTACHED
        return HOOK_FAILED if self.errors else HOOK_NO_LIBRARY


class StatusTracker:
    """State machine over stream records: starting -> running -> stopped|failed."""

    def __init__(self) -> None:
        self.state = STARTING
        self.exit_code: Optional[int] = None
        self.error: Optional[dict[str, Any]] = None
        self.detach_reason: Optional[str] = None
        self.reported_end: Optional[str] = None
        self.records = 0
        self.protocols: dict[str, ProtocolStats] = {}
        self._handlers: dict[str, Callable[[dict], None]] = {
            "stream_start": self._on_stream_start,
            "library": self._on_library,
            "keylog": self._on_keylog,
            "data": self._on_data,
            "error": self._on_error,
            "usage_error": self._on_usage_error,
            "detach": self._on_detach,
            "stream_end": self._on_stream_end,
            **{kind: self._on_activity for kind in ACTIVITY_RECORD_TYPES},
        }

    # -- feeding -------------------------------------------------------------

    def feed(self, record: dict) -> None:
        """Account one decoded JSONL record (unknown types only count)."""
        if not isinstance(record, dict):
            return
        self.records += 1
        if self.state == STARTING and record.get("type") != "usage_error":
            self.state = RUNNING
        handler = self._handlers.get(record.get("type"))
        if handler is not None:
            handler(record)

    def process_exited(self, returncode: Optional[int]) -> None:
        """The child is gone; settle the state if ``stream_end`` never came."""
        if self.state in TERMINAL_STATES:
            return
        if self.exit_code is None:
            self.exit_code = returncode
        if self.error is None and returncode not in CLEAN_EXIT_CODES:
            self.error = {"error_type": "ProcessExited",
                          "message": f"friTap exited with code {returncode} without stream_end"}
        self._settle()

    # -- record handlers -----------------------------------------------------

    def _stats(self, record: dict) -> ProtocolStats:
        return self.protocols.setdefault(str(record.get("protocol") or "unknown"), ProtocolStats())

    def _on_stream_start(self, record: dict) -> None:
        self.state = RUNNING

    def _on_library(self, record: dict) -> None:
        library = str(record.get("library") or record.get("module") or "?")
        libraries = self._stats(record).libraries
        if library not in libraries:
            libraries.append(library)

    def _on_keylog(self, record: dict) -> None:
        self._stats(record).keys += 1

    def _on_data(self, record: dict) -> None:
        stats = self._stats(record)
        stats.data_events += 1
        stats.data_bytes += _data_len(record)

    def _on_activity(self, record: dict) -> None:
        self._stats(record).other_events += 1

    def _on_error(self, record: dict) -> None:
        if "event" not in record:  # closing runtime-error record (no event class)
            self.error = _runtime_error(record)
            return
        errors = self._stats(record).errors
        if len(errors) < MAX_ERRORS_PER_PROTOCOL:
            errors.append(_short(record.get("error") or record.get("description")))

    def _on_usage_error(self, record: dict) -> None:
        self.error = {"error_type": "usage_error", "message": _short(record.get("error"))}
        self.exit_code = record.get("exit_code")
        self.state = FAILED

    def _on_detach(self, record: dict) -> None:
        self.detach_reason = _short(record.get("reason")) or "detached"

    def _on_stream_end(self, record: dict) -> None:
        self.exit_code = record.get("exit_code")
        reported = record.get("ended_by")
        self.reported_end = reported if reported in ENDED_BY_VALUES else None
        self._settle()

    def _settle(self) -> None:
        clean = self.exit_code in CLEAN_EXIT_CODES or (
            self.exit_code is None and self.error is None)
        self.state = STOPPED if clean else FAILED

    # -- reporting -----------------------------------------------------------

    def ended_by(self, stop_requested: bool = False) -> Optional[str]:
        """Why the session ended, or ``None`` while it is still active.

        ``error`` for a failed run; ``stopped`` when ``stop_capture`` ended it.
        Otherwise the ``ended_by`` the friTap child reported in ``stream_end``
        (it knows whether the duration timer, a signal or the target ended
        the run); for a child that reported none it is inferred:
        ``target_exited`` for exit code 3 (target detached/exited -- a normal
        end, not a failure), else ``duration``.
        """
        if self.state not in TERMINAL_STATES:
            return None
        if self.state == FAILED:
            return ENDED_BY_ERROR
        if stop_requested:
            return ENDED_BY_STOPPED
        if self.reported_end is not None:
            return self.reported_end
        if self.exit_code == EXIT_TARGET_DETACHED:
            return ENDED_BY_TARGET_EXITED
        if self.exit_code is None and self.detach_reason:
            return ENDED_BY_TARGET_EXITED
        return ENDED_BY_DURATION

    def hook_status(self) -> str:
        """``attached`` once any protocol hooked; ``failed`` on a failed run."""
        if any(stats.hooked() for stats in self.protocols.values()):
            return HOOK_ATTACHED
        return HOOK_FAILED if self.state == FAILED else HOOK_NO_LIBRARY

    def protocols_in_use(self) -> list[str]:
        """Protocols that produced keys, plaintext or session records (sorted)."""
        return sorted(name for name, stats in self.protocols.items() if stats.active())

    def idle_hooks(self) -> dict[str, list[str]]:
        """``{protocol: libraries}`` for protocols hooked without any activity."""
        return {name: list(stats.libraries) for name, stats in sorted(self.protocols.items())
                if stats.status() == PROTOCOL_IDLE}

    def snapshot(self) -> dict[str, Any]:
        """JSON-safe summary (no payloads, no key material)."""
        doc: dict[str, Any] = {
            "state": self.state,
            "hook_status": self.hook_status(),
            "protocols_in_use": self.protocols_in_use(),
            "idle_hooks": self.idle_hooks(),
            "exit_code": self.exit_code,
            "records": self.records,
            "protocols": {name: stats.to_dict() for name, stats in sorted(self.protocols.items())},
        }
        if self.detach_reason:
            doc["detach_reason"] = self.detach_reason
        if self.error:
            doc["error"] = dict(self.error)
        return doc


def _data_len(record: dict) -> int:
    """Plaintext bytes of a ``data`` record: ``data_len`` if the reader kept only
    the length, else half the hex ``data`` string."""
    length = record.get("data_len")
    if isinstance(length, int) and not isinstance(length, bool) and length >= 0:
        return length
    payload = record.get("data")
    return len(payload) // 2 if isinstance(payload, str) else 0


def _runtime_error(record: dict) -> dict[str, Any]:
    error = {"error_type": str(record.get("error_type") or "RuntimeError"),
             "message": _short(record.get("message"))}
    if record.get("hint"):
        error["hint"] = _short(record.get("hint"))
    return error


def _short(value: Any) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= MAX_ERROR_CHARS else text[:MAX_ERROR_CHARS] + "..."


__all__ = [
    "StatusTracker", "ProtocolStats", "STARTING", "RUNNING", "STOPPED", "FAILED",
    "TERMINAL_STATES", "HOOK_ATTACHED", "HOOK_NO_LIBRARY", "HOOK_FAILED",
    "PROTOCOL_ACTIVE", "PROTOCOL_IDLE", "PROTOCOL_STATUS_VALUES", "ACTIVITY_RECORD_TYPES",
    "ENDED_BY_VALUES", "ENDED_BY_TARGET_EXITED", "ENDED_BY_DURATION", "ENDED_BY_STOPPED",
    "ENDED_BY_ERROR",
]
