"""
One live capture: a friTap CLI subprocess plus its JSONL reader thread.

The child gets its own process group (``start_new_session``), so a SIGINT sent
by :meth:`CaptureSession.stop` reaches only friTap, which then runs its normal
teardown (tap/keylog/pcap finalized, ``stream_end`` written). Its stderr goes
to ``<session_dir>/stderr.log``; user phase markers go to ``phases.jsonl``.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import IO, Any, Callable, Optional

from friTap.agent_api.capture.runner import CaptureRequest, session_keylog_files
from friTap.agent_api.capture.status import TERMINAL_STATES, StatusTracker
from friTap.agent_api.errors import ToolError
from friTap.analysis._limits import safe_json_loads
from friTap.analysis.digest import _iso as iso_utc
from friTap.output.stdout_stream import STREAM_SCHEMA

STDERR_NAME = "stderr.log"
PHASES_NAME = "phases.jsonl"
DEBUG_LOG_NAME = "debug.log"
DEFAULT_STOP_TIMEOUT_S = 15.0
_KILL_GRACE_S = 5.0
_STDERR_TAIL_BYTES = 2000

_IS_WINDOWS = os.name == "nt"

#: Largest stream line decoded (after the plaintext of a data record was dropped).
MAX_RECORD_BYTES = 16 * 1024 * 1024
#: ``data`` records start with this envelope (``stdout_stream.envelope`` key order).
_DATA_RECORD_PREFIX = json.dumps({"schema": STREAM_SCHEMA, "type": "data"})[:-1].encode()
#: The hex plaintext of a ``data`` record; only its length is needed.
_DATA_HEX = re.compile(rb'"data": "([0-9a-fA-F]*)"')


class CaptureSession:
    """A running (or finished) capture subprocess and its live status."""

    def __init__(self, session_id: str, request: CaptureRequest, argv: list[str],
                 clock: Callable[[], float] = time.time) -> None:
        self.session_id = session_id
        self.request = request
        self.argv = list(argv)
        self._clock = clock
        self._tracker = StatusTracker()
        self._lock = threading.Lock()
        self._phases: list[dict[str, Any]] = []
        self._process: Optional[subprocess.Popen] = None
        self._reader: Optional[threading.Thread] = None
        self._stderr: Optional[IO] = None
        self.started_at: Optional[float] = None
        self.ended_at: Optional[float] = None
        self._stop_requested = False

    @property
    def session_dir(self) -> Path:
        return self.request.session_dir

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> "CaptureSession":
        """Launch the child and the stdout reader thread."""
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._stderr = open(self.session_dir / STDERR_NAME, "wb")
        self.started_at = self._clock()
        try:
            self._process = subprocess.Popen(
                self.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=self._stderr, env=self._child_env(), **_new_group_kwargs())
        except OSError:
            self._close_stderr()
            raise
        self._reader = threading.Thread(
            target=self._read_stream, name=f"fritap-capture-{self.session_id}", daemon=True)
        self._reader.start()
        return self

    def _child_env(self) -> dict[str, str]:
        """Child environment: friTap's debug log goes into the session dir, not the cwd."""
        env = dict(os.environ)
        env["FRITAP_DEBUG_LOG"] = str(self.session_dir / DEBUG_LOG_NAME)
        return env

    def is_running(self) -> bool:
        """True until the child exited and its stream was fully read."""
        return self._reader is not None and self._reader.is_alive()

    def stop(self, timeout: float = DEFAULT_STOP_TIMEOUT_S) -> dict[str, Any]:
        """SIGINT the child, escalate to terminate/kill, return the final status."""
        process = self._process
        if process is not None and process.poll() is None:
            with self._lock:
                if self._tracker.state not in TERMINAL_STATES:
                    self._stop_requested = True
            _interrupt(process)
            _wait_or_escalate(process, timeout)
        if self._reader is not None:
            self._reader.join(timeout=_KILL_GRACE_S)
        return self.status()

    # -- phases --------------------------------------------------------------

    def mark_phase(self, label: str) -> dict[str, Any]:
        """Record a timestamped phase marker (also appended to phases.jsonl).

        Raises:
            ToolError: ``bad_param`` when the session already ended.
        """
        entry = self._phase_entry(label)
        with self._lock:
            self._reject_if_ended()
            self._phases.append(entry)
            with open(self.session_dir / PHASES_NAME, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return dict(entry)

    def _phase_entry(self, label: str) -> dict[str, Any]:
        now = self._clock()
        t_rel = None if self.started_at is None else round(max(0.0, now - self.started_at), 3)
        return {"t": now, "at": iso_utc(now), "t_rel": t_rel, "label": label}

    def _reject_if_ended(self) -> None:
        """Caller holds ``self._lock``."""
        state = self._tracker.state
        if state in TERMINAL_STATES:
            raise ToolError(f"capture session {self.session_id!r} is {state}; "
                            "phases can only be marked while it runs", "bad_param",
                            hint="start a new capture with start_capture", param="session_id")

    # -- status --------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """JSON-safe status: state, counters, files, phases, timing."""
        with self._lock:
            doc = self._tracker.snapshot()
            doc["ended_by"] = self._tracker.ended_by(self._stop_requested)
            phases = [dict(p) for p in self._phases]
        doc.update(self._describe(phases))
        if doc["state"] == "failed":
            doc["stderr_tail"] = self._stderr_tail()
        return doc

    @property
    def state(self) -> str:
        with self._lock:
            return self._tracker.state

    def _describe(self, phases: list[dict[str, Any]]) -> dict[str, Any]:
        req = self.request
        tap = req.tap_path
        doc: dict[str, Any] = {
            "session_id": self.session_id,
            "target": req.target,
            "pid": self._process.pid if self._process else None,
            "elapsed_s": round(self._elapsed(), 3),
            "duration_s": req.duration_s,
            "capture": req.capture,
            "tap": str(tap),
            "tap_bytes": tap.stat().st_size if tap.exists() else 0,
            "stderr_log": str(self.session_dir / STDERR_NAME),
            "phases": phases,
        }
        for key, path in (("keylog", req.keylog_path), ("pcap", req.pcap_path)):
            if path is not None:
                doc[key] = str(path)
        if req.keylog_path is not None:
            doc["keylog_files"] = [str(path) for path in session_keylog_files(self.session_dir)]
        return doc

    def _elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.ended_at if self.ended_at is not None else self._clock()
        return max(0.0, end - self.started_at)

    def _stderr_tail(self) -> str:
        path = self.session_dir / STDERR_NAME
        try:
            with open(path, "rb") as fh:
                fh.seek(max(0, path.stat().st_size - _STDERR_TAIL_BYTES))
                return fh.read().decode("utf-8", errors="replace")
        except OSError:
            return ""

    # -- reader thread -------------------------------------------------------

    def _read_stream(self) -> None:
        process = self._process
        assert process is not None and process.stdout is not None
        for raw in process.stdout:
            record = _decode(raw)
            if record is not None:
                with self._lock:
                    self._tracker.feed(record)
        returncode = process.wait()
        with self._lock:
            self._tracker.process_exited(returncode)
        self.ended_at = self._clock()
        self._close_stderr()

    def _close_stderr(self) -> None:
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None


def _decode(raw: bytes) -> Optional[dict]:
    """One stream line as a dict (``None`` if not a JSON object).

    The plaintext of a ``data`` record is never decoded or kept: the hex
    string is replaced by its byte length (``data_len``) before parsing.
    """
    if raw.startswith(_DATA_RECORD_PREFIX):
        raw = _DATA_HEX.sub(_data_len_field, raw, count=1)
    record = safe_json_loads(raw, max_bytes=MAX_RECORD_BYTES)
    return record if isinstance(record, dict) else None


def _data_len_field(match: "re.Match[bytes]") -> bytes:
    return b'"data_len": %d' % (len(match.group(1)) // 2)


def _new_group_kwargs() -> dict[str, Any]:
    if _IS_WINDOWS:
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _interrupt(process: subprocess.Popen) -> None:
    sig = signal.CTRL_BREAK_EVENT if _IS_WINDOWS else signal.SIGINT
    try:
        process.send_signal(sig)
    except OSError:
        pass  # already gone


def _wait_or_escalate(process: subprocess.Popen, timeout: float) -> None:
    for action, wait_s in ((None, timeout), (process.terminate, _KILL_GRACE_S),
                           (process.kill, _KILL_GRACE_S)):
        if action is not None:
            try:
                action()
            except OSError:
                return
        try:
            process.wait(timeout=wait_s)
            return
        except subprocess.TimeoutExpired:
            continue


__all__ = ["CaptureSession", "STDERR_NAME", "PHASES_NAME", "DEBUG_LOG_NAME", "DEFAULT_STOP_TIMEOUT_S",
           "TERMINAL_STATES"]
