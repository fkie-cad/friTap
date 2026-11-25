"""Process-scoped libbpf runtime discovery and session producer."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import subprocess
import sysconfig
from pathlib import Path
from queue import Empty, Queue
from threading import Thread, current_thread

from ..android import kill_adb_child, popen_adb, run_adb
from .base import BackendInvalidArgumentError, BackendInvalidOperationError

_ABI = "fritap-ebpf/3"
_NAME = "fritap-ebpf-agent"
_LOG = logging.getLogger(__name__)
# The reader normally drains within the first bound; a slow device drain gets
# the longer one before the capture is declared incomplete.
_READER_JOIN_SECONDS = 5
_READER_DRAIN_SECONDS = 30


class NativeError(BackendInvalidOperationError):
    def __init__(self, status: str, detail: str):
        self.status = status
        super().__init__(detail)


def _native_binary_candidates(name: str, build_dir: str) -> tuple[Path, Path]:
    """Installed copy in the active Python scripts directory first, then the repo build."""
    return (
        Path(sysconfig.get_path("scripts")).resolve() / name,
        Path(__file__).resolve().parents[2] / build_dir / name,
    )


def _find_native_binary(name: str, build_dir: str) -> Path | None:
    """Return the first executable *name* from the scripts dir or *build_dir* (repo-relative)."""
    for candidate in _native_binary_candidates(name, build_dir):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def resolve_runtime() -> Path:
    attempts = []
    for path in _native_binary_candidates(_NAME, "agent_ebpf/build"):
        if not path.is_file():
            attempts.append(f"{path} (missing)")
            continue
        try:
            result = subprocess.run(
                [str(path), "--version"], capture_output=True, timeout=3, check=True,
            )
        except (OSError, subprocess.SubprocessError):
            attempts.append(f"{path} (could not execute)")
            continue
        if result.stdout.strip() == _ABI.encode():
            return path
        attempts.append(f"{path} (incompatible runtime ABI)")
    raise NativeError(
        "setup_required",
        "Build with make -C agent_ebpf or install the native executable in the active "
        "Python scripts directory. Checked " + ", ".join(attempts),
    )


def validate_pid(target: str) -> str:
    if not re.fullmatch(r"[0-9]{1,10}", target) or not 0 < int(target) <= 2**31 - 1:
        raise BackendInvalidArgumentError("eBPF attach requires one positive numeric PID")
    return str(int(target))


def _read_status(record: dict) -> dict:
    if not isinstance(record, dict):
        raise NativeError("unsupported", "Invalid native startup response")
    kind = record.get("type")
    if kind == "ready" and record.get("build_id") and record.get("kernel"):
        # Runtime ABI 3 originally supported only ring buffers.
        transport = record.get("transport", "ring")
        if transport in ("ring", "perf"):
            return {**record, "transport": transport}
    if kind == "error":
        raise _native_failure(record)
    raise NativeError("unsupported", "Invalid native startup response")


def _native_failure(record: dict) -> NativeError:
    """Turn a native error record into NativeError; malformed records become unsupported."""
    try:
        status, stage = record["status"], record["stage"]
        reason = os.strerror(record["errno"])
    except (KeyError, TypeError, ValueError, OverflowError):
        return NativeError("unsupported", "Invalid native error response")
    if not isinstance(status, str):
        return NativeError("unsupported", "Invalid native error response")
    return NativeError(status, f"{status} at {stage}: {reason}")


def _run_runtime(command: list[str], serial: str | None, **kwargs):
    """Run a runtime command; ADB command lines get their own session (see run_adb)."""
    return (run_adb if serial else subprocess.run)(command, **kwargs)


def _runtime_command(serial: str | None) -> list[str]:
    if serial is None:
        return [str(resolve_runtime())]

    command = ["adb", "-s", serial, "shell", "-T", f"/data/local/tmp/{_NAME}"]
    try:
        result = run_adb([*command, "--version"], capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NativeError("setup_required", "Could not reach the Android eBPF runtime through ADB") from exc
    if result.returncode == 126 or b"Permission denied" in result.stderr:
        raise NativeError("permission_denied", "The ADB shell cannot execute the Android eBPF runtime")
    if result.returncode or result.stdout.strip() != _ABI.encode():
        raise NativeError(
            "setup_required",
            f"Deploy a compatible Android eBPF runtime to /data/local/tmp/{_NAME} on {serial}",
        )
    return command


def preflight(target: str, *, serial: str | None = None) -> dict:
    pid = validate_pid(target)
    command = _runtime_command(serial)
    try:
        result = _run_runtime(
            [*command, "preflight", pid], serial, capture_output=True, timeout=15, check=False,
        )
        status = _read_status(json.loads(result.stdout))
        if result.returncode:
            raise NativeError("unsupported", f"Native preflight exited with status {result.returncode}")
        return status
    except OSError as exc:
        raise NativeError("setup_required", f"Could not launch native runtime: {exc}") from exc
    except (subprocess.TimeoutExpired, ValueError) as exc:
        raise NativeError("unsupported", "Native preflight did not return a valid result") from exc


class EbpfCaptureProducer:
    """Forward native records serially and wait for confirmed attachment."""

    def __init__(self, pid: str, *, keylog_path: str | None = None, serial: str | None = None):
        self.pid = validate_pid(pid)
        self.keylog_path = keylog_path
        self.serial = serial
        self._process = None
        self._reader = None
        self._startup = Queue(maxsize=1)
        self.metadata = {}

    def start_key_extraction(self) -> None:
        """Placeholder for native TLS key extraction."""
        _LOG.warning("TLS key extraction is currently not implemented for the eBPF backend.")

    def start(self, emit, finished) -> None:
        if self.keylog_path:
            self.start_key_extraction()
        command = _runtime_command(self.serial)
        mode = "capture-remote" if self.serial else "capture"
        try:
            if self.serial:
                # Own session: a terminal Ctrl+C must not kill adb before the stop drain.
                self._process = popen_adb(
                    [*command, mode, self.pid], stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                )
            else:
                self._process = subprocess.Popen([*command, mode, self.pid], stdout=subprocess.PIPE)
        except OSError as exc:
            raise NativeError("setup_required", f"Could not launch native runtime: {exc}") from exc
        self._reader = Thread(
            target=self._read, args=(emit, finished), daemon=True, name="fritap-ebpf-reader",
        )
        self._reader.start()
        try:
            outcome = self._startup.get(timeout=15)
        except Empty as exc:
            raise NativeError("unsupported", "Timed out waiting for native attachment") from exc
        if isinstance(outcome, Exception):
            raise outcome
        self.metadata = outcome
        _LOG.info("Attached to PID %s using OpenSSL build %s on Linux %s (transport: %s)",
                  self.pid, outcome["build_id"], outcome["kernel"], outcome["transport"])

    def _read(self, emit, finished) -> None:
        process = self._process
        started = False
        error = None
        try:
            with process.stdout as stream:
                first = stream.readline()
                if not first:
                    raise NativeError("unsupported", "Native runtime exited during attachment")
                status = _read_status(json.loads(first))
                started = True
                self._startup.put(status)
                saw_loss_count = False
                for line in stream:
                    record = json.loads(line)
                    kind = record["type"]
                    if kind == "data":
                        direction = "write" if record["write"] else "read"
                        emit({
                            "contentType": "datalog",
                            "function": f"SSL_{direction}" + ("_ex" if record["ex"] else ""),
                            "direction": direction,
                            "ssl_session_id": str(record["connection"]),
                            "library": "OpenSSL 3" if self.serial else "libssl.so.3",
                        }, bytes.fromhex(record["data"]))
                    elif kind == "loss":
                        saw_loss_count = True
                        if record["count"]:
                            emit({"contentType": "capture_loss", "count": record["count"]}, None)
                    else:
                        _read_status(record)
            code = process.wait()
            if code or not saw_loss_count:
                raise NativeError("unsupported", f"Native capture ended without a clean drain (exit {code})")
        except Exception as exc:
            error = exc
        if started:
            finished(error)
        else:
            self._startup.put(error)

    def stop(self) -> None:
        process = self._process
        if process is None:
            return
        if self.serial:
            # Keep ADB stdout open so the device can detach and drain before exit.
            self._request_remote_stop(process)
        elif process.poll() is None:
            process.terminate()
        self._join_reader(_READER_JOIN_SECONDS)
        if process.poll() is None:
            self._kill(process)
            self._join_reader(_READER_JOIN_SECONDS)
            raise RuntimeError("Native eBPF runtime did not stop cleanly")
        if self._join_reader(_READER_DRAIN_SECONDS - _READER_JOIN_SECONDS):
            raise NativeError(
                "unsupported",
                "Native eBPF reader did not drain; the capture output is incomplete",
            )

    @staticmethod
    def _request_remote_stop(process) -> None:
        stdin = process.stdin
        if stdin is None:
            return
        with contextlib.suppress(BrokenPipeError):
            try:
                if process.poll() is None:
                    stdin.write(b"stop\n")
                    stdin.flush()
            finally:
                stdin.close()

    def _join_reader(self, timeout: float) -> bool:
        """Join the reader thread for up to *timeout* s; return True while it still runs."""
        reader = self._reader
        if reader is None or reader is current_thread():
            return False
        reader.join(timeout=timeout)
        return reader.is_alive()

    def _kill(self, process) -> None:
        if self.serial:
            kill_adb_child(process, wait_seconds=_READER_JOIN_SECONDS)
        else:
            process.kill()
            process.wait(timeout=_READER_JOIN_SECONDS)
