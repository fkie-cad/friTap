"""Run limits of the tshark process boundary in :mod:`friTap.offline.tshark`.

A crafted capture can drive a Wireshark dissector into an endless loop (or an
endless stream of output); friTap must stop such a tshark instead of hanging
or exhausting memory, without cutting legitimately long runs short:

* one shared time budget, :func:`tshark_timeout_for` (size-scaled,
  ``$FRITAP_TSHARK_TIMEOUT`` override), enforced for buffered
  (:func:`_run_capture`) and streaming (:func:`stream_packets`) runs;
* a short fixed budget for the ``--version`` / ``-G defaultprefs`` probes;
* a cap on buffered stdout (``$FRITAP_TSHARK_MAX_OUTPUT``);
* the child is always reaped and no watchdog / drain thread outlives a run,
  also when the consumer of a stream stops early.

The fake tshark is a small Python script written to ``tmp_path`` behind an
executable ``tshark`` shell wrapper (``exec`` keeps one process, so the PID
friTap sees is the script's), passed in as the tshark path like
``--tshark-path`` would.
"""

from __future__ import annotations

import contextlib
import gc
import logging
import os
import signal
import subprocess
import sys
import threading
import time

import pytest

from friTap.offline import cli as offline_cli
from friTap.offline import tshark as tshark_mod
from friTap.offline.schannel import correlate
from friTap.offline.tshark import (
    TsharkLimitError,
    TsharkOutputLimitError,
    TsharkTimeoutError,
)

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a friTap dependency
    psutil = None

posix_only = pytest.mark.skipif(sys.platform == "win32",
                                reason="the fake tshark is a POSIX shell wrapper")

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_CAPTURES1 = os.path.join(_REPO_ROOT, "captures1.pcapng")
_MIB = 1024 * 1024

_INDEX = '{"index":{"_index":"packets-1","_type":"doc"}}'
_ROW = '{"timestamp":"1","layers":{"frame_number":["1"]}}'

# Fake tshark bodies (run after the probe dispatch, see _fake_tshark).
_SLEEP_FOREVER = "time.sleep(3600)\n"
_IGNORE_SIGTERM_AND_SLEEP = ("signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                             "time.sleep(3600)\n")
_ROWS_FOREVER = ("while True:\n"
                 f"    print({_INDEX!r}); print({_ROW!r}, flush=True)\n"
                 "    time.sleep(0.005)\n")
_ONE_ROW_THEN_SILENCE = (f"print({_INDEX!r}); print({_ROW!r}, flush=True)\n"
                         "time.sleep(3600)\n")
_FLOOD_STDOUT = ("chunk = b'x' * 65535 + b'\\n'\n"
                 "while True:\n    sys.stdout.buffer.write(chunk)\n")
_WATCHED_THREADS = ("tshark-watchdog", "tshark-stderr")


# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------

def _fake_tshark(tmp_path, body: str, *, probe: str = "pass") -> str:
    """Write a fake tshark running *body* (and *probe* for --version / -G)."""
    script = tmp_path / "fake_tshark.py"
    script.write_text(
        "import os, signal, sys, time\n"
        "args = sys.argv[1:]\n"
        "if '--version' in args or '-G' in args:\n"
        f"    {probe}\n"
        "    sys.exit(0)\n" + body)
    wrapper = tmp_path / "tshark"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    wrapper.chmod(0o755)
    return str(wrapper)


def _capture(tmp_path, size: int = 64) -> str:
    """A (sparse) stand-in capture file of *size* bytes."""
    path = tmp_path / "capture.pcapng"
    with open(path, "wb") as handle:
        handle.truncate(size)
    return str(path)


def _within(seconds: float, fn):
    """Run *fn* on a thread; fail (instead of hanging the suite) after *seconds*."""
    outcome: dict = {}

    def target():
        try:
            outcome["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the test thread
            outcome["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), f"tshark run did not finish within {seconds} s"
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def _live_tshark_threads() -> set:
    return {t for t in threading.enumerate()
            if t.name in _WATCHED_THREADS and t.is_alive()}


def _assert_reaped(proc) -> None:
    """*proc* exited and was waited for: not running, not a zombie."""
    assert proc.returncode is not None, "the tshark child was never reaped"
    with pytest.raises(ProcessLookupError):
        os.kill(proc.pid, 0)
    if psutil is not None:
        assert not psutil.pid_exists(proc.pid)


@pytest.fixture
def spawned(monkeypatch):
    """Record every process spawned through ``subprocess.Popen``."""
    processes: list = []

    class _TrackingPopen(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            processes.append(self)

    monkeypatch.setattr(tshark_mod.subprocess, "Popen", _TrackingPopen)
    return processes


@pytest.fixture
def no_prefs_probe(monkeypatch):
    """Skip the ``-G defaultprefs`` probe so only the capture run is spawned."""
    monkeypatch.setattr(tshark_mod, "_supported_body_decompression_prefs",
                        lambda _path: ())


@pytest.fixture
def clean_limits_env(monkeypatch):
    """No limit overrides from the outer environment; fresh warn-once memory."""
    monkeypatch.delenv(tshark_mod.TSHARK_TIMEOUT_ENV, raising=False)
    monkeypatch.delenv(tshark_mod.TSHARK_MAX_OUTPUT_ENV, raising=False)
    monkeypatch.setattr(tshark_mod, "_WARNED_ENV_VALUES", set())


@pytest.fixture
def fast_kill(monkeypatch):
    """Shorten the SIGTERM -> SIGKILL grace period."""
    monkeypatch.setattr(tshark_mod, "_TSHARK_KILL_GRACE", 0.3)


class _Records(logging.Handler):
    """Collect the tshark module's records (its logger does not propagate to caplog)."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def warnings(self) -> list[str]:
        return [r.getMessage() for r in self.records if r.levelno == logging.WARNING]


@pytest.fixture
def tshark_log():
    handler = _Records()
    tshark_mod.logger.addHandler(handler)
    yield handler
    tshark_mod.logger.removeHandler(handler)


# ---------------------------------------------------------------------------
# Default policy: size scaling
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("size", "expected"), [
    (0, 600.0),                 # floor
    (10 * _MIB, 600.0),         # 100 s < floor
    (60 * _MIB, 600.0),         # exactly the floor
    (100 * _MIB, 1000.0),       # 10 s per MiB
    (1024 * _MIB, 10240.0),     # 1 GiB -> ~2.8 h
])
def test_default_budget_scales_with_capture_size(tmp_path, clean_limits_env, size, expected):
    assert tshark_mod.tshark_timeout_for(_capture(tmp_path, size)) == expected


def test_budget_sums_several_inputs_and_accepts_pathlike(tmp_path, clean_limits_env):
    first, second = tmp_path / "a.pcap", tmp_path / "b.pcap"
    for path in (first, second):
        with open(path, "wb") as handle:
            handle.truncate(50 * _MIB)
    assert tshark_mod.tshark_timeout_for([first, str(second)]) == 1000.0
    assert tshark_mod.tshark_timeout_for(first) == 600.0


@pytest.mark.parametrize("inputs", [None, [], "/no/such/capture.pcapng",
                                    ["/no/such/a", "/no/such/b"]])
def test_unreadable_inputs_get_the_floor(clean_limits_env, inputs):
    assert tshark_mod.tshark_timeout_for(inputs) == 600.0


def test_capture_run_budget_follows_the_r_capture(tmp_path, monkeypatch, no_prefs_probe):
    fake = _fake_tshark(tmp_path, "print('ok')\n")
    capture = _capture(tmp_path)
    seen = []
    monkeypatch.setattr(tshark_mod, "tshark_timeout_for",
                        lambda inputs: seen.append(list(inputs)) or 600.0)
    assert tshark_mod._run_capture([fake, "-r", capture, "-T", "fields"]) == "ok\n"
    assert list(tshark_mod.stream_packets([fake, "-r", capture, "-T", "ek"])) == []
    assert seen == [[capture], [capture]]


# ---------------------------------------------------------------------------
# Environment overrides
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("raw", "expected"), [
    ("12.5", 12.5),
    (" 90 ", 90.0),
    ("1e3", 1000.0),
    ("0", None),
    ("0.0", None),
    ("none", None),
    ("NONE", None),
    ("None", None),
])
def test_timeout_env_override(tmp_path, monkeypatch, clean_limits_env, raw, expected):
    monkeypatch.setenv(tshark_mod.TSHARK_TIMEOUT_ENV, raw)
    # A fixed override: not scaled by the (large) capture.
    assert tshark_mod.tshark_timeout_for(_capture(tmp_path, 1024 * _MIB)) == expected


@pytest.mark.parametrize("raw", ["abc", "-5", "inf", "nan", "10s", "1,5"])
def test_invalid_timeout_env_is_ignored_with_one_warning(
        tmp_path, monkeypatch, clean_limits_env, tshark_log, raw):
    monkeypatch.setenv(tshark_mod.TSHARK_TIMEOUT_ENV, raw)
    capture = _capture(tmp_path, 100 * _MIB)
    assert tshark_mod.tshark_timeout_for(capture) == 1000.0
    assert tshark_mod.tshark_timeout_for(capture) == 1000.0
    warnings = tshark_log.warnings()
    assert len(warnings) == 1  # once per value, not once per tshark run
    assert tshark_mod.TSHARK_TIMEOUT_ENV in warnings[0] and repr(raw) in warnings[0]


def test_blank_timeout_env_means_default(tmp_path, monkeypatch, clean_limits_env, tshark_log):
    monkeypatch.setenv(tshark_mod.TSHARK_TIMEOUT_ENV, "   ")
    assert tshark_mod.tshark_timeout_for(_capture(tmp_path)) == 600.0
    assert tshark_log.warnings() == []


@pytest.mark.parametrize(("raw", "expected"), [
    ("1048576", _MIB),
    ("512K", 512 * 1024),
    ("1M", _MIB),
    ("8G", 8 * 1024 * _MIB),
    ("8GiB", 8 * 1024 * _MIB),
    ("8gb", 8 * 1024 * _MIB),
    ("1.5m", int(1.5 * _MIB)),
    ("0", None),
    ("none", None),
])
def test_max_output_env_override(monkeypatch, clean_limits_env, raw, expected):
    monkeypatch.setenv(tshark_mod.TSHARK_MAX_OUTPUT_ENV, raw)
    assert tshark_mod.tshark_max_output_bytes() == expected


@pytest.mark.parametrize("raw", ["lots", "-1", "G", "4X"])
def test_invalid_max_output_env_falls_back_to_default(
        monkeypatch, clean_limits_env, tshark_log, raw):
    monkeypatch.setenv(tshark_mod.TSHARK_MAX_OUTPUT_ENV, raw)
    assert tshark_mod.tshark_max_output_bytes() == 4 * 1024 * _MIB
    assert len(tshark_log.warnings()) == 1


def test_max_output_default_is_4_gib(clean_limits_env):
    assert tshark_mod.tshark_max_output_bytes() == 4 * 1024 * _MIB


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

def test_limit_errors_are_runtime_errors():
    assert issubclass(TsharkTimeoutError, TsharkLimitError)
    assert issubclass(TsharkOutputLimitError, TsharkLimitError)
    assert issubclass(TsharkLimitError, RuntimeError)


def test_timeout_message_is_one_line_naming_budget_and_env_var():
    error = tshark_mod._tshark_timeout_error(10240.0, "/data/big.pcapng")
    message = str(error)
    assert "\n" not in message
    assert "10240 s" in message and "/data/big.pcapng" in message
    assert "FRITAP_TSHARK_TIMEOUT" in message
    assert error.timeout == 10240.0


def test_output_limit_message_is_one_line_naming_cap_and_env_var():
    error = tshark_mod._tshark_output_limit_error(_MIB)
    assert "\n" not in str(error)
    assert str(_MIB) in str(error) and "FRITAP_TSHARK_MAX_OUTPUT" in str(error)
    assert error.limit == _MIB


# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------

def test_watchdog_without_budget_arms_no_thread():
    before = _live_tshark_threads()
    watchdog = tshark_mod._Watchdog(object(), None)
    assert _live_tshark_threads() == before
    watchdog.cancel()
    assert watchdog.fired is False


def test_watchdog_leaves_an_already_exited_process_alone():
    class _Exited:
        terminated = False

        def poll(self):
            return 0

        def terminate(self):
            self.terminated = True

    proc = _Exited()
    watchdog = tshark_mod._Watchdog(proc, 0.01)
    time.sleep(0.2)
    watchdog.cancel()
    assert watchdog.fired is False and proc.terminated is False


# ---------------------------------------------------------------------------
# Buffered runs (_run_capture)
# ---------------------------------------------------------------------------

@posix_only
def test_buffered_run_times_out_and_leaves_no_child(
        tmp_path, monkeypatch, spawned, no_prefs_probe, clean_limits_env):
    monkeypatch.setenv(tshark_mod.TSHARK_TIMEOUT_ENV, "0.5")
    fake = _fake_tshark(tmp_path, _SLEEP_FOREVER)
    capture = _capture(tmp_path)
    before = _live_tshark_threads()
    started = time.monotonic()
    with pytest.raises(TsharkTimeoutError) as info:
        _within(30, lambda: tshark_mod._run_capture([fake, "-r", capture]))
    assert time.monotonic() - started < 15
    assert info.value.timeout == 0.5 and capture in str(info.value)
    assert len(spawned) == 1
    _assert_reaped(spawned[0])
    assert _live_tshark_threads() == before


@posix_only
def test_buffered_run_kills_a_tshark_that_ignores_sigterm(
        tmp_path, monkeypatch, spawned, no_prefs_probe, clean_limits_env, fast_kill):
    monkeypatch.setenv(tshark_mod.TSHARK_TIMEOUT_ENV, "1")
    fake = _fake_tshark(tmp_path, _IGNORE_SIGTERM_AND_SLEEP)
    with pytest.raises(TsharkTimeoutError):
        _within(30, lambda: tshark_mod._run_capture([fake, "-r", _capture(tmp_path)]))
    _assert_reaped(spawned[0])
    assert spawned[0].returncode == -signal.SIGKILL


@posix_only
def test_buffered_output_cap_stops_a_flood(
        tmp_path, monkeypatch, spawned, no_prefs_probe, clean_limits_env):
    monkeypatch.setenv(tshark_mod.TSHARK_MAX_OUTPUT_ENV, "1M")
    fake = _fake_tshark(tmp_path, _FLOOD_STDOUT)
    before = _live_tshark_threads()
    with pytest.raises(TsharkOutputLimitError) as info:
        _within(30, lambda: tshark_mod._run_capture([fake, "-r", _capture(tmp_path)]))
    assert info.value.limit == _MIB
    _assert_reaped(spawned[0])
    assert _live_tshark_threads() == before


@posix_only
def test_buffered_run_within_budget_returns_text_output(
        tmp_path, spawned, no_prefs_probe, clean_limits_env):
    body = ("sys.stdout.buffer.write(b'1\\n2\\r\\n\\xff3\\n')\n"
            "sys.stderr.write('chatter\\n' * 50000)\n")
    fake = _fake_tshark(tmp_path, body)
    before = _live_tshark_threads()
    out = _within(30, lambda: tshark_mod._run_capture([fake, "-r", _capture(tmp_path)]))
    # Decoded like the former text-mode pipe: replacement char, universal newlines.
    assert out == "1\n2\n\ufffd3\n"
    _assert_reaped(spawned[0])
    assert _live_tshark_threads() == before


@posix_only
def test_buffered_nonzero_exit_is_an_ordinary_failure(
        tmp_path, spawned, no_prefs_probe, clean_limits_env):
    fake = _fake_tshark(tmp_path, "sys.stderr.write('tshark: boom\\n')\nsys.exit(2)\n")
    with pytest.raises(RuntimeError) as info:
        _within(30, lambda: tshark_mod._run_capture([fake, "-r", _capture(tmp_path)]))
    assert not isinstance(info.value, TsharkLimitError)
    assert "code 2" in str(info.value) and "tshark: boom" in str(info.value)
    _assert_reaped(spawned[0])


@posix_only
def test_high_level_helpers_time_out_through_the_tshark_path(
        tmp_path, monkeypatch, spawned, no_prefs_probe, clean_limits_env):
    monkeypatch.setenv(tshark_mod.TSHARK_TIMEOUT_ENV, "0.5")
    fake = _fake_tshark(tmp_path, _SLEEP_FOREVER)
    capture = _capture(tmp_path)
    for run in (lambda: tshark_mod.list_tls_streams(fake, capture, None),
                lambda: tshark_mod.follow_tls_stream(fake, capture, 0, None),
                lambda: tshark_mod.extract_ssh_connections(fake, capture)):
        with pytest.raises(TsharkTimeoutError):
            _within(30, run)
    assert len(spawned) == 3
    for proc in spawned:
        _assert_reaped(proc)


# ---------------------------------------------------------------------------
# Streaming runs (stream_packets)
# ---------------------------------------------------------------------------

@posix_only
def test_streaming_run_times_out_after_yielding_rows(
        tmp_path, monkeypatch, spawned, no_prefs_probe, clean_limits_env):
    monkeypatch.setenv(tshark_mod.TSHARK_TIMEOUT_ENV, "1")
    fake = _fake_tshark(tmp_path, _ROWS_FOREVER)
    capture = _capture(tmp_path)
    rows: list = []
    before = _live_tshark_threads()

    def consume():
        for row in tshark_mod.stream_packets([fake, "-r", capture, "-T", "ek"]):
            rows.append(row)

    with pytest.raises(TsharkTimeoutError) as info:
        _within(30, consume)
    assert rows, "rows produced before the deadline are still delivered"
    assert info.value.timeout == 1.0
    _assert_reaped(spawned[0])
    assert _live_tshark_threads() == before


@posix_only
def test_streaming_run_times_out_while_tshark_is_silent(
        tmp_path, monkeypatch, spawned, no_prefs_probe, clean_limits_env):
    monkeypatch.setenv(tshark_mod.TSHARK_TIMEOUT_ENV, "0.5")
    fake = _fake_tshark(tmp_path, _ONE_ROW_THEN_SILENCE)
    rows: list = []

    def consume():
        rows.extend(tshark_mod.stream_packets([fake, "-r", _capture(tmp_path), "-T", "ek"]))

    with pytest.raises(TsharkTimeoutError):
        _within(30, consume)
    _assert_reaped(spawned[0])


@posix_only
def test_streaming_timeout_wins_over_truncated_capture_tolerance(
        tmp_path, monkeypatch, spawned, no_prefs_probe, clean_limits_env):
    monkeypatch.setenv(tshark_mod.TSHARK_TIMEOUT_ENV, "0.5")
    body = ("sys.stderr.write('tshark: The file appears to have been cut short "
            "in the middle of a packet.\\n'); sys.stderr.flush()\n" + _ONE_ROW_THEN_SILENCE)
    fake = _fake_tshark(tmp_path, body)
    with pytest.raises(TsharkTimeoutError):
        _within(30, lambda: list(tshark_mod.stream_packets(
            [fake, "-r", _capture(tmp_path), "-T", "ek"])))
    _assert_reaped(spawned[0])


@posix_only
def test_early_generator_close_kills_the_child(
        tmp_path, spawned, no_prefs_probe, clean_limits_env):
    fake = _fake_tshark(tmp_path, _ROWS_FOREVER)
    before = _live_tshark_threads()
    packets = tshark_mod.stream_packets([fake, "-r", _capture(tmp_path), "-T", "ek"])
    assert _within(30, lambda: next(packets))["layers"] == {"frame_number": ["1"]}
    _within(30, packets.close)
    _assert_reaped(spawned[0])
    # The default (600 s) watchdog was disarmed, not left ticking.
    assert _live_tshark_threads() == before


@posix_only
def test_consumer_exception_under_closing_kills_the_child(
        tmp_path, spawned, no_prefs_probe, clean_limits_env):
    fake = _fake_tshark(tmp_path, _ROWS_FOREVER)
    before = _live_tshark_threads()

    def consume():
        packets = tshark_mod.stream_packets([fake, "-r", _capture(tmp_path), "-T", "ek"])
        with contextlib.closing(packets):
            for _row in packets:
                raise ValueError("consumer failed")

    with pytest.raises(ValueError, match="consumer failed"):
        _within(30, consume)
    _assert_reaped(spawned[0])
    assert _live_tshark_threads() == before


@posix_only
def test_dropped_generator_is_reaped(tmp_path, spawned, no_prefs_probe, clean_limits_env):
    fake = _fake_tshark(tmp_path, _ROWS_FOREVER)
    packets = tshark_mod.stream_packets([fake, "-r", _capture(tmp_path), "-T", "ek"])
    _within(30, packets.__next__)
    del packets  # never closed explicitly: finalization must stop tshark
    _within(30, gc.collect)
    _assert_reaped(spawned[0])


@posix_only
def test_unstarted_generator_spawns_nothing(tmp_path, spawned, no_prefs_probe):
    packets = tshark_mod.stream_packets([_fake_tshark(tmp_path, _ROWS_FOREVER), "-T", "ek"])
    packets.close()
    assert spawned == []


# ---------------------------------------------------------------------------
# Probes (--version, -G defaultprefs)
# ---------------------------------------------------------------------------

def test_probes_use_the_fixed_probe_timeout(monkeypatch):
    monkeypatch.setenv(tshark_mod.TSHARK_VERSION_CACHE_DISABLE_ENV, "1")
    tshark_mod._clear_tshark_version_cache()
    tshark_mod._supported_body_decompression_prefs.cache_clear()
    timeouts = []

    class _Completed:
        stdout = "TShark (Wireshark) 4.6.7 (Git commit b439fb7b47a9).\n"

    def fake_run(argv, **kwargs):
        timeouts.append((argv[1], kwargs.get("timeout")))
        return _Completed()

    monkeypatch.setattr(tshark_mod.subprocess, "run", fake_run)
    try:
        assert tshark_mod._query_tshark_version("/fake/tshark") == (4, 6, 7)
        tshark_mod._supported_body_decompression_prefs("/fake/tshark")
    finally:
        tshark_mod._supported_body_decompression_prefs.cache_clear()
    assert timeouts == [("--version", 30.0), ("-G", 30.0)]
    assert tshark_mod.TSHARK_PROBE_TIMEOUT == 30.0


@posix_only
def test_hanging_probes_give_up_and_reap(tmp_path, monkeypatch, spawned):
    monkeypatch.setattr(tshark_mod, "TSHARK_PROBE_TIMEOUT", 0.5)
    # The capture-run budget does not apply to probes: even "no limit" here
    # leaves them bounded.
    monkeypatch.setenv(tshark_mod.TSHARK_TIMEOUT_ENV, "0")
    monkeypatch.setenv(tshark_mod.TSHARK_VERSION_CACHE_DISABLE_ENV, "1")
    tshark_mod._clear_tshark_version_cache()
    tshark_mod._supported_body_decompression_prefs.cache_clear()
    fake = _fake_tshark(tmp_path, "", probe="time.sleep(3600)")
    try:
        started = time.monotonic()
        assert _within(30, lambda: tshark_mod._query_tshark_version(fake)) == ()
        assert _within(30, lambda: tshark_mod.no_body_decompression_opts(fake)) == []
        assert time.monotonic() - started < 15
    finally:
        tshark_mod._supported_body_decompression_prefs.cache_clear()
    assert len(spawned) == 2
    for proc in spawned:
        _assert_reaped(proc)


# ---------------------------------------------------------------------------
# Callers: schannel fields pass, CLI
# ---------------------------------------------------------------------------

def test_schannel_fields_pass_propagates_a_timeout(monkeypatch, no_prefs_probe):
    def _timed_out(_cmd):
        raise tshark_mod._tshark_timeout_error(600.0, "x.pcap")

    monkeypatch.setattr(tshark_mod, "_run_capture", _timed_out)
    with pytest.raises(TsharkTimeoutError):
        correlate.run_fields_pass("tshark", "x.pcap", "tls", ["tls.stream"])


def test_schannel_fields_pass_still_swallows_ordinary_failures(monkeypatch, no_prefs_probe):
    def _failed(_cmd):
        raise RuntimeError("tshark exited with code 2.")

    monkeypatch.setattr(tshark_mod, "_run_capture", _failed)
    assert correlate.run_fields_pass("tshark", "x.pcap", "tls", ["tls.stream"]) == ""


@pytest.mark.parametrize("error", [
    tshark_mod._tshark_timeout_error(600.0, "cap.pcapng"),
    tshark_mod._tshark_output_limit_error(_MIB),
])
def test_cli_prints_one_line_for_a_tshark_limit(tmp_path, monkeypatch, capsys, error):
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x0a\x0d\x0d\x0a")

    def _stopped(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(offline_cli, "find_tshark", lambda *_a, **_k: "/fake/tshark")
    monkeypatch.setattr(offline_cli, "convert_pcap_to_tap", _stopped)
    rc = offline_cli.run_offline_pcap_to_tap(
        ["--from-pcap", str(pcap), "--tap", str(tmp_path / "o.tap")])
    captured = capsys.readouterr()
    assert rc == 1
    error_lines = [line for line in captured.out.splitlines() if line.startswith("Error")]
    assert error_lines == [f"Error: {error}"]
    assert "Traceback" not in captured.out + captured.err


# ---------------------------------------------------------------------------
# Real tshark under the default policy
# ---------------------------------------------------------------------------

def _real_tshark() -> str | None:
    try:
        return tshark_mod.find_tshark()
    except RuntimeError:
        return None


_REAL_TSHARK = _real_tshark()
needs_real_tshark = pytest.mark.skipif(
    _REAL_TSHARK is None or not os.path.isfile(_CAPTURES1),
    reason="needs a real tshark and captures1.pcapng")


@needs_real_tshark
def test_real_tshark_runs_under_the_default_policy(spawned, clean_limits_env):
    assert tshark_mod.tshark_timeout_for(_CAPTURES1) == 600.0
    before = _live_tshark_threads()

    fields = _within(120, lambda: tshark_mod._run_capture(
        [_REAL_TSHARK, "-r", _CAPTURES1, "-c", "5", "-T", "fields", "-e", "frame.number"]))
    assert fields.split() == ["1", "2", "3", "4", "5"]

    rows = _within(120, lambda: list(tshark_mod.stream_packets(
        [_REAL_TSHARK, "-r", _CAPTURES1, "-c", "5", "-T", "ek", "-e", "frame.number"])))
    assert [tshark_mod.ek_first(tshark_mod.ek_field(r["layers"], "frame.number"))
            for r in rows] == ["1", "2", "3", "4", "5"]

    streams = _within(120, lambda: tshark_mod.list_tls_streams(_REAL_TSHARK, _CAPTURES1, None))
    assert isinstance(streams, list)

    capture_runs = [p for p in spawned if "-r" in p.args]
    assert len(capture_runs) == 3
    for proc in capture_runs:
        assert proc.returncode == 0
        _assert_reaped(proc)
    assert _live_tshark_threads() == before
