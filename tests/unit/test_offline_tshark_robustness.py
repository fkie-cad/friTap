"""Robustness of the tshark process boundary in :mod:`friTap.offline.tshark`.

Real subprocesses (``sys.executable -c``) stand in for tshark, so most tests
need no tshark: undecodable stderr must not hang :func:`stream_packets`, a
consumer that raises must not leave tshark running, a capture cut short in its
last packet converts what was readable, and failure messages keep tshark's
``tshark:`` error line. The ``tshark --version`` on-disk cache is covered at
the end; every test points it at ``tmp_path`` so the real home is never touched.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time

import pytest

from friTap.offline import pipeline_api
from friTap.offline import tshark as tshark_mod

_TSHARK = shutil.which("tshark")

_ROW = '{"timestamp":"1","layers":{"frame_number":["1"]}}'
_EK_LINES = ('print(\'{"index":{"_index":"packets"}}\')\n'
             f"print('{_ROW}')\n")
_ENDLESS_WRITER = ("line = '{\"layers\":{\"frame_number\":[\"1\"]}}'\n"
                   "while True:\n    print(line, flush=True)\n")
_CUT_SHORT = ('tshark: The file "x.pcap" appears to have been cut short in the '
              'middle of a packet.')


def _python_cmd(body: str) -> list:
    return [sys.executable, "-c", "import sys\n" + body]


def _run_with_timeout(fn, timeout: float = 60):
    outcome: dict = {}

    def target():
        try:
            outcome["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the test thread
            outcome["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    assert not thread.is_alive(), "stream_packets did not finish (deadlock?)"
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


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


@pytest.fixture
def spawned(monkeypatch):
    """Record every process ``stream_packets`` spawns."""
    processes: list = []

    class _TrackingPopen(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            processes.append(self)

    monkeypatch.setattr(tshark_mod.subprocess, "Popen", _TrackingPopen)
    return processes


# ---------------------------------------------------------------------------
# Undecodable output
# ---------------------------------------------------------------------------

def test_invalid_utf8_stderr_flood_does_not_hang():
    # 4 MiB of non-UTF-8 stderr, far beyond the pipe buffer, before any row.
    body = ("sys.stderr.buffer.write(b'\\xff\\xfe bad \\x80\\n' * 400000)\n"
            "sys.stderr.flush()\n" + _EK_LINES)
    packets = _run_with_timeout(lambda: list(tshark_mod.stream_packets(_python_cmd(body))))
    assert packets == [json.loads(_ROW)]


def test_invalid_utf8_in_stdout_is_replaced_not_raised():
    body = ("sys.stdout.buffer.write(b'\\xff garbage\\n')\n"
            "sys.stdout.buffer.write("
            "b'{\"layers\":{\"x\":[\"\\xe9t\\xe9\"]}}\\n')\n")
    packets = _run_with_timeout(lambda: list(tshark_mod.stream_packets(_python_cmd(body))))
    assert packets == [{"layers": {"x": ["\ufffdt\ufffd"]}}]


def test_invalid_utf8_stderr_still_reaches_the_error_message():
    body = ("sys.stderr.buffer.write(b'tshark: bad \\xff byte\\n')\nsys.exit(2)\n")
    with pytest.raises(RuntimeError) as excinfo:
        _run_with_timeout(lambda: list(tshark_mod.stream_packets(_python_cmd(body))))
    assert "tshark: bad \ufffd byte" in str(excinfo.value)


def test_stderr_drain_survives_a_failing_sink():
    calls = []

    def sink(line):
        calls.append(line)
        if len(calls) == 1:
            raise ValueError("bad line")

    proc = subprocess.Popen(_python_cmd("sys.stderr.write('one\\ntwo\\nthree\\n')"),
                            stderr=subprocess.PIPE, encoding="utf-8", errors="replace")
    thread = tshark_mod._start_stderr_drain(proc, sink)
    proc.wait()
    thread.join(10)
    assert not thread.is_alive()
    assert [c.strip() for c in calls] == ["one", "two", "three"]


def test_version_query_tolerates_undecodable_output(tmp_path, monkeypatch):
    monkeypatch.setenv(tshark_mod.TSHARK_VERSION_CACHE_DISABLE_ENV, "1")
    script = tmp_path / "tshark"
    script.write_text("#!/bin/sh\nprintf 'TShark \\377 (Wireshark) 4.6.7\\n'\n")
    script.chmod(0o755)
    assert tshark_mod._query_tshark_version(str(script)) == (4, 6, 7)


# ---------------------------------------------------------------------------
# Deterministic reaping when the consumer raises
# ---------------------------------------------------------------------------

def test_closing_a_raising_consumer_reaps_the_process(spawned):
    started = time.monotonic()
    with pytest.raises(KeyError):
        with pipeline_api._closing_packets(
                tshark_mod.stream_packets(_python_cmd(_ENDLESS_WRITER))) as packets:
            for _pkt in packets:
                raise KeyError("consumer failed")
    assert time.monotonic() - started < 10.0
    assert spawned and spawned[0].poll() is not None


def test_closing_packets_accepts_plain_iterables():
    with pipeline_api._closing_packets(iter([1, 2])) as packets:
        assert list(packets) == [1, 2]


def _tls_pass_kwargs(packet_source) -> dict:
    return dict(tls_ports=(), extra_decode_as=(), heuristic=False,
                bus=pipeline_api.EventBus(), state=object(),
                result=pipeline_api.ConvertResult(tap_path="x.tap"),
                tracker=pipeline_api.StreamDirectionTracker(),
                packet_source=packet_source)


def _raise(*_args, **_kwargs):
    raise KeyError("consumer failed")


def test_run_tls_combined_pass_reaps_tshark_when_the_consumer_raises(
        spawned, monkeypatch):
    monkeypatch.setattr(pipeline_api.TlsSinglePass, "feed", _raise)
    source = lambda cmd: tshark_mod.stream_packets(_python_cmd(_ENDLESS_WRITER))  # noqa: E731
    with pytest.raises(KeyError):  # excinfo keeps the frames (and the generator) alive
        pipeline_api.run_tls_combined_pass(
            "/usr/bin/tshark", "x.pcap", None, app_data_marker="tls.app_data",
            **_tls_pass_kwargs(source))
    assert spawned and spawned[0].poll() is not None


# ---------------------------------------------------------------------------
# Truncated captures
# ---------------------------------------------------------------------------

def test_truncated_capture_after_rows_warns_and_returns_the_rows(tshark_log):
    body = _EK_LINES + f"sys.stderr.write({_CUT_SHORT!r} + '\\n')\nsys.exit(14)\n"
    packets = _run_with_timeout(lambda: list(tshark_mod.stream_packets(_python_cmd(body))))
    assert packets == [json.loads(_ROW)]
    assert any("truncated" in message for message in tshark_log.warnings())


def test_truncated_capture_without_rows_still_raises():
    body = f"sys.stderr.write({_CUT_SHORT!r} + '\\n')\nsys.exit(14)\n"
    with pytest.raises(RuntimeError) as excinfo:
        _run_with_timeout(lambda: list(tshark_mod.stream_packets(_python_cmd(body))))
    assert "cut short" in str(excinfo.value)


def test_other_failures_after_rows_still_raise():
    body = _EK_LINES + "sys.stderr.write('tshark: something else\\n')\nsys.exit(2)\n"
    with pytest.raises(RuntimeError):
        _run_with_timeout(lambda: list(tshark_mod.stream_packets(_python_cmd(body))))


def _write_small_pcap(path) -> None:
    from scapy.all import IP, TCP, Raw, wrpcap

    wrpcap(str(path), [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i, dport=80)
                       / Raw(b"x" * 100) for i in range(5)])


@pytest.mark.skipif(_TSHARK is None, reason="tshark not installed")
def test_real_tshark_truncated_capture_converts_the_complete_packets(tmp_path, tshark_log):
    pcap = tmp_path / "trunc.pcap"
    _write_small_pcap(pcap)
    data = pcap.read_bytes()
    pcap.write_bytes(data[:-50])  # cut the last packet short
    cmd = [_TSHARK, "-r", str(pcap), "-T", "ek", "-e", "frame.number"]
    packets = _run_with_timeout(lambda: list(tshark_mod.stream_packets(cmd)))
    assert len(packets) == 4
    assert any("truncated" in message for message in tshark_log.warnings())


# ---------------------------------------------------------------------------
# Failure messages keep the ``tshark:`` line
# ---------------------------------------------------------------------------

_LISTING_FAILURE = ("sys.stderr.write('tshark: Unknown protocol -- \"foo\"\\n')\n"
                    "sys.stderr.write('tshark: Valid protocols are:\\n')\n"
                    "for i in range(300):\n    sys.stderr.write(f'\\tproto{i}\\n')\n"
                    "sys.exit(1)\n")


def test_stream_packets_error_keeps_the_scrolled_out_tshark_line():
    with pytest.raises(RuntimeError) as excinfo:
        _run_with_timeout(lambda: list(tshark_mod.stream_packets(
            _python_cmd(_LISTING_FAILURE))))
    message = str(excinfo.value)
    assert "code 1" in message
    assert 'tshark: Unknown protocol -- "foo"' in message
    assert "proto299" in message  # the tail is still there


def test_run_capture_error_keeps_the_scrolled_out_tshark_line():
    with pytest.raises(RuntimeError) as excinfo:
        tshark_mod._run_capture(_python_cmd(_LISTING_FAILURE))
    message = str(excinfo.value)
    assert 'tshark: Unknown protocol -- "foo"' in message
    assert "proto299" in message


def test_stderr_summary_does_not_repeat_tshark_lines_in_the_tail():
    summary = tshark_mod._summarize_stderr("tshark: one\nplain\n")
    assert summary.text() == "tshark: one\nplain"


@pytest.mark.skipif(_TSHARK is None, reason="tshark not installed")
def test_real_tshark_bad_decode_as_names_the_unknown_protocol(tmp_path):
    pcap = tmp_path / "small.pcap"
    _write_small_pcap(pcap)
    cmd = [_TSHARK, "-r", str(pcap), "-d", "tcp.port==1,nosuchproto", "-T", "ek"]
    with pytest.raises(RuntimeError) as excinfo:
        _run_with_timeout(lambda: list(tshark_mod.stream_packets(cmd)))
    assert "nosuchproto" in str(excinfo.value)


# ---------------------------------------------------------------------------
# tshark --version on-disk cache
# ---------------------------------------------------------------------------

@pytest.fixture
def version_cache(tmp_path, monkeypatch):
    """Cache under ``tmp_path``; fake ``tshark --version``; yields the run log."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.delenv(tshark_mod.TSHARK_VERSION_CACHE_DISABLE_ENV, raising=False)
    tshark_mod._clear_tshark_version_cache()
    runs: list = []
    output = {"stdout": "TShark (Wireshark) 4.6.7 (Git commit b439fb7b47a9).\n"}

    class _Completed:
        def __init__(self):
            self.stdout = output["stdout"]

    def fake_run(cmd, **kwargs):
        runs.append(cmd)
        return _Completed()

    monkeypatch.setattr(tshark_mod.subprocess, "run", fake_run)
    yield runs, output
    tshark_mod._clear_tshark_version_cache()


def _binary(tmp_path):
    binary = tmp_path / "tshark"
    binary.write_text("#!/bin/sh\n")
    return binary


def _cache_file(tmp_path):
    return tmp_path / "cache" / "fritap" / "tshark_version.json"


def test_disk_cache_spares_a_new_process_the_spawn(tmp_path, version_cache):
    runs, _ = version_cache
    binary = _binary(tmp_path)
    assert tshark_mod.tshark_version(str(binary)) == (4, 6, 7)
    assert _cache_file(tmp_path).is_file()
    tshark_mod._clear_tshark_version_cache()  # as if a new process started
    assert tshark_mod.tshark_version(str(binary)) == (4, 6, 7)
    assert len(runs) == 1


def test_disk_cache_misses_when_the_binary_changes(tmp_path, version_cache):
    runs, _ = version_cache
    binary = _binary(tmp_path)
    tshark_mod.tshark_version(str(binary))
    tshark_mod._clear_tshark_version_cache()
    binary.write_text("#!/bin/sh\n# upgraded, and larger\n")
    stat = os.stat(binary)
    os.utime(binary, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    assert tshark_mod.tshark_version(str(binary)) == (4, 6, 7)
    assert len(runs) == 2
    entries = json.loads(_cache_file(tmp_path).read_text())
    assert list(entries) == [os.path.realpath(binary)]  # one entry per binary


def test_disk_cache_never_stores_failures(tmp_path, version_cache):
    runs, output = version_cache
    output["stdout"] = "no version here"
    binary = _binary(tmp_path)
    assert tshark_mod.tshark_version(str(binary)) == ()
    assert not _cache_file(tmp_path).exists()
    tshark_mod._clear_tshark_version_cache()
    assert tshark_mod.tshark_version(str(binary)) == ()
    assert len(runs) == 2


def test_disk_cache_can_be_disabled(tmp_path, version_cache, monkeypatch):
    runs, _ = version_cache
    monkeypatch.setenv(tshark_mod.TSHARK_VERSION_CACHE_DISABLE_ENV, "1")
    binary = _binary(tmp_path)
    tshark_mod.tshark_version(str(binary))
    tshark_mod._clear_tshark_version_cache()
    tshark_mod.tshark_version(str(binary))
    assert len(runs) == 2
    assert not _cache_file(tmp_path).exists()


@pytest.mark.parametrize("content", ["not json", "[1, 2]",
                                     '{"%s": {"mtime_ns": 0}}', '{"%s": "x"}'])
def test_corrupt_disk_cache_is_ignored_and_repaired(tmp_path, version_cache, content):
    runs, _ = version_cache
    binary = _binary(tmp_path)
    cache_file = _cache_file(tmp_path)
    cache_file.parent.mkdir(parents=True)
    cache_file.write_text(content.replace("%s", os.path.realpath(binary)))
    assert tshark_mod.tshark_version(str(binary)) == (4, 6, 7)
    assert len(runs) == 1
    tshark_mod._clear_tshark_version_cache()
    assert tshark_mod.tshark_version(str(binary)) == (4, 6, 7)
    assert len(runs) == 1  # the rewritten file now answers


def test_wrong_typed_cached_version_is_ignored(tmp_path, version_cache):
    runs, _ = version_cache
    binary = _binary(tmp_path)
    key = tshark_mod._tshark_version_cache_key(str(binary))
    cache_file = _cache_file(tmp_path)
    cache_file.parent.mkdir(parents=True)
    cache_file.write_text(json.dumps({key[0]: {"mtime_ns": key[1], "size": key[2],
                                               "version": ["4", "6"]}}))
    assert tshark_mod.tshark_version(str(binary)) == (4, 6, 7)
    assert len(runs) == 1


def test_unwritable_cache_dir_is_silent(tmp_path, version_cache, monkeypatch):
    runs, _ = version_cache
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where the cache dir should be")
    monkeypatch.setenv("XDG_CACHE_HOME", str(blocker))
    binary = _binary(tmp_path)
    assert tshark_mod.tshark_version(str(binary)) == (4, 6, 7)
    assert tshark_mod.tshark_version(str(binary)) == (4, 6, 7)  # memory cache still works
    assert len(runs) == 1


def test_cache_path_falls_back_to_platformdirs(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.delenv(tshark_mod.TSHARK_VERSION_CACHE_DISABLE_ENV, raising=False)
    import platformdirs

    monkeypatch.setattr(platformdirs, "user_cache_dir", lambda name: str(tmp_path / name))
    assert tshark_mod._tshark_version_cache_path() == str(
        tmp_path / "fritap" / "tshark_version.json")
