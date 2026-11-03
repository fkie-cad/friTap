"""Opt-in decoder process isolation (friTap.decoder_isolation).

Covers: byte-identical results versus in-process decoding, worker crash /
segfault / timeout handling with quarantine and auto-restart, the circuit
breaker, hostile worker replies, stateful context handles, thread safety,
orphan-free shutdown and the opt-in switch.
"""

from __future__ import annotations

import ast
import gzip
import logging
import os
import sys
import threading
import time
import zlib
from argparse import Namespace
from pathlib import Path

import pytest

from friTap import decoder_isolation as di
from friTap.decoder_isolation import client
from friTap.decoder_isolation import protocol as P
from friTap.decoder_isolation.breaker import CircuitBreaker
from friTap.decoder_isolation.quarantine import MAX_FILES, quarantine_input
from friTap.decoder_isolation.supervisor import (
    BREAKER_OPEN_MESSAGE,
    DecoderSupervisor,
    WorkerFailure,
    get_supervisor,
    set_supervisor,
)
from friTap.parsers import decompress as d

brotli = pytest.importorskip("brotli")
zstandard = pytest.importorskip("zstandard")

PACKAGE_DIR = Path(di.__file__).resolve().parent
POSIX = os.name == "posix"


# --- fixtures ---------------------------------------------------------------------

@pytest.fixture(scope="module")
def shared_supervisor(tmp_path_factory):
    """One test-hook-enabled worker for the module (restarts lazily after crashes)."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("FRITAP_DECODER_QUARANTINE_DIR", str(tmp_path_factory.mktemp("quar")))
        sup = DecoderSupervisor(test_hooks=True)
        previous = set_supervisor(sup)
        yield sup
        sup.shutdown()
        set_supervisor(previous)


@pytest.fixture
def quarantine_dir(tmp_path, monkeypatch):
    path = tmp_path / "decoder_crashes"
    monkeypatch.setenv("FRITAP_DECODER_QUARANTINE_DIR", str(path))
    return path


@pytest.fixture
def isolated(shared_supervisor, quarantine_dir):
    """Isolation on, routed through the shared supervisor."""
    set_supervisor(shared_supervisor)
    di.enable_decoder_isolation(True)
    yield shared_supervisor
    di.enable_decoder_isolation(None)


@pytest.fixture
def own_supervisor(quarantine_dir):
    """A private supervisor for destructive tests; always shut down."""
    created = []

    def make(**kwargs):
        kwargs.setdefault("test_hooks", True)
        sup = DecoderSupervisor(**kwargs)
        created.append(sup)
        return sup

    yield make
    for sup in created:
        sup.shutdown()


@pytest.fixture
def error_log():
    """Records logged by friTap.decoder_isolation (independent of propagation)."""
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = logging.getLogger("friTap.decoder_isolation")
    handler = _Collect(level=logging.DEBUG)
    logger.addHandler(handler)
    yield records
    logger.removeHandler(handler)


@pytest.fixture(autouse=True)
def _isolation_off_by_default(monkeypatch):
    monkeypatch.delenv(di.ISOLATE_DECODERS_ENV, raising=False)
    di.enable_decoder_isolation(None)
    yield
    di.enable_decoder_isolation(None)


def _in_process(fn, *args, **kwargs):
    """Run *fn* with isolation forced off; exceptions are returned as values."""
    di.enable_decoder_isolation(False)
    try:
        return _outcome(fn, *args, **kwargs)
    finally:
        di.enable_decoder_isolation(True)


def _outcome(fn, *args, **kwargs):
    try:
        return ("ok", fn(*args, **kwargs))
    except Exception as exc:  # compare type + message
        return ("raise", type(exc), str(exc))


def _gzip(data: bytes) -> bytes:
    return gzip.compress(data, mtime=0)


def _raw_deflate(data: bytes) -> bytes:
    comp = zlib.compressobj(wbits=-15)
    return comp.compress(data) + comp.flush()


def _sync_flushed_deflate(data: bytes) -> bytes:
    comp = zlib.compressobj(wbits=-15)
    return (comp.compress(data) + comp.flush(zlib.Z_SYNC_FLUSH))[:-4]


TEXT = b"friTap decoder isolation " * 400
BIG = os.urandom(512) * 2048  # 1 MiB, compressible


BODY_CASES = [
    ("gzip", _gzip(TEXT), d.MAX_DECOMPRESSED_BODY),
    ("x-gzip", _gzip(TEXT), d.MAX_DECOMPRESSED_BODY),
    ("GZIP ", _gzip(TEXT), d.MAX_DECOMPRESSED_BODY),
    ("deflate", _raw_deflate(TEXT), d.MAX_DECOMPRESSED_BODY),
    ("deflate", zlib.compress(TEXT), d.MAX_DECOMPRESSED_BODY),
    ("permessage-deflate", _sync_flushed_deflate(TEXT), d.MAX_DECOMPRESSED_BODY),
    ("br", brotli.compress(TEXT), d.MAX_DECOMPRESSED_BODY),
    ("brotli", brotli.compress(TEXT), d.MAX_DECOMPRESSED_BODY),
    ("zstd", zstandard.ZstdCompressor().compress(TEXT), d.MAX_DECOMPRESSED_BODY),
    ("gzip", _gzip(BIG), d.MAX_DECOMPRESSED_BODY),
    ("br", brotli.compress(BIG), d.MAX_DECOMPRESSED_BODY),
    # error cases
    ("gzip", b"\x1f\x8b\x08 corrupt body", d.MAX_DECOMPRESSED_BODY),
    ("gzip", _gzip(TEXT)[:-12], d.MAX_DECOMPRESSED_BODY),
    ("deflate", b"not deflate at all", d.MAX_DECOMPRESSED_BODY),
    ("br", b"\xff\xfe\xfd junk", d.MAX_DECOMPRESSED_BODY),
    ("br", brotli.compress(TEXT)[:-5], d.MAX_DECOMPRESSED_BODY),
    ("zstd", b"\x28\xb5\x2f\xfd junk", d.MAX_DECOMPRESSED_BODY),
    ("zstd", zstandard.ZstdCompressor().compress(TEXT)[:-3], d.MAX_DECOMPRESSED_BODY),
    ("gzip", _gzip(TEXT), 100),
    ("br", brotli.compress(TEXT), 100),
    ("zstd", zstandard.ZstdCompressor().compress(TEXT), 100),
    ("deflate", _raw_deflate(TEXT), 100),
    ("compress", b"whatever", d.MAX_DECOMPRESSED_BODY),
    ("", b"abc", d.MAX_DECOMPRESSED_BODY),
    ("gzip", b"", d.MAX_DECOMPRESSED_BODY),
]


# --- round-trip equality ----------------------------------------------------------

@pytest.mark.parametrize("encoding,body,max_out", BODY_CASES)
def test_decompress_body_matches_in_process(isolated, encoding, body, max_out):
    expected = _in_process(d.decompress_body, body, encoding, max_out)
    assert _outcome(d.decompress_body, body, encoding, max_out) == expected


@pytest.mark.parametrize("encoding,body", [
    ("gzip", b"\x00\x01framing" + _gzip(TEXT)),
    ("gzip", b"no gzip member here"),
    ("gzip", _gzip(TEXT)),
    ("br", brotli.compress(TEXT)),
    ("zstd", b"junk"),
    ("rot13", b"abc"),
])
def test_decompress_lenient_matches_in_process(isolated, encoding, body):
    expected = _in_process(d.decompress_lenient, body, encoding)
    assert _outcome(d.decompress_lenient, body, encoding) == expected


def test_decompress_lenient_limit_matches_in_process(isolated):
    body = b"prefix" + _gzip(TEXT)
    expected = _in_process(d.decompress_lenient, body, "gzip", 50)
    assert _outcome(d.decompress_lenient, body, "gzip", 50) == expected


@pytest.mark.parametrize("body,kwargs", [
    (b"head\x1f\x8b\x08junk" + _gzip(TEXT) + b"tail", {}),
    (b"nothing", {}),
    (_gzip(TEXT), {"max_out": 10}),
    (b"\x1f\x8b\x08" * 10 + _gzip(TEXT), {"max_candidates": 3}),
])
def test_find_embedded_gzip_matches_in_process(isolated, body, kwargs):
    expected = _in_process(d.find_embedded_gzip, body, **kwargs)
    assert _outcome(d.find_embedded_gzip, body, **kwargs) == expected


@pytest.mark.parametrize("packed,kwargs", [
    (_gzip(TEXT), {}),
    (zlib.compress(TEXT), {}),
    (_gzip(TEXT)[:-20], {}),
    (_gzip(TEXT)[:-20], {"require_eof": True}),
    (b"\x78\x9c corrupt", {}),
    (_gzip(TEXT), {"limit": 64}),
    (_gzip(TEXT), {"limit": 0}),
    (_gzip(TEXT), {"limit": -1}),
    (b"", {}),
])
def test_inflate_bounded_matches_in_process(isolated, packed, kwargs):
    expected = _in_process(d.inflate_bounded, packed, **kwargs)
    assert _outcome(d.inflate_bounded, packed, **kwargs) == expected


@pytest.mark.parametrize("packed,limit", [
    (_gzip(TEXT), d.MAX_INFLATE), (_gzip(TEXT)[:-9], d.MAX_INFLATE), (_gzip(TEXT), 10),
])
def test_inflate_bounded_checked_matches_in_process(isolated, packed, limit):
    expected = _in_process(d.inflate_bounded_checked, packed, limit)
    assert _outcome(d.inflate_bounded_checked, packed, limit) == expected


def test_vulnerable_brotli_guard_runs_in_parent(own_supervisor, monkeypatch):
    sup = own_supervisor()
    set_supervisor(sup)
    monkeypatch.setattr(d, "_BROTLI_VERSION", "1.1.0")
    body = brotli.compress(TEXT)
    expected = _in_process(d.decompress_body, body, "br")
    di.enable_decoder_isolation(True)
    try:
        assert _outcome(d.decompress_body, body, "br") == expected
        assert "CVE-2026-111497" in expected[1][1]
        assert sup.pid is None, "a blocked br body must not reach the worker"
    finally:
        set_supervisor(None)


def test_unpatched_brotli_override_is_forwarded(isolated, monkeypatch):
    monkeypatch.setattr(d, "_BROTLI_VERSION", "1.1.0")
    monkeypatch.setenv(d.ALLOW_UNPATCHED_BROTLI_ENV, "1")
    data, err = d.decompress_body(brotli.compress(TEXT), "br")
    assert (data, err) == (TEXT, "")


def test_missing_decoder_message_matches(isolated, monkeypatch):
    monkeypatch.setattr(d, "_zstd", False)
    expected = _in_process(d.decompress_body, b"abc", "zstd")
    assert _outcome(d.decompress_body, b"abc", "zstd") == expected


# --- worker contents and hardening ------------------------------------------------

def test_worker_imports_no_fritap_or_frida(isolated):
    reply = isolated.request(P.Op.TEST_LIST_MODULES, max_reply=1 << 20)
    modules = set(reply.data.decode().split("\n"))
    assert "_fritap_decoder_engine" in modules
    assert not {m for m in modules if m == "friTap" or m.startswith("friTap.")}
    assert not {m for m in modules if m.split(".")[0] in ("frida", "frida_tools")}


@pytest.mark.skipif(not POSIX, reason="Windows gets process separation only")
def test_worker_reports_hardening(isolated):
    reply = isolated.request(P.Op.TEST_HARDENING)
    report = P.safe_worker_text(reply.text).split(",")
    assert {"close-fds", "rlimit-core", "rlimit-nofile", "nice"} <= set(report)
    if sys.platform == "darwin":
        assert "macos-sandbox" in report
    if sys.platform.startswith("linux"):
        assert "rlimit-as" in report


@pytest.mark.parametrize("module", ["protocol.py", "hardening.py", "worker_main.py"])
def test_worker_side_modules_are_stdlib_only(module):
    tree = ast.parse((PACKAGE_DIR / module).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"{module}: relative import"
            imported.add((node.module or "").split(".")[0])
    assert not imported & {"friTap", "frida", "pickle", "marshal"}


def test_test_ops_refused_without_hooks(own_supervisor):
    sup = own_supervisor(test_hooks=False)
    reply = sup.request(P.Op.TEST_EXIT, arg0=1)
    assert reply.status == P.Status.UNSUPPORTED
    assert sup.pid is not None


# --- crash, segfault, timeout -----------------------------------------------------

def _assert_recovers(sup):
    data, err = client.isolated_decompress_body(_gzip(TEXT), "gzip", 1 << 20, supervisor=sup)
    assert (data, err) == (TEXT, "")


def test_worker_exit_is_contained(own_supervisor, quarantine_dir, error_log):
    sup = own_supervisor()
    _assert_recovers(sup)
    first_pid = sup.pid
    result = sup.request(P.Op.TEST_EXIT, arg0=1, data=b"EVIL" * 10, label="br")
    assert isinstance(result, WorkerFailure) and result.kind == "crash"
    assert "exit code 1" in result.message
    messages = [r.getMessage() for r in error_log if r.levelno >= logging.ERROR]
    assert any("possible exploit attempt" in m and "br input of 40 bytes" in m
               for m in messages)
    samples = list(quarantine_dir.glob("*.bin"))
    assert len(samples) == 1 and samples[0].read_bytes() == b"EVIL" * 10
    _assert_recovers(sup)
    assert sup.pid not in (None, first_pid)


@pytest.mark.skipif(not POSIX, reason="signal exit codes are POSIX")
def test_worker_segfault_is_contained(own_supervisor, quarantine_dir):
    sup = own_supervisor()
    result = sup.request(P.Op.TEST_SEGV, data=b"crash-me", label="zstd")
    assert isinstance(result, WorkerFailure) and result.kind == "crash"
    assert "SIGSEGV" in result.message or "SIGBUS" in result.message
    assert len(list(quarantine_dir.glob("*.bin"))) == 1
    _assert_recovers(sup)


def test_decompress_body_reports_crash_as_error(isolated, monkeypatch):
    def crash(*_args, **_kwargs):
        return WorkerFailure("crash", "decoder worker crashed (killed by SIGSEGV)")

    monkeypatch.setattr(isolated, "request", crash)
    body = _gzip(TEXT)
    assert d.decompress_body(body, "gzip") == (
        body, "decompress failed: decoder worker crashed (killed by SIGSEGV)")
    with pytest.raises(zlib.error, match="decoder worker crashed"):
        d.inflate_bounded(body)
    assert d.find_embedded_gzip(body) is None
    assert d.decompress_lenient(body, "br")[2].startswith("decompress failed: decoder")


def test_timeout_kills_and_restarts(own_supervisor, quarantine_dir):
    sup = own_supervisor(timeout=0.5)
    _assert_recovers(sup)
    started = time.monotonic()
    result = sup.request(P.Op.TEST_SLEEP, arg0=30_000, label="gzip")
    assert time.monotonic() - started < 10
    assert isinstance(result, WorkerFailure) and result.kind == "timeout"
    assert "timed out" in result.message
    _assert_recovers(sup)


def test_timeout_env_override(monkeypatch):
    from friTap.decoder_isolation.supervisor import default_timeout
    monkeypatch.setenv("FRITAP_DECODER_TIMEOUT", "2.5")
    assert default_timeout() == 2.5
    monkeypatch.setenv("FRITAP_DECODER_TIMEOUT", "bogus")
    assert default_timeout() == 10.0


def test_circuit_breaker_opens_and_never_falls_back(own_supervisor, monkeypatch):
    now = [1000.0]
    breaker = CircuitBreaker(max_failures=2, window=60, cooldown=60, clock=lambda: now[0])
    sup = own_supervisor(breaker=breaker)
    for _ in range(3):
        assert sup.request(P.Op.TEST_EXIT, arg0=3).kind == "crash"
    blocked = sup.request(P.Op.PING)
    assert blocked == WorkerFailure("breaker", BREAKER_OPEN_MESSAGE)
    assert sup.pid is None
    body = _gzip(TEXT)
    assert client.isolated_decompress_body(body, "gzip", 1 << 20, supervisor=sup) == (
        body, "decompress failed: " + BREAKER_OPEN_MESSAGE)
    now[0] += 61
    _assert_recovers(sup)


def test_breaker_window_forgets_old_failures():
    now = [0.0]
    breaker = CircuitBreaker(max_failures=5, window=60, cooldown=60, clock=lambda: now[0])
    for _ in range(5):
        assert not breaker.record_failure()
        now[0] += 20
    assert not breaker.record_failure() and not breaker.is_open()


# --- hostile replies --------------------------------------------------------------

def _raw(sup, request_id_offset=1, **fields):
    """A reply frame for the next TEST_RAW_REPLY request, with fields overridden."""
    values = dict(op=P.Op.TEST_RAW_REPLY, request_id=sup._request_id + request_id_offset)
    values.update(fields)
    return P.encode_frame(values.pop("op"), values.pop("request_id"), **values)


@pytest.mark.parametrize("make_reply", [
    pytest.param(lambda sup: _raw(sup, request_id_offset=5), id="wrong-request-id"),
    pytest.param(lambda sup: _raw(sup, status=0x99), id="junk-status"),
    pytest.param(lambda sup: _raw(sup, op=P.Op.PING), id="wrong-op"),
    pytest.param(lambda sup: P.HEADER.pack(P.MAGIC, P.VERSION, P.Op.TEST_RAW_REPLY, 0, 0,
                                           sup._request_id + 1, 0, 0, 0, 0, 1 << 31),
                 id="declared-length-over-cap"),
    pytest.param(lambda sup: _raw(sup) + b"trailing", id="length-mismatch"),
    pytest.param(lambda sup: b"XX" + _raw(sup)[2:], id="bad-magic"),
    pytest.param(lambda sup: b"\x00\x01", id="short-frame"),
    pytest.param(lambda sup: _raw(sup, text=b"x" * (P.MAX_TEXT_LEN + 1)), id="text-over-cap"),
    pytest.param(lambda sup: _raw(sup, data=b"y" * 5000), id="data-over-max-out"),
])
def test_hostile_reply_is_rejected(own_supervisor, quarantine_dir, error_log, make_reply):
    sup = own_supervisor()
    _assert_recovers(sup)
    crafted = make_reply(sup)
    result = sup.request(P.Op.TEST_RAW_REPLY, data=crafted, max_reply=1024, label="br")
    assert isinstance(result, WorkerFailure) and result.kind == "protocol"
    assert any("invalid reply" in r.getMessage() or "oversized" in r.getMessage()
               for r in error_log)
    _assert_recovers(sup)


def test_oversized_message_rejected_before_reading(own_supervisor, quarantine_dir):
    sup = own_supervisor()
    crafted = _raw(sup, data=b"z" * (2 << 20))
    result = sup.request(P.Op.TEST_RAW_REPLY, data=crafted, max_reply=1024)
    assert isinstance(result, WorkerFailure) and result.kind == "protocol"
    assert "oversized" in result.message
    _assert_recovers(sup)


def test_member_outside_input_is_a_violation():
    frame = P.Frame(P.Op.FIND_GZIP_MEMBER, P.Status.OK, 0, 1, 0, 10, 5, b"", b"x")
    assert client._check_member(frame, b"\x1f\x8b\x08" + b"a" * 8)
    good = frame._replace(arg0=0, arg1=3)
    assert client._check_member(good, b"\x1f\x8b\x08") is None


def test_safe_worker_text_filters_controls():
    raw = "ok\x1b[31mred\nforged line‮evil\x00".encode() + b"\xff"
    text = P.safe_worker_text(raw)
    assert "\x1b" not in text and "\n" not in text and "‮" not in text
    assert "\\x1b" in text and "\\u202e" in text and "�" in text
    assert len(P.safe_worker_text(b"a" * 100_000)) == P.MAX_LOG_TEXT_CHARS


def test_parse_reply_validates_every_field():
    good = P.encode_frame(P.Op.DECOMPRESS_BODY, 7, data=b"abc")
    assert P.parse_reply(good, op=P.Op.DECOMPRESS_BODY, request_id=7, max_data=3).data == b"abc"
    for kwargs in ({"request_id": 8, "max_data": 3}, {"request_id": 7, "max_data": 2}):
        with pytest.raises(P.ProtocolError):
            P.parse_reply(good, op=P.Op.DECOMPRESS_BODY, **kwargs)
    bad_status = P.encode_frame(P.Op.DECOMPRESS_BODY, 7, status=P.Status.HANDLE_LOST)
    with pytest.raises(P.ProtocolError):
        P.parse_reply(bad_status, op=P.Op.DECOMPRESS_BODY, request_id=7, max_data=0)


def test_input_too_large_is_refused(own_supervisor, monkeypatch):
    sup = own_supervisor()
    monkeypatch.setattr(P, "MAX_REQUEST_DATA", 10)
    assert sup.request(P.Op.PING, data=b"x" * 11).kind == "too_large"
    assert sup.pid is None


# --- stateful contexts ------------------------------------------------------------

def test_context_create_call_destroy(own_supervisor):
    sup = own_supervisor()
    created = client.create_context("test_echo_state", b"A", supervisor=sup)
    assert created.status is client.ContextStatus.OK
    handle = created.handle
    feed = client.ContextOp.FEED
    assert client.call_context(handle, feed, b"B", 100, supervisor=sup).data == b"AB"
    assert client.call_context(handle, feed, b"C", 100, supervisor=sup).data == b"ABC"
    over = client.call_context(handle, feed, b"D", 2, supervisor=sup)
    assert over.status is client.ContextStatus.LIMIT and over.data == b""
    client.destroy_context(handle, supervisor=sup)
    gone = client.call_context(handle, feed, b"E", 100, supervisor=sup)
    assert gone.status is client.ContextStatus.LOST and gone.context_lost


def test_unknown_context_kind(own_supervisor):
    sup = own_supervisor()
    reply = client.create_context("qpack_decoder_v99", supervisor=sup)
    assert reply.status is client.ContextStatus.UNSUPPORTED and reply.handle is None


def test_test_kind_needs_hooks(own_supervisor):
    sup = own_supervisor(test_hooks=False)
    assert client.create_context("test_echo_state", supervisor=sup).status is \
        client.ContextStatus.UNSUPPORTED


def test_zlib_stream_context_matches_in_process(own_supervisor):
    sup = own_supervisor()
    comp = zlib.compressobj(wbits=-15)
    messages = [b"hello " * 50, b"hello again " * 50, b"and again " * 50]
    wire = [(comp.compress(m) + comp.flush(zlib.Z_SYNC_FLUSH)) for m in messages]
    handle = client.create_context("zlib_stream", P.pack_i64(-15), supervisor=sup).handle
    local = zlib.decompressobj(-15)
    for chunk in wire:
        expected = d.inflate_stream_bounded(local, chunk, 1 << 20)
        got = client.call_context(handle, client.ContextOp.FEED, chunk, 1 << 20, supervisor=sup)
        assert (got.status, got.data) == (client.ContextStatus.OK, expected)
    poisoned = client.call_context(handle, client.ContextOp.FEED, wire[0], 1, supervisor=sup)
    assert poisoned.status is client.ContextStatus.LIMIT
    after = client.call_context(handle, client.ContextOp.FEED, wire[0], 1 << 20, supervisor=sup)
    assert after.status is client.ContextStatus.ERROR


def test_context_lost_after_restart(own_supervisor, quarantine_dir):
    sup = own_supervisor()
    handle = client.create_context("test_echo_state", supervisor=sup).handle
    assert sup.request(P.Op.TEST_EXIT, arg0=1).kind == "crash"
    lost = client.call_context(handle, client.ContextOp.FEED, b"x", 10, supervisor=sup)
    assert lost.status is client.ContextStatus.LOST and lost.context_lost
    assert lost.error == client.CONTEXT_LOST_ERROR
    fresh = client.create_context("test_echo_state", supervisor=sup).handle
    assert fresh.generation == handle.generation + 1
    # The stale handle id may equal a new one; the generation keeps them apart.
    assert client.call_context(handle, client.ContextOp.FEED, b"x", 10,
                               supervisor=sup).status is client.ContextStatus.LOST
    assert client.call_context(fresh, client.ContextOp.FEED, b"x", 10,
                               supervisor=sup).data == b"x"


def test_crash_during_context_call_reports_worker_failed(own_supervisor, monkeypatch):
    sup = own_supervisor()
    handle = client.create_context("test_echo_state", supervisor=sup).handle
    monkeypatch.setattr(sup, "request_in_generation",
                        lambda *a, **k: (WorkerFailure("crash", "decoder worker crashed"), 0))
    reply = client.call_context(handle, client.ContextOp.FEED, b"x", 10, supervisor=sup)
    assert reply.status is client.ContextStatus.WORKER_FAILED and reply.context_lost


# --- concurrency, shutdown --------------------------------------------------------

def test_eight_threads(isolated):
    jobs = [("gzip", _gzip(TEXT)), ("br", brotli.compress(TEXT)),
            ("zstd", zstandard.ZstdCompressor().compress(TEXT)),
            ("deflate", _raw_deflate(TEXT))]
    errors: list[str] = []

    def run(index):
        for i in range(25):
            encoding, body = jobs[(index + i) % len(jobs)]
            data, err = d.decompress_body(body, encoding)
            if (data, err) != (TEXT, ""):
                errors.append(f"{encoding}: {err}")

    threads = [threading.Thread(target=run, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert not errors


def test_shutdown_leaves_no_orphans(own_supervisor):
    psutil = pytest.importorskip("psutil")
    sup = own_supervisor()
    _assert_recovers(sup)
    pid = sup.pid
    assert pid in {child.pid for child in psutil.Process().children(recursive=True)}
    sup.shutdown()
    assert sup.pid is None
    assert pid not in {child.pid for child in psutil.Process().children(recursive=True)}
    assert not psutil.pid_exists(pid) or psutil.Process(pid).status() == psutil.STATUS_ZOMBIE


def test_worker_exits_when_parent_closes_pipe(own_supervisor):
    pytest.importorskip("psutil")
    sup = own_supervisor()
    _assert_recovers(sup)
    process = sup._process
    sup._conn.close()  # what the worker sees when the parent dies
    process.join(5)
    assert process.exitcode == 0


def test_singleton_shutdown_registered(monkeypatch):
    set_supervisor(None)
    sup = get_supervisor()
    assert get_supervisor() is sup
    di.shutdown_decoder_worker()
    assert get_supervisor() is not sup
    di.shutdown_decoder_worker()


# --- quarantine -------------------------------------------------------------------

def test_quarantine_is_bounded(quarantine_dir, monkeypatch):
    from friTap.decoder_isolation import quarantine
    monkeypatch.setattr(quarantine, "MAX_SAMPLE_BYTES", 8)
    for n in range(MAX_FILES + 5):
        path = quarantine_input(f"sample-{n:02d}-payload".encode(), "br/../x", "crash")
        assert path is not None and path.parent == quarantine_dir
    samples = list(quarantine_dir.glob("*.bin"))
    assert len(samples) == MAX_FILES
    assert all(len(p.read_bytes()) == 8 for p in samples)
    assert all("/" not in p.name and ".." not in p.name.split("_")[2] for p in samples)
    if POSIX:
        assert all((p.stat().st_mode & 0o777) == 0o600 for p in samples)


# --- switch -----------------------------------------------------------------------

def test_switch_env_and_override(monkeypatch):
    assert not di.decoder_isolation_enabled()
    monkeypatch.setenv(di.ISOLATE_DECODERS_ENV, "1")
    assert di.decoder_isolation_enabled()
    di.enable_decoder_isolation(False)
    assert not di.decoder_isolation_enabled()
    di.enable_decoder_isolation(None)
    monkeypatch.setenv(di.ISOLATE_DECODERS_ENV, "0")
    assert not di.decoder_isolation_enabled()
    di.enable_decoder_isolation()
    assert di.decoder_isolation_enabled()


def test_cli_flag_enables_isolation(monkeypatch):
    from friTap.friTap import _apply_decoder_isolation_flag
    _apply_decoder_isolation_flag(Namespace(isolate_decoders=False))
    assert not di.decoder_isolation_enabled()
    monkeypatch.setenv(di.ISOLATE_DECODERS_ENV, "")
    _apply_decoder_isolation_flag(Namespace(isolate_decoders=True))
    assert di.decoder_isolation_enabled()
    assert os.environ[di.ISOLATE_DECODERS_ENV] == "1"


def test_cli_parser_has_flag():
    source = (PACKAGE_DIR.parent / "friTap.py").read_text()
    assert '"--isolate-decoders"' in source


def test_default_off_stays_in_process(monkeypatch):
    previous = set_supervisor(None)
    try:
        def no_worker(*_a, **_k):
            raise AssertionError("worker used while isolation is off")

        monkeypatch.setattr("friTap.decoder_isolation.supervisor.get_supervisor", no_worker)
        monkeypatch.setattr(client, "get_supervisor", no_worker)
        assert d._isolated_decoders() is None
        assert d.decompress_body(_gzip(TEXT), "gzip") == (TEXT, "")
        assert d.decompress_lenient(b"xx" + _gzip(TEXT), "gzip")[0] == TEXT
        assert d.inflate_bounded(zlib.compress(TEXT)) == TEXT
        assert d.find_embedded_gzip(b"x" + _gzip(TEXT)) == (1, TEXT)
    finally:
        set_supervisor(previous)


def test_isolated_calls_reach_worker(isolated, monkeypatch):
    seen: list[int] = []
    real = isolated.request_in_generation

    def spy(op, **kwargs):
        seen.append(op)
        return real(op, **kwargs)

    monkeypatch.setattr(isolated, "request_in_generation", spy)
    d.decompress_body(_gzip(TEXT), "gzip")
    d.inflate_bounded(zlib.compress(TEXT))
    d.find_embedded_gzip(b"x" + _gzip(TEXT))
    d.decompress_lenient(b"x" + _gzip(TEXT), "gzip")
    assert seen == [P.Op.DECOMPRESS_BODY, P.Op.INFLATE_CHECKED, P.Op.FIND_GZIP_MEMBER,
                    P.Op.DECOMPRESS_BODY, P.Op.FIND_GZIP_MEMBER]
