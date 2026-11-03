#!/usr/bin/env python3

"""Machine-readable capture output: ``-j -`` JSONL on stdout, ``--tap`` and the
``devices`` / ``apps`` listing subcommands. Frida is never touched."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import textwrap
import types

import pytest

import friTap.friTap as fritap_cli
from friTap.commands import devices as devices_cmd
from friTap.events import (
    DatalogEvent,
    EventBus,
    FlowEvent,
    HookBreadcrumbEvent,
    KeylogEvent,
    SessionEvent,
)
from friTap.exit_codes import EXIT_OK, EXIT_RUNTIME_ERROR, EXIT_TARGET_DETACHED
from friTap.flow.tap_reader import TapReader
from friTap.legacy.session_manager import SessionManager
from friTap.output import stdout_stream
from friTap.output.jsonl_stdout_handler import JsonlStdoutHandler, event_type_name
from friTap.output.key_material import redact_key_record
from friTap.output.stdout_stream import STREAM_SCHEMA, argv_requests_stdout_stream
from friTap.output.tap_handler import TapOutputHandler
from tests.unit import test_memory_scan_teardown as _teardown
from tests.unit.test_memory_scan_teardown import _FakePcap, _make_logger

exits = _teardown.exits

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NSS_LINE = "CLIENT_RANDOM " + "aa" * 32 + " " + "bb" * 48


# --------------------------------------------------------------------------
# -j - : JSONL stream schema
# --------------------------------------------------------------------------

def _stream_handler(include_keys=False):
    buffer = io.StringIO()
    bus = EventBus()
    handler = JsonlStdoutHandler(include_key_material=include_keys, stream=buffer)
    handler.setup(bus)
    return handler, bus, buffer


def _records(buffer):
    return [json.loads(line) for line in buffer.getvalue().splitlines()]


def test_every_line_has_type_and_schema():
    handler, bus, buffer = _stream_handler()
    bus.emit(SessionEvent(event_type="started", session_id="1"))
    bus.emit(DatalogEvent(data=b"\x00GET", function="SSL_write", src_port=1, dst_port=443))
    handler.close()
    records = _records(buffer)
    assert [r["type"] for r in records] == ["stream_start", "session", "data", "stream_end"]
    assert all(r["schema"] == STREAM_SCHEMA for r in records)
    session, data = records[1], records[2]
    assert session["event"] == "SessionEvent" and session["event_type"] == "started"
    assert data["data"] == b"\x00GET".hex()


def test_internal_events_are_not_streamed():
    handler, bus, buffer = _stream_handler()
    bus.emit(HookBreadcrumbEvent(marker="x"))
    bus.emit(FlowEvent(flow=object(), flow_event_type="completed"))
    handler.close()
    assert [r["type"] for r in _records(buffer)] == ["stream_start", "stream_end"]


def test_key_material_is_redacted_without_keylog():
    handler, bus, buffer = _stream_handler(include_keys=False)
    bus.emit(KeylogEvent(key_data=NSS_LINE, payload={"secret": "x"}))
    handler.close()
    keylog = _records(buffer)[1]
    assert keylog["type"] == "keylog" and keylog["redacted"] is True
    assert "key_data" not in keylog and "payload" not in keylog
    assert keylog["label"] == "CLIENT_RANDOM" and keylog["client_random"] == "aa" * 32
    assert "bb" * 48 not in buffer.getvalue()
    assert _records(buffer)[0]["key_material"] is False


def test_key_material_included_when_keylog_requested():
    handler, bus, buffer = _stream_handler(include_keys=True)
    bus.emit(KeylogEvent(key_data=NSS_LINE))
    handler.close()
    keylog = _records(buffer)[1]
    assert keylog["key_data"] == NSS_LINE and "redacted" not in keylog


def test_close_is_idempotent_and_drops_later_events():
    handler, bus, buffer = _stream_handler()
    handler.close()
    handler.close()
    bus.emit(SessionEvent(event_type="started"))
    assert [r["type"] for r in _records(buffer)] == ["stream_start", "stream_end"]


@pytest.mark.parametrize("name,expected", [
    ("KeylogEvent", "keylog"), ("SocketTraceEvent", "socket_trace"),
    ("PlatformReportEvent", "platform_report"), ("Weird", "weird"),
])
def test_event_type_names(name, expected):
    assert event_type_name(name) == expected


def test_redact_non_nss_key_line():
    record = redact_key_record({"key_data": "SSH_ENC_KEY_C2S deadbeef", "payload": None})
    assert record == {"label": "SSH_ENC_KEY_C2S", "redacted": True}


@pytest.mark.parametrize("argv,expected", [
    (["-j", "-", "app"], True), (["--json", "-"], True), (["--json=-"], True),
    (["-j", "out.json"], False), (["-j"], False), (["app"], False),
])
def test_argv_requests_stdout_stream(argv, expected):
    assert argv_requests_stdout_stream(argv) is expected


# --------------------------------------------------------------------------
# -j - : stdout stays pure JSONL (fd-level redirect, run in a subprocess)
# --------------------------------------------------------------------------

_PURITY_SCRIPT = textwrap.dedent("""
    import logging, os, sys
    from friTap.events import EventBus, SessionEvent
    from friTap.output.jsonl_stdout_handler import JsonlStdoutHandler
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    print("banner before claim is fine to stderr?")  # flushed then redirected
    handler = JsonlStdoutHandler()
    bus = EventBus()
    handler.setup(bus)
    print("a stray print")
    logging.getLogger("friTap").info("a log line bound to sys.stdout")
    os.write(1, b"native write to fd 1\\n")
    bus.emit(SessionEvent(event_type="started"))
    handler.close()
""")


def test_stdout_is_pure_jsonl_after_claim():
    script = "import friTap.output.stdout_stream as s; s.claim_stdout_for_json_stream()\n" \
        + _PURITY_SCRIPT
    proc = subprocess.run([sys.executable, "-c", script], cwd=REPO_ROOT,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.splitlines()
    assert lines, proc.stderr
    records = [json.loads(line) for line in lines]  # every line is JSON
    assert [r["type"] for r in records] == ["stream_start", "session", "stream_end"]
    for noise in ("a stray print", "a log line bound", "native write to fd 1", "banner"):
        assert noise in proc.stderr


def test_usage_error_with_json_stream_writes_json_record():
    script = ("import sys; sys.argv=['fritap','-j','-','--no-such-flag','app']\n"
              "from friTap.friTap import cli\ncli()\n")
    proc = subprocess.run([sys.executable, "-c", script], cwd=REPO_ROOT,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 2
    records = [json.loads(line) for line in proc.stdout.splitlines()]
    assert records[0]["type"] == "usage_error" and records[0]["exit_code"] == 2
    assert "Usage:" in proc.stderr


def test_claim_is_idempotent_with_pipes():
    stdout_r, stdout_w = os.pipe()
    stderr_r, stderr_w = os.pipe()
    stdout_stream._reset_for_tests()
    try:
        first = stdout_stream.claim_stdout_for_json_stream(stdout_w, stderr_w)
        assert stdout_stream.claim_stdout_for_json_stream(stdout_w, stderr_w) is first
        first.write("{}\n")
        first.flush()
        os.write(stdout_w, b"noise\n")  # stdout_w now aliases stderr
        assert os.read(stdout_r, 100) == b"{}\n"
        assert os.read(stderr_r, 100) == b"noise\n"
        first.close()
    finally:
        stdout_stream._reset_for_tests()
        for fd in (stdout_r, stdout_w, stderr_r, stderr_w):
            try:
                os.close(fd)
            except OSError:
                pass


def test_factory_picks_stdout_handler_for_dash():
    from friTap.config import FriTapConfig
    from friTap.output.factory import OutputHandlerFactory
    import logging
    config = FriTapConfig.from_legacy_params(app="x", json_output="-", keylog="k.log")
    config.output.tap_output = "x.tap"
    handlers, _ = OutputHandlerFactory.create_handlers(
        config, None, None, {"session_info": {}}, logging.getLogger("t"))
    stdout_handlers = [h for h in handlers if isinstance(h, JsonlStdoutHandler)]
    assert len(stdout_handlers) == 1 and stdout_handlers[0]._include_key_material
    assert any(isinstance(h, TapOutputHandler) for h in handlers)


def test_tap_output_keeps_main_agent_with_memory_scan():
    from friTap.config import FriTapConfig, memory_scan_only
    config = FriTapConfig.from_legacy_params(app="x", memory_scan=True)
    assert memory_scan_only(config)
    config.output.tap_output = "x.tap"
    assert not memory_scan_only(config)


# --------------------------------------------------------------------------
# --tap : finalized on every stop path
# --------------------------------------------------------------------------

def _datalog(direction, data, ts):
    return DatalogEvent(
        data=data, function="SSL_write" if direction == "write" else "SSL_read",
        direction=direction, src_addr="10.0.0.2", src_port=50000,
        dst_addr="93.184.216.34", dst_port=443, timestamp=ts)


def _tap_logger(tmp_path):
    """A teardown-ready SSL_Logger with a real TapOutputHandler on a real bus."""
    path = str(tmp_path / "cap.tap")
    handler = TapOutputHandler(path, target="curl")
    bus = EventBus()
    handler.setup(bus)
    bus.emit(_datalog("write", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 1000.0))
    bus.emit(_datalog("read", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", 1000.1))
    obj = _make_logger(_FakePcap())
    obj._is_memory_scan_only = lambda: False
    obj._output_handlers = [handler]
    return obj, path


def _assert_tap_finalized(path):
    reader = TapReader(path)
    reader.open()
    try:
        assert reader.header.flags & 0x1, "FLOW_INDEX flag must be set (finalized)"
        assert reader.flow_count >= 1
        flows = reader.read_all_flows()
        assert flows and flows[0].request is not None
    finally:
        reader.close()


def test_tap_finalized_on_normal_stop(exits, tmp_path):
    obj, path = _tap_logger(tmp_path)
    obj.cleanup()
    _assert_tap_finalized(path)
    assert exits == [EXIT_OK]


def test_tap_finalized_on_duration_stop(exits, tmp_path, monkeypatch):
    from friTap.legacy import session_manager as sm_mod
    monkeypatch.setattr(sm_mod.os, "_exit", lambda code: exits.append(code))
    obj, path = _tap_logger(tmp_path)
    for attr in ("full_capture", "mobile", "pcap_name", "live", "socket_trace",
                 "debug_output", "debug"):
        monkeypatch.setattr(type(obj), attr, None, raising=False)
    obj._session_manager = SessionManager(obj)
    obj._session_manager.TEARDOWN_WAIT_SECONDS = 0
    fritap_cli._stop_capture_after_duration(obj, 5, obj.logger)
    _assert_tap_finalized(path)
    assert exits and exits[0] == EXIT_OK


def test_tap_finalized_on_target_detach(exits, tmp_path):
    obj, path = _tap_logger(tmp_path)
    obj.on_detach("process-terminated")
    _assert_tap_finalized(path)
    assert exits == [EXIT_TARGET_DETACHED]


def test_tap_handler_releases_written_flows(exits, tmp_path):
    """Headless --tap must not keep completed (already written) flows in memory."""
    obj, path = _tap_logger(tmp_path)
    handler = obj._output_handlers[0]
    assert handler._collector.get_flows() == []
    obj.cleanup()
    _assert_tap_finalized(path)


def test_tap_handler_close_with_mocks_is_idempotent():
    calls = []
    flow = types.SimpleNamespace(flow_id="f1")
    collector = types.SimpleNamespace(
        subscribe=lambda cb: None, flush=lambda: calls.append("flush"),
        get_flows=lambda: [flow], on_data=None, on_ohttp=None,
        on_library_detected=None, on_session_event=None)
    writer = types.SimpleNamespace(
        open=lambda path, target="": calls.append("open"), path="x.tap", flow_count=1,
        written_flow_ids=set(), on_flow_event=None,
        write_flow=lambda f: calls.append(("write", f.flow_id)),
        close=lambda: calls.append("close"))
    handler = TapOutputHandler("x.tap", collector_factory=lambda: collector,
                               writer_factory=lambda: writer)
    handler.setup(types.SimpleNamespace(subscribe=lambda *a, **k: None))
    handler.close()
    handler.close()
    assert calls == ["open", "flush", ("write", "f1"), "close"]


def test_tap_handler_still_finalizes_when_flush_raises():
    closed = []

    def boom():
        raise RuntimeError("flush failed")

    collector = types.SimpleNamespace(subscribe=lambda cb: None, flush=boom,
                                      get_flows=lambda: [], on_data=None, on_ohttp=None,
                                      on_library_detected=None, on_session_event=None)
    writer = types.SimpleNamespace(open=lambda path, target="": None, path="x.tap",
                                   flow_count=0, written_flow_ids=set(),
                                   on_flow_event=None, write_flow=None,
                                   close=lambda: closed.append(True))
    handler = TapOutputHandler("x.tap", collector_factory=lambda: collector,
                               writer_factory=lambda: writer)
    handler.setup(types.SimpleNamespace(subscribe=lambda *a, **k: None))
    handler.close()
    assert closed == [True]


# --------------------------------------------------------------------------
# devices / apps
# --------------------------------------------------------------------------

def _device(dev_id="emulator-5554", name="Android Emulator", dev_type="usb",
            apps=(), processes=()):
    return types.SimpleNamespace(
        id=dev_id, name=name, type=dev_type,
        enumerate_applications=lambda: list(apps),
        enumerate_processes=lambda: list(processes))


def _fake_backend(monkeypatch, **kwargs):
    kwargs.setdefault("enumerate_processes", lambda device: device.enumerate_processes())
    fake = types.SimpleNamespace(**kwargs)
    monkeypatch.setattr(devices_cmd, "_backend", lambda: fake)
    return fake


def _run(command, tokens):
    out, err = io.StringIO(), io.StringIO()
    code = devices_cmd.run_listing_cli(command, tokens, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_devices_json(monkeypatch):
    _fake_backend(monkeypatch, enumerate_devices=lambda: [
        _device("local", "Local System", "local"), _device()])
    code, out, _ = _run("devices", ["--json"])
    assert code == EXIT_OK
    doc = json.loads(out)
    assert doc["schema"] == "fritap.devices/1"
    assert doc["devices"][1] == {"id": "emulator-5554", "name": "Android Emulator",
                                 "type": "usb"}


def test_devices_table(monkeypatch):
    _fake_backend(monkeypatch, enumerate_devices=lambda: [_device()])
    code, out, _ = _run("devices", [])
    assert code == EXIT_OK and "emulator-5554" in out and out.startswith("ID")


def test_apps_json_on_device(monkeypatch):
    apps = [types.SimpleNamespace(name="Zeta", identifier="com.z", pid=0),
            types.SimpleNamespace(name="Alpha", identifier="com.a", pid=42)]
    seen = {}

    def get_device(mobile=False, host=None):
        seen["id"] = mobile
        return _device(apps=apps)

    _fake_backend(monkeypatch, get_device=get_device)
    code, out, _ = _run("apps", ["-m", "emulator-5554", "--json"])
    doc = json.loads(out)
    assert code == EXIT_OK and seen["id"] == "emulator-5554"
    assert doc["schema"] == "fritap.apps/1" and doc["device"]["id"] == "emulator-5554"
    assert [a["identifier"] for a in doc["apps"]] == ["com.a", "com.z"]  # running first
    assert doc["apps"][0] == {"name": "Alpha", "identifier": "com.a", "pid": 42,
                              "kind": "app"}


def test_apps_running_filter_and_process_fallback(monkeypatch):
    procs = [types.SimpleNamespace(name="curl", pid=7)]
    _fake_backend(monkeypatch, get_device=lambda mobile=False, host=None: _device(
        "local", dev_type="local", processes=procs))
    code, out, _ = _run("apps", ["--running", "--json"])
    assert json.loads(out)["apps"] == [{"name": "curl", "identifier": None, "pid": 7,
                                        "kind": "process"}]


def test_apps_usb_and_host_selection(monkeypatch):
    seen = []
    _fake_backend(monkeypatch, get_device=lambda mobile=False, host=None:
                  seen.append((mobile, host)) or _device())
    _run("apps", ["-m", "--json"])
    _run("apps", ["-H", "10.0.0.1:27042", "--json"])
    _run("apps", ["--json"])
    assert seen == [(True, None), (False, "10.0.0.1:27042"), (False, None)]


def test_frida_error_is_structured_json(monkeypatch):
    class InvalidArgumentError(Exception):
        pass

    def get_device(mobile=False, host=None):
        raise InvalidArgumentError("device not found")

    _fake_backend(monkeypatch, get_device=get_device)
    code, out, _ = _run("apps", ["--device", "nope", "--json"])
    assert code == EXIT_RUNTIME_ERROR
    assert json.loads(out) == {"error": "device not found",
                               "error_type": "InvalidArgumentError",
                               "exit_code": EXIT_RUNTIME_ERROR}


def test_backend_error_reports_the_underlying_error_type(monkeypatch):
    from friTap.backends.base import BackendInvalidArgumentError

    class InvalidArgumentError(Exception):
        pass

    def get_device(mobile=False, host=None):
        raise BackendInvalidArgumentError(
            "device not found", original_exception=InvalidArgumentError("device not found"))

    _fake_backend(monkeypatch, get_device=get_device)
    code, out, _ = _run("apps", ["--device", "nope", "--json"])
    assert code == EXIT_RUNTIME_ERROR
    assert json.loads(out)["error_type"] == "InvalidArgumentError"


def test_usage_error_is_structured_json():
    code, out, _ = _run("apps", ["-H", "--json"])
    assert code == 2 and json.loads(out)["exit_code"] == 2


def test_error_without_json_goes_to_stderr(monkeypatch):
    def boom():
        raise RuntimeError("no frida")

    _fake_backend(monkeypatch, enumerate_devices=boom)
    code, out, err = _run("devices", [])
    assert code == EXIT_RUNTIME_ERROR and out == "" and "no frida" in err


# --------------------------------------------------------------------------
# dispatch guards
# --------------------------------------------------------------------------

@pytest.mark.parametrize("argv,expected", [
    (["fritap", "devices"], ("devices", [])),
    (["fritap", "devices", "--json"], ("devices", ["--json"])),
    (["fritap", "apps", "-m", "X", "--running", "--json"],
     ("apps", ["-m", "X", "--running", "--json"])),
    (["fritap", "apps", "-H", "h:1"], ("apps", ["-H", "h:1"])),
])
def test_dispatch_listing_subcommands(argv, expected):
    assert fritap_cli._dispatch_special_mode(argv) == expected


@pytest.mark.parametrize("argv", [
    ["fritap", "apps", "-k", "keys.log"],          # capture of a process named 'apps'
    ["fritap", "devices", "-v"],
    ["fritap", "apps", "--json", "out.json"],      # -j/--json with a path = capture
    ["fritap", "devices", "--running"],             # --running is apps-only
    ["fritap", "-m", "apps"],                       # option first = capture
    ["fritap", "-k", "k.log", "devices"],
])
def test_dispatch_falls_through_to_capture(argv):
    assert fritap_cli._dispatch_special_mode(argv) is None


def test_main_runs_listing(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["fritap", "devices", "--json"])
    seen = []
    monkeypatch.setattr(devices_cmd, "run_listing_cli",
                        lambda kind, tokens: seen.append((kind, tokens)) or 0)
    assert fritap_cli.main() == 0
    assert seen == [("devices", ["--json"])]


# --------------------------------------------------------------------------
# -j - : run outcome (error record + exit_code on stream_end)
# --------------------------------------------------------------------------

@pytest.fixture
def clean_stream_state():
    stdout_stream._reset_for_tests()
    yield
    stdout_stream._reset_for_tests()


def _close_with_exit_status(status):
    handler, _bus, buffer = _stream_handler()
    stdout_stream.register_exit_status_provider(lambda: status)
    handler.close()
    return _records(buffer)


def test_stream_end_carries_exit_code_on_success(clean_stream_state):
    records = _close_with_exit_status(EXIT_OK)
    assert [r["type"] for r in records] == ["stream_start", "stream_end"]
    assert records[-1]["exit_code"] == EXIT_OK


def test_stream_end_exit_code_is_null_without_provider(clean_stream_state):
    handler, _bus, buffer = _stream_handler()
    handler.close()
    assert _records(buffer)[-1] == {**_records(buffer)[-1], "exit_code": None}


def test_runtime_error_record_precedes_stream_end(clean_stream_state):
    stdout_stream.note_runtime_error("ExecutableNotFoundError", "no such file", hint="check path")
    records = _close_with_exit_status(EXIT_RUNTIME_ERROR)
    assert [r["type"] for r in records] == ["stream_start", "error", "stream_end"]
    error = records[1]
    assert error["schema"] == STREAM_SCHEMA
    assert error["error_type"] == "ExecutableNotFoundError"
    assert error["message"] == "no such file" and error["hint"] == "check path"
    assert error["exit_code"] == EXIT_RUNTIME_ERROR == records[2]["exit_code"]


def test_first_noted_error_wins(clean_stream_state):
    stdout_stream.note_runtime_error("First", "a")
    stdout_stream.note_runtime_error("Second", "b")
    error = _close_with_exit_status(EXIT_RUNTIME_ERROR)[1]
    assert error["error_type"] == "First" and "hint" not in error


def test_error_record_reflects_final_exit_code(clean_stream_state):
    # The target detached first (3); a later runtime error keeps exit code 3.
    stdout_stream.note_runtime_error("TransportError", "connection closed")
    records = _close_with_exit_status(EXIT_TARGET_DETACHED)
    assert records[1]["type"] == "error" and records[1]["exit_code"] == EXIT_TARGET_DETACHED


def test_runtime_exit_without_noted_cause_still_gets_error_record(clean_stream_state):
    records = _close_with_exit_status(EXIT_RUNTIME_ERROR)
    assert records[1]["type"] == "error" and records[1]["exit_code"] == EXIT_RUNTIME_ERROR
    assert records[1]["error_type"] == "RuntimeError" and "stderr" in records[1]["message"]


def test_noted_error_is_dropped_on_clean_exit(clean_stream_state):
    stdout_stream.note_runtime_error("Ignored", "x")
    assert [r["type"] for r in _close_with_exit_status(EXIT_OK)] == ["stream_start", "stream_end"]


def test_target_detach_without_error_has_no_error_record(clean_stream_state):
    records = _close_with_exit_status(EXIT_TARGET_DETACHED)
    assert [r["type"] for r in records] == ["stream_start", "stream_end"]
    assert records[-1]["exit_code"] == EXIT_TARGET_DETACHED


def test_cli_note_uses_underlying_error_type_and_hint(clean_stream_state):
    wrapped = RuntimeError("Internal error: unable to find application")
    wrapped.original_exception = type("InvalidArgumentError", (Exception,), {})()
    fritap_cli._note_stream_runtime_error(wrapped, ["first line", "  -> do this", "  -> then that"])
    error = _close_with_exit_status(EXIT_RUNTIME_ERROR)[1]
    assert error["error_type"] == "InvalidArgumentError"
    assert error["message"] == "Internal error: unable to find application"
    assert error["hint"] == "first line do this then that"


def test_cli_registers_logger_exit_status(clean_stream_state):
    fake_logger = types.SimpleNamespace(_exit_status=EXIT_OK)
    fritap_cli._register_stream_exit_status(fake_logger)
    fake_logger._exit_status = EXIT_RUNTIME_ERROR  # read lazily, at stream_end
    assert stdout_stream.final_exit_code() == EXIT_RUNTIME_ERROR


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX spawn path")
def test_spawn_failure_streams_error_record_and_exits_one():
    proc = subprocess.run(
        [sys.executable, "-m", "friTap.friTap", "-j", "-", "-s", "--", "/nonexistent/binary"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
    assert proc.returncode == EXIT_RUNTIME_ERROR, proc.stderr
    records = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [r["type"] for r in records] == ["stream_start", "error", "stream_end"]
    assert records[1]["exit_code"] == records[2]["exit_code"] == EXIT_RUNTIME_ERROR
    assert "/nonexistent/binary" in records[1]["message"]


# --------------------------------------------------------------------------
# -j file.jsonl : same internal-event filter as the stream
# --------------------------------------------------------------------------

def test_jsonl_file_skips_internal_events(tmp_path):
    from friTap.output.jsonl_handler import INTERNAL_EVENTS, JsonlOutputHandler
    path = tmp_path / "out.jsonl"
    handler, bus = JsonlOutputHandler(str(path)), EventBus()
    handler.setup(bus)
    bus.emit(HookBreadcrumbEvent(marker="x"))
    bus.emit(FlowEvent(flow=object(), flow_event_type="completed"))
    bus.emit(SessionEvent(event_type="started"))
    handler.close()
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert [line["event_type"] for line in lines] == ["started"]
    assert {"HookBreadcrumbEvent", "FlowEvent"} <= INTERNAL_EVENTS


# --------------------------------------------------------------------------
# apps: duplicate enumeration
# --------------------------------------------------------------------------

def test_apps_duplicates_keep_the_running_entry(monkeypatch):
    apps = [types.SimpleNamespace(name="Google", identifier="com.google.q", pid=0),
            types.SimpleNamespace(name="Google", identifier="com.google.q", pid=1442),
            types.SimpleNamespace(name="Maps", identifier="com.maps", pid=0),
            types.SimpleNamespace(name="Maps", identifier="com.maps", pid=0)]
    _fake_backend(monkeypatch, get_device=lambda mobile=False, host=None: _device(apps=apps))
    code, out, _ = _run("apps", ["--json"])
    assert code == EXIT_OK
    assert json.loads(out)["apps"] == [
        {"name": "Google", "identifier": "com.google.q", "pid": 1442, "kind": "app"},
        {"name": "Maps", "identifier": "com.maps", "pid": 0, "kind": "app"}]


def test_process_duplicates_are_deduped_by_pid():
    procs = [{"name": "curl", "identifier": None, "pid": 7, "kind": "process"},
             {"name": "curl", "identifier": None, "pid": 7, "kind": "process"},
             {"name": "curl", "identifier": None, "pid": 8, "kind": "process"}]
    assert [p["pid"] for p in devices_cmd.dedupe_entries(procs)] == [7, 8]


# --------------------------------------------------------------------------
# python -m friTap.friTap: subcommand return codes propagate
# --------------------------------------------------------------------------

@pytest.mark.filterwarnings("ignore:.*found in sys.modules:RuntimeWarning")
def test_module_main_propagates_subcommand_exit_code(monkeypatch):
    import runpy
    monkeypatch.setattr(sys, "argv", ["fritap", "apps", "--device", "nope", "--json"])
    monkeypatch.setattr(devices_cmd, "run_listing_cli", lambda kind, tokens: EXIT_RUNTIME_ERROR)
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("friTap.friTap", run_name="__main__")
    assert exc.value.code == EXIT_RUNTIME_ERROR


def test_module_apps_unknown_device_exits_one():
    proc = subprocess.run(
        [sys.executable, "-m", "friTap.friTap", "apps", "--device", "nope", "--json"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
    assert proc.returncode == EXIT_RUNTIME_ERROR, proc.stderr
    assert json.loads(proc.stdout)["exit_code"] == EXIT_RUNTIME_ERROR
