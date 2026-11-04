"""Unit tests for agent_api live capture: argv, status tracking, sessions, tools."""

from __future__ import annotations

import json
import sys
import textwrap
import time
from pathlib import Path

import pytest

from friTap.agent_api import ToolContext, ToolError, protocol_catalog, tools_capture
from friTap.agent_api.capture import manager as manager_module
from friTap.agent_api.capture.manager import SessionManager
from friTap.agent_api.capture.runner import (
    CaptureRequest,
    build_argv,
    session_keylog_files,
    validate_request,
)
from friTap.agent_api.capture.session import DEBUG_LOG_NAME, PHASES_NAME, CaptureSession
from friTap.agent_api.capture.status import StatusTracker
from friTap.agent_api.registry import Registry
from friTap.agent_api.services import capture as capture_service
from friTap.agent_api.services import discovery

CMD = ["fritap"]
SESSION = Path("/s")


def _req(**kw) -> CaptureRequest:
    return CaptureRequest(**{"target": "com.app", "session_dir": SESSION, **kw})


# ---------------------------------------------------------------------------
# build_argv goldens
# ---------------------------------------------------------------------------

def test_argv_defaults_auto_protocol_plaintext():
    assert build_argv(_req(), CMD) == [
        "fritap", "-s", "--protocol", "auto", "--tap", "/s/capture.tap",
        "--duration", "60", "--non-interactive", "-q", "-j", "-", "--", "com.app"]


def test_argv_explicit_protocols_keys_mode_and_attach():
    argv = build_argv(_req(protocols=("tls", "rc4"), capture="keys", spawn=False,
                           duration_s=5), CMD)
    assert argv == [
        "fritap", "--protocol", "tls,rc4", "--tap", "/s/capture.tap", "-k", "/s/keys.log",
        "--duration", "5", "--non-interactive", "-q", "-j", "-", "--", "com.app"]


def test_argv_full_mode_writes_keylog_and_pcap():
    argv = build_argv(_req(capture="full"), CMD)
    assert argv[argv.index("-k") + 1] == "/s/keys.log"
    assert argv[argv.index("-p") + 1] == "/s/plain.pcap"


def test_argv_follow_exec_false_and_spawn_args_after_separator():
    argv = build_argv(_req(target="/bin/curl", args=("-s", "https://x"), follow_exec=False), CMD)
    assert "--no-follow-exec" in argv
    assert argv[-4:] == ["--", "/bin/curl", "-s", "https://x"]


@pytest.mark.parametrize("device,host,expected", [
    (None, None, []), ("local", None, []), ("usb", None, ["-m"]),
    ("emulator-5556", None, ["-m", "emulator-5556"]),
    ("usb", "10.0.0.2:27042", ["-H", "10.0.0.2:27042"]),
])
def test_argv_device_selection(device, host, expected):
    argv = build_argv(_req(device=device, host=host, spawn=False), CMD)
    assert argv[1:argv.index("--protocol")] == expected


def test_argv_protocol_options_use_catalog_flags(monkeypatch):
    seen = {}

    def fake_flags(options):
        seen.update(options)
        return ["--pairip-safe", "--force-scan", "libfoo.so"]

    monkeypatch.setattr(protocol_catalog, "options_to_cli_flags", fake_flags)
    argv = build_argv(_req(protocol_options={"pairip_safe": True}), CMD)
    assert seen == {"pairip_safe": True}
    assert argv[-5:] == ["--pairip-safe", "--force-scan", "libfoo.so", "--", "com.app"]


def test_default_command_runs_fritap_module():
    assert build_argv(_req())[:3] == [sys.executable, "-m", "friTap.friTap"]


# ---------------------------------------------------------------------------
# validate_request
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kw,param", [
    ({"duration_s": 0}, "duration_s"), ({"duration_s": 3601}, "duration_s"),
    ({"capture": "all"}, "capture"), ({"target": "  "}, "target"),
    ({"args": ("-x",), "spawn": False}, "args"),
    # -m/-H values must never be parsed as further friTap options.
    ({"device": "--custom_script=/tmp/evil.js"}, "device"),
    ({"device": "-p/tmp/out.pcap"}, "device"),
    ({"host": "--custom_script=/tmp/evil.js"}, "host"),
])
def test_validate_request_rejects(kw, param):
    with pytest.raises(ToolError) as info:
        validate_request(_req(**kw))
    assert info.value.extra["param"] == param


def test_validate_request_delegates_options_to_catalog(monkeypatch):
    def reject(protocols, options):
        raise ToolError("nope", "unsupported_option", option="libraries")

    monkeypatch.setattr(protocol_catalog, "validate_protocol_options", reject)
    with pytest.raises(ToolError) as info:
        validate_request(_req(protocol_options={"libraries": ["x"]}))
    assert info.value.error_type == "unsupported_option"


# ---------------------------------------------------------------------------
# StatusTracker (records shaped like a real `-j -` run of curl on macOS)
# ---------------------------------------------------------------------------

RECORDED = [
    '{"schema":"fritap.events/1","type":"stream_start","timestamp":1.0,"key_material":true}',
    '{"schema":"fritap.events/1","type":"library","event":"LibraryDetectedEvent",'
    '"timestamp":1.1,"protocol":"tls","library":"libssl.3.dylib","module":"libssl.3.dylib","path":"/x"}',
    '{"schema":"fritap.events/1","type":"library","event":"LibraryDetectedEvent",'
    '"timestamp":1.2,"protocol":"tls","library":"libssl.3.dylib","module":"libssl.3.dylib","path":"/x"}',
    '{"schema":"fritap.events/1","type":"keylog","event":"KeylogEvent","timestamp":1.3,'
    '"protocol":"tls","key_data":"CLIENT_RANDOM aa SECRETSECRET","payload":null}',
    '{"schema":"fritap.events/1","type":"data","event":"DatalogEvent","timestamp":1.4,'
    '"protocol":"tls","data":"474554202f20485454502f312e310d0a","function":"SSL_write",'
    '"direction":"write"}',
    '{"schema":"fritap.events/1","type":"error","event":"ErrorEvent","timestamp":1.5,'
    '"protocol":"tls","error":"hook failed","severity":"warning"}',
    '{"schema":"fritap.events/1","type":"detach","event":"DetachEvent","timestamp":1.6,'
    '"protocol":"tls","reason":"process-terminated"}',
    '{"schema":"fritap.events/1","type":"stream_end","timestamp":1.7,"exit_code":3}',
]


def _feed(lines) -> StatusTracker:
    tracker = StatusTracker()
    for line in lines:
        tracker.feed(json.loads(line))
    return tracker


def test_tracker_counts_recorded_stream():
    tracker = _feed(RECORDED)
    snap = tracker.snapshot()
    tls = snap["protocols"]["tls"]
    assert snap["state"] == "stopped" and snap["exit_code"] == 3
    assert snap["hook_status"] == "attached" and tls["hook_status"] == "attached"
    assert tls["libraries"] == ["libssl.3.dylib"]
    assert (tls["keys"], tls["data_events"], tls["data_bytes"]) == (1, 1, 16)
    assert tls["errors"] == ["hook failed"]
    assert snap["detach_reason"] == "process-terminated"


def test_tracker_never_stores_payload_or_key_material():
    dumped = json.dumps(_feed(RECORDED).snapshot())
    assert "474554" not in dumped and "SECRET" not in dumped


def test_tracker_groups_by_record_protocol_and_keeps_untagged_visible():
    """Records are counted under the protocol the agent tagged them with (the
    agent resolves auto/all to the hook's record protocol, ABI >= 3); a record
    without a tag is grouped as "unknown" rather than silently merged into tls."""
    untagged = [line.replace('"protocol":"tls","data"', '"data"') for line in RECORDED]
    assert untagged != RECORDED
    snap = _feed(untagged).snapshot()
    assert "unknown" in snap["protocols"]
    tls = snap["protocols"]["tls"]
    assert (tls["libraries"], tls["keys"]) == (["libssl.3.dylib"], 1)


# Trimmed from a real `--protocol auto -j -` run of Homebrew curl on macOS: the
# speculative RC4 key hooks attach to libssl/libcrypto (they export RC4_set_key)
# next to the TLS hooks, but only TLS produces keys/plaintext/sessions.
RECORDED_AUTO = [
    '{"schema":"fritap.events/1","type":"stream_start","timestamp":1.0,"key_material":true}',
    '{"schema":"fritap.events/1","type":"console","event":"ConsoleEvent","timestamp":1.05,'
    '"protocol":"tls","message":"libssl.3.dylib found & will be hooked on MacOS!","level":"info"}',
    '{"schema":"fritap.events/1","type":"library","event":"LibraryDetectedEvent","timestamp":1.1,'
    '"protocol":"tls","library":"libssl.3.dylib","module":"","path":"/opt/homebrew/lib/libssl.3.dylib"}',
    '{"schema":"fritap.events/1","type":"library","event":"LibraryDetectedEvent","timestamp":1.11,'
    '"protocol":"rc4","library":"libssl.3.dylib","module":"","path":"/opt/homebrew/lib/libssl.3.dylib"}',
    '{"schema":"fritap.events/1","type":"library","event":"LibraryDetectedEvent","timestamp":1.12,'
    '"protocol":"rc4","library":"libcrypto.3.dylib","module":"","path":"/opt/homebrew/lib/libcrypto.3.dylib"}',
    '{"schema":"fritap.events/1","type":"library","event":"LibraryDetectedEvent","timestamp":1.13,'
    '"protocol":"tls","library":"libboringssl.dylib","module":"","path":"/usr/lib/libboringssl.dylib"}',
    '{"schema":"fritap.events/1","type":"platform_report","event":"PlatformReportEvent",'
    '"timestamp":1.14,"protocol":"tls","platform":"MacOS","target":"macos"}',
    '{"schema":"fritap.events/1","type":"session","event":"SessionEvent","timestamp":1.2,'
    '"protocol":"tls","session_id":"ab","event_type":"SESSION_STARTED","server_name":"example.com"}',
    '{"schema":"fritap.events/1","type":"keylog","event":"KeylogEvent","timestamp":1.3,'
    '"protocol":"tls","key_data":"CLIENT_HANDSHAKE_TRAFFIC_SECRET aa","redacted":true}',
    '{"schema":"fritap.events/1","type":"data","event":"DatalogEvent","timestamp":1.4,'
    '"protocol":"tls","data":"474554202f","function":"SSL_write","direction":"write"}',
    '{"schema":"fritap.events/1","type":"detach","event":"DetachEvent","timestamp":1.6,'
    '"protocol":"tls","reason":"process-terminated"}',
    '{"schema":"fritap.events/1","type":"stream_end","timestamp":1.7,"exit_code":3}',
]


def test_auto_capture_reports_tls_active_and_rc4_idle():
    snap = _feed(RECORDED_AUTO).snapshot()
    tls, rc4 = snap["protocols"]["tls"], snap["protocols"]["rc4"]
    assert tls["status"] == "active" and rc4["status"] == "idle"
    assert snap["protocols_in_use"] == ["tls"]
    assert snap["idle_hooks"] == {"rc4": ["libssl.3.dylib", "libcrypto.3.dylib"]}
    assert (rc4["keys"], rc4["data_events"], rc4["other_events"]) == (0, 0, 0)
    assert tls["other_events"] == 1  # the session record


def test_auto_capture_keeps_backward_compatible_hook_status():
    snap = _feed(RECORDED_AUTO).snapshot()
    assert snap["hook_status"] == "attached"
    assert {p["hook_status"] for p in snap["protocols"].values()} == {"attached"}


def test_idle_protocol_becomes_active_on_its_first_key():
    rc4_key = ('{"schema":"fritap.events/1","type":"keylog","event":"KeylogEvent","timestamp":1.5,'
               '"protocol":"rc4","payload":{"classifier":"rc4"},"redacted":true}')
    snap = _feed([*RECORDED_AUTO[:-1], rc4_key]).snapshot()
    assert snap["protocols"]["rc4"]["status"] == "active"
    assert snap["protocols_in_use"] == ["rc4", "tls"] and snap["idle_hooks"] == {}


@pytest.mark.parametrize("record_type", ["session", "ohttp", "message"])
def test_session_like_records_mark_a_protocol_active(record_type):
    line = (f'{{"schema":"fritap.events/1","type":"{record_type}","timestamp":1.2,'
            '"protocol":"signal"}')
    snap = _feed([RECORDED_AUTO[0], line]).snapshot()
    assert snap["protocols"]["signal"]["status"] == "active"
    assert snap["protocols_in_use"] == ["signal"]


def test_hooks_without_activity_are_idle_not_in_use():
    snap = _feed(RECORDED_AUTO[:7]).snapshot()  # libraries only, no traffic yet
    assert snap["protocols_in_use"] == []
    assert set(snap["idle_hooks"]) == {"tls", "rc4"}
    assert snap["hook_status"] == "attached"


def test_unhooked_protocol_status_is_failed_or_no_library():
    error = ('{"schema":"fritap.events/1","type":"error","event":"ErrorEvent","timestamp":1.5,'
             '"protocol":"ssh","error":"symbol not found"}')
    snap = _feed([RECORDED_AUTO[0], error]).snapshot()
    assert snap["protocols"]["ssh"]["status"] == "failed"
    assert snap["protocols_in_use"] == [] and snap["idle_hooks"] == {}


def test_console_and_platform_records_are_not_activity():
    snap = _feed(RECORDED_AUTO[:2] + RECORDED_AUTO[6:7]).snapshot()
    assert snap["protocols"] == {} and snap["protocols_in_use"] == []
    assert snap["hook_status"] == "no_library_seen"


def test_tracker_starting_then_running():
    tracker = StatusTracker()
    assert tracker.state == "starting"
    tracker.feed(json.loads(RECORDED[0]))
    assert tracker.state == "running"
    assert tracker.hook_status() == "no_library_seen"


def test_tracker_runtime_error_record_fails_run():
    tracker = _feed([
        RECORDED[0],
        '{"schema":"fritap.events/1","type":"error","timestamp":2.0,'
        '"error_type":"ExecutableNotFoundError","message":"no exe","hint":"check path","exit_code":1}',
        '{"schema":"fritap.events/1","type":"stream_end","timestamp":2.1,"exit_code":1}',
    ])
    snap = tracker.snapshot()
    assert snap["state"] == "failed" and snap["hook_status"] == "failed"
    assert snap["error"] == {"error_type": "ExecutableNotFoundError",
                             "message": "no exe", "hint": "check path"}


def test_tracker_usage_error():
    tracker = _feed(['{"type":"usage_error","error":"bad flag","exit_code":2}'])
    assert tracker.state == "failed" and tracker.exit_code == 2
    assert tracker.error["error_type"] == "usage_error"


def test_tracker_process_exit_without_stream_end():
    tracker = _feed(RECORDED[:2])
    tracker.process_exited(-9)
    assert tracker.state == "failed" and tracker.exit_code == -9
    assert tracker.error["error_type"] == "ProcessExited"


def test_tracker_process_exit_after_stream_end_keeps_state():
    tracker = _feed(RECORDED)
    tracker.process_exited(0)
    assert tracker.state == "stopped" and tracker.exit_code == 3


def test_tracker_ignores_non_dict_records():
    tracker = StatusTracker()
    tracker.feed(["not", "a", "record"])
    assert tracker.records == 0


# ---------------------------------------------------------------------------
# CaptureSession / SessionManager with a fake friTap child
# ---------------------------------------------------------------------------

FAKE_CHILD = textwrap.dedent('''
    import json, os, signal, sys, time
    argv = sys.argv[1:]
    target = argv[argv.index("--") + 1]
    tap = argv[argv.index("--tap") + 1]
    def emit(kind, **fields):
        print(json.dumps({"schema": "fritap.events/1", "type": kind, **fields}), flush=True)
    def stop(code):
        source = os.environ.get("FRITAP_FAKE_TAP_SOURCE")
        open(tap, "wb").write(open(source, "rb").read() if source else b"TAPDATA")
        emit("stream_end", exit_code=code)
        sys.exit(code)
    signal.signal(signal.SIGINT, lambda *a: stop(0))
    if os.environ.get("FRITAP_DEBUG_LOG"):
        open(os.environ["FRITAP_DEBUG_LOG"], "w").write("debug")
    emit("stream_start", key_material=False)
    if target == "fail":
        emit("error", error_type="ExecutableNotFoundError", message="no such app", exit_code=1)
        stop(1)
    emit("library", event="LibraryDetectedEvent", protocol="tls", library="libssl.so")
    emit("keylog", event="KeylogEvent", protocol="tls", label="CLIENT_RANDOM", redacted=True)
    emit("data", event="DatalogEvent", protocol="tls", data="00ff")
    if target == "short":
        stop(3)
    if target == "timed":
        stop(0)
    while True:
        time.sleep(0.05)
''')


@pytest.fixture
def fake_manager(tmp_path):
    script = tmp_path / "fake_fritap.py"
    script.write_text(FAKE_CHILD)
    manager = SessionManager(max_sessions=2, command=[sys.executable, str(script)])
    yield manager
    manager.stop_all(timeout=2)


@pytest.fixture
def ctx(tmp_path):
    return ToolContext(root=tmp_path / "root")


def _wait_for(session, predicate, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = session.status()
        if predicate(status):
            return status
        time.sleep(0.05)
    raise AssertionError(f"timeout; last status {session.status()}")


def test_session_start_status_phase_stop(fake_manager, ctx):
    session = fake_manager.start(_req(target="app"), ctx)
    assert session.session_dir == ctx.root / ".fritap-sessions" / session.session_id
    status = _wait_for(session, lambda s: s["protocols"].get("tls", {}).get("data_events"))
    assert status["state"] == "running" and status["hook_status"] == "attached"

    assert status["ended_by"] is None
    entry = session.mark_phase("login")
    assert entry["label"] == "login"
    assert entry["t_rel"] == pytest.approx(entry["t"] - session.started_at, abs=1e-3)
    assert entry["t_rel"] >= 0
    lines = (session.session_dir / PHASES_NAME).read_text().splitlines()
    assert json.loads(lines[0])["label"] == "login"

    final = session.stop(timeout=5)
    assert final["state"] == "stopped" and final["exit_code"] == 0
    assert final["ended_by"] == "stopped"
    assert final["tap_bytes"] == len(b"TAPDATA")
    assert final["phases"][0]["label"] == "login"
    assert not session.is_running()


def test_session_debug_log_goes_into_session_dir(fake_manager, ctx):
    session = fake_manager.start(_req(target="short"), ctx)
    _wait_for(session, lambda s: s["state"] in ("stopped", "failed"))
    assert (session.session_dir / DEBUG_LOG_NAME).read_text() == "debug"


def test_session_status_lists_split_keylog_files(fake_manager, ctx):
    session = fake_manager.start(_req(target="short", capture="keys"), ctx)
    _wait_for(session, lambda s: s["state"] in ("stopped", "failed"))
    assert session.status()["keylog_files"] == []
    (session.session_dir / "keys.tls.log").write_text("CLIENT_RANDOM a b\n")
    status = session.status()
    assert status["keylog"].endswith("keys.log")
    assert status["keylog_files"] == [str(session.session_dir / "keys.tls.log")]


def test_session_keylog_files_base_first(tmp_path):
    for name in ("keys.ssh.log", "keys.log", "keys.tls.log", "other.log", "keys.bogus.log"):
        (tmp_path / name).write_text("x")
    assert [p.name for p in session_keylog_files(tmp_path)] == [
        "keys.log", "keys.ssh.log", "keys.tls.log"]


def test_session_short_lived_target_stops_itself(fake_manager, ctx):
    session = fake_manager.start(_req(target="short"), ctx)
    status = _wait_for(session, lambda s: s["state"] in ("stopped", "failed"))
    assert status["state"] == "stopped" and status["exit_code"] == 3
    assert status["ended_by"] == "target_exited"


def test_session_duration_elapsed_ends_by_duration(fake_manager, ctx):
    session = fake_manager.start(_req(target="timed"), ctx)
    status = _wait_for(session, lambda s: s["state"] in ("stopped", "failed"))
    assert (status["state"], status["exit_code"], status["ended_by"]) == ("stopped", 0, "duration")
    assert session.stop(timeout=2)["ended_by"] == "duration"  # stop after the end is a no-op


def test_mark_phase_t_rel_uses_session_clock(tmp_path):
    ticks = iter([100.0, 102.5])
    session = CaptureSession("s1", _req(target="app", session_dir=tmp_path), [],
                             clock=lambda: next(ticks))
    session.started_at = next(ticks)
    entry = session.mark_phase("login")
    assert (entry["t"], entry["t_rel"]) == (102.5, 2.5)


@pytest.mark.parametrize("lines,stop_requested,expected", [
    ([], False, None),
    (['{"type":"stream_start"}'], False, None),
    (['{"type":"stream_end","exit_code":3}'], False, "target_exited"),
    (['{"type":"stream_end","exit_code":0}'], False, "duration"),
    (['{"type":"stream_end","exit_code":0}'], True, "stopped"),
    (['{"type":"stream_end","exit_code":1}'], True, "error"),
    (['{"type":"usage_error","error":"x","exit_code":2}'], False, "error"),
    (['{"type":"detach","reason":"process-terminated"}', '{"type":"stream_end"}'],
     False, "target_exited"),
])
def test_tracker_ended_by(lines, stop_requested, expected):
    assert _feed(lines).ended_by(stop_requested) == expected


def test_session_failure_reports_error_and_stderr_tail(fake_manager, ctx):
    session = fake_manager.start(_req(target="fail"), ctx)
    status = _wait_for(session, lambda s: s["state"] in ("stopped", "failed"))
    assert status["state"] == "failed"
    assert status["error"]["error_type"] == "ExecutableNotFoundError"
    assert "stderr_tail" in status


def test_capture_forbidden_without_allow_capture(fake_manager, tmp_path):
    with pytest.raises(ToolError) as info:
        fake_manager.start(_req(), ToolContext(root=tmp_path, allow_capture=False))
    assert info.value.error_type == "forbidden"
    assert "--allow-capture" in info.value.hint


def test_capture_target_allow_list(fake_manager, tmp_path):
    ctx = ToolContext(root=tmp_path, allow_targets=("com.android.*",))
    with pytest.raises(ToolError) as info:
        fake_manager.start(_req(target="com.evil"), ctx)
    assert info.value.error_type == "forbidden"
    assert fake_manager.start(_req(target="com.android.x"), ctx).session_id


def test_max_sessions_limit(fake_manager, ctx):
    fake_manager.start(_req(target="a"), ctx)
    fake_manager.start(_req(target="b"), ctx)
    with pytest.raises(ToolError) as info:
        fake_manager.start(_req(target="c"), ctx)
    assert info.value.error_type == "limit_reached"


def test_tap_path_for_states(fake_manager, ctx, monkeypatch):
    monkeypatch.setattr(manager_module, "default_manager", fake_manager)
    with pytest.raises(ToolError) as info:
        manager_module.tap_path_for("nope")
    assert info.value.error_type == "not_found"

    session = fake_manager.start(_req(target="app"), ctx)
    with pytest.raises(ToolError) as info:
        manager_module.tap_path_for(session.session_id)
    assert info.value.error_type == "capture_running"
    assert info.value.hint == "call stop_capture first"

    _wait_for(session, lambda s: s["state"] == "running")  # SIGINT handler installed
    session.stop(timeout=5)
    assert manager_module.tap_path_for(session.session_id) == session.request.tap_path


def test_tap_path_for_missing_tap(fake_manager, ctx):
    session = fake_manager.start(_req(target="fail"), ctx)
    _wait_for(session, lambda s: s["state"] == "failed")
    session.request.tap_path.unlink()
    with pytest.raises(ToolError) as info:
        fake_manager.tap_path_for(session.session_id)
    assert info.value.error_type == "not_found"


# ---------------------------------------------------------------------------
# Tools (registry round trip with the fake child)
# ---------------------------------------------------------------------------

@pytest.fixture
def tool_registry(fake_manager, monkeypatch):
    monkeypatch.setattr(capture_service, "default_manager", fake_manager)
    registry = Registry()
    tools_capture.register_all(registry)
    return registry


def test_tool_names_and_result_schemas(tool_registry):
    assert tool_registry.names() == [
        "capture_status", "list_apps", "list_devices", "list_sessions",
        "mark_phase", "start_capture", "stop_capture"]
    assert all(spec.result_schema for spec in tool_registry.specs())
    protocols = tool_registry.get("start_capture").params_schema["properties"]["protocols"]
    assert "tls" in protocols["items"]["enum"]
    assert tool_registry.get("start_capture").mutating


def test_tools_capture_round_trip(tool_registry, ctx):
    started = tool_registry.call("start_capture", {"target": "app", "duration_s": 30},
                                 context=ctx)
    sid = started["session_id"]
    assert started["schema"] == "fritap.capture_start/1"
    assert started["argv"][0] == "fritap" and "--duration" in started["argv"]

    phase = tool_registry.call("mark_phase", {"session_id": sid, "label": "p1"}, context=ctx)
    assert phase["label"] == "p1" and isinstance(phase["t_rel"], float)
    status = tool_registry.call("capture_status", {"session_id": sid}, context=ctx)
    assert status["session_id"] == sid
    _wait_for(capture_service.default_manager.get(sid), lambda s: s["state"] == "running")

    final = tool_registry.call("stop_capture", {"session_id": sid}, context=ctx)
    assert final["state"] == "stopped"
    listed = tool_registry.call("list_sessions", {}, context=ctx)["sessions"]
    assert [row["session_id"] for row in listed] == [sid]


def test_tools_reject_unknown_protocol(tool_registry, ctx):
    with pytest.raises(ToolError) as info:
        tool_registry.call("start_capture", {"target": "app", "protocols": ["ipsecx"]},
                           context=ctx)
    assert info.value.error_type == "bad_param"


def test_tools_unknown_session(tool_registry, ctx):
    with pytest.raises(ToolError) as info:
        tool_registry.call("capture_status", {"session_id": "s0"}, context=ctx)
    assert info.value.error_type == "not_found"


# ---------------------------------------------------------------------------
# protocol_options file paths are sandboxed under ctx.root
# ---------------------------------------------------------------------------

def _capture_ctx(root: Path) -> ToolContext:
    root.mkdir(parents=True, exist_ok=True)
    return ToolContext(root=root)


@pytest.mark.parametrize("option", ["offsets", "patterns"])
def test_option_path_inside_root_is_resolved_absolute(fake_manager, tmp_path, option):
    ctx = _capture_ctx(tmp_path / "root")
    (ctx.root / "hooks.json").write_text("{}")
    session = fake_manager.start(_req(target="short", protocol_options={option: "hooks.json"}),
                                 ctx)
    resolved = str((ctx.root / "hooks.json").resolve())
    assert session.request.protocol_options[option] == resolved
    assert session.argv[session.argv.index(f"--{option}") + 1] == resolved


@pytest.mark.parametrize("value", ["../outside.json", "/etc/hosts"])
def test_option_path_outside_root_is_forbidden(fake_manager, tmp_path, value):
    ctx = _capture_ctx(tmp_path / "root")
    (tmp_path / "outside.json").write_text("{}")
    with pytest.raises(ToolError) as info:
        fake_manager.start(_req(protocol_options={"offsets": value}), ctx)
    assert info.value.error_type == "forbidden"
    assert info.value.extra == {"option": "offsets", "param": "options.offsets"}
    assert fake_manager.sessions() == []


def test_option_path_symlink_escape_is_forbidden(fake_manager, tmp_path):
    ctx = _capture_ctx(tmp_path / "root")
    (tmp_path / "secret.json").write_text("{}")
    (ctx.root / "link.json").symlink_to(tmp_path / "secret.json")
    with pytest.raises(ToolError) as info:
        fake_manager.start(_req(protocol_options={"patterns": "link.json"}), ctx)
    assert info.value.error_type == "forbidden"


def test_option_path_must_exist(fake_manager, tmp_path):
    ctx = _capture_ctx(tmp_path / "root")
    with pytest.raises(ToolError) as info:
        fake_manager.start(_req(protocol_options={"offsets": "missing.json"}), ctx)
    assert info.value.error_type == "not_found"


def test_option_inline_json_passes_verbatim(fake_manager, tmp_path):
    ctx = _capture_ctx(tmp_path / "root")
    inline = '{"openssl": {"SSL_read": "0x10"}}'
    session = fake_manager.start(_req(target="short", protocol_options={"offsets": inline}),
                                 ctx)
    assert session.request.protocol_options["offsets"] == inline


def test_inline_json_patterns_rejected(fake_manager, tmp_path):
    """--patterns only loads files (PatternLoader): inline JSON is a bad_param, never passed."""
    ctx = _capture_ctx(tmp_path / "root")
    with pytest.raises(ToolError) as info:
        fake_manager.start(_req(protocol_options={"patterns": '{"openssl": {}}'}), ctx)
    assert info.value.error_type == "bad_param"
    assert info.value.extra["param"] == "options.patterns"
    assert "file" in info.value.hint


def test_inline_value_only_for_path_or_json_options():
    inline = '{"a": 1}'
    assert protocol_catalog.is_inline_value("offsets", inline)
    assert not protocol_catalog.is_inline_value("patterns", inline)
    deep = "[" * 200 + "]" * 200
    assert not protocol_catalog.is_inline_json(deep)  # untrusted JSON depth guard


def test_start_capture_tool_rejects_option_path_escape(tool_registry, tmp_path):
    ctx = _capture_ctx(tmp_path / "root")
    with pytest.raises(ToolError) as info:
        tool_registry.call("start_capture", {"target": "app",
                                             "protocol_options": {"patterns": "../../x.json"}},
                           context=ctx)
    assert info.value.error_type == "forbidden"


@pytest.mark.parametrize("value,expected", [
    ('{"a": 1}', True), ("[1]", True), ("  {}  ", True),
    ("{not json", False), ("hooks.json", False), ("", False),
])
def test_is_inline_json(value, expected):
    assert protocol_catalog.is_inline_json(value) is expected


def test_path_option_names():
    assert protocol_catalog.path_option_names() == ("offsets", "patterns")


# ---------------------------------------------------------------------------
# session_id flow: start_capture -> stop_capture -> get_digest(session_id)
# ---------------------------------------------------------------------------

def _write_sample_tap(path: Path) -> Path:
    from friTap.flow.models import Flow, FlowChunk, FlowState
    from friTap.flow.tap_writer import TapWriter
    from friTap.parsers.base import ParseResult

    flow = Flow(flow_id="f-1", connection_id="f-1", src_addr="10.0.0.1", src_port=50000,
                dst_addr="93.184.216.34", dst_port=443, state=FlowState.COMPLETE,
                started=1_700_000_000.0)
    flow.chunks.append(FlowChunk(data=b"GET / HTTP/1.1\r\n\r\n", direction="write",
                                 timestamp=1_700_000_000.0))
    flow.request = ParseResult(protocol="HTTP/1.1", method="GET", url="/", host="example.com",
                               headers={"host": "example.com"}, is_complete=True)
    writer = TapWriter()
    writer.open(str(path), target="test")
    writer.write_flow(flow)
    writer.close()
    return path


def test_session_id_flows_from_capture_to_read_tools(fake_manager, ctx, tmp_path, monkeypatch):
    from friTap.agent_api import tools_read
    from friTap.agent_api.registry import registry as process_registry

    # Read tools resolve session_id through manager.tap_path_for -> the module's
    # default_manager; capture tools use capture_service.default_manager. In a
    # server process both are the same process-global SessionManager.
    assert capture_service.default_manager is manager_module.default_manager
    assert {"start_capture", "get_digest"} <= set(process_registry.names())
    monkeypatch.setattr(capture_service, "default_manager", fake_manager)
    monkeypatch.setattr(manager_module, "default_manager", fake_manager)
    monkeypatch.setenv("FRITAP_FAKE_TAP_SOURCE", str(_write_sample_tap(tmp_path / "sample.tap")))
    registry = Registry()
    tools_capture.register_all(registry)
    tools_read.register_all(registry)

    sid = registry.call("start_capture", {"target": "app"}, context=ctx)["session_id"]
    with pytest.raises(ToolError) as info:
        registry.call("get_digest", {"session_id": sid}, context=ctx)
    assert info.value.error_type == "capture_running"

    _wait_for(fake_manager.get(sid), lambda s: s["state"] == "running")
    assert registry.call("stop_capture", {"session_id": sid}, context=ctx)["state"] == "stopped"
    digest = registry.call("get_digest", {"session_id": sid}, context=ctx)
    assert digest["schema"].startswith("fritap.digest/")
    assert digest["source"]["file"] == fake_manager.get(sid).request.tap_path.name
    assert digest["source"]["flows_total"] == 1


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device,expected", [
    (None, False), ("local", False), ("usb", True), ("emulator-5556", "emulator-5556")])
def test_device_selector_mapping(device, expected):
    from friTap.agent_api.capture.runner import device_selector
    assert device_selector(device) == expected


def test_list_apps_wraps_listing_functions(monkeypatch):
    from friTap.commands import devices as listing

    calls = {}

    class Dev:
        id, name, type = "emulator-5556", "Emu", "usb"

    def resolve(args):
        calls["args"] = args
        return Dev()

    apps = [{"name": f"a{i}", "identifier": f"com.a{i}", "pid": i, "kind": "app"}
            for i in range(3)]
    monkeypatch.setattr(listing, "resolve_device", resolve)
    monkeypatch.setattr(listing, "list_apps", lambda dev, running_only=False: apps)
    doc = discovery.list_apps("emulator-5556", running=True, limit=2)
    assert calls["args"].device == "emulator-5556" and calls["args"].running_only
    assert doc["device"]["id"] == "emulator-5556"
    assert [a["identifier"] for a in doc["apps"]] == ["com.a0", "com.a1"]
    assert doc["total"] == 3 and doc["next_cursor"] == "2"


def test_list_devices(monkeypatch):
    from friTap.commands import devices as listing

    monkeypatch.setattr(listing, "list_devices",
                        lambda: [{"id": "local", "name": "Local", "type": "local"}])
    assert discovery.list_devices() == {
        "schema": "fritap.devices/1",
        "devices": [{"id": "local", "name": "Local", "type": "local"}]}


# ---------------------------------------------------------------------------
# Python API builder additions
# ---------------------------------------------------------------------------

def test_api_tap_builder():
    from friTap.api import FriTap

    assert FriTap("app").tap("out.tap").build_config().output.tap_output == "out.tap"


def test_api_protocols_builder():
    from friTap.api import FriTap

    config = FriTap("app").protocols(["tls", "rc4", "tls"]).build_config()
    assert config.protocols == ["tls", "rc4"] and config.protocol == "tls"


def test_api_protocol_after_protocols_replaces_selection():
    from friTap.api import FriTap

    config = FriTap("app").protocols(["tls", "rc4"]).protocol("ssh").build_config()
    assert config.protocols == ["ssh"] and config.protocol == "ssh"


def test_api_protocols_empty_keeps_default():
    from friTap.api import FriTap

    config = FriTap("app").protocols([]).build_config()
    assert config.protocols == ["tls"]
