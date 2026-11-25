"""Unit tests for start_capture with backend=ebpf: defaults, validation, argv, session round trip."""

from __future__ import annotations

import sys
import textwrap
import time
from pathlib import Path

import pytest

from friTap.agent_api import ToolContext, ToolError, tools_capture
from friTap.agent_api.capture.manager import SessionManager
from friTap.agent_api.capture.runner import CaptureRequest, build_argv, validate_request
from friTap.agent_api.registry import Registry
from friTap.agent_api.services import capture as capture_service

CMD = ["fritap"]
SESSION = Path("/s")
PID = "4242"


def _ebpf_req(**kw) -> CaptureRequest:
    fields = {"target": PID, "session_dir": SESSION, "backend": "ebpf", "spawn": False,
              "protocols": ("tls",), **kw}
    return CaptureRequest(**fields)


# ---------------------------------------------------------------------------
# request_from_params defaults
# ---------------------------------------------------------------------------

def test_request_from_params_ebpf_defaults_to_attach_and_tls():
    req = capture_service.request_from_params({"target": PID, "backend": "ebpf"})
    assert (req.backend, req.spawn, req.protocols) == ("ebpf", False, ("tls",))


def test_request_from_params_ebpf_keeps_explicit_values_for_validation():
    req = capture_service.request_from_params(
        {"target": PID, "backend": "ebpf", "spawn": True, "protocols": ["ssh"]})
    assert req.spawn is True and req.protocols == ("ssh",)


def test_request_from_params_frida_defaults_unchanged():
    req = capture_service.request_from_params({"target": "com.app"})
    assert (req.backend, req.spawn, req.protocols) == ("frida", True, ())


# ---------------------------------------------------------------------------
# build_argv
# ---------------------------------------------------------------------------

def test_argv_ebpf_attaches_with_file_outputs_only():
    assert build_argv(_ebpf_req(duration_s=5), CMD) == [
        "fritap", "--backend", "ebpf", "--protocol", "tls", "--tap", "/s/capture.tap",
        "--duration", "5", "--non-interactive", "-q", "--", PID]


def test_argv_ebpf_never_streams_stdout_or_spawns():
    argv = build_argv(_ebpf_req(protocols=()), CMD)
    assert "-j" not in argv and "-s" not in argv
    assert argv[argv.index("--protocol") + 1] == "tls"


def test_argv_ebpf_android_device_selector():
    argv = build_argv(_ebpf_req(device="emulator-5556"), CMD)
    assert argv[1:5] == ["--backend", "ebpf", "-m", "emulator-5556"]


def test_argv_frida_unchanged_by_backend_field():
    req = CaptureRequest(target="com.app", session_dir=SESSION, backend="frida")
    assert build_argv(req, CMD) == [
        "fritap", "-s", "--protocol", "auto", "--tap", "/s/capture.tap",
        "--duration", "60", "--non-interactive", "-q", "-j", "-", "--", "com.app"]


# ---------------------------------------------------------------------------
# validate_request
# ---------------------------------------------------------------------------

def test_validate_request_accepts_ebpf_attach():
    validate_request(_ebpf_req())


@pytest.mark.parametrize("kw,param", [
    ({"spawn": True}, "spawn"),
    ({"protocols": ("ssh",)}, "protocols"),
    ({"protocols": ("tls", "rc4")}, "protocols"),
    ({"target": "com.app"}, "target"),
    ({"target": "0"}, "target"),
    ({"capture": "keys"}, "capture"),
    ({"capture": "full"}, "capture"),
    ({"host": "10.0.0.2:27042"}, "host"),
    ({"follow_exec": True}, "follow_exec"),
    ({"anti_root": True}, "anti_root"),
    ({"protocol_options": {"pairip_safe": True}}, "protocol_options"),
])
def test_validate_request_rejects_unsupported_ebpf(kw, param):
    with pytest.raises(ToolError) as info:
        validate_request(_ebpf_req(**kw))
    assert info.value.error_type == "bad_param"
    assert info.value.extra["param"] == param
    assert info.value.hint


def test_validate_request_spawn_error_is_actionable():
    with pytest.raises(ToolError) as info:
        validate_request(_ebpf_req(spawn=True))
    assert "attach" in str(info.value) and "spawn=false" in info.value.hint


def test_validate_request_rejects_unknown_backend():
    req = CaptureRequest(target="com.app", session_dir=SESSION, backend="gdb")
    with pytest.raises(ToolError) as info:
        validate_request(req)
    assert info.value.extra["param"] == "backend"


# ---------------------------------------------------------------------------
# Tool round trip with a fake eBPF child (no stdout stream, writes the .tap on SIGINT)
# ---------------------------------------------------------------------------

FAKE_EBPF_CHILD = textwrap.dedent('''
    import signal, sys, time
    argv = sys.argv[1:]
    assert "-j" not in argv and "-s" not in argv, argv
    tap = argv[argv.index("--tap") + 1]
    def stop(*_):
        open(tap, "wb").write(b"TAPDATA")
        sys.exit(0)
    signal.signal(signal.SIGINT, stop)
    print("eBPF capture running", file=sys.stderr, flush=True)
    while True:
        time.sleep(0.05)
''')


def _wait_for_banner(stderr_log: Path, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if stderr_log.exists() and b"running" in stderr_log.read_bytes():
            return
        time.sleep(0.05)
    raise AssertionError("fake eBPF child never started")


@pytest.fixture
def ebpf_registry(tmp_path, monkeypatch):
    script = tmp_path / "fake_ebpf.py"
    script.write_text(FAKE_EBPF_CHILD)
    manager = SessionManager(max_sessions=2, command=[sys.executable, str(script)])
    monkeypatch.setattr(capture_service, "default_manager", manager)
    registry = Registry()
    tools_capture.register_all(registry)
    yield registry
    manager.stop_all(timeout=2)


def test_start_capture_tool_accepts_backend_and_reports_it(ebpf_registry, tmp_path):
    ctx = ToolContext(root=tmp_path / "root")
    started = ebpf_registry.call("start_capture", {"target": PID, "backend": "ebpf"}, context=ctx)
    assert started["requested_backend"] == "ebpf"
    assert started["argv"][:3] == ["fritap", "--backend", "ebpf"]
    assert "-j" not in started["argv"] and "-s" not in started["argv"]

    sid = started["session_id"]
    status = ebpf_registry.call("capture_status", {"session_id": sid}, context=ctx)
    assert status["requested_backend"] == "ebpf"
    assert status["records"] == 0  # no JSONL stream under eBPF
    _wait_for_banner(Path(status["stderr_log"]))  # SIGINT handler installed

    final = ebpf_registry.call("stop_capture", {"session_id": sid}, context=ctx)
    assert final["state"] == "stopped" and final["ended_by"] == "stopped"
    assert final["tap_bytes"] == len(b"TAPDATA")


def test_start_capture_tool_rejects_ebpf_spawn(ebpf_registry, tmp_path):
    ctx = ToolContext(root=tmp_path / "root")
    with pytest.raises(ToolError) as info:
        ebpf_registry.call("start_capture", {"target": PID, "backend": "ebpf", "spawn": True},
                           context=ctx)
    assert info.value.extra["param"] == "spawn"


def test_start_capture_tool_rejects_ebpf_non_tls(ebpf_registry, tmp_path):
    ctx = ToolContext(root=tmp_path / "root")
    with pytest.raises(ToolError) as info:
        ebpf_registry.call("start_capture",
                           {"target": PID, "backend": "ebpf", "protocols": ["ssh"]}, context=ctx)
    assert info.value.extra["param"] == "protocols"


def test_start_capture_schema_has_no_spawn_default():
    """A schema default would fill spawn=true and make every eBPF call fail."""
    registry = Registry()
    tools_capture.register_all(registry)
    props = registry.get("start_capture").params_schema["properties"]
    assert "default" not in props["spawn"]
    assert props["backend"]["enum"] == ["frida", "ebpf"]
