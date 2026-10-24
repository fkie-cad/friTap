"""Tests for friTap's automatic Wine -> GDB key-extraction routing in
``SSL_Logger`` (detection, spawn/attach argument mapping, and the
plaintext-unsupported notice)."""

import logging
import threading
import types

from friTap.legacy.ssl_logger_core import SSL_Logger


def _make_logger(*, spawn=True, target="wine app.exe", target_argv=None,
                 keylog=None, pcap=None, live=False, socket_trace=None,
                 payload_modification=False, device_id=None, mobile=False,
                 host=None, pid=None, wine_mode="auto", backend="frida",
                 backend_explicit=False):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.wine.routing")
    obj.logger.setLevel(logging.DEBUG)
    obj.pid = pid
    obj._done_event = threading.Event()
    obj._config = types.SimpleNamespace(
        target=target,
        target_argv=target_argv,
        backend=backend,
        backend_explicit=backend_explicit,
        device=types.SimpleNamespace(
            spawn=spawn, device_id=device_id, mobile=mobile, host=host,
        ),
        output=types.SimpleNamespace(
            keylog=keylog, pcap=pcap, live=live, socket_trace=socket_trace,
            verbose=False,
        ),
        hooking=types.SimpleNamespace(
            payload_modification=payload_modification, wine_mode=wine_mode,
        ),
    )
    return obj


# --- detection ------------------------------------------------------------

def test_detects_wine_spawn_on_linux(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"])
    assert obj._should_use_wine_gdb() is True


def test_non_wine_target_not_routed(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["/usr/bin/notepad"], target="/usr/bin/notepad")
    assert obj._should_use_wine_gdb() is False


def test_not_routed_off_linux(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Windows")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"])
    assert obj._should_use_wine_gdb() is False


def test_not_routed_for_remote_device(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], device_id="deadbeef")
    assert obj._should_use_wine_gdb() is False


def test_attach_pid_detected_via_proc(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=False, target="4321", target_argv=None)
    monkeypatch.setattr(obj, "_pid_is_wine", lambda pid: int(pid) == 4321)
    assert obj._should_use_wine_gdb() is True


# --- --wine precedence ----------------------------------------------------

def test_wine_off_disables_route(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], wine_mode="off")
    assert obj._should_use_wine_gdb() is False


def test_wine_on_forces_route_even_for_nonwine(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["/usr/bin/foo"], target="/usr/bin/foo",
                       wine_mode="on")
    assert obj._should_use_wine_gdb() is True


def test_explicit_backend_frida_suppresses_auto_route(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"],
                       backend="frida", backend_explicit=True)
    assert obj._should_use_wine_gdb() is False


def test_wine_on_overrides_explicit_backend_frida(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"],
                       backend="frida", backend_explicit=True, wine_mode="on")
    assert obj._should_use_wine_gdb() is True


# --- argument mapping / run ------------------------------------------------

def _patch_runner(monkeypatch):
    """Patch both extraction entry points; spawn uses launch_and_attach, attach
    uses run_wine_key_extraction. Returns (spawn_calls, attach_calls)."""
    spawn_calls, attach_calls = {}, {}

    import agent_gdb.wine.wine_key_extract as wke
    monkeypatch.setattr(wke, "launch_and_attach", lambda **kw: spawn_calls.update(kw) or 0)
    monkeypatch.setattr(wke, "run_wine_key_extraction", lambda **kw: attach_calls.update(kw) or 0)
    return spawn_calls, attach_calls


def test_run_maps_spawn_arguments(monkeypatch):
    spawn_calls, _ = _patch_runner(monkeypatch)
    obj = _make_logger(spawn=True, target_argv=["wine", "/p/app.exe", "--foo"],
                       keylog="k.log")
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    # Spawn launches Wine normally and attaches (robust on wow64).
    assert spawn_calls["wine_cmd"] == "wine"
    assert spawn_calls["program"] == "/p/app.exe"
    assert spawn_calls["program_args"] == ["--foo"]
    assert spawn_calls["keylog"] == "k.log"
    assert obj._done_event.is_set()


def test_run_maps_attach_pid(monkeypatch):
    _, attach_calls = _patch_runner(monkeypatch)
    obj = _make_logger(spawn=False, target="4321", keylog="k.log")
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert attach_calls["attach"] == "4321"


def test_plaintext_request_warns(monkeypatch, caplog):
    _patch_runner(monkeypatch)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"],
                       keylog="k.log", pcap="out.pcap")
    with caplog.at_level(logging.WARNING):
        obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert "not currently supported for Wine" in caplog.text


def test_missing_keylog_defaults_with_warning(monkeypatch, caplog):
    spawn_calls, _ = _patch_runner(monkeypatch)
    obj = _make_logger(spawn=True, target_argv=["wine", "app.exe"], keylog=None)
    with caplog.at_level(logging.WARNING):
        obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert spawn_calls["keylog"].endswith("wine_sslkeys.log")
    assert "No keylog file given" in caplog.text
