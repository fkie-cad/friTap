"""Embedded sessions (API/TUI), the -pm watcher, and the TUI's main-session detach.

1. A target death in an embedded session (``FriTap.start`` / the TUI) used to
   reach ``cleanup()``'s ``os._exit`` — killing the whole host program — unless
   ``_tui_mode`` happened to be set. ``set_embedded()`` makes the session
   finalize its outputs and mark itself stopped without exiting.
2. ``-pm`` started a new watchdog ``Observer`` on every ``instrument()``
   (children included), leaking the earlier ones, and its ``ModWatcher``
   referenced ``self._backend`` / ``self.script`` it did not have.
3. The TUI unloads the main script (finish_fritap) before cleanup(), so
   ``detach_with_timeout`` took the destroyed script for a dead target and
   never ``session.detach()``-ed the main session.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

import friTap.legacy.ssl_logger_core as core
from friTap.api import FriTapSession
from friTap.legacy.ssl_logger_core import SSL_Logger, _PayloadModWatcher

REPORT = {"version": 1, "repeat": False, "total_ms": 3,
          "steps": [{"name": "detachAll", "ok": True, "ms": 1}],
          "logs": [], "dropped_logs": 0}


class _FakeScript:
    def __init__(self):
        self.is_destroyed = False
        self.exports_sync = types.SimpleNamespace(graceful_detach=lambda: REPORT)


@pytest.fixture
def exits(monkeypatch):
    calls = []
    monkeypatch.setattr(core.os, "_exit", calls.append)
    return calls


def _make_logger(tmp_path, **kwargs):
    obj = SSL_Logger("test_app", json_output=str(tmp_path / "out.json"), **kwargs)
    obj.logger = logging.getLogger("test.embedded_lifecycle")
    obj._backend = MagicMock()
    obj.script = _FakeScript()
    obj.process = None
    obj._start_consumer_thread()
    return obj


def _unload_destroys_script(obj):
    def unload(script):
        script.is_destroyed = True
    obj._backend.unload_script.side_effect = unload


# ----------------------------------------------------------------------
# 1. Embedded flag: target death finalizes, never exits
# ----------------------------------------------------------------------

def test_cli_session_owns_the_process_exit():
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._tui_mode = False
    assert obj._owns_process_exit() is True


@pytest.mark.parametrize("embedded,tui", [(True, False), (False, True), (True, True)])
def test_embedded_or_tui_session_never_owns_the_exit(embedded, tui):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._tui_mode = tui
    obj.set_embedded(embedded)
    assert obj._owns_process_exit() is False


def test_embedded_target_death_finalizes_outputs_without_exiting(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj.set_embedded(True)

    obj.on_detach("process-terminated")

    assert exits == []
    doc = json.loads((tmp_path / "out.json").read_text())
    assert doc["detach_report_status"]
    assert obj.running is False
    assert obj._done_event.is_set()


def test_embedded_target_death_lets_wait_return(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj.set_embedded(True)
    session = FriTapSession(obj, obj._event_bus)
    waiter = threading.Thread(target=session.wait, daemon=True)
    waiter.start()

    obj.on_detach("process-terminated")
    waiter.join(timeout=5)

    assert not waiter.is_alive()
    assert session.is_running is False
    assert exits == []


def test_embedded_target_death_then_stop_is_harmless(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj.set_embedded(True)
    obj.on_detach("process-terminated")

    FriTapSession(obj, obj._event_bus).stop()

    assert exits == []


def test_embedded_cleanup_marks_stopped_even_when_a_step_raises(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj.set_embedded(True)
    obj._run_cleanup_steps = MagicMock(side_effect=RuntimeError("boom"))

    obj.cleanup()

    assert exits == []
    assert obj.running is False
    assert obj._done_event.is_set()


def test_embedded_cleanup_says_no_goodbye(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj.set_embedded(True)
    obj.special_logger = MagicMock()

    obj.cleanup()

    obj.special_logger.info.assert_not_called()


def test_cli_target_death_still_exits_with_detached_status(tmp_path, exits):
    obj = _make_logger(tmp_path)

    obj.on_detach("process-terminated")

    assert exits == [3]


def test_wait_for_completion_does_not_exit_when_embedded(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj.set_embedded(True)
    obj._done_event.set()

    obj.wait_for_completion()

    assert exits == []


def test_api_start_marks_the_logger_embedded(monkeypatch):
    import friTap.api as api
    import friTap.ssl_logger as ssl_logger_mod
    from friTap.events import EventBus

    created = []

    class _Fake:
        def __init__(self, config=None):
            self._event_bus = EventBus()
            self._plugin_loader = None
            self.running = False
            self._embedded = False
            created.append(self)

        def install_signal_handler(self):
            assert self._embedded is True  # embedded before anything can detach

        def start_fritap_session(self):
            assert self._embedded is True

    monkeypatch.setattr(ssl_logger_mod, "SSL_Logger", _Fake)
    api.FriTap("com.example").start()

    assert created[0]._embedded is True


def test_tui_worker_marks_the_logger_embedded():
    """The TUI worker sets ``_embedded`` next to ``_tui_mode`` on its SSL_Logger."""
    from tests.unit.test_tui_capture_restart import (
        _enter_starting_window,
        _logger_stub,
        _make_controller,
        _run_worker_with,
    )
    controller, _s, _a, _p = _make_controller()
    _enter_starting_window(controller)
    stub = _logger_stub(running=False, _embedded=False)

    _run_worker_with(controller, stub)

    assert stub._tui_mode is True
    assert stub._embedded is True


# ----------------------------------------------------------------------
# 2. -pm: one watcher per session, posting to the main script
# ----------------------------------------------------------------------

class _FakeObserver:
    instances: list = []

    def __init__(self):
        self.scheduled = []
        self.started = 0
        self.stopped = 0
        self.joined = []
        _FakeObserver.instances.append(self)

    def schedule(self, handler, path):
        self.scheduled.append((handler, path))

    def start(self):
        self.started += 1

    def stop(self):
        self.stopped += 1

    def join(self, timeout=None):
        self.joined.append(timeout)


@pytest.fixture
def fake_observer(monkeypatch):
    _FakeObserver.instances = []
    monkeypatch.setattr(core, "Observer", _FakeObserver)
    return _FakeObserver


def test_payload_mod_watcher_starts_once_per_session(fake_observer):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.pm")
    obj._observer = None

    obj._start_payload_mod_watcher()
    obj._start_payload_mod_watcher()

    assert len(fake_observer.instances) == 1
    assert fake_observer.instances[0].started == 1
    assert isinstance(fake_observer.instances[0].scheduled[0][0], _PayloadModWatcher)


def test_instrument_main_and_children_share_one_watcher(fake_observer):
    """Drive the real instrument() (rig from test_multi_script_handshake)."""
    from tests.unit.test_multi_script_handshake import (
        FakeBackend,
        FakeProcess,
    )
    from tests.unit.test_multi_script_handshake import (
        _make_logger as _make_rig_logger,
    )
    backend = FakeBackend()
    obj = _make_rig_logger(backend)
    obj._config.hooking.payload_modification = True

    obj.instrument(FakeProcess(100), None)
    obj.instrument(FakeProcess(200), None)
    obj.instrument(FakeProcess(300), None)

    assert len(fake_observer.instances) == 1
    assert fake_observer.instances[0].started == 1


def test_stop_payload_mod_watcher_is_bounded_and_idempotent(fake_observer):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.pm")
    obj._observer = None
    obj._start_payload_mod_watcher()
    observer = fake_observer.instances[0]

    obj._stop_payload_mod_watcher()
    obj._stop_payload_mod_watcher()

    assert observer.stopped == 1
    assert observer.joined == [5]
    assert obj._observer is None


def test_cleanup_stops_the_payload_mod_watcher(tmp_path, exits, fake_observer):
    obj = _make_logger(tmp_path)
    obj.set_embedded(True)
    obj._start_payload_mod_watcher()

    obj.on_detach("process-terminated")  # target death: cleanup() only

    assert fake_observer.instances[0].stopped == 1
    assert obj._observer is None


def test_finish_fritap_stops_the_payload_mod_watcher(tmp_path, exits, fake_observer):
    obj = _make_logger(tmp_path)
    obj._start_payload_mod_watcher()

    obj.finish_fritap()

    assert fake_observer.instances[0].stopped == 1


def _modified(path):
    return types.SimpleNamespace(event_type="modified", src_path=str(path))


@pytest.mark.parametrize("name", ["readmod", "writemod"])
def test_watcher_posts_file_hex_to_the_main_script(tmp_path, monkeypatch, name):
    monkeypatch.chdir(tmp_path)
    (tmp_path / f"{name}.bin").write_bytes(b"\x44\x41\x53")
    host = types.SimpleNamespace(script=object(), _backend=MagicMock(),
                                 logger=logging.getLogger("test.pm"))

    _PayloadModWatcher(host).on_any_event(_modified(tmp_path / f"{name}.bin"))

    host._backend.post_message.assert_called_once_with(host.script, name, "444153")


def test_watcher_follows_the_current_main_script(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "readmod.bin").write_bytes(b"\x01")
    host = types.SimpleNamespace(script=object(), _backend=MagicMock(),
                                 logger=logging.getLogger("test.pm"))
    watcher = _PayloadModWatcher(host)
    host.script = new_main = object()  # e.g. an exec'd image's new agent

    watcher.on_any_event(_modified(tmp_path / "readmod.bin"))

    assert host._backend.post_message.call_args.args[0] is new_main


def test_watcher_ignores_other_files_and_events(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    host = types.SimpleNamespace(script=object(), _backend=MagicMock(),
                                 logger=logging.getLogger("test.pm"))
    watcher = _PayloadModWatcher(host)

    watcher.on_any_event(_modified(tmp_path / "other.bin"))
    watcher.on_any_event(types.SimpleNamespace(event_type="created",
                                               src_path=str(tmp_path / "readmod.bin")))

    host._backend.post_message.assert_not_called()


def test_watcher_survives_a_missing_file_and_a_dead_script(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    records = []
    log = logging.getLogger("test.pm.errors")
    handler = logging.Handler()
    handler.emit = records.append
    log.addHandler(handler)
    try:
        host = types.SimpleNamespace(script=object(), _backend=MagicMock(), logger=log)
        _PayloadModWatcher(host).on_any_event(_modified(tmp_path / "readmod.bin"))
        host.script = None
        (tmp_path / "writemod.bin").write_bytes(b"\x01")
        _PayloadModWatcher(host).on_any_event(_modified(tmp_path / "writemod.bin"))
    finally:
        log.removeHandler(handler)

    host._backend.post_message.assert_not_called()
    assert any("Watcher error" in r.getMessage() for r in records)


# ----------------------------------------------------------------------
# 3. TUI order: the main session is always detached, exactly once
# ----------------------------------------------------------------------

def _tui_teardown(obj):
    """friTap/tui/capture_controller.py::_run_session's finally block."""
    obj.finish_fritap()
    obj.pcap_cleanup(obj.full_capture, obj.mobile, obj.pcap_name)
    obj.cleanup(obj.live, obj.socket_trace, obj.full_capture, obj.debug_output)


def test_tui_teardown_detaches_the_main_session_once(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj._tui_mode = True
    obj.set_embedded(True)
    obj.process = MagicMock(name="main-session")
    _unload_destroys_script(obj)

    _tui_teardown(obj)
    obj.cleanup()  # a repeated cleanup must not detach again

    obj._backend.detach.assert_called_once_with(obj.process)
    # finish_fritap already unloaded it; detach_with_timeout does not unload twice.
    assert obj._backend.unload_script.call_count == 1
    assert exits == []


def test_tui_teardown_closes_outputs_before_the_detach(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj._tui_mode = True
    obj.process = MagicMock(name="main-session")
    _unload_destroys_script(obj)
    order = []
    real_close = obj.close_output_handlers

    def close_output_handlers():
        order.append("close")
        real_close()

    obj.close_output_handlers = close_output_handlers
    obj._backend.detach.side_effect = lambda p: order.append("detach")

    obj.finish_fritap()
    assert order == []  # outputs still open after finish_fritap
    obj.pcap_cleanup(obj.full_capture, obj.mobile, obj.pcap_name)
    obj.cleanup()

    # Outputs close in cleanup() before step 6 (the finally re-runs the
    # idempotent close); the detach comes after, exactly once.
    assert order.index("close") < order.index("detach")
    assert order.count("detach") == 1


def test_tui_teardown_after_target_death_skips_the_detach(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj._tui_mode = True
    obj.process = MagicMock(name="main-session")
    obj._target_gone = True
    _unload_destroys_script(obj)

    _tui_teardown(obj)

    obj._backend.detach.assert_not_called()


def test_destroyed_script_we_did_not_unload_still_means_target_gone(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj.process = MagicMock(name="main-session")
    obj.script.is_destroyed = True

    obj.detach_with_timeout(timeout=2)

    obj._backend.detach.assert_not_called()


def test_main_session_detach_is_bounded(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj.process = MagicMock(name="main-session")
    obj._main_script_unloaded = True
    release = threading.Event()
    obj._backend.detach.side_effect = lambda p: release.wait(10)
    obj._detach_agent_gracefully()

    started = time.monotonic()
    obj.detach_with_timeout(timeout=0.5)
    elapsed = time.monotonic() - started
    release.set()

    assert elapsed < 3
    obj._backend.detach.assert_called_once_with(obj.process)
