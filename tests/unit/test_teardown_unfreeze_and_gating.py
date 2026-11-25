"""Teardown on Android: frozen targets, wedged agents and spawn gating.

* Bug 2: an app frozen by Android's cached-apps freezer (Gemini hands off to
  another package and is frozen seconds later) never answers graceful_detach.
  Teardown now thaws the main target and every child first (root, via adb),
  and an agent whose RPC still timed out is released anyway: unload and
  session.detach at once, bounded by WEDGED_RELEASE_TIMEOUT.
* Bug 3: spawn gating stayed on during teardown, holding unrelated spawns.
  It is now disabled first, and the spawns it still holds are resumed.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
import types
from unittest.mock import MagicMock

from friTap.legacy import android_unfreeze
from friTap.legacy.android_unfreeze import build_unfreeze_command, unfreeze_android_pids
from friTap.legacy.session_manager import SessionManager
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.legacy.ssl_logger_state import _ChildAgent

REPORT = {"version": 1, "repeat": False, "total_ms": 3, "steps": [], "logs": [],
          "dropped_logs": 0}


class _FakeScript:
    def __init__(self, on_graceful=lambda: REPORT):
        self.is_destroyed = False
        self.exports_sync = types.SimpleNamespace(graceful_detach=on_graceful)


def _make_logger(script, android=False):
    obj = SSL_Logger("com.example.app", mobile="SERIAL1")
    obj.logger = logging.getLogger("test.teardown.unfreeze")
    obj._backend = MagicMock()
    obj.device = MagicMock(name="device")
    obj.process = MagicMock(name="main-session")
    obj.script = script
    obj.pid = 1234
    obj._android_target_cached = android
    obj._finalize_live_scan = lambda: None
    obj._release_lsass_contributor = lambda: None
    return obj


# --- android_unfreeze helper ------------------------------------------------

def test_unfreeze_command_thaws_each_valid_pid_as_root():
    command = build_unfreeze_command([1234, 1234, None, "5; rm -rf /", True, 77])
    assert command.startswith("su -c '")
    assert "for p in 1234 77;" in command
    assert "/sys/fs/cgroup/uid_*/pid_$p/cgroup.freeze" in command
    assert "rm" not in command


def test_unfreeze_without_valid_pids_runs_nothing():
    runner = MagicMock()
    assert unfreeze_android_pids("S", [None, 0], runner=runner) is False
    runner.assert_not_called()


def test_unfreeze_runs_one_bounded_adb_shell_on_the_serial():
    runner = MagicMock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    assert unfreeze_android_pids("SERIAL1", [42], timeout=1.5, runner=runner) is True
    argv = runner.call_args.args[0]
    assert argv[:4] == ["adb", "-s", "SERIAL1", "shell"]
    assert runner.call_args.kwargs["timeout"] == 1.5


def test_unfreeze_never_raises_on_adb_timeout():
    runner = MagicMock(side_effect=subprocess.TimeoutExpired("adb", 1))
    assert unfreeze_android_pids("S", [42], runner=runner) is False


# --- unfreeze before graceful_detach ----------------------------------------

def test_android_main_and_child_pids_are_thawed_before_the_rpc(monkeypatch):
    order = []
    script = _FakeScript(lambda: (order.append("graceful"), REPORT)[1])
    obj = _make_logger(script, android=True)
    obj._child_agents.append(_ChildAgent(pid=555, session=MagicMock(), script=_FakeScript()))
    monkeypatch.setattr(
        "friTap.legacy.ssl_logger_teardown.unfreeze_android_pids",
        lambda serial, pids: order.append(("unfreeze", serial, list(pids))))

    obj._detach_all_agents_gracefully(5)
    obj._detach_all_agents_gracefully(5)  # idempotent: one adb call

    unfreezes = [o for o in order if isinstance(o, tuple)]
    assert len(unfreezes) == 1
    _, serial, pids = unfreezes[0]
    assert serial == "SERIAL1" and pids == [1234, 555]
    assert order.index(unfreezes[0]) < order.index("graceful")


def test_non_android_target_is_not_thawed(monkeypatch):
    obj = _make_logger(_FakeScript(), android=False)
    calls = []
    monkeypatch.setattr("friTap.legacy.ssl_logger_teardown.unfreeze_android_pids",
                        lambda *a: calls.append(a))
    obj._detach_all_agents_gracefully(5)
    assert calls == []


def test_unfreeze_failure_does_not_break_teardown(monkeypatch):
    obj = _make_logger(_FakeScript(), android=True)

    def boom(*_a):
        raise RuntimeError("adb exploded")

    monkeypatch.setattr("friTap.legacy.ssl_logger_teardown.unfreeze_android_pids", boom)
    obj._detach_all_agents_gracefully(5)
    assert obj._graceful_detach_outcome == SSL_Logger.GRACEFUL_OK


# --- release after an entry timeout -----------------------------------------

def test_main_agent_is_released_within_bound_after_entry_timeout():
    """A frozen target: RPC never enters; unload + detach still run, both bounded."""
    release = threading.Event()
    obj = _make_logger(_FakeScript(lambda: release.wait(30)))
    obj.GRACEFUL_ENTRY_TIMEOUT = 0.2
    obj.WEDGED_RELEASE_TIMEOUT = 0.4
    obj._backend.unload_script.side_effect = lambda _s: release.wait(30)  # frozen
    obj._backend.detach.side_effect = lambda _p: release.wait(30)         # frozen too
    try:
        started = time.monotonic()
        obj.detach_with_timeout(timeout=5)
        elapsed = time.monotonic() - started
        assert elapsed < 1.5  # 0.2 s entry bound + 0.4 s release bound
        assert obj._graceful_detach_outcome == SSL_Logger.GRACEFUL_TIMEOUT
        obj._backend.unload_script.assert_called_once_with(obj.script)
        obj._backend.detach.assert_called_once_with(obj.process)
        assert obj._main_session_detached is False
    finally:
        release.set()


def test_wedged_release_runs_unload_and_detach_concurrently():
    obj = _make_logger(_FakeScript())
    obj.WEDGED_RELEASE_TIMEOUT = 2.0
    unload_started = threading.Event()
    obj._backend.unload_script.side_effect = lambda _s: (unload_started.set(), time.sleep(1))
    obj._backend.detach.side_effect = lambda _p: unload_started.wait(1)

    started = time.monotonic()
    assert obj._release_wedged_agent(obj.script, obj.process, "main") is True
    assert time.monotonic() - started < 1.5  # not unload (1 s) + detach serialized
    assert unload_started.is_set()


# --- spawn gating is disabled first -----------------------------------------

def test_teardown_disables_spawn_gating_before_any_agent_detach():
    order = []
    obj = _make_logger(_FakeScript(lambda: (order.append("graceful"), REPORT)[1]))
    obj._spawn_gating_enabled = True
    held = types.SimpleNamespace(pid=999, identifier="com.instagram.android")
    obj._backend.disable_spawn_gating.side_effect = lambda _d: order.append("disable")
    obj._backend.enumerate_pending_spawn.side_effect = lambda _d: (order.append("enum"), [held])[1]
    obj._backend.resume.side_effect = lambda _d, pid: order.append(("resume", pid))
    obj._backend.unload_script.side_effect = lambda _s: order.append("unload")
    obj._backend.detach.side_effect = lambda _p: order.append("detach")
    obj._resume_quietly = lambda pid: order.append(("resume", pid))
    obj._start_consumer_thread()

    obj._shutdown_agent_and_drain()
    obj.detach_with_timeout(timeout=5)

    assert order[0] == "disable"
    assert order.index(("resume", 999)) < order.index("graceful")
    assert order.index("graceful") < order.index("unload") < order.index("detach")
    obj._backend.disable_spawn_gating.assert_called_once_with(obj.device)  # idempotent


def test_gating_left_alone_when_friTap_never_enabled_it():
    obj = _make_logger(_FakeScript())
    obj._disable_spawn_gating_for_teardown()
    obj._backend.disable_spawn_gating.assert_not_called()


def test_disable_gating_failure_is_swallowed():
    obj = _make_logger(_FakeScript())
    obj._spawn_gating_enabled = True
    obj._backend.disable_spawn_gating.side_effect = RuntimeError("device gone")
    obj._disable_spawn_gating_for_teardown()  # must not raise
    obj._backend.enumerate_pending_spawn.assert_not_called()


def test_enable_spawn_gating_records_it_for_teardown():
    logger = MagicMock()
    logger._spawn_gating_enabled = False
    SessionManager._enable_spawn_gating(logger)
    assert logger._spawn_gating_enabled is True


def test_session_finish_disables_gating_before_unloading():
    order = []
    logger = MagicMock()
    logger._disable_spawn_gating_for_teardown.side_effect = lambda: order.append("disable")
    logger._backend.unload_script.side_effect = lambda _s: order.append("unload")
    manager = SessionManager(logger)
    manager.finish()
    assert order[:2] == ["disable", "unload"]


def test_android_unfreeze_module_bound_is_short():
    assert android_unfreeze.UNFREEZE_TIMEOUT <= 5
