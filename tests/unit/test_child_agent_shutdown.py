"""Child gating: ``self.script`` stays the MAIN target's agent.

Before the fix ``instrument()`` assigned every new script to ``self.script``, so
with ``--enable_child_gating`` (or spawn gating / a child's exec) the shutdown's
graceful_detach, the detach report and the unload went to the LAST child
instead of the main app — and the main agent was never gracefully detached.
Now a child's agent is kept in ``_child_agents``; the shutdown detaches the
main agent first, then the children (bounded, best effort, DEBUG only), and
unloads the children after the main one.
"""

from __future__ import annotations

import logging
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

from friTap.legacy.ssl_logger_core import SSL_Logger, _InstrumentRequest

MAIN_REPORT = {"version": 1, "repeat": False, "total_ms": 3, "steps": [],
               "logs": [], "dropped_logs": 0}
CHILD_REPORT = {"version": 1, "repeat": False, "total_ms": 9,
                "steps": [{"name": "detachAll", "ok": True, "ms": 1}],
                "logs": [], "dropped_logs": 0}
CHILD_PID = 4242


class _FakeScript:
    def __init__(self, name, on_graceful=None, destroyed=False):
        self.name = name
        self.is_destroyed = destroyed
        self.graceful_calls = 0

        def graceful_detach():
            self.graceful_calls += 1
            return on_graceful() if on_graceful is not None else None

        self.exports_sync = types.SimpleNamespace(graceful_detach=graceful_detach)

    def __repr__(self):
        return f"<_FakeScript {self.name}>"


def _make_logger(scripts, timeout=None):
    """A real SSL_Logger whose backend hands out *scripts* in order."""
    obj = SSL_Logger("test_app", enable_child_gating=True)
    obj.logger = logging.getLogger("test.child_agents")
    obj._config.device.timeout = timeout
    obj._backend = MagicMock()
    obj._backend.create_script.side_effect = list(scripts)
    obj.device = MagicMock(name="device")
    obj.process = MagicMock(name="main-session")
    obj.get_agent_script = lambda: "// agent"
    obj._warn_on_stale_agent_bundle = lambda _source: None
    obj._load_script_bounded = lambda _script: None
    obj._check_agent_abi = MagicMock()
    obj._build_script_context = lambda *_a: None
    obj._finalize_live_scan = lambda: None
    obj._release_lsass_contributor = lambda: None
    return obj


def _instrument_child(obj, session):
    """Drive the real child-gating path: attach, watch, instrument, resume."""
    obj._backend.attach.return_value = session
    obj._instrument_gated_process(_InstrumentRequest(
        pid=CHILD_PID, label="child process", watch_as_main=False))


def test_child_instrument_keeps_the_main_script():
    main, child = _FakeScript("main"), _FakeScript("child")
    obj = _make_logger([main, child])
    child_session = MagicMock(name="child-session")

    obj.instrument(obj.process, None)
    _instrument_child(obj, child_session)

    assert obj.script is main
    assert obj.process is not child_session
    [record] = obj._child_agents
    assert (record.pid, record.session, record.script) == (CHILD_PID, child_session, child)
    obj._check_agent_abi.assert_called_once_with()  # the main agent only


def test_exec_image_of_the_main_target_becomes_the_main_script():
    """_watch_process moves self.process onto the main target's exec'd image
    before instrumenting it: that image's agent IS the new main agent."""
    old_main, new_main = _FakeScript("old"), _FakeScript("new")
    obj = _make_logger([old_main, new_main])
    obj.instrument(obj.process, None)

    new_session = MagicMock(name="exec-image-session")
    obj._watch_process(new_session, 1000, is_main=True)
    obj.instrument(new_session, None)

    assert obj.script is new_main
    assert obj._child_agents == []


def test_shutdown_detaches_the_main_agent_first_and_reports_only_it():
    order = []
    main = _FakeScript("main", lambda: (order.append("main"), MAIN_REPORT)[1])
    child = _FakeScript("child", lambda: (order.append("child"), CHILD_REPORT)[1])
    obj = _make_logger([main, child])
    obj.instrument(obj.process, None)
    _instrument_child(obj, MagicMock(name="child-session"))
    obj._start_consumer_thread()

    obj._shutdown_agent_and_drain()

    assert order == ["main", "child"]
    assert obj.detach_report == MAIN_REPORT
    assert obj._child_agents[0].graceful_outcome == SSL_Logger.GRACEFUL_OK


def test_children_are_unloaded_after_the_main_agent_then_detached():
    main, child = _FakeScript("main", lambda: MAIN_REPORT), _FakeScript("child")
    obj = _make_logger([main, child])
    child_session = MagicMock(name="child-session")
    obj.instrument(obj.process, None)
    _instrument_child(obj, child_session)
    obj._start_consumer_thread()

    obj._shutdown_agent_and_drain()
    obj.detach_with_timeout(timeout=5)

    assert [c.args[0] for c in obj._backend.unload_script.call_args_list] == [main, child]
    assert [c.args[0] for c in obj._backend.detach.call_args_list] == [obj.process, child_session]
    assert main.graceful_calls == child.graceful_calls == 1
    assert obj._child_agents == []
    obj._release_child_agents()  # idempotent: nothing left to release
    assert obj._backend.unload_script.call_count == 2


def test_cli_cleanup_routes_everything_to_the_main_agent(monkeypatch):
    """End to end through _run_cleanup_steps: report from main, both unloaded."""
    import friTap.legacy.ssl_logger_core as core
    monkeypatch.setattr(core.os, "_exit", lambda _code: None)
    main, child = _FakeScript("main", lambda: MAIN_REPORT), _FakeScript("child",
                                                                        lambda: CHILD_REPORT)
    obj = _make_logger([main, child])
    obj.instrument(obj.process, None)
    _instrument_child(obj, MagicMock(name="child-session"))
    obj._start_consumer_thread()

    obj._run_cleanup_steps()

    assert obj.detach_report == MAIN_REPORT
    unloaded = [c.args[0] for c in obj._backend.unload_script.call_args_list]
    assert unloaded == [main, child]


def test_a_wedged_child_is_bounded_and_left_to_process_exit():
    release = threading.Event()
    main = _FakeScript("main", lambda: MAIN_REPORT)
    wedged = _FakeScript("wedged", lambda: release.wait(30))
    obj = _make_logger([main, wedged], timeout=1)
    child_session = MagicMock(name="child-session")
    obj.instrument(obj.process, None)
    _instrument_child(obj, child_session)
    try:
        started = time.monotonic()
        obj._detach_child_agents_gracefully(1)
        assert time.monotonic() - started < 3
        assert obj._child_agents[0].graceful_outcome == SSL_Logger.GRACEFUL_TIMEOUT

        obj._release_child_agents()
        obj._backend.unload_script.assert_not_called()
        obj._backend.detach.assert_not_called()
    finally:
        release.set()


def test_many_wedged_children_share_one_deadline():
    release = threading.Event()
    scripts = [_FakeScript("main")] + [
        _FakeScript(f"wedged-{i}", lambda: release.wait(30)) for i in range(3)]
    obj = _make_logger(scripts)
    obj.instrument(obj.process, None)
    for i in range(3):
        obj._register_child_agent(MagicMock(name=f"child-{i}"), scripts[i + 1])
    try:
        started = time.monotonic()
        obj._detach_child_agents_gracefully(1)
        assert time.monotonic() - started < 2.5  # not 3 x 1 s
    finally:
        release.set()


@pytest.mark.parametrize("outcome_source", ["destroyed", "failed"])
def test_dead_or_failed_child_is_not_unloaded(outcome_source):
    def boom():
        raise RuntimeError("script has been destroyed")

    child = (_FakeScript("child", destroyed=True) if outcome_source == "destroyed"
             else _FakeScript("child", boom))
    obj = _make_logger([_FakeScript("main"), child])
    obj.instrument(obj.process, None)
    obj._register_child_agent(MagicMock(name="child-session"), child)

    obj._detach_child_agents_gracefully(1)
    obj._release_child_agents()

    assert child.graceful_calls == (0 if outcome_source == "destroyed" else 1)
    obj._backend.unload_script.assert_not_called()
    obj._backend.detach.assert_not_called()


def test_child_reports_go_to_debug_only():
    main = _FakeScript("main", lambda: MAIN_REPORT)
    child = _FakeScript("child", lambda: CHILD_REPORT)
    obj = _make_logger([main, child])
    obj.instrument(obj.process, None)
    _instrument_child(obj, MagicMock(name="child-session"))
    obj.logger = MagicMock()

    obj._detach_child_agents_gracefully(1)

    obj.logger.debug.assert_any_call(
        "child pid %s: %s", CHILD_PID, "Agent detach: 1/1 steps ok, 0 failed, total 9 ms")
    obj.logger.info.assert_not_called()
    obj.logger.warning.assert_not_called()
    assert obj.detach_report is None  # the main agent's RPC has not run here


def test_finish_fritap_releases_the_children_after_the_main_agent():
    """finish_fritap alone (Wine watcher, probe, LSASS helper) unloads too."""
    main, child = _FakeScript("main", lambda: MAIN_REPORT), _FakeScript("child")
    obj = _make_logger([main, child])
    obj.instrument(obj.process, None)
    _instrument_child(obj, MagicMock(name="child-session"))
    obj._start_consumer_thread()

    obj.finish_fritap()

    assert [c.args[0] for c in obj._backend.unload_script.call_args_list] == [main, child]
    assert child.graceful_calls == 1
