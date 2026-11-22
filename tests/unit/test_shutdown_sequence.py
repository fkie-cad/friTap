"""The host shutdown sequence: graceful_detach RPC first, then drain, then close.

Every stop path (SIGINT, --duration, target death, API stop, TUI) runs
``SSL_Logger._shutdown_agent_and_drain``: stop instrumentation, call the
agent's ``graceful_detach`` RPC while the message consumer still runs and the
outputs are open, then stop the consumer and drain the queue completely. Only
then do the cleanup steps close the outputs. ``detach_with_timeout`` keeps the
unload/session.detach part and never calls graceful_detach a second time.
"""

from __future__ import annotations

import logging
import threading
import types
from unittest.mock import MagicMock

import pytest

import friTap.legacy.ssl_logger_core as core
from friTap.api import FriTapSession
from friTap.legacy.ssl_logger_core import SSL_Logger

WAIT = 5.0
REPORT = {"version": 1, "repeat": False, "total_ms": 3, "steps": [], "logs": [],
          "dropped_logs": 0}


class _FakeScript:
    """A frida Script stand-in whose graceful_detach runs *on_graceful*."""

    def __init__(self, on_graceful=lambda: REPORT, destroyed=False):
        self.is_destroyed = destroyed
        self.graceful_calls = 0

        def graceful_detach():
            self.graceful_calls += 1
            return on_graceful()

        self.exports_sync = types.SimpleNamespace(graceful_detach=graceful_detach)


def _make_logger(order, script, timeout=None):
    """A headless SSL_Logger with a real consumer thread and recorded effects."""
    obj = SSL_Logger("test_app")
    obj.logger = logging.getLogger("test.shutdown.sequence")
    obj._config.device.timeout = timeout
    obj.script = script
    obj.process = None
    obj._handlers_active = True
    obj._output_handlers = []
    obj.close_output_handlers = lambda: order.append("close")
    obj.on_fritap_message = lambda _job, message, _data: order.append(message)
    obj._finalize_live_scan = lambda: None
    obj._release_lsass_contributor = lambda: None
    obj._start_consumer_thread()
    return obj


def _enqueue(obj, *messages):
    for message in messages:
        obj._message_queue.put_nowait((message, None))


def test_graceful_rpc_runs_before_consumer_stop_and_output_close():
    order = []
    obj = _make_logger(order, None)
    obj.script = _FakeScript(lambda: (order.append(
        ("graceful", obj._consumer_thread is not None)), REPORT)[1])

    obj._run_cleanup_steps()

    assert order[0] == ("graceful", True)  # the consumer was still running
    assert order[-1] == "close"
    assert obj.detach_report == REPORT
    assert obj._consumer_thread is None


def test_messages_sent_during_the_rpc_are_consumed_before_outputs_close():
    order = []
    obj = _make_logger(order, None)
    obj._consumer_stop.set()  # worst case: nothing consumes them live
    obj._consumer_thread.join(WAIT)

    def graceful():
        _enqueue(obj, *[f"msg-{i}" for i in range(50)])
        return REPORT

    obj.script = _FakeScript(graceful)
    obj._run_cleanup_steps()

    assert order == [f"msg-{i}" for i in range(50)] + ["close"]
    assert obj._message_queue.empty()


def test_wedged_graceful_rpc_times_out_and_outputs_still_close():
    order = []
    release = threading.Event()
    obj = _make_logger(order, _FakeScript(lambda: release.wait(WAIT * 4)), timeout=1)
    try:
        obj._run_cleanup_steps()
        assert order[-1] == "close"
        assert obj._graceful_detach_outcome == SSL_Logger.GRACEFUL_TIMEOUT
        assert obj.detach_report is None
    finally:
        release.set()


def test_wedged_graceful_rpc_makes_detach_skip_unload_and_session_detach():
    obj = _make_logger([], _FakeScript())
    obj._graceful_detach_outcome = SSL_Logger.GRACEFUL_TIMEOUT
    obj.process = MagicMock()
    obj._backend = MagicMock()
    obj.detach_with_timeout(timeout=WAIT)
    obj._backend.unload_script.assert_not_called()
    obj._backend.detach.assert_not_called()


@pytest.mark.parametrize("destroyed, target_gone", [(True, False), (False, True)])
def test_dead_script_skips_the_rpc(destroyed, target_gone):
    order = []
    script = _FakeScript(destroyed=destroyed)
    obj = _make_logger(order, script)
    obj._target_gone = target_gone
    _enqueue(obj, "late")

    obj._run_cleanup_steps()

    assert script.graceful_calls == 0
    assert obj._graceful_detach_outcome == SSL_Logger.GRACEFUL_SKIPPED
    assert order == ["late", "close"]


def test_target_death_path_skips_the_rpc(monkeypatch):
    monkeypatch.setattr(core.os, "_exit", lambda code: None)
    order = []
    script = _FakeScript()  # not (yet) marked destroyed by frida
    obj = _make_logger(order, script)
    obj.pcap_cleanup = lambda *a, **k: None
    obj._end_session("process-terminated")
    assert script.graceful_calls == 0
    assert "close" in order


def test_detach_with_timeout_does_not_call_graceful_a_second_time():
    script = _FakeScript()
    obj = _make_logger([], script)
    obj.process = MagicMock()
    obj._backend = MagicMock()
    obj._shutdown_agent_and_drain()
    obj.detach_with_timeout(timeout=WAIT)
    assert script.graceful_calls == 1
    obj._backend.unload_script.assert_called_once_with(script)
    obj._backend.detach.assert_called_once_with(obj.process)


def test_detach_with_timeout_alone_still_calls_graceful_once():
    """Callers that invoke detach_with_timeout directly still get the RPC."""
    script = _FakeScript()
    obj = _make_logger([], script)
    obj.process = MagicMock()
    obj._backend = MagicMock()
    obj.detach_with_timeout(timeout=WAIT)
    assert script.graceful_calls == 1
    assert obj.detach_report == REPORT


def test_failed_rpc_leaves_no_report_and_detach_treats_script_as_dead():
    def boom():
        raise RuntimeError("script has been destroyed")

    obj = _make_logger([], _FakeScript(boom))
    obj.process = MagicMock()
    obj._backend = MagicMock()
    obj._shutdown_agent_and_drain()
    obj.detach_with_timeout(timeout=WAIT)
    assert obj._graceful_detach_outcome == SSL_Logger.GRACEFUL_FAILED
    assert obj.detach_report is None
    obj._backend.unload_script.assert_not_called()


def test_old_bundle_returning_nothing_is_tolerated(caplog):
    obj = _make_logger([], _FakeScript(lambda: None))
    obj.logger = MagicMock()
    obj._shutdown_agent_and_drain()
    assert obj.detach_report is None
    obj.logger.info.assert_any_call("Agent detach: agent returned no detach report")


def test_api_stop_calls_graceful_before_the_drain_and_unload():
    order = []
    script = _FakeScript(lambda: (order.append("graceful"), REPORT)[1])
    obj = _make_logger(order, script)
    obj._backend = MagicMock()
    obj._backend.unload_script.side_effect = lambda _s: order.append("unload")
    _enqueue(obj, "queued")

    FriTapSession(obj, obj._event_bus).stop()

    assert script.graceful_calls == 1
    assert order.index("graceful") < order.index("unload")
    assert order.index("queued") < order.index("unload")
    assert obj._consumer_thread is None


def test_finish_then_cleanup_runs_the_rpc_and_drain_once():
    """TUI path: finish_fritap() then cleanup() must not repeat steps 1-3."""
    script = _FakeScript()
    obj = _make_logger([], script)
    obj._backend = MagicMock()
    obj._stop_consumer_thread = MagicMock(wraps=obj._stop_consumer_thread)
    obj.finish_fritap()
    obj._run_cleanup_steps()
    assert script.graceful_calls == 1
    assert obj._stop_consumer_thread.call_count == 1
