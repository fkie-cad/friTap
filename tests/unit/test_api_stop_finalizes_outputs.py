"""API ``FriTapSession.stop()`` runs the CLI's full teardown, without exiting.

Before the fix, ``stop()`` only called ``finish_fritap()`` (graceful detach,
drain, unload) and never closed an output handler: the JSON document was never
completed (no closing, no ``detach_report``), the plaintext/full capture were
never finalized and ``running`` stayed True. ``stop()`` now goes through
``SSL_Logger.stop_fritap_session()``: ``cleanup(exit_process=False)`` (every CLI
step, outputs closed exactly once, no ``os._exit``) and then ``finish_fritap()``
for the host-only resources. The TUI keeps its own order (finish_fritap, then
cleanup) and must still close its outputs exactly once, in cleanup.
"""

from __future__ import annotations

import json
import logging
import types
from unittest.mock import MagicMock

import pytest

import friTap.legacy.ssl_logger_core as core
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.output.json_handler import JsonOutputHandler
from tests.unit._api_session_helpers import embedded_api_session

REPORT = {"version": 1, "repeat": False, "total_ms": 3,
          "steps": [{"name": "detachAll", "ok": True, "ms": 1}],
          "logs": [], "dropped_logs": 0}


class _FakeScript:
    def __init__(self, report=REPORT):
        self.is_destroyed = False
        self.graceful_calls = 0

        def graceful_detach():
            self.graceful_calls += 1
            return report

        self.exports_sync = types.SimpleNamespace(graceful_detach=graceful_detach)


@pytest.fixture
def exits(monkeypatch):
    """Record os._exit instead of ending the test run."""
    calls = []
    monkeypatch.setattr(core.os, "_exit", calls.append)
    return calls


def _make_logger(tmp_path):
    """A real SSL_Logger with a real JSON output handler and a fake agent."""
    obj = SSL_Logger("test_app", json_output=str(tmp_path / "out.json"))
    obj.logger = logging.getLogger("test.api_stop")
    obj._backend = MagicMock()
    obj.script = _FakeScript()
    obj.process = None
    obj._start_consumer_thread()
    return obj


def _json_handler(obj) -> JsonOutputHandler:
    return next(h for h in obj._output_handlers if isinstance(h, JsonOutputHandler))


def _count_closes(handler) -> list:
    calls = []
    real_close = handler.close

    def close():
        calls.append("close")
        real_close()

    handler.close = close
    return calls


def test_api_stop_completes_the_json_document_with_the_detach_report(tmp_path, exits):
    obj = _make_logger(tmp_path)
    closes = _count_closes(_json_handler(obj))

    embedded_api_session(obj).stop()

    doc = json.loads((tmp_path / "out.json").read_text())
    assert doc["detach_report"] == REPORT
    assert closes == ["close"]
    assert exits == []  # the embedding interpreter keeps running
    assert obj.running is False  # FriTapSession.is_running / wait() see the stop
    assert obj._done_event.is_set()


def test_second_stop_is_harmless(tmp_path, exits):
    obj = _make_logger(tmp_path)
    closes = _count_closes(_json_handler(obj))
    session = embedded_api_session(obj)

    session.stop()
    unloads_after_first = obj._backend.unload_script.call_count
    session.stop()

    assert closes == ["close"]
    assert obj.script.graceful_calls == 1
    assert obj._backend.unload_script.call_count == unloads_after_first
    assert exits == []


def test_api_stop_runs_the_cli_finalizers_then_releases_host_resources(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj.process = MagicMock(name="main-session")
    obj.device = MagicMock(name="device")
    order = []

    def record(name, real=None):
        def step(*args, **kwargs):
            order.append(name)
            return real(*args, **kwargs) if real is not None else None
        return step

    obj.pcap_cleanup = record("pcap_cleanup")
    obj._save_learned_offsets = record("learned_offsets")
    obj._finalize_live_scan = record("live_scan")
    json_handler = _json_handler(obj)
    json_handler.close = record("close", json_handler.close)
    obj._close_request_context_sidecar = record("sidecar")
    obj._finalize_plaintext_pcap = record("plaintext_pcap")
    obj._backend.detach.side_effect = record("session_detach")
    obj._backend.off_process_crashed.side_effect = record("off_process_crashed")

    embedded_api_session(obj).stop()

    assert order == ["pcap_cleanup", "learned_offsets", "live_scan", "close", "sidecar",
                     "plaintext_pcap", "session_detach", "off_process_crashed"]
    obj._backend.detach.assert_called_once_with(obj.process)
    assert exits == []


def test_tui_order_closes_outputs_once_and_only_in_cleanup(tmp_path, exits):
    """The TUI calls finish_fritap(), pcap_cleanup(), then cleanup(): the
    outputs must stay open through finish_fritap (the TUI still needs them)
    and be closed exactly once, by cleanup."""
    obj = _make_logger(tmp_path)
    obj._tui_mode = True
    closes = _count_closes(_json_handler(obj))

    obj.finish_fritap()
    assert closes == []
    obj.pcap_cleanup(obj.full_capture, obj.mobile, obj.pcap_name)
    obj.cleanup(obj.live, obj.socket_trace, obj.full_capture, obj.debug_output)
    obj.cleanup(obj.live, obj.socket_trace, obj.full_capture, obj.debug_output)

    assert closes == ["close"]
    assert json.loads((tmp_path / "out.json").read_text())["detach_report"] == REPORT
    assert exits == []
    assert obj.script.graceful_calls == 1


def test_cleanup_without_exit_neither_exits_nor_says_goodbye(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj.special_logger = MagicMock()

    obj.cleanup(exit_process=False)

    assert exits == []
    obj.special_logger.info.assert_not_called()


def test_cli_cleanup_still_says_goodbye_and_exits(tmp_path, exits):
    obj = _make_logger(tmp_path)
    obj.special_logger = MagicMock()
    obj.set_exit_status(3)

    obj.cleanup()

    assert exits == [3]
    obj.special_logger.info.assert_called_once_with(
        "\nThanks for using friTap. Have a great day!")
