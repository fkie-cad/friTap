"""Target death must close every output handler (the JSON document) exactly once.

The live JSON writer (JsonOutputHandler) assembles session.json in its
idempotent close(); SSL_Logger.close_output_handlers() is the single call site.
A killed target (frida 'detached': process-terminated / process-replaced) must
reach it once, even when frida reports the detach twice, when an earlier
teardown step raises, and when the scanner ends concurrently.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest

from tests.unit import test_memory_scan_teardown as _teardown
from tests.unit.test_memory_scan_teardown import _FakePcap, _make_logger  # noqa: F401

# Re-expose the shared ``exits`` fixture (an assignment, so pytest finds it and
# the test parameters of the same name are not flagged as redefinitions).
exits = _teardown.exits


class _JsonHandler:
    """Counts real closes the way JsonOutputHandler does (idempotent)."""

    def __init__(self):
        self.effective_closes = 0
        self._closed = False

    def close(self):
        if not self._closed:
            self._closed = True
            self.effective_closes += 1


def _dying_logger():
    obj = _make_logger(_FakePcap())
    obj._is_memory_scan_only = lambda: False
    handler = _JsonHandler()
    spy = MagicMock(wraps=handler)
    obj._output_handlers = [spy]
    return obj, handler, spy


@pytest.mark.parametrize("reason", ["process-terminated", "process-replaced",
                                    "connection-terminated"])
def test_target_death_closes_the_json_handler_once(exits, reason):
    obj, handler, spy = _dying_logger()

    obj.on_detach(reason)
    obj.on_detach(reason)  # frida may report the same death twice

    assert handler.effective_closes == 1
    assert spy.close.call_count == 1
    assert obj._done_event.is_set()
    assert exits == [0]


def test_concurrent_detach_and_scanner_end_close_once(exits):
    obj, handler, spy = _dying_logger()
    obj._is_memory_scan_only = lambda: True

    threads = [threading.Thread(target=obj.on_detach, args=("process-terminated",)),
               threading.Thread(target=obj._on_memory_scan_ended)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)

    assert handler.effective_closes == 1


def test_json_is_closed_even_if_an_earlier_teardown_step_raises(exits):
    obj, handler, _spy = _dying_logger()

    def boom():
        raise RuntimeError("plugin unload exploded")

    obj._stop_instrument_thread = boom

    obj.on_detach("process-terminated")

    assert handler.effective_closes == 1
    assert exits == [0]


def test_legacy_json_finalize_uses_the_streaming_writer_once(monkeypatch):
    import io

    from friTap.legacy.ssl_logger_core import SSL_Logger

    released = []
    monkeypatch.setattr("friTap.output.json_stream.release_json_stream_writer",
                        released.append)
    import types

    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = MagicMock()
    obj._config = types.SimpleNamespace(output=types.SimpleNamespace(json_output="session.json"))
    obj.session_data = {"session_info": {}}
    obj.json_file = io.StringIO()
    writer = object()
    obj._legacy_json_stream = writer

    obj._finalize_json_output()
    obj._finalize_json_output()

    assert released == [writer]
    assert obj.json_file.closed
    assert "end_time" in obj.session_data["session_info"]
