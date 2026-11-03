"""Byte budget + drop policy of the Frida message queue (SSL_Logger)."""

import logging
import queue
from unittest.mock import MagicMock

import pytest

from friTap.events import ConsoleEvent
from friTap.legacy import ssl_logger_core
from friTap.legacy.ssl_logger_core import ByteBudgetQueue, SSL_Logger
from friTap.message_router import MessageRouter


def _msg(n_bytes):
    return ({"type": "send", "payload": {"contentType": "datalog"}}, b"x" * n_bytes)


class TestByteBudgetQueue:
    def test_byte_budget_raises_full(self):
        q = ByteBudgetQueue(maxsize=100, max_bytes=100)
        q.put_nowait(_msg(60))
        with pytest.raises(queue.Full):
            q.put_nowait(_msg(60))
        assert q.qsize() == 1 and q.queued_bytes > 60

    def test_budget_released_on_get(self):
        q = ByteBudgetQueue(maxsize=100, max_bytes=100)
        q.put_nowait(_msg(60))
        q.get_nowait()
        assert q.queued_bytes == 0
        q.put_nowait(_msg(60))

    def test_blocking_put_does_not_wait_on_bytes(self):
        q = ByteBudgetQueue(maxsize=100, max_bytes=10)
        with pytest.raises(queue.Full):
            q.put(_msg(60), block=True, timeout=None)  # would hang if it waited

    def test_count_cap_still_applies(self):
        q = ByteBudgetQueue(maxsize=2, max_bytes=10 ** 9)
        q.put_nowait(_msg(1))
        q.put_nowait(_msg(1))
        with pytest.raises(queue.Full):
            q.put_nowait(_msg(1))
        assert q.queued_bytes == sum(len(m[1]) for m in (_msg(1), _msg(1))) + 2 * len("datalog")

    def test_payload_strings_count_toward_budget(self):
        q = ByteBudgetQueue(maxsize=10, max_bytes=50)
        with pytest.raises(queue.Full):
            q.put_nowait(({"type": "send", "payload": {"console": "y" * 100}}, None))

    def test_non_dict_items_are_tolerated(self):
        q = ByteBudgetQueue(maxsize=10, max_bytes=50)
        q.put_nowait(("filler", None))
        assert q.get_nowait() == ("filler", None)


def _make_logger(max_bytes):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.queue_budget")
    obj._backend = MagicMock()
    obj.script = MagicMock()
    obj.startup = False
    obj._message_queue = ByteBudgetQueue(maxsize=10000, max_bytes=max_bytes)
    obj._queue_drop_count = 0
    return obj


class TestDropPolicy:
    def test_byte_budget_triggers_drop_and_logs_once_per_interval(self, caplog, monkeypatch):
        obj = _make_logger(max_bytes=100)
        handler = obj._internal_callback_wrapper(obj.script)
        ticks = [1000.0, 1001.0, 1002.0, 1060.0]
        monkeypatch.setattr(ssl_logger_core.time, "monotonic",
                            lambda: ticks.pop(0) if ticks else 1060.0)
        with caplog.at_level(logging.WARNING):
            handler(*_msg(50))      # fits
            handler(*_msg(80))      # dropped -> logged
            handler(*_msg(80))      # dropped, same interval -> silent
            handler(*_msg(80))      # dropped, same interval -> silent
            handler(*_msg(80))      # dropped, interval elapsed -> logged
        assert obj._message_queue.qsize() == 1
        assert obj._queue_drop_count == 4
        records = [r for r in caplog.records if "queue full" in r.getMessage()]
        assert len(records) == 2
        assert "dropped 3 message(s) since the last report, 4 in total" in records[1].getMessage()

    def test_default_queue_has_byte_budget(self):
        assert ssl_logger_core.MESSAGE_QUEUE_MAX_BYTES == 256 * 1024 * 1024
        assert ssl_logger_core.MESSAGE_QUEUE_MAX_MESSAGES == 10000


class TestConsoleTextNeutralised:
    def test_ssl_logger_escapes_console_fields(self):
        payload = {"contentType": "console", "console": "\x1b[31mred", "console_dev": "\x1b]0;t\x07"}
        SSL_Logger._neutralize_console_text(payload)
        assert payload["console"] == "\\x1b[31mred"
        assert payload["console_dev"] == "\\x1b]0;t\\x07"

    def test_message_router_escapes_console_event(self):
        events = []
        router = MessageRouter(type("Bus", (), {"emit": lambda s, e: events.append(e)})())
        router._emit_console({"console": "ok\x1b[2J\nnext"})
        (event,) = [e for e in events if isinstance(e, ConsoleEvent)]
        assert event.message == "ok\\x1b[2J\nnext"
