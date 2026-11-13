#!/usr/bin/env python3

"""Agent ``devlog_debug`` messages reach the debug log.

The agent's structured logger sends ``{contentType: "console_debug", message}``.
The router used to drop them (only ``console``/``console_dev`` were routed), so
``[ssl-identity]``-style diagnostics never reached ``--debug-log``. They now take
the console_dev path: a debug-level :class:`~friTap.events.ConsoleEvent`, which
the console sink logs with ``logger.debug`` (never at info level).
"""

from __future__ import annotations

import logging

from friTap.events import ConsoleEvent
from friTap.message_router import MessageRouter
from friTap.output.console_handler import ConsoleOutputHandler


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _route(payload: dict):
    bus = _Bus()
    MessageRouter(bus).route(payload, b"")
    return bus.events


def test_console_debug_becomes_a_debug_console_event():
    events = _route({"contentType": "console_debug", "level": "debug",
                     "message": "[ssl-identity] layout libwebviewchromium.so"})
    assert len(events) == 1
    assert isinstance(events[0], ConsoleEvent)
    assert events[0].level == "debug"
    assert events[0].message == "[ssl-identity] layout libwebviewchromium.so"


def test_console_debug_matches_console_dev_routing():
    dev = _route({"contentType": "console_dev", "console_dev": "same text"})
    dbg = _route({"contentType": "console_debug", "message": "same text"})
    assert [(e.level, e.message) for e in dev] == [(e.level, e.message) for e in dbg]


def test_console_debug_escapes_terminal_control_sequences():
    events = _route({"contentType": "console_debug", "message": "a\x1b[2Jb"})
    assert "\x1b" not in events[0].message


def test_console_debug_without_message_is_an_empty_debug_event():
    events = _route({"contentType": "console_debug"})
    assert len(events) == 1 and events[0].level == "debug" and events[0].message == ""


def test_console_debug_is_logged_at_debug_level_only():
    handler = ConsoleOutputHandler()
    capture = _ListHandler()
    logger = logging.getLogger("friTap")
    previous_level = logger.level
    logger.addHandler(capture)
    logger.setLevel(logging.DEBUG)
    try:
        for event in _route({"contentType": "console_debug", "message": "[ssl-identity] x"}):
            handler.on_console(event)
    finally:
        logger.removeHandler(capture)
        logger.setLevel(previous_level)
    assert [(r.levelno, r.getMessage()) for r in capture.records] == [(logging.DEBUG, "[ssl-identity] x")]
