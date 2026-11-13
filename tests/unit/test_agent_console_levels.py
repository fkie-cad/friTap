#!/usr/bin/env python3

"""Agent devlog levels (``console_info`` / ``console_warn`` / ``console_error``).

The router used to drop them. They now take the console_debug path: a
debug-level :class:`~friTap.events.ConsoleEvent` tagged ``origin="agent_dev"``
whose text carries the agent level and callsite. Agent dev diagnostics stay out
of the JSONL outputs unless debug output is on, and never reach the TUI
activity log.
"""

from __future__ import annotations

import io
import json
import logging

import pytest

from friTap.config import FriTapConfig, OutputConfig
from friTap.events import (
    AGENT_DEV_ORIGIN,
    ConsoleEvent,
    EventBus,
    is_agent_dev_console,
)
from friTap.message_router import MessageRouter, format_devlog_prefix
from friTap.output.factory import OutputHandlerFactory
from friTap.output.jsonl_handler import JsonlOutputHandler
from friTap.output.jsonl_stdout_handler import JsonlStdoutHandler
from friTap.protocols.registry import create_default_registry
from friTap.tui.handlers import TuiOutputHandler, belongs_in_activity_log


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _route(payload: dict):
    bus = _Bus()
    MessageRouter(bus).route(payload, b"")
    return bus.events


def _devlog(level: str, message: str = "boom", **callsite) -> dict:
    return {"contentType": f"console_{level}", "level": level,
            "time": "2026-11-10T00:00:00Z", "message": message, **callsite}


# --------------------------------------------------------------------------
# Router
# --------------------------------------------------------------------------

@pytest.mark.parametrize("level", ["info", "warn", "error"])
def test_devlog_level_becomes_a_prefixed_debug_console_event(level):
    events = _route(_devlog(level, "hook ready", file="nss.ts", line=42, col=7,
                            func="install"))
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, ConsoleEvent)
    assert event.level == "debug"
    assert event.origin == AGENT_DEV_ORIGIN
    assert event.message == f"[agent {level} nss.ts:42 install] hook ready"


def test_devlog_without_callsite_has_a_bare_level_prefix():
    events = _route(_devlog("warn", "no stack"))
    assert events[0].message == "[agent warn] no stack"


@pytest.mark.parametrize("callsite, expected_prefix", [
    ({"file": "a.ts"}, "[agent error a.ts]"),
    ({"file": "a.ts", "line": 3}, "[agent error a.ts:3]"),
    ({"func": "f"}, "[agent error f]"),
    ({"line": 3, "func": "f"}, "[agent error f]"),
])
def test_devlog_prefix_omits_missing_callsite_parts(callsite, expected_prefix):
    assert format_devlog_prefix("error", callsite) == expected_prefix


def test_devlog_escapes_control_sequences_in_message_and_callsite():
    events = _route(_devlog("error", "a\x1b[2Jb\rc", file="x\x1b]0;t\x07.ts",
                            line="1\x1b[31m", func="f\x9bg"))
    message = events[0].message
    for raw in ("\x1b", "\x07", "\r", "\x9b"):
        assert raw not in message
    assert message.startswith("[agent error x\\x1b]0;t\\x07.ts:1\\x1b[31m f\\x9bg] ")
    assert message.endswith("a\\x1b[2Jb\\rc")


def test_devlog_extras_do_not_change_the_message():
    payload = _devlog("info", "m", file="f.ts", line=1, func="g")
    payload["module"] = "libssl.so"
    assert _route(payload)[0].message == "[agent info f.ts:1 g] m"


@pytest.mark.parametrize("payload", [
    {"contentType": "console_dev", "console_dev": "dev"},
    {"contentType": "console_debug", "message": "dbg"},
    _devlog("info"),
])
def test_agent_dev_messages_are_tagged_agent_dev(payload):
    assert is_agent_dev_console(_route(payload)[0])


def test_plain_console_is_not_agent_dev():
    event = _route({"contentType": "console", "console": "hello"})[0]
    assert event.origin == "" and event.level == "info"
    assert not is_agent_dev_console(event)


# --------------------------------------------------------------------------
# JSONL outputs
# --------------------------------------------------------------------------

def _stdout_records(include_agent_dev_logs: bool, *events):
    buffer = io.StringIO()
    bus = EventBus()
    handler = JsonlStdoutHandler(stream=buffer,
                                 include_agent_dev_logs=include_agent_dev_logs)
    handler.setup(bus)
    for event in events:
        bus.emit(event)
    records = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [r for r in records if r["type"] == "console"]


def _dev_event():
    return ConsoleEvent(message="[agent warn] x", level="debug", origin=AGENT_DEV_ORIGIN)


def test_jsonl_stdout_drops_agent_dev_logs_without_debug():
    records = _stdout_records(False, _dev_event(), ConsoleEvent(message="user"))
    assert [r["message"] for r in records] == ["user"]
    assert records[0]["origin"] == ""


def test_jsonl_stdout_keeps_agent_dev_logs_with_debug():
    records = _stdout_records(True, _dev_event(), ConsoleEvent(message="user"))
    assert [r["message"] for r in records] == ["[agent warn] x", "user"]
    assert records[0]["origin"] == AGENT_DEV_ORIGIN


@pytest.mark.parametrize("include_agent_dev_logs, expected", [
    (False, ["user"]),
    (True, ["[agent warn] x", "user"]),
])
def test_jsonl_file_filters_agent_dev_logs(tmp_path, include_agent_dev_logs, expected):
    path = tmp_path / "events.jsonl"
    bus = EventBus()
    handler = JsonlOutputHandler(str(path), include_agent_dev_logs=include_agent_dev_logs)
    handler.setup(bus)
    bus.emit(_dev_event())
    bus.emit(ConsoleEvent(message="user"))
    handler.close()
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert [r["message"] for r in records if r["event_type"] == "ConsoleEvent"] == expected


@pytest.mark.parametrize("debug_output", [False, True])
def test_factory_wires_debug_output_into_jsonl_handler(tmp_path, debug_output):
    config = FriTapConfig(target="app", debug_output=debug_output,
                          output=OutputConfig(json_output=str(tmp_path / "e.jsonl")))
    registry = create_default_registry(["tls"])
    handlers, _ = OutputHandlerFactory.create_handlers(
        config, None, registry.get("tls"), {}, logging.getLogger("friTap.tests.devlog"),
        protocol_registry=registry,
    )
    jsonl = [h for h in handlers if isinstance(h, JsonlOutputHandler)]
    assert len(jsonl) == 1
    assert jsonl[0]._include_agent_dev_logs is debug_output


# --------------------------------------------------------------------------
# TUI activity log
# --------------------------------------------------------------------------

class _RecordingApp:
    def __init__(self):
        self.calls = []

    def call_from_thread(self, func, *args):
        self.calls.append(args)


def test_activity_log_filter_rejects_agent_dev_logs_only():
    assert not belongs_in_activity_log(_dev_event())
    assert belongs_in_activity_log(ConsoleEvent(message="user"))
    assert belongs_in_activity_log(ConsoleEvent(message="plain debug", level="debug"))


def test_tui_handler_never_forwards_agent_dev_logs():
    app = _RecordingApp()
    handler = TuiOutputHandler(app)
    handler._on_console(_dev_event())
    user_event = ConsoleEvent(message="user")
    handler._on_console(user_event)
    assert app.calls == [(user_event,)]
