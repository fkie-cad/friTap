"""Per-event process origin ({pid, process, role}) for multi-process captures.

The host stamps every agent message in ``_internal_callback_wrapper`` with the
origin of the script that sent it; the router copies it to
``FriTapEvent.process_origin``; the JSONL stream, the .tap FLOW meta and the
verbose console carry it. Single-process output and the keylog file stay as before.
"""

from __future__ import annotations

import io
import json
import logging
import queue
import types

from friTap.events import (
    PROCESS_ORIGIN_KEY,
    ConsoleEvent,
    DatalogEvent,
    EventBus,
    FriTapEvent,
    KeylogEvent,
)
from friTap.flow.collector import FlowCollector
from friTap.flow.tap_format import decode_flow, encode_flow
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.legacy.ssl_logger_state import _ChildAgent
from friTap.message_router import MessageRouter
from friTap.output import KeylogOutputHandler
from friTap.output.console_handler import ConsoleOutputHandler, origin_prefix
from friTap.output.jsonl_stdout_handler import JsonlStdoutHandler
from friTap.protocols.tls_handler import TlsKeylogFormatter

KEY_LINE = "CLIENT_RANDOM " + "ab" * 32 + " " + "cd" * 48
MAIN_PID = 4242
CHILD_PID = 4343
CHILD_ORIGIN = {"pid": CHILD_PID, "process": "com.example.app:remote", "role": "child"}


# --- host-side stamping -------------------------------------------------------

def _logger():
    logger = SSL_Logger.__new__(SSL_Logger)
    logger.logger = logging.getLogger("test.origin")
    logger._message_queue = queue.Queue()
    logger._queue_drop_count = 0
    logger.pid = MAIN_PID
    logger._config = types.SimpleNamespace(target="com.example.app")
    logger.resolved_process_name = None
    logger.script = object()
    return logger


def _add_child(logger, pid=CHILD_PID):
    script = object()
    logger._child_agents.append(_ChildAgent(pid=pid, session=object(), script=script))
    return script


def _send(logger, script, payload):
    logger._internal_callback_wrapper(script)({"type": "send", "payload": payload}, None)
    message, _data = logger._message_queue.get_nowait()
    return message["payload"]


def test_main_script_messages_carry_the_target_origin():
    logger = _logger()
    payload = _send(logger, logger.script, {"contentType": "keylog", "keylog": KEY_LINE})
    assert payload[PROCESS_ORIGIN_KEY] == {
        "pid": MAIN_PID, "process": "com.example.app", "role": "target"}


def test_main_origin_prefers_the_resolved_process_name():
    logger = _logger()
    logger._config.target = str(MAIN_PID)
    logger.resolved_process_name = "curl"
    payload = _send(logger, logger.script, {"contentType": "console"})
    assert payload[PROCESS_ORIGIN_KEY]["process"] == "curl"


def test_child_script_messages_carry_the_child_pid_and_default_role():
    logger = _logger()
    child = _add_child(logger)
    payload = _send(logger, child, {"contentType": "datalog"})
    assert payload[PROCESS_ORIGIN_KEY] == {"pid": CHILD_PID, "process": None, "role": "child"}


def test_child_origin_uses_the_registered_name_and_role():
    logger = _logger()
    child = _add_child(logger)
    logger.set_process_origin(CHILD_PID, "com.example.app:remote", "spawn")
    payload = _send(logger, child, {"contentType": "datalog"})
    assert payload[PROCESS_ORIGIN_KEY] == {
        "pid": CHILD_PID, "process": "com.example.app:remote", "role": "spawn"}


def test_existing_origin_is_not_overwritten():
    logger = _logger()
    preset = {"pid": 1, "process": "agent-said", "role": "x"}
    payload = _send(logger, logger.script, {"contentType": "keylog", PROCESS_ORIGIN_KEY: preset})
    assert payload[PROCESS_ORIGIN_KEY] is preset


def test_non_dict_payloads_are_queued_untouched():
    logger = _logger()
    logger._internal_callback_wrapper(logger.script)({"type": "error", "description": "x"}, None)
    message, _ = logger._message_queue.get_nowait()
    assert message == {"type": "error", "description": "x"}


def test_origin_registry_round_trip_and_copy():
    logger = _logger()
    assert logger.origin_for_pid(CHILD_PID) is None
    logger.set_process_origin(CHILD_PID, "svc", "child")
    entry = logger.origin_for_pid(CHILD_PID)
    entry["role"] = "mutated"
    assert logger.origin_for_pid(CHILD_PID) == {"pid": CHILD_PID, "process": "svc", "role": "child"}


def test_instrumented_spawn_registers_its_identifier():
    logger = _logger()
    request = types.SimpleNamespace(pid=CHILD_PID, label="spawned process", identifier="com.x:svc")
    logger._note_instrumented_origin(request)
    assert logger.origin_for_pid(CHILD_PID) == {"pid": CHILD_PID, "process": "com.x:svc", "role": "spawn"}
    # Known origin wins over a later identifier (e.g. the exec'd image).
    logger._note_instrumented_origin(types.SimpleNamespace(pid=CHILD_PID, label="exec'd image",
                                                           identifier="/bin/other"))
    assert logger.origin_for_pid(CHILD_PID)["process"] == "com.x:svc"


# --- router -------------------------------------------------------------------

def _routed(payload, data=b""):
    bus = EventBus()
    events = []
    bus.subscribe(FriTapEvent, events.append)
    MessageRouter(bus).route(payload, data)
    return events


def test_router_copies_the_origin_onto_keylog_and_datalog_events():
    keylog = _routed({"contentType": "keylog", "keylog": KEY_LINE, PROCESS_ORIGIN_KEY: CHILD_ORIGIN})
    data = _routed({"contentType": "datalog", "function": "SSL_read",
                    PROCESS_ORIGIN_KEY: CHILD_ORIGIN}, b"hello")
    assert [type(e) for e in keylog] == [KeylogEvent]
    assert keylog[0].process_origin == CHILD_ORIGIN
    assert isinstance(data[0], DatalogEvent) and data[0].process_origin == CHILD_ORIGIN


def test_router_leaves_origin_none_without_a_stamp():
    events = _routed({"contentType": "keylog", "keylog": KEY_LINE})
    assert events[0].process_origin is None


def test_router_sanitizes_a_malformed_origin():
    hostile = {"pid": "1; rm", "process": "\x1b[31mevil" + "x" * 500, "role": 7}
    events = _routed({"contentType": "keylog", "keylog": KEY_LINE, PROCESS_ORIGIN_KEY: hostile})
    origin = events[0].process_origin
    assert origin["pid"] is None and origin["role"] is None
    assert "\x1b" not in origin["process"] and len(origin["process"]) <= 120


def test_console_event_keeps_its_own_origin_tag():
    events = _routed({"contentType": "console", "console": "hi", PROCESS_ORIGIN_KEY: CHILD_ORIGIN})
    assert isinstance(events[0], ConsoleEvent)
    assert events[0].origin == "" and events[0].process_origin == CHILD_ORIGIN


def test_origin_field_is_keyword_only():
    event = KeylogEvent(1.0, "tls", KEY_LINE)
    assert event.key_data == KEY_LINE and event.process_origin is None


# --- outputs ------------------------------------------------------------------

def _stream_records(event):
    stream = io.StringIO()
    handler = JsonlStdoutHandler(include_key_material=False, stream=stream)
    bus = EventBus()
    handler.setup(bus)
    bus.emit(event)
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_jsonl_stream_emits_origin_when_present():
    records = _stream_records(DatalogEvent(data=b"x", process_origin=CHILD_ORIGIN))
    assert records[-1]["type"] == "data"
    assert records[-1]["process_origin"] == CHILD_ORIGIN


def test_jsonl_stream_omits_origin_when_absent():
    records = _stream_records(DatalogEvent(data=b"x"))
    assert "process_origin" not in records[-1]


def test_keylog_file_stays_plain_nss(tmp_path):
    keys = tmp_path / "keys.log"
    handler = KeylogOutputHandler(str(keys), formatter=TlsKeylogFormatter())
    bus = EventBus()
    handler.setup(bus)
    try:
        bus.emit(KeylogEvent(key_data=KEY_LINE, process_origin=CHILD_ORIGIN))
    finally:
        handler.close()
    assert keys.read_text() == KEY_LINE + "\n"


def test_console_prefix_only_for_non_main_processes():
    assert origin_prefix(KeylogEvent(key_data=KEY_LINE)) == ""
    main = {"pid": MAIN_PID, "process": "app", "role": "target"}
    assert origin_prefix(KeylogEvent(key_data=KEY_LINE, process_origin=main)) == ""
    child = KeylogEvent(key_data=KEY_LINE, process_origin=CHILD_ORIGIN)
    assert origin_prefix(child) == f"[{CHILD_PID} com.example.app:remote] "


def _console_lines(caplog, event):
    handler = ConsoleOutputHandler(verbose=True)
    bus = EventBus()
    handler.setup(bus)
    with caplog.at_level(logging.INFO, logger="friTap"):
        bus.emit(event)
    return [r.getMessage() for r in caplog.records]


def test_single_process_console_output_unchanged(caplog):
    main = {"pid": MAIN_PID, "process": "app", "role": "target"}
    assert _console_lines(caplog, KeylogEvent(key_data=KEY_LINE, process_origin=main)) == [KEY_LINE]


def test_child_console_output_is_prefixed(caplog):
    lines = _console_lines(caplog, KeylogEvent(key_data=KEY_LINE, process_origin=CHILD_ORIGIN))
    assert lines == [f"[{CHILD_PID} com.example.app:remote] {KEY_LINE}"]


# --- flows / .tap -------------------------------------------------------------

def _request_event(origin=None):
    return DatalogEvent(
        data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", function="SSL_write",
        direction="write", src_addr="10.0.0.2", src_port=51000, dst_addr="93.184.216.34",
        dst_port=443, timestamp=100.0, process_origin=origin)


def _collected_flow(origin=None):
    collector = FlowCollector()
    collector.set_capture_target("com.example.app")
    collector.on_data(_request_event(origin))
    (flow,) = collector.get_flows()
    return flow


def test_child_flow_carries_pid_role_and_name_through_tap():
    flow = decode_flow(encode_flow(_collected_flow(CHILD_ORIGIN)))
    assert (flow.pid, flow.process_role) == (CHILD_PID, "child")
    assert flow.process_name == "com.example.app:remote"


def test_main_flow_keeps_the_capture_target_name():
    main = {"pid": MAIN_PID, "process": "other", "role": "target"}
    flow = _collected_flow(main)
    assert (flow.pid, flow.process_role, flow.process_name) == (MAIN_PID, "target", "com.example.app")


def test_flow_without_origin_writes_no_pid_meta():
    flow = _collected_flow()
    decoded = decode_flow(encode_flow(flow))
    assert decoded.pid is None and decoded.process_role == ""
    assert b'"pid"' not in encode_flow(flow) and b"process_role" not in encode_flow(flow)


def test_origin_prefix_escapes_process_name():
    origin = {"pid": CHILD_PID, "process": "evil\x1b[2J", "role": "child"}
    prefix = origin_prefix(KeylogEvent(key_data=KEY_LINE, process_origin=origin))
    assert "\x1b" not in prefix and "evil\\x1b[2J" in prefix
