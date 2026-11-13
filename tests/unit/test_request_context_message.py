#!/usr/bin/env python3

"""The opt-in ``request_context`` message on the host: schema, router bounds, collector wiring and buffering."""

from __future__ import annotations

import logging
import time
import types
from typing import get_args

import pytest
from pydantic import TypeAdapter, ValidationError

from friTap.caller_stack_shapes import (
    REQUEST_CONTEXT_FRAME_LIMIT,
    REQUEST_CONTEXT_URL_LIMIT,
)
from friTap.constants import ContentType
from friTap.events import EventBus, RequestContextEvent
from friTap.flow import request_context_join
from friTap.flow.collector import FlowCollector
from friTap.message_router import REQUEST_CONTEXT_EVENTS, MessageRouter
from friTap.schemas.agent_messages import (
    AgentMessage,
    RequestContextMessage,
    RequestContextPoint,
)


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _route(payload: dict):
    bus = _Bus()
    MessageRouter(bus).route(payload, b"")
    return bus.events


def _payload(**overrides) -> dict:
    payload = {"contentType": "request_context", "event": "start", "req_id": "r1"}
    payload.update(overrides)
    return payload


# --- schema ---------------------------------------------------------------

def test_content_type_constant():
    assert ContentType.REQUEST_CONTEXT == "request_context"


def test_schema_validates_through_agent_message_union():
    msg = TypeAdapter(AgentMessage).validate_python(_payload(
        event="response", stack_kind="cronet", url="https://api.example.com/v1?q=1",
        method="GET", frames=["com.example.Api.fetch"], thread="OkHttp", tid=42,
        t_ms=1731500000000.5, status=200, negotiated_protocol="h2", cached=False,
        webview_id=None, main_frame=None))
    assert isinstance(msg, RequestContextMessage)
    assert msg.protocol == "tls"
    assert msg.negotiated_protocol == "h2"
    assert msg.frames == ["com.example.Api.fetch"]


def test_schema_requires_event_and_req_id():
    with pytest.raises(ValidationError):
        RequestContextMessage(req_id="r1")
    with pytest.raises(ValidationError):
        RequestContextMessage(event="start")
    with pytest.raises(ValidationError):
        RequestContextMessage(event="bogus", req_id="r1")


def test_schema_optional_fields_default_to_none():
    msg = RequestContextMessage(event="end", req_id="r1")
    assert msg.url is None and msg.status is None and msg.cached is None
    assert msg.frames == []


def test_router_event_set_matches_the_schema_literal():
    assert REQUEST_CONTEXT_EVENTS == frozenset(get_args(RequestContextPoint))


def test_join_event_constants_match_the_schema_literal():
    join_events = {
        value for name, value in vars(request_context_join).items()
        if name.startswith("EVENT_") and isinstance(value, str)
    }
    assert join_events == set(get_args(RequestContextPoint))


# --- router ---------------------------------------------------------------

def test_valid_payload_becomes_an_event():
    before = time.time()
    events = _route(_payload(
        event="response", stack_kind="gms-cronet",
        url="https://api.example.com/v1/items?id=7&token=abc", method="POST",
        frames=["com.example.Api.post", "org.chromium.net.UrlRequest.start"],
        thread="Worker-1", tid=1234, t_ms=1731500000123, status=201,
        negotiated_protocol="h3", cached=True, error=None, protocol="tls"))
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, RequestContextEvent)
    assert event.event == "response"
    assert event.req_id == "r1"
    assert event.stack_kind == "gms-cronet"
    # The full URL, query included, is kept (only capped/escaped).
    assert event.url == "https://api.example.com/v1/items?id=7&token=abc"
    assert event.method == "POST"
    assert event.frames == ["com.example.Api.post", "org.chromium.net.UrlRequest.start"]
    assert (event.thread, event.tid, event.status) == ("Worker-1", 1234, 201)
    assert event.t_ms == 1731500000123.0 and isinstance(event.t_ms, float)
    assert event.negotiated_protocol == "h3"
    assert event.cached is True
    assert event.error == ""
    assert event.protocol == "tls"
    # Host receive time on the same clock as every other event.
    assert before <= event.timestamp <= time.time()


def test_webview_fields_pass_through():
    (event,) = _route(_payload(event="webview_request", stack_kind="webview",
                               webview_id="wv-3", main_frame=True))
    assert (event.webview_id, event.main_frame) == ("wv-3", True)


def test_hostile_strings_are_escaped():
    (event,) = _route(_payload(
        req_id="r\x1b[31m", url="https://x.example/\x1b]0;pwn\x07",
        method="GET\x00", thread="t\x1b", frames=["a.B\x1b[2J"],
        negotiated_protocol="h2\x9b", error="boom\x1b", stack_kind="cronet\x07",
        webview_id="w\x1b"))
    for text in (event.req_id, event.url, event.method, event.thread, event.frames[0],
                 event.negotiated_protocol, event.error, event.stack_kind, event.webview_id):
        assert "\x1b" not in text and "\x07" not in text and "\x00" not in text
        assert "\x9b" not in text


def test_url_is_capped_at_2048():
    url = "https://example.com/?q=" + "a" * 5000
    (event,) = _route(_payload(url=url))
    assert REQUEST_CONTEXT_URL_LIMIT == 2048
    assert event.url == url[:2048]


def test_frames_are_capped_in_count_and_length():
    frames = ["c%d.%s" % (i, "m" * 500) for i in range(100)]
    (event,) = _route(_payload(frames=frames))
    assert len(event.frames) == REQUEST_CONTEXT_FRAME_LIMIT == 32
    assert all(len(frame) <= 120 for frame in event.frames)
    assert event.frames[0].startswith("c0.")


def test_non_string_frames_are_skipped():
    (event,) = _route(_payload(frames=["a.b", 7, None, {"x": 1}, ["y"], "c.d"]))
    assert event.frames == ["a.b", "c.d"]


@pytest.mark.parametrize("bad", [
    {"event": "bogus"},
    {"event": None},
    {"event": ["start"]},          # unhashable: must not raise TypeError
    {"event": {"a": 1}},
    {"req_id": ""},
    {"req_id": None},
    {"req_id": 17},
    {"req_id": ["r"]},
])
def test_malformed_payloads_are_dropped(bad):
    assert _route(_payload(**bad)) == []


def test_missing_event_or_req_id_is_dropped():
    assert _route({"contentType": "request_context", "req_id": "r"}) == []
    assert _route({"contentType": "request_context", "event": "start"}) == []


def test_drop_is_logged_at_debug():
    records = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = logging.getLogger("friTap.router")
    handler = _Capture(level=logging.DEBUG)
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        _route(_payload(event="nope\x1b"))
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
    dropped = [r for r in records if r.startswith("request_context dropped")]
    assert len(dropped) == 1
    assert "\x1b" not in dropped[0]


@pytest.mark.parametrize("field_name,bad", [
    ("tid", "12"), ("tid", True), ("tid", 1.5),
    ("status", "200"), ("status", False),
    ("t_ms", "now"), ("t_ms", True), ("t_ms", float("nan")), ("t_ms", float("inf")),
    ("cached", "yes"), ("cached", 1),
    ("main_frame", 0),
])
def test_wrongly_typed_optionals_become_none(field_name, bad):
    (event,) = _route(_payload(**{field_name: bad}))
    assert getattr(event, field_name) is None


def test_wrongly_typed_text_and_frames_become_empty():
    (event,) = _route(_payload(url=123, method={"x": 1}, frames="a.b", thread=["t"]))
    assert (event.url, event.method, event.thread, event.frames) == ("", "", "", [])


# --- collector ------------------------------------------------------------

def test_collector_folds_events_from_the_bus_into_the_store():
    bus = EventBus()
    collector = FlowCollector()
    seen = []
    collector.set_request_context_sink(seen.append)
    bus.subscribe(RequestContextEvent, collector.on_request_context)
    MessageRouter(bus).route(_payload(), b"")
    MessageRouter(bus).route(_payload(event="end"), b"")
    assert len(collector._request_contexts) == 1  # one req_id, two lifecycle points
    assert collector.get_flows() == []
    collector.flush()
    (record,) = seen
    assert record["t_end"] is not None


def test_collector_store_is_bounded():
    from friTap.flow.request_context_join import RequestContextStore
    collector = FlowCollector()
    collector._request_contexts = RequestContextStore(
        collector._classify_request_frames, max_contexts=3)
    seen = []
    collector.set_request_context_sink(seen.append)
    for i in range(5):
        collector.on_request_context(RequestContextEvent(event="start", req_id=str(i)))
    assert len(collector._request_contexts) == 3
    assert [record["req_id"] for record in seen] == ["0", "1"]  # oldest pushed out


def test_collector_clear_drops_live_contexts():
    collector = FlowCollector()
    collector.on_request_context(RequestContextEvent(event="start", req_id="r"))
    collector.clear()
    assert len(collector._request_contexts) == 0


# --- subscription ---------------------------------------------------------

def test_subscribe_to_wires_every_collector_handler():
    from friTap.events import (
        CallerStackEvent,
        DatalogEvent,
        KeylogEvent,
        LibraryDetectedEvent,
        OhttpEvent,
        SessionEvent,
    )
    subscriptions = {}
    bus = types.SimpleNamespace(
        subscribe=lambda etype, cb, **k: subscriptions.setdefault(etype, []).append(cb))
    collector = FlowCollector()
    collector.subscribe_to(bus)
    assert subscriptions == {
        DatalogEvent: [collector.on_data],
        KeylogEvent: [collector.on_keylog],
        OhttpEvent: [collector.on_ohttp],
        LibraryDetectedEvent: [collector.on_library_detected],
        SessionEvent: [collector.on_session_event],
        CallerStackEvent: [collector.on_sdk],
        RequestContextEvent: [collector.on_request_context],
    }


def test_subscribe_to_routes_request_contexts_from_the_bus():
    bus = EventBus()
    collector = FlowCollector()
    collector.subscribe_to(bus)
    MessageRouter(bus).route(_payload(), b"")
    assert len(collector._request_contexts) == 1


def test_tap_handler_subscribes_collector_and_registers_the_sink():
    from friTap.output.tap_handler import TapOutputHandler

    calls = []
    collector = types.SimpleNamespace(
        subscribe=lambda cb: None,
        subscribe_to=lambda bus: calls.append(("subscribe_to", bus)),
        set_request_context_sink=lambda sink: calls.append(("sink", sink)))
    writer = types.SimpleNamespace(open=lambda path, target="": None, path="x.tap",
                                   on_flow_event=None, write_request_context="WRITE")
    handler = TapOutputHandler("x.tap", collector_factory=lambda: collector,
                               writer_factory=lambda: writer)
    handler.setup("BUS")
    assert calls == [("sink", "WRITE"), ("subscribe_to", "BUS")]
