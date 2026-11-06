#!/usr/bin/env python3

"""The MessageRouter resolves a ``caller_stack`` backtrace to its owning SDK.

Opt-in SDK/caller attribution (``--attribute-sdk``): the agent captures the
calling thread's backtrace once per connection and emits an additive
``caller_stack`` message carrying Java and native frames. The host router hands
those frames to :func:`friTap.analysis.attribution.sdk.classify_frames` (purely
as lookup keys — the attacker-controlled frame strings are never echoed) and, on
a match, emits ONE :class:`~friTap.events.CallerStackEvent` carrying only the
trusted ``{sdk,vendor,category}`` dict plus the ``ssl_session_id`` join key. An
unresolvable stack is a no-op (no event), so a flow without a known SDK keeps
``sdk = None``.
"""

from __future__ import annotations

from friTap.events import CallerStackEvent
from friTap.message_router import MessageRouter


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _route(payload: dict):
    bus = _Bus()
    MessageRouter(bus).route(payload, b"")
    return bus.events


def test_java_frames_resolve_to_facebook_sdk():
    events = _route({
        "contentType": "caller_stack",
        "ssl_session_id": "deadbeef",
        "java_frames": [
            "com.facebook.appevents.AppEventsLogger",
            "okhttp3.RealCall",
        ],
    })
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, CallerStackEvent)
    assert event.ssl_session_id == "deadbeef"
    assert event.sdk == {"sdk": "Facebook SDK", "vendor": "Meta", "category": "social"}


def test_native_only_frames_resolve_to_flutter():
    events = _route({
        "contentType": "caller_stack",
        "ssl_session_id": "cafef00d",
        "java_frames": [],
        "native_frames": [
            {"module": "libflutter.so", "symbol": "ssl_write", "address": "0x1000"},
            {"module": "libc.so", "address": "0x2000"},
        ],
    })
    assert len(events) == 1
    assert events[0].sdk == {"sdk": "Flutter", "vendor": "Google", "category": "framework"}


def test_unresolvable_stack_emits_nothing():
    events = _route({
        "contentType": "caller_stack",
        "ssl_session_id": "beadfeed",
        "java_frames": ["com.example.app.MainActivity"],
        "native_frames": [{"module": "libc.so"}],
    })
    assert events == []


def test_connection_5_tuple_is_forwarded_onto_event():
    # The agent now populates the connection 5-tuple on the caller_stack (the
    # ssl_session_id is still "0" at first write); the router validates it the
    # same way as a datalog record and forwards it so the collector can join on
    # it. Addresses come through get_addr_string; ports are coerced to range.
    events = _route({
        "contentType": "caller_stack",
        "ssl_session_id": "0",
        "src_addr": "10.0.0.2",
        "src_port": 51000,
        "dst_addr": "93.184.216.34",
        "dst_port": 443,
        "ss_family": "AF_INET",
        "java_frames": ["com.facebook.appevents.AppEventsLogger"],
    })
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, CallerStackEvent)
    assert event.ssl_session_id == "0"
    assert (event.src_addr, event.src_port) == ("10.0.0.2", 51000)
    assert (event.dst_addr, event.dst_port) == ("93.184.216.34", 443)
    assert event.sdk["sdk"] == "Facebook SDK"


def test_malformed_frames_do_not_crash():
    # Frames are attacker-controlled: non-string Java frames and native frames
    # without a usable module are ignored rather than raising.
    events = _route({
        "contentType": "caller_stack",
        "ssl_session_id": "f00d",
        "java_frames": [123, None, "com.facebook.appevents.AppEventsLogger"],
        "native_frames": [{"symbol": "x"}, {"module": 42}, "not-a-dict"],
    })
    assert len(events) == 1
    assert events[0].sdk["sdk"] == "Facebook SDK"
