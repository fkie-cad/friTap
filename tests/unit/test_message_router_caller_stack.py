#!/usr/bin/env python3

"""The MessageRouter resolves a ``caller_stack`` backtrace to its owning SDK.

Opt-in SDK/caller attribution (``--attribute-sdk``): the agent captures the
calling thread's backtrace once per connection and emits an additive
``caller_stack`` message carrying Java and native frames. The host router hands
those frames to :func:`friTap.analysis.attribution.sdk.classify_frames` (purely
as lookup keys) and ALWAYS emits ONE :class:`~friTap.events.CallerStackEvent`:
``sdk`` is the trusted ``{sdk,vendor,category}`` dict on a match, else ``None``.
The attacker-controlled frame strings travel only under ``event.untrusted``,
escaped and capped at 120 characters (16 frames per kind), so an unclassified
stack still reaches the collector as the flow's ``caller_stack``.
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


def test_native_only_frames_resolve_to_react_native():
    # libflutter.so is a transport (deny-listed as originator), so a
    # non-transport native SDK module exercises native-only resolution.
    events = _route({
        "contentType": "caller_stack",
        "ssl_session_id": "cafef00d",
        "java_frames": [],
        "native_frames": [
            {"module": "libhermes.so", "symbol": "ssl_write", "address": "0x1000"},
            {"module": "libc.so", "address": "0x2000"},
        ],
    })
    assert len(events) == 1
    assert events[0].sdk == {"sdk": "React Native", "vendor": "Meta", "category": "framework"}


def test_native_only_transport_frames_have_no_sdk():
    events = _route({
        "contentType": "caller_stack",
        "ssl_session_id": "cafef00e",
        "java_frames": [],
        "native_frames": [
            {"module": "libflutter.so", "symbol": "ssl_write", "address": "0x1000"},
            {"module": "libc.so", "address": "0x2000"},
        ],
    })
    assert len(events) == 1
    assert events[0].sdk is None


def test_unresolvable_stack_emits_event_without_sdk():
    events = _route({
        "contentType": "caller_stack",
        "ssl_session_id": "beadfeed",
        "java_frames": ["com.example.app.MainActivity"],
        "native_frames": [{"module": "libc.so"}],
    })
    (event,) = events
    assert isinstance(event, CallerStackEvent)
    assert event.sdk is None
    assert event.untrusted["java_frames"] == ["com.example.app.MainActivity"]
    assert event.untrusted["native_frames"] == [{"module": "libc.so", "symbol": ""}]


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


def test_identity_fields_pass_through_to_event():
    events = _route({
        "contentType": "caller_stack",
        "src_addr": "10.0.0.2", "src_port": 40000,
        "dst_addr": "93.184.216.34", "dst_port": 443,
        "java_frames": ["com.facebook.appevents.AppEventsLogger"],
        "client_random": "ab" * 32,
        "tid": 4242,
        "thread_name": "OkHttp Dispatch",
        "pid": 1234,
        "transport_module": "libssl.so",
    })
    (event,) = events
    assert event.client_random == "ab" * 32
    assert (event.tid, event.pid) == (4242, 1234)
    assert event.thread_name == "OkHttp Dispatch"
    assert event.transport_module == "libssl.so"


def test_identity_fields_default_when_absent_or_invalid():
    (event,) = _route({
        "contentType": "caller_stack",
        "java_frames": ["com.facebook.appevents.AppEventsLogger"],
        "tid": "not-a-number",
    })
    assert event.client_random == "" and event.thread_name == ""
    assert (event.tid, event.pid) == (0, 0)
    assert event.transport_module == ""


def test_client_random_is_normalized_to_lower_case():
    (event,) = _route({
        "contentType": "caller_stack",
        "java_frames": [],
        "client_random": "AB" * 32,
    })
    assert event.client_random == "ab" * 32


def test_untrusted_frames_are_capped_and_escaped():
    long_text = "x" * 500
    (event,) = _route({
        "contentType": "caller_stack",
        "java_frames": ["evil\x1b[31m"] + [long_text] * 40,
        "native_frames": [{"module": long_text, "symbol": "s\x07"}] * 40,
        "thread_name": "t\x1b" + long_text,
        "transport_module": long_text,
    })
    untrusted = event.untrusted
    assert len(untrusted["java_frames"]) == 16
    assert len(untrusted["native_frames"]) == 16
    assert "\x1b" not in untrusted["java_frames"][0]
    assert untrusted["java_frames"][0].startswith("evil\\x1b")
    assert all(len(f) <= 120 for f in untrusted["java_frames"])
    frame = untrusted["native_frames"][0]
    assert len(frame["module"]) == 120 and frame["symbol"] == "s\\x07"
    # Only frames live under untrusted; thread/module names are the capped
    # top-level fields.
    assert set(untrusted) == {"native_frames", "java_frames"}
    assert len(event.thread_name) == 120 and "\x1b" not in event.thread_name
    assert len(event.transport_module) == 120


def test_non_list_frames_yield_empty_untrusted_lists():
    (event,) = _route({
        "contentType": "caller_stack",
        "java_frames": "not-a-list",
        "native_frames": {"module": "x"},
    })
    assert event.untrusted["java_frames"] == []
    assert event.untrusted["native_frames"] == []


def test_debug_line_names_counts_and_sdk():
    import logging

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
        _route({
            "contentType": "caller_stack",
            "client_random": "cd" * 32,
            "java_frames": ["com.facebook.appevents.AppEventsLogger"],
            "native_frames": [{"module": "libc.so"}, {"module": "libssl.so"}],
        })
        _route({"contentType": "caller_stack", "java_frames": []})
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
    lines = [r for r in records if r.startswith("caller_stack ")]
    assert lines == [
        "caller_stack cr=" + "cd" * 8 + " native=2 java=1 sdk=Facebook SDK",
        "caller_stack cr=- native=0 java=0 sdk=-",
    ]


def test_non_negative_int_coercion():
    from friTap.caller_stack_shapes import non_negative_int
    assert [non_negative_int(v) for v in (7, "42", " 3 ", -5, True, "x", None, 1.5, [])] == \
        [7, 42, 3, 0, 0, 0, 0, 0, 0]


def test_frames_are_sliced_before_escaping(monkeypatch):
    from friTap import caller_stack_shapes
    calls = []

    def counting(value, limit):
        calls.append(value)
        return str(value)[:limit]

    monkeypatch.setattr(caller_stack_shapes, "capped_text", counting)
    caller_stack_shapes.untrusted_caller_stack({"java_frames": ["f"] * 500, "native_frames": [1, {}] * 100})
    assert len(calls) == 16 + 2 * 16  # 16 java frames, 16 native frames x (module, symbol)


def test_lookup_keys_are_raw_and_filtered():
    from friTap.caller_stack_shapes import caller_stack_lookup_keys
    java, native = caller_stack_lookup_keys({
        "java_frames": ["a\x1b", 3], "native_frames": [{"module": "m"}, {"module": ""}, "x"]})
    assert (java, native) == (["a\x1b"], ["m"])


def test_strict_int_rejects_bools_strings_and_floats():
    from friTap.caller_stack_shapes import strict_int
    assert strict_int(7) == 7 and strict_int(-1) == -1
    assert [strict_int(v) for v in (True, "7", 7.0, None)] == [None] * 4


def test_finite_float_rejects_bools_non_finite_and_huge_ints():
    from friTap.caller_stack_shapes import finite_float
    assert finite_float(3) == 3.0 and isinstance(finite_float(3), float)
    assert finite_float(1.5) == 1.5
    junk = (True, float("nan"), float("inf"), "1.0", None, 10 ** 400)
    assert [finite_float(v) for v in junk] == [None] * len(junk)


def test_bounded_strings_skips_non_strings_caps_and_escapes():
    from friTap.caller_stack_shapes import bounded_strings
    first, second, *rest = bounded_strings(["ab\x1b", 3, "cdef", "g"], 2, 3)
    assert rest == [] and second == "cde"
    assert len(first) == 3 and "\x1b" not in first
    assert bounded_strings("not a list", 5, 5) == []
