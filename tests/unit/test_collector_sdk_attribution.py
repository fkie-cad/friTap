#!/usr/bin/env python3

"""FlowCollector joins a resolved caller-stack SDK onto its flow, and the
``.tap`` format round-trips the ``sdk`` field.

Opt-in SDK/caller attribution (``--attribute-sdk``): the MessageRouter resolves
a ``caller_stack`` backtrace to an SDK and emits a
:class:`~friTap.events.CallerStackEvent` carrying the trusted
``{sdk,vendor,category}`` dict plus the connection 5-tuple (and, best-effort, the
``ssl_session_id``).

The collector joins primarily on the **5-tuple**: at the first SSL_read/SSL_write
where the backtrace is captured ``SSL_get_session(ssl)`` is still null, so every
caller_stack carries ``ssl_session_id == "0"`` — an id-only join matched nothing.
The 5-tuple IS stable at first write, so the collector matches a flow on its
stored src/dst addr+port (direction-insensitive), stashes for a flow created
LATER (backtrace before the first data event), guards against OS fd/port reuse by
attributing to the earliest flow that lacks an SDK, and never clobbers an SDK.
A flow with no caller_stack keeps ``sdk=None``.
"""

from __future__ import annotations

from friTap.events import CallerStackEvent, DatalogEvent, EventBus
from friTap.flow.collector import FlowCollector
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.tap_format import decode_flow, encode_flow

SRC_ADDR = "10.0.0.2"
SRC_PORT = 51000
DST_ADDR = "93.184.216.34"
DST_PORT = 443
SESSION_ID = "FEEDFACE" * 4
FB_SDK = {"sdk": "Facebook SDK", "vendor": "Meta", "category": "social"}


def _wire_up():
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    bus.subscribe(CallerStackEvent, collector.on_sdk)
    return bus, collector


def _make_datalog(ssl_session_id=SESSION_ID, timestamp=1000.0,
                  src_addr=SRC_ADDR, dst_addr=DST_ADDR):
    return DatalogEvent(
        data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        function="SSL_write",
        direction="write",
        src_addr=src_addr,
        src_port=SRC_PORT,
        dst_addr=dst_addr,
        dst_port=DST_PORT,
        ssl_session_id=ssl_session_id,
        timestamp=timestamp,
    )


def _caller_stack(ssl_session_id="0", sdk=None,
                  src_addr=SRC_ADDR, src_port=SRC_PORT,
                  dst_addr=DST_ADDR, dst_port=DST_PORT):
    """A caller_stack carrying the connection 5-tuple (as the agent now emits).

    ``ssl_session_id`` defaults to ``"0"`` — the real on-device value at the
    first SSL_read/SSL_write — so the join rests on the 5-tuple alone.
    """
    return CallerStackEvent(
        ssl_session_id=ssl_session_id,
        src_addr=src_addr,
        src_port=src_port,
        dst_addr=dst_addr,
        dst_port=dst_port,
        sdk=sdk or dict(FB_SDK),
    )


# ---------------------------------------------------------------------------
# Join by 5-tuple: data first, then caller_stack (ssl_session_id == "0")
# ---------------------------------------------------------------------------

def test_caller_stack_after_flow_attaches_sdk_by_tuple():
    bus, collector = _wire_up()
    bus.emit(_make_datalog())
    flow = collector.get_flows()[0]
    assert flow.sdk is None  # no attribution yet

    bus.emit(_caller_stack())  # ssl_session_id == "0"; joins on the 5-tuple
    assert collector.get_flows()[0].sdk == FB_SDK


def test_tuple_join_is_direction_insensitive():
    """The backtrace may be captured at a read (src/dst reversed vs a write flow).

    The unordered-endpoint key makes the swapped 5-tuple match anyway.
    """
    bus, collector = _wire_up()
    bus.emit(_make_datalog())  # flow stored as src=local, dst=peer (a write)
    # A read-captured caller_stack carries the reversed orientation.
    bus.emit(_caller_stack(src_addr=DST_ADDR, src_port=DST_PORT,
                           dst_addr=SRC_ADDR, dst_port=SRC_PORT))
    assert collector.get_flows()[0].sdk == FB_SDK


# ---------------------------------------------------------------------------
# Join: caller_stack first (stash on the 5-tuple), then the flow is created
# ---------------------------------------------------------------------------

def test_caller_stack_before_flow_backfills_on_creation_by_tuple():
    bus, collector = _wire_up()
    bus.emit(_caller_stack())  # no flow yet -> stashed on the 5-tuple
    assert collector.get_flows() == []  # nothing created by the stack event

    bus.emit(_make_datalog())  # flow born -> drains the tuple stash at birth
    assert collector.get_flows()[0].sdk == FB_SDK


# ---------------------------------------------------------------------------
# A different 5-tuple does not match
# ---------------------------------------------------------------------------

def test_caller_stack_other_tuple_does_not_attach():
    bus, collector = _wire_up()
    bus.emit(_make_datalog())
    # Different server address -> different 5-tuple key; ssl_session_id "0" is
    # not a usable secondary key, so nothing matches.
    bus.emit(_caller_stack(dst_addr="203.0.113.9"))
    assert collector.get_flows()[0].sdk is None


# ---------------------------------------------------------------------------
# No caller_stack at all -> sdk stays None
# ---------------------------------------------------------------------------

def test_flow_without_caller_stack_has_no_sdk():
    bus, collector = _wire_up()
    bus.emit(_make_datalog())
    assert collector.get_flows()[0].sdk is None


# ---------------------------------------------------------------------------
# Empty / missing SDK is a no-op
# ---------------------------------------------------------------------------

def test_empty_sdk_event_is_noop():
    bus, collector = _wire_up()
    bus.emit(_make_datalog())
    bus.emit(CallerStackEvent(ssl_session_id="0", src_addr=SRC_ADDR,
                              src_port=SRC_PORT, dst_addr=DST_ADDR,
                              dst_port=DST_PORT, sdk=None))
    assert collector.get_flows()[0].sdk is None


# ---------------------------------------------------------------------------
# No usable join key (no 5-tuple, ssl_session_id == "0") is a no-op
# ---------------------------------------------------------------------------

def test_caller_stack_without_tuple_or_real_sid_is_noop():
    bus, collector = _wire_up()
    bus.emit(_make_datalog())
    bus.emit(CallerStackEvent(ssl_session_id="0", sdk=dict(FB_SDK)))  # no 5-tuple
    assert collector.get_flows()[0].sdk is None


# ---------------------------------------------------------------------------
# Secondary match: a real (non-"0") ssl_session_id still joins
# ---------------------------------------------------------------------------

def test_real_session_id_is_secondary_match():
    bus, collector = _wire_up()
    bus.emit(_make_datalog(ssl_session_id=SESSION_ID))
    # Different 5-tuple, but the real session id matches as a secondary key.
    bus.emit(_caller_stack(ssl_session_id=SESSION_ID, dst_addr="203.0.113.9"))
    assert collector.get_flows()[0].sdk == FB_SDK


# ---------------------------------------------------------------------------
# OS fd/port reuse: each caller_stack attributes to a DISTINCT unattributed flow
# ---------------------------------------------------------------------------

def _inject_flow(collector, flow_id, conn_id):
    """White-box: register a minimal ACTIVE flow sharing the test 5-tuple.

    Mirrors :meth:`FlowCollector._make_flow` by also adding the flow to the
    per-connection index, so per-connection SDK propagation sees it.
    """
    flow = Flow(flow_id=flow_id, connection_id=conn_id,
                src_addr=SRC_ADDR, src_port=SRC_PORT,
                dst_addr=DST_ADDR, dst_port=DST_PORT,
                state=FlowState.ACTIVE, started=1000.0)
    collector._flows[flow_id] = flow
    collector._index_flow(flow)
    return flow


def test_fd_reuse_picks_earliest_unattributed_flow():
    bus, collector = _wire_up()
    # Two distinct connections that reused the same 5-tuple over time.
    flow_a = _inject_flow(collector, "c-a:0", "c-a")
    flow_b = _inject_flow(collector, "c-b:0", "c-b")

    # One caller_stack stamps only the earliest unattributed flow.
    bus.emit(_caller_stack())
    assert flow_a.sdk == FB_SDK
    assert flow_b.sdk is None  # not clobbered / not over-attributed

    # The second connection's caller_stack takes the next unattributed flow.
    bus.emit(_caller_stack())
    assert flow_b.sdk == FB_SDK

    # A third stack has no unattributed flow to claim -> neither is clobbered.
    bus.emit(_caller_stack(sdk={"sdk": "Other", "vendor": "x", "category": "y"}))
    assert flow_a.sdk == FB_SDK
    assert flow_b.sdk == FB_SDK


def test_existing_sdk_is_never_clobbered():
    bus, collector = _wire_up()
    flow = _inject_flow(collector, "c-a:0", "c-a")
    flow.sdk = {"sdk": "Preset", "vendor": "x", "category": "y"}
    bus.emit(_caller_stack())
    assert flow.sdk == {"sdk": "Preset", "vendor": "x", "category": "y"}


# ---------------------------------------------------------------------------
# Per-connection propagation: one caller_stack attributes every flow of its
# connection (e.g. all HTTP/2 streams multiplexed over one TLS connection).
# ---------------------------------------------------------------------------

def test_caller_stack_propagates_to_all_connection_flows():
    bus, collector = _wire_up()
    # One HTTP/2 connection, three multiplexed stream flows sharing connection_id.
    s0 = _inject_flow(collector, "c-h2:0", "c-h2")
    s1 = _inject_flow(collector, "c-h2:1", "c-h2")
    s2 = _inject_flow(collector, "c-h2:2", "c-h2")

    # The connection's lone caller_stack attributes ALL of its streams.
    bus.emit(_caller_stack())
    assert s0.sdk == FB_SDK
    assert s1.sdk == FB_SDK
    assert s2.sdk == FB_SDK


def test_propagation_stays_within_the_connection():
    bus, collector = _wire_up()
    # Two concurrent connections to the same peer (same 5-tuple), distinct ids.
    a0 = _inject_flow(collector, "c-a:0", "c-a")
    a1 = _inject_flow(collector, "c-a:1", "c-a")
    b0 = _inject_flow(collector, "c-b:0", "c-b")

    # First caller_stack attributes connection c-a and ALL its streams, but not b.
    bus.emit(_caller_stack())
    assert a0.sdk == FB_SDK and a1.sdk == FB_SDK
    assert b0.sdk is None

    # The second connection's caller_stack attributes b0 (next unattributed).
    other = {"sdk": "AppsFlyer", "vendor": "AppsFlyer", "category": "attribution"}
    bus.emit(_caller_stack(sdk=other))
    assert b0.sdk == other
    # c-a keeps its own SDK — never clobbered by b's stack.
    assert a0.sdk == FB_SDK and a1.sdk == FB_SDK


def test_stream_born_after_join_inherits_connection_sdk():
    """A stream flow created AFTER its connection's caller_stack already joined
    inherits the connection's SDK at birth (via _stamp_metadata)."""
    bus, collector = _wire_up()
    # An earlier stream of the connection is already attributed and indexed.
    _inject_flow(collector, "c-h2:0", "c-h2").sdk = dict(FB_SDK)

    # A later stream of the SAME connection is born (no pending stash for it).
    newborn = Flow(flow_id="c-h2:1", connection_id="c-h2",
                   src_addr=SRC_ADDR, src_port=SRC_PORT,
                   dst_addr=DST_ADDR, dst_port=DST_PORT,
                   state=FlowState.ACTIVE, started=2000.0)
    assert newborn.sdk is None
    collector._stamp_metadata(newborn, _make_datalog(timestamp=2000.0))
    assert newborn.sdk == FB_SDK


def test_stream_of_unattributed_connection_stays_none_at_birth():
    """Birth-time inheritance only fires when a sibling already carries an SDK."""
    bus, collector = _wire_up()
    _inject_flow(collector, "c-h2:0", "c-h2")  # sibling, but NOT attributed

    newborn = Flow(flow_id="c-h2:1", connection_id="c-h2",
                   src_addr=SRC_ADDR, src_port=SRC_PORT,
                   dst_addr=DST_ADDR, dst_port=DST_PORT,
                   state=FlowState.ACTIVE, started=2000.0)
    collector._stamp_metadata(newborn, _make_datalog(timestamp=2000.0))
    assert newborn.sdk is None


def test_released_sibling_sdk_survives_via_connection_map():
    """Headless path (retain_completed=False): the connection's first flow is
    attributed then written and released from _flows, yet a later flow of the
    SAME connection still inherits the SDK from the persistent per-connection
    map -- the case the live _flows scan alone cannot cover."""
    bus, collector = _wire_up()
    s0 = _inject_flow(collector, "c-h2:0", "c-h2")
    bus.emit(_caller_stack())                      # on_sdk attributes s0 + records map
    assert s0.sdk == FB_SDK
    assert collector._connection_sdks["c-h2"] == FB_SDK

    # Simulate the headless writer releasing s0 after persisting it.
    collector._flows.pop("c-h2:0")
    collector._unindex_flow(s0)

    newborn = Flow(flow_id="c-h2:1", connection_id="c-h2",
                   src_addr=SRC_ADDR, src_port=SRC_PORT,
                   dst_addr=DST_ADDR, dst_port=DST_PORT,
                   state=FlowState.ACTIVE, started=2000.0)
    collector._stamp_metadata(newborn, _make_datalog(timestamp=2000.0))
    assert newborn.sdk == FB_SDK                   # inherited from the map, not _flows


# ---------------------------------------------------------------------------
# Arrival-before-flow stash is drained (and consumed) on the first flow's birth
# ---------------------------------------------------------------------------

def test_tuple_stash_drained_and_consumed_on_birth():
    bus, collector = _wire_up()
    bus.emit(_caller_stack())           # stashed on the 5-tuple (no flow yet)
    bus.emit(_make_datalog(ssl_session_id="A" * 32))  # first flow drains it
    flows = collector.get_flows()
    assert flows[0].sdk == FB_SDK
    # The stash entry is consumed, not left to re-apply to unrelated later flows.
    assert collector._sdk_pending == {}

    # Continued traffic on the SAME live 5-tuple (no close between) is the same
    # connection, so a sibling stream inherits the connection's SDK by
    # propagation -- NOT from the (already-consumed) stash. Distinct connections
    # that reuse a 5-tuple over time keep separate connection_ids and are not
    # cross-attributed (see test_propagation_stays_within_the_connection).
    bus.emit(_make_datalog(ssl_session_id="B" * 32, timestamp=2000.0))
    sibling = collector.get_flows()[1]
    assert sibling.connection_id == flows[0].connection_id  # same connection
    assert sibling.sdk == FB_SDK                             # inherited, not stashed


# ---------------------------------------------------------------------------
# .tap round-trip
# ---------------------------------------------------------------------------

def _flow_with_sdk(sdk):
    flow = Flow(flow_id="f-1", connection_id="c-1", src_addr=SRC_ADDR, src_port=SRC_PORT,
                dst_addr=DST_ADDR, dst_port=DST_PORT, ssl_session_id=SESSION_ID,
                state=FlowState.COMPLETE, started=1000.0, ended=1001.0)
    flow.chunks.append(FlowChunk(data=b"x" * 16, direction="write", timestamp=1000.0))
    flow.sdk = sdk
    return flow


def test_tap_roundtrip_persists_sdk():
    decoded = decode_flow(encode_flow(_flow_with_sdk(dict(FB_SDK))))
    assert decoded.sdk == FB_SDK


def test_tap_roundtrip_absent_sdk_is_none():
    decoded = decode_flow(encode_flow(_flow_with_sdk(None)))
    assert decoded.sdk is None
    # And the compact record carries no "sdk" key when unset.
    assert b'"sdk"' not in encode_flow(_flow_with_sdk(None))
