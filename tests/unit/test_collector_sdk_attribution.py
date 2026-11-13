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

from friTap.events import CallerStackEvent, DatalogEvent, EventBus, SessionEvent
from friTap.flow.collector import FlowCollector, _ConnectionAttribution
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.tap_format import decode_flow, encode_flow

SRC_ADDR = "10.0.0.2"
SRC_PORT = 51000
DST_ADDR = "93.184.216.34"
DST_PORT = 443
SESSION_ID = "FEEDFACE" * 4
FB_SDK = {"sdk": "Facebook SDK", "vendor": "Meta", "category": "social"}


def _mixed_connection_ids(collector) -> set[str]:
    """The connection ids whose attribution record is marked mixed."""
    return {conn_id for conn_id, record in collector._connection_attributions.items()
            if record.mixed}


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
# An unclassified stack (sdk=None) still joins: caller_stack set, sdk stays None
# ---------------------------------------------------------------------------

def test_empty_sdk_event_stores_caller_stack_only():
    bus, collector = _wire_up()
    bus.emit(_make_datalog())
    bus.emit(CallerStackEvent(ssl_session_id="0", src_addr=SRC_ADDR,
                              src_port=SRC_PORT, dst_addr=DST_ADDR,
                              dst_port=DST_PORT, sdk=None,
                              thread_name="OkHttp", transport_module="libssl.so"))
    flow = collector.get_flows()[0]
    assert flow.sdk is None
    assert flow.caller_stack["thread_name"] == "OkHttp"
    assert flow.caller_stack["transport_module"] == "libssl.so"


# ---------------------------------------------------------------------------
# No usable join key (no cr, no 5-tuple, ssl_session_id == "0") is a no-op
# ---------------------------------------------------------------------------

def test_caller_stack_without_cr_tuple_or_real_sid_is_noop():
    bus, collector = _wire_up()
    bus.emit(_make_datalog())
    bus.emit(CallerStackEvent(ssl_session_id="0", sdk=dict(FB_SDK)))  # no keys
    flow = collector.get_flows()[0]
    assert flow.sdk is None
    assert flow.caller_stack is None
    assert collector._sdk_pending.is_empty()


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


def _register_live_connection(collector, conn_id):
    """White-box: give *conn_id* live connection state, as on_data does, so the
    per-connection attribution maps are written for it."""
    collector._connections[conn_id] = collector._new_connection_state(
        conn_id, _make_datalog())


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
    _register_live_connection(collector, "c-h2")
    s0 = _inject_flow(collector, "c-h2:0", "c-h2")
    bus.emit(_caller_stack())                      # on_sdk attributes s0 + records map
    assert s0.sdk == FB_SDK
    assert collector._connection_attributions["c-h2"].sdk == FB_SDK

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
    assert collector._sdk_pending.is_empty()

    # Continued traffic on the SAME live 5-tuple (no close between) is the same
    # connection, so a sibling stream inherits the connection's SDK by
    # propagation -- NOT from the (already-consumed) stash. Distinct connections
    # that reuse a 5-tuple over time keep separate connection_ids and are not
    # cross-attributed (see test_propagation_stays_within_the_connection).
    # Within IDLE_THRESHOLD: a 1000 s gap would idle-reset the connection into
    # a new lifetime, which must NOT inherit (see test_idle_reset_*).
    bus.emit(_make_datalog(ssl_session_id="B" * 32, timestamp=1010.0))
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


# ---------------------------------------------------------------------------
# client_random join (cr -> tuple -> session id), stash, cap/TTL, inheritance
# ---------------------------------------------------------------------------

CLIENT_RANDOM = "ab" * 32
OTHER_SDK = {"sdk": "AppsFlyer", "vendor": "AppsFlyer", "category": "attribution"}


def _cr_datalog(client_random=CLIENT_RANDOM, timestamp=1000.0, **kwargs):
    event = _make_datalog(timestamp=timestamp, **kwargs)
    event.client_random = client_random
    return event


def _cr_stack(client_random=CLIENT_RANDOM, sdk=None, **tuple_fields):
    """A caller_stack keyed only by client_random (no 4-tuple) unless given."""
    return CallerStackEvent(
        ssl_session_id="0", client_random=client_random, sdk=sdk,
        thread_name="worker", tid=7, pid=99, transport_module="libssl.so",
        untrusted={"native_frames": [{"module": "libapp.so", "symbol": "send"}],
                   "java_frames": ["com.example.Net"]},
        **tuple_fields,
    )


def test_cr_only_stack_joins_existing_flow():
    bus, collector = _wire_up()
    bus.emit(_cr_datalog())
    bus.emit(_cr_stack())
    flow = collector.get_flows()[0]
    assert flow.sdk is None  # unclassified
    assert flow.caller_stack == {
        "transport_module": "libssl.so", "thread_name": "worker", "tid": 7, "pid": 99,
        "native_frames": [{"module": "libapp.so", "symbol": "send"}],
        "java_frames": ["com.example.Net"],
    }


def test_cr_join_carries_classified_sdk():
    bus, collector = _wire_up()
    bus.emit(_cr_datalog())
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    assert collector.get_flows()[0].sdk == FB_SDK


def test_cr_wins_over_tuple():
    """Two connections on the same 4-tuple: the cr picks the right one, not the
    earliest unattributed tuple match."""
    bus, collector = _wire_up()
    bus.emit(_cr_datalog(client_random="11" * 32, ssl_session_id="A" * 32))
    bus.emit(_cr_datalog(client_random="22" * 32, ssl_session_id="B" * 32,
                         timestamp=1001.0))
    first, second = collector.get_flows()
    assert first.connection_id != second.connection_id
    bus.emit(_cr_stack(client_random="22" * 32, sdk=dict(FB_SDK),
                       src_addr=SRC_ADDR, src_port=SRC_PORT,
                       dst_addr=DST_ADDR, dst_port=DST_PORT))
    first, second = collector.get_flows()
    assert second.sdk == FB_SDK and second.caller_stack is not None
    assert first.sdk is None and first.caller_stack is None


def test_unknown_cr_stack_with_tuple_joins_datalogs_without_cr():
    """A stack whose cr no connection has taught (the datalogs never carry it)
    still joins by its 4-tuple instead of expiring in the stash."""
    bus, collector = _wire_up()
    bus.emit(_make_datalog())  # no cr on the data
    bus.emit(_cr_stack(sdk=dict(FB_SDK), src_addr=SRC_ADDR, src_port=SRC_PORT,
                       dst_addr=DST_ADDR, dst_port=DST_PORT))
    assert collector.get_flows()[0].sdk == FB_SDK
    assert collector._sdk_pending.is_empty()


def test_unknown_cr_stack_without_tuple_is_stashed_under_the_cr():
    """A cr-only stack (no tuple, no real sid) is parked under the cr -- no
    O(flows) tuple scan -- and applied once a record carries the cr."""
    bus, collector = _wire_up()
    bus.emit(_make_datalog())  # no cr on the data
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    assert collector.get_flows()[0].sdk is None
    assert ("cr", CLIENT_RANDOM) in collector._sdk_pending
    bus.emit(_cr_datalog(timestamp=1001.0))
    assert all(f.sdk == FB_SDK for f in collector.get_flows())
    assert collector._sdk_pending.is_empty()


def _end_session(bus, connection_id):
    from friTap.events import SessionEvent
    from friTap.flow.collector import SESSION_ENDED
    bus.emit(SessionEvent(event_type=SESSION_ENDED, connection_id=connection_id))


def test_late_cr_stack_after_finalize_joins_by_tuple():
    """The connection was finalized (its cr index entry forgotten) before the
    stack arrived: the stack's tuple still finds the finished flow."""
    bus, collector = _wire_up()
    bus.subscribe(SessionEvent, collector.on_session_event)
    bus.emit(_cr_datalog())
    _end_session(bus, collector.get_flows()[0].connection_id)
    assert CLIENT_RANDOM not in collector._conn_by_client_random
    bus.emit(_cr_stack(sdk=dict(FB_SDK), src_addr=SRC_ADDR, src_port=SRC_PORT,
                       dst_addr=DST_ADDR, dst_port=DST_PORT))
    assert collector.get_flows()[0].sdk == FB_SDK
    assert collector._sdk_pending.is_empty()


def test_cr_stack_tuple_fallback_skips_a_connection_with_another_cr():
    """Port reuse: the tuple matches a live connection known by a DIFFERENT cr,
    so the stack must not attach there; it is stashed for its own connection."""
    bus, collector = _wire_up()
    bus.emit(_cr_datalog(client_random="11" * 32))
    bus.emit(_cr_stack(sdk=dict(FB_SDK), src_addr=SRC_ADDR, src_port=SRC_PORT,
                       dst_addr=DST_ADDR, dst_port=DST_PORT))
    assert collector.get_flows()[0].sdk is None
    assert ("cr", CLIENT_RANDOM) in collector._sdk_pending


def test_double_indexed_stash_is_consumed_once():
    """Stashed under BOTH cr and tuple: the flow born on the tuple takes it, and
    a later record teaching the cr finds nothing left to drain."""
    bus, collector = _wire_up()
    bus.emit(_cr_stack(sdk=dict(FB_SDK), src_addr=SRC_ADDR, src_port=SRC_PORT,
                       dst_addr=DST_ADDR, dst_port=DST_PORT))
    assert ("cr", CLIENT_RANDOM) in collector._sdk_pending
    assert len(collector._sdk_pending) == 1
    bus.emit(_make_datalog(ssl_session_id="A" * 32))  # tuple, no cr: drains it
    assert collector.get_flows()[0].sdk == FB_SDK
    assert collector._sdk_pending.is_empty()
    assert ("cr", CLIENT_RANDOM) not in collector._sdk_pending
    bus.emit(_cr_datalog(ssl_session_id="A" * 32, timestamp=1001.0))
    assert collector._sdk_pending.is_empty()


def test_stack_without_cr_falls_back_to_tuple():
    bus, collector = _wire_up()
    bus.emit(_make_datalog())
    bus.emit(_cr_stack(client_random="", sdk=dict(FB_SDK), src_addr=SRC_ADDR,
                       src_port=SRC_PORT, dst_addr=DST_ADDR, dst_port=DST_PORT))
    assert collector.get_flows()[0].sdk == FB_SDK


def test_cr_stash_drains_at_flow_birth():
    bus, collector = _wire_up()
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))  # before any data: stashed under cr
    assert ("cr", CLIENT_RANDOM) in collector._sdk_pending
    bus.emit(_cr_datalog())
    flow = collector.get_flows()[0]
    assert flow.sdk == FB_SDK and flow.caller_stack["tid"] == 7
    assert collector._sdk_pending.is_empty()


def test_cr_stash_backfills_flow_born_before_cr_was_known():
    """The first record lacks the cr (agent lookup pending); the stash is applied
    when a later record of the same connection teaches the cr."""
    bus, collector = _wire_up()
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    bus.emit(_make_datalog(ssl_session_id="A" * 32))  # no cr yet, same tuple
    assert collector.get_flows()[0].caller_stack is None
    bus.emit(_cr_datalog(ssl_session_id="A" * 32, timestamp=1001.0))
    flows = collector.get_flows()
    assert all(f.caller_stack is not None and f.sdk == FB_SDK for f in flows)
    assert collector._sdk_pending.is_empty()


def test_cr_join_is_case_insensitive_through_the_router():
    """The router lower-cases every client_random (datalog and caller_stack),
    so an upper-case --modern value still joins a lower-case one."""
    from friTap.message_router import MessageRouter

    bus, collector = _wire_up()
    router = MessageRouter(bus)
    router.route({
        "contentType": "datalog", "function": "SSL_write", "ssl_session_id": "",
        "src_addr": SRC_ADDR, "src_port": SRC_PORT, "dst_addr": DST_ADDR,
        "dst_port": DST_PORT, "ss_family": "AF_INET",
        "client_random": CLIENT_RANDOM.upper(),
    }, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    router.route({"contentType": "caller_stack", "java_frames": [],
                  "client_random": CLIENT_RANDOM, "thread_name": "t"}, b"")
    flows = collector.get_flows()
    assert len(flows) == 1
    assert flows[0].caller_stack["thread_name"] == "t"


def test_stash_expires_after_ttl_on_injected_clock():
    from friTap.flow.caller_stack_stash import STASH_TTL_SECONDS

    bus, collector = _wire_up()
    clock = [5000.0]
    collector._now = lambda: clock[0]
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    clock[0] += STASH_TTL_SECONDS + 1
    bus.emit(_cr_datalog(timestamp=clock[0]))
    flow = collector.get_flows()[0]
    assert flow.sdk is None and flow.caller_stack is None
    assert collector._sdk_pending.is_empty()


def test_stash_within_ttl_still_drains():
    from friTap.flow.caller_stack_stash import STASH_TTL_SECONDS

    bus, collector = _wire_up()
    clock = [5000.0]
    collector._now = lambda: clock[0]
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    clock[0] += STASH_TTL_SECONDS - 1
    bus.emit(_cr_datalog(timestamp=clock[0]))
    assert collector.get_flows()[0].sdk == FB_SDK


def test_stash_is_capped_dropping_the_oldest():
    from friTap.flow.caller_stack_stash import MAX_STASHED

    bus, collector = _wire_up()
    clock = [1000.0]
    collector._now = lambda: clock[0]
    for index in range(MAX_STASHED + 5):
        clock[0] += 0.01
        bus.emit(_cr_stack(client_random=f"{index:064x}"))
    assert len(collector._sdk_pending) == MAX_STASHED
    assert ("cr", f"{0:064x}") not in collector._sdk_pending
    assert ("cr", f"{MAX_STASHED + 4:064x}") in collector._sdk_pending


def test_stream_born_after_cr_join_inherits_caller_stack():
    bus, collector = _wire_up()
    bus.emit(_cr_datalog())
    bus.emit(_cr_stack())
    conn_id = collector.get_flows()[0].connection_id
    assert collector._connection_attributions[conn_id].caller_stack["tid"] == 7

    newborn = Flow(flow_id=f"{conn_id}:9", connection_id=conn_id,
                   src_addr=SRC_ADDR, src_port=SRC_PORT,
                   dst_addr=DST_ADDR, dst_port=DST_PORT,
                   state=FlowState.ACTIVE, started=2000.0)
    collector._stamp_metadata(newborn, _cr_datalog(timestamp=2000.0))
    assert newborn.caller_stack["tid"] == 7
    assert newborn.sdk is None


def test_port_reuse_selects_flow_without_caller_stack():
    """The tuple fallback skips flows that already carry a caller stack, even
    an unclassified one (sdk None)."""
    bus, collector = _wire_up()
    flow_a = _inject_flow(collector, "c-a:0", "c-a")
    flow_b = _inject_flow(collector, "c-b:0", "c-b")
    bus.emit(CallerStackEvent(ssl_session_id="0", src_addr=SRC_ADDR,
                              src_port=SRC_PORT, dst_addr=DST_ADDR,
                              dst_port=DST_PORT, sdk=None))  # unclassified
    assert flow_a.caller_stack is not None and flow_a.sdk is None
    assert flow_b.caller_stack is None
    bus.emit(_caller_stack())
    assert flow_b.sdk == FB_SDK and flow_b.caller_stack is not None
    assert flow_a.sdk is None


def test_finalize_and_clear_drop_cr_join_state():
    bus, collector = _wire_up()
    bus.emit(_cr_datalog())
    bus.emit(_cr_stack())
    assert CLIENT_RANDOM in collector._conn_by_client_random
    conn = next(iter(collector._connections.values()))
    with collector._lock:
        collector._finalize_connection(conn, 2000.0, [])
    assert CLIENT_RANDOM not in collector._conn_by_client_random
    assert collector._connection_attributions == {}
    bus.emit(_cr_stack(client_random="cd" * 32))
    collector.clear()
    assert collector._sdk_pending.is_empty()
    assert collector._conn_by_client_random == {}


def test_tap_roundtrip_persists_caller_stack():
    flow = _flow_with_sdk(None)
    flow.caller_stack = {"transport_module": "libssl.so", "thread_name": "w",
                         "tid": 1, "pid": 2,
                         "native_frames": [{"module": "m", "symbol": "s"}],
                         "java_frames": ["j"]}
    assert decode_flow(encode_flow(flow)).caller_stack == flow.caller_stack
    assert b'"caller_stack"' not in encode_flow(_flow_with_sdk(None))
    assert decode_flow(encode_flow(_flow_with_sdk(None))).caller_stack is None


def test_tap_read_rebounds_hand_crafted_caller_stack():
    flow = _flow_with_sdk(None)
    flow.caller_stack = {"thread_name": "\x1b" + "y" * 300, "tid": "junk",
                         "native_frames": ["bad", {"module": 5}] * 20,
                         "java_frames": "nope"}
    decoded = decode_flow(encode_flow(flow)).caller_stack
    assert decoded["thread_name"].startswith("\\x1b") and len(decoded["thread_name"]) == 80
    assert decoded["tid"] == 0 and decoded["java_frames"] == []
    assert decoded["native_frames"] == [{"module": "", "symbol": ""}] * 8
    flow.caller_stack = ["not", "a", "dict"]
    assert decode_flow(encode_flow(flow)).caller_stack is None


FULL_ATTRIBUTION = {
    "transport": {"module": "libcronet.143.0.so", "kind": "gms-cronet"},
    "originator": {"sdk": "Facebook", "vendor": "Meta", "category": "social"},
    "confidence": "high",
    "source": "java-request",
    "bucket": "cache",
    "mixed": True,
}


def test_tap_roundtrip_persists_attribution():
    flow = _flow_with_sdk(None)
    flow.attribution = {**FULL_ATTRIBUTION,
                        "transport": dict(FULL_ATTRIBUTION["transport"]),
                        "originator": dict(FULL_ATTRIBUTION["originator"])}
    assert decode_flow(encode_flow(flow)).attribution == FULL_ATTRIBUTION


def test_tap_omits_attribution_when_none():
    flow = _flow_with_sdk(None)
    assert flow.attribution is None
    assert b'"attribution"' not in encode_flow(flow)
    assert decode_flow(encode_flow(flow)).attribution is None


def test_tap_read_rebounds_hand_crafted_attribution():
    flow = _flow_with_sdk(None)
    flow.attribution = {
        "evil": "x",
        "transport": {"module": "m" * 500, "kind": "Bogus Kind!", "extra": 1},
        "originator": {"sdk": "S", "vendor": 7, "unknown": "u"},
        "confidence": "certain",
        "source": "native-stack",
        "mixed": "yes",
    }
    decoded = decode_flow(encode_flow(flow)).attribution
    assert decoded == {"transport": {"module": "m" * 80},
                       "originator": {"sdk": "S"},
                       "source": "native-stack"}
    flow.attribution = ["not", "a", "dict"]
    assert decode_flow(encode_flow(flow)).attribution is None


def test_tap_file_roundtrip_persists_attribution(tmp_path):
    from friTap.flow.tap_reader import TapReader
    from friTap.flow.tap_writer import TapWriter
    flow = _flow_with_sdk(None)
    flow.attribution = dict(FULL_ATTRIBUTION)
    path = tmp_path / "attribution.tap"
    writer = TapWriter()
    writer.open(str(path), target="test")
    writer.write_flow(flow)
    writer.close()
    with TapReader(str(path)) as reader:
        flows = reader.read_all_flows()
    assert [f.attribution for f in flows] == [FULL_ATTRIBUTION]



# ---------------------------------------------------------------------------
# Transport vs originator attribution (flow.attribution, friTap/flow/attribution.py)
# ---------------------------------------------------------------------------

SIGNAL_SDK = {"sdk": "Signal", "vendor": "Signal", "category": "messaging"}
GMS_CRONET_PATH = ("/data/user_de/0/com.google.android.gms/app_chimera/m/0/"
                   "dynamite/libcronet.143.0.so")


def _wire_up_with_libraries(target=""):
    from friTap.events import LibraryDetectedEvent
    bus, collector = _wire_up()
    bus.subscribe(LibraryDetectedEvent, collector.on_library_detected)
    bus.subscribe(SessionEvent, collector.on_session_event)
    if target:
        collector.set_capture_target(target)
    return bus, collector


def _lib_datalog(library, protocol="tls", **kwargs):
    event = _make_datalog(**kwargs)
    event.library = library
    event.protocol = protocol
    if protocol == "quic":
        event.data = b""
        event.transport = "udp"
        event.stream_id = 0
        event.http3_headers = [[":method", "GET"], [":scheme", "https"],
                               [":authority", "example.com"], [":path", "/"]]
    return event


def _lib_cr_datalog(library, client_random=CLIENT_RANDOM, timestamp=1000.0):
    event = _lib_datalog(library, timestamp=timestamp)
    event.client_random = client_random
    return event


def _newborn(conn_id, seq=9):
    return Flow(flow_id=f"{conn_id}:{seq}", connection_id=conn_id,
                src_addr=SRC_ADDR, src_port=SRC_PORT,
                dst_addr=DST_ADDR, dst_port=DST_PORT,
                state=FlowState.ACTIVE, started=2000.0)


def test_transport_stamped_on_tls_flow():
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_datalog("/system/lib64/libssl.so"))
    assert collector.get_flows()[0].attribution == {
        "transport": {"module": "libssl.so", "kind": "other"}}


def test_transport_stamped_on_quic_flow():
    bus, collector = _wire_up_with_libraries(target="com.android.chrome")
    bus.emit(_lib_datalog("libmonochrome_64.so", protocol="quic"))
    flows = collector.get_flows()
    assert flows and all(f.transport == "quic" for f in flows)
    assert flows[0].attribution["transport"] == {
        "module": "libmonochrome_64.so", "kind": "chrome"}


def test_transport_absent_on_non_tls_flow_and_without_library():
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_datalog("libssl.so", protocol="rc4"))
    bus.emit(_lib_datalog("", dst_addr="203.0.113.7"))
    rc4_flow, unlabelled = collector.get_flows()
    assert rc4_flow.transport == "rc4" and rc4_flow.attribution is None
    assert rc4_flow.layer("tls") is None
    assert unlabelled.attribution is None


def test_monochrome_in_webview_app_is_webview():
    bus, collector = _wire_up_with_libraries(target="com.fritap.attributionfixture")
    bus.emit(_lib_datalog("libmonochrome_64.so"))
    assert collector.get_flows()[0].attribution["transport"]["kind"] == "webview"


def test_cronet_with_gms_path_from_library_event_is_gms_cronet():
    from friTap.events import LibraryDetectedEvent
    bus, collector = _wire_up_with_libraries()
    bus.emit(LibraryDetectedEvent(library="", module="libcronet.143.0.so",
                                  path=GMS_CRONET_PATH))
    bus.emit(_lib_datalog("libcronet.143.0.so"))
    assert collector.get_flows()[0].attribution["transport"] == {
        "module": "libcronet.143.0.so", "kind": "gms-cronet"}


def test_module_paths_are_capped_dropping_the_oldest():
    from friTap.events import LibraryDetectedEvent
    from friTap.flow.collector import MAX_MODULE_PATHS
    bus, collector = _wire_up_with_libraries()
    for index in range(MAX_MODULE_PATHS + 5):
        bus.emit(LibraryDetectedEvent(library="x", module=f"lib{index}.so",
                                      path=f"/p/lib{index}.so"))
    assert len(collector._module_paths) == MAX_MODULE_PATHS
    assert "lib0.so" not in collector._module_paths
    assert f"lib{MAX_MODULE_PATHS + 4}.so" in collector._module_paths


def test_direct_join_on_libsignal_is_high():
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_datalog("libsignal_jni.so"))
    bus.emit(_caller_stack(sdk=dict(SIGNAL_SDK)))
    flow = collector.get_flows()[0]
    assert flow.sdk == SIGNAL_SDK
    assert flow.attribution == {
        "transport": {"module": "libsignal_jni.so", "kind": "libsignal"},
        "originator": SIGNAL_SDK, "source": "native-stack", "confidence": "high"}


def test_direct_join_on_monochrome_is_medium():
    bus, collector = _wire_up_with_libraries(target="com.fritap.attributionfixture")
    bus.emit(_lib_cr_datalog("libmonochrome_64.so"))
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    attribution = collector.get_flows()[0].attribution
    assert attribution["transport"]["kind"] == "webview"
    assert attribution["source"] == "native-stack"
    assert attribution["confidence"] == "medium"


def test_unclassified_stack_sets_no_originator():
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_cr_datalog("libssl.so"))
    bus.emit(_cr_stack())  # sdk None
    flow = collector.get_flows()[0]
    assert flow.caller_stack is not None and flow.sdk is None
    assert flow.attribution == {"transport": {"module": "libssl.so", "kind": "other"}}
    assert _mixed_connection_ids(collector) == set()


def test_siblings_and_later_born_stream_inherit_low():
    bus, collector = _wire_up()
    s0 = _inject_flow(collector, "c-h2:0", "c-h2")
    s1 = _inject_flow(collector, "c-h2:1", "c-h2")
    bus.emit(_caller_stack())
    assert s0.attribution["source"] == "native-stack"
    assert s0.attribution["confidence"] == "medium"
    assert s1.attribution == {"originator": FB_SDK, "source": "connection-fallback",
                              "confidence": "low"}
    newborn = _newborn("c-h2")
    collector._stamp_metadata(newborn, _lib_datalog("libssl.so", timestamp=2000.0))
    assert newborn.attribution == {
        "transport": {"module": "libssl.so", "kind": "other"},
        "originator": FB_SDK, "source": "connection-fallback", "confidence": "low"}


def test_cr_join_makes_earliest_flow_direct_and_later_ones_inherit():
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_cr_datalog("libssl.so"))
    conn_id = collector.get_flows()[0].connection_id
    sibling = _inject_flow(collector, f"{conn_id}:5", conn_id)
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    first = collector.get_flows()[0]
    assert first.attribution["confidence"] == "medium"
    assert sibling.attribution["source"] == "connection-fallback"
    assert sibling.attribution["confidence"] == "low"


def test_stash_drained_by_first_flow_is_direct():
    bus, collector = _wire_up_with_libraries()
    bus.emit(_caller_stack(sdk=dict(SIGNAL_SDK)))  # stashed: no flow yet
    bus.emit(_lib_datalog("libsignal_jni.so"))
    attribution = collector.get_flows()[0].attribution
    assert attribution["source"] == "native-stack"
    assert attribution["confidence"] == "high"


def test_stash_drained_after_an_earlier_stack_is_inherited():
    """A stash entry drained by a later flow of a connection that already had a
    caller stack is a connection-level claim, not a direct join."""
    bus, collector = _wire_up()
    _inject_flow(collector, "c-h2:0", "c-h2")
    bus.emit(_caller_stack())                       # joins c-h2:0
    bus.emit(_caller_stack(sdk=dict(OTHER_SDK)))    # nothing unattributed -> stashed
    newborn = _newborn("c-h2")
    collector._stamp_metadata(newborn, _make_datalog(timestamp=2000.0))
    assert newborn.attribution["confidence"] == "low"


def test_two_sdks_on_one_connection_mark_every_flow_mixed():
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_cr_datalog("libssl.so"))
    conn_id = collector.get_flows()[0].connection_id
    sibling = _inject_flow(collector, f"{conn_id}:5", conn_id)
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    assert "mixed" not in collector.get_flows()[0].attribution
    bus.emit(_cr_stack(sdk=dict(OTHER_SDK)))
    assert _mixed_connection_ids(collector) == {conn_id}
    assert collector._connection_attributions[conn_id].sdk == FB_SDK  # first still wins
    first = collector.get_flows()[0]
    assert first.sdk == FB_SDK and first.attribution["originator"] == FB_SDK
    assert first.attribution["mixed"] is True
    assert sibling.attribution["mixed"] is True

    newborn = _newborn(conn_id)
    collector._stamp_metadata(newborn, _lib_cr_datalog("libssl.so", timestamp=2000.0))
    assert newborn.attribution["mixed"] is True
    assert newborn.attribution["confidence"] == "low"


def test_same_sdk_twice_is_not_mixed():
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_cr_datalog("libssl.so"))
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    assert "mixed" not in collector.get_flows()[0].attribution


def test_sdk_after_sdk_less_first_stack_becomes_the_connection_sdk():
    """An unclassified first stack records no SDK, so a later classified stack
    supplies the connection's SDK -- it is not a second, differing one."""
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_cr_datalog("libssl.so"))
    conn_id = collector.get_flows()[0].connection_id
    bus.emit(_cr_stack())                            # sdk None
    assert collector._connection_attributions[conn_id].sdk is None
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    record = collector._connection_attributions[conn_id]
    assert record.sdk == FB_SDK
    assert record.caller_stack["tid"] == 7
    assert record.mixed is False
    assert _mixed_connection_ids(collector) == set()
    newborn = _newborn(conn_id)
    collector._stamp_metadata(newborn, _lib_cr_datalog("libssl.so", timestamp=2000.0))
    assert newborn.sdk == FB_SDK
    assert "mixed" not in newborn.attribution


def test_late_stack_on_finalized_connection_leaves_no_entry():
    """A tuple join onto a completed flow whose connection was already
    finalized still attributes the flow, but must not re-create per-connection
    entries that nothing will ever pop again."""
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_datalog("libssl.so"))
    conn_id = collector.get_flows()[0].connection_id
    _end_session(bus, conn_id)
    assert conn_id not in collector._connections
    bus.emit(_caller_stack())
    assert collector.get_flows()[0].sdk == FB_SDK
    _assert_no_connection_entries(collector, conn_id)


def _assert_no_connection_entries(collector, conn_id):
    assert conn_id not in collector._connection_attributions


def test_late_stack_after_lru_eviction_leaves_no_entry(monkeypatch):
    """An LRU-evicted connection is finalized; a still-ACTIVE flow of it (which
    the old "any ACTIVE flow" liveness fallback accepted) must not let a late
    stack re-create per-connection entries."""
    import friTap.flow.collector as collector_module
    monkeypatch.setattr(collector_module, "MAX_TRACKED_CONNECTIONS", 1)
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_datalog("libssl.so"))
    conn_id = collector.get_flows()[0].connection_id
    bus.emit(_lib_datalog("libssl.so", ssl_session_id="CAFE" * 8,
                          dst_addr="203.0.113.7"))  # a second connection evicts conn_id
    assert conn_id not in collector._connections
    straggler = _inject_flow(collector, f"{conn_id}:7", conn_id)
    bus.emit(_caller_stack(sdk=dict(FB_SDK)))
    assert straggler.sdk == FB_SDK
    _assert_no_connection_entries(collector, conn_id)


def test_late_stack_after_idle_sweep_leaves_no_entry():
    from friTap.flow.collector import IDLE_THRESHOLD
    bus, collector = _wire_up_with_libraries()
    collector.use_event_clock(True)
    bus.emit(_lib_datalog("libssl.so"))
    conn_id = collector.get_flows()[0].connection_id
    with collector._lock:
        collector._observe_event_time(1000.0 + 3 * IDLE_THRESHOLD)
        collector._periodic_sweep([])
    assert conn_id not in collector._connections
    straggler = _inject_flow(collector, f"{conn_id}:7", conn_id)
    bus.emit(_caller_stack(sdk=dict(FB_SDK)))
    assert straggler.sdk == FB_SDK
    _assert_no_connection_entries(collector, conn_id)


def test_cr_join_after_first_flow_released_makes_no_flow_direct():
    """Headless path: the connection's first flow was written and released
    before its cr-keyed stack arrived. The remaining (later) flows did not
    carry the captured stack, so they inherit -- none becomes native-stack."""
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_cr_datalog("libssl.so"))
    first = collector.get_flows()[0]
    conn_id = first.connection_id
    later = _inject_flow(collector, f"{conn_id}:5", conn_id)
    collector._release_flow(first)
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    assert later.attribution["source"] == "connection-fallback"
    assert later.attribution["confidence"] == "low"
    newborn = _newborn(conn_id)
    collector._stamp_metadata(newborn, _lib_cr_datalog("libssl.so", timestamp=2000.0))
    assert newborn.attribution["confidence"] == "low"


def test_mixed_marking_queues_each_flow_once():
    bus, collector = _wire_up_with_libraries()
    bus.emit(_lib_cr_datalog("libssl.so"))
    conn_id = collector.get_flows()[0].connection_id
    _inject_flow(collector, f"{conn_id}:5", conn_id)
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    pending: list = []
    with collector._lock:
        collector._attribute_connection(conn_id, _stashed(OTHER_SDK), pending)
    flows = [flow for _, flow in pending]
    assert len(flows) == len({id(flow) for flow in flows}) == 2
    assert all(flow.attribution["mixed"] is True for flow in flows)


def _stashed(sdk):
    from friTap.flow.caller_stack_stash import StashedCallerStack
    return StashedCallerStack(sdk=dict(sdk), caller_stack={"tid": 1}, stashed_at=0.0)


def test_finalize_and_clear_drop_attribution_maps():
    from friTap.events import LibraryDetectedEvent
    bus, collector = _wire_up_with_libraries()
    bus.emit(LibraryDetectedEvent(library="x", module="libssl.so", path="/l/libssl.so"))
    bus.emit(_lib_cr_datalog("libssl.so"))
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    bus.emit(_cr_stack(sdk=dict(OTHER_SDK)))
    conn = next(iter(collector._connections.values()))
    assert _mixed_connection_ids(collector) == {conn.conn_id}
    with collector._lock:
        collector._finalize_connection(conn, 2000.0, [])
    assert collector._connection_attributions == {}
    collector._connection_attributions["other"] = _ConnectionAttribution(sdk_names={"A", "B"})
    assert collector._module_paths
    collector.clear()
    assert collector._connection_attributions == {}
    # Process-lifetime state (like _detected_libraries): kept across clear().
    assert collector._module_paths == {"libssl.so": "/l/libssl.so", "x": "/l/libssl.so"}


# ---------------------------------------------------------------------------
# Connection-state lifetimes: idle-reset / conn_id reuse
# ---------------------------------------------------------------------------

def _record_events(collector):
    events = []
    collector.subscribe(lambda flow, event_type: events.append((event_type, flow.flow_id)))
    return events


def _read_response(timestamp):
    event = _make_datalog(timestamp=timestamp)
    event.data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    event.function, event.direction = "SSL_read", "read"
    return event


def _idle_reset_after_attributed_flow():
    """First lifetime: one flow joined to FB_SDK; then an idle gap rebuilds the
    connection state under the same conn_id and mints its next flow."""
    bus, collector = _wire_up()
    bus.emit(_make_datalog())
    bus.emit(_caller_stack())
    bus.emit(_make_datalog(timestamp=1000.0 + 1000.0))  # > IDLE_THRESHOLD
    old, new = collector.live_flows()
    assert old.connection_id == new.connection_id
    assert new.flow_id == f"{new.connection_id}:1"
    return bus, collector, old, new


def test_idle_reset_new_lifetime_does_not_inherit_previous_lifetime():
    _bus, collector, old, new = _idle_reset_after_attributed_flow()
    assert old.sdk == FB_SDK
    assert new.sdk is None and new.caller_stack is None
    assert not (new.attribution or {}).get("originator")


def test_idle_reset_first_flow_of_new_lifetime_is_direct_on_later_join():
    bus, collector, _old, new = _idle_reset_after_attributed_flow()
    bus.emit(_caller_stack(sdk=dict(OTHER_SDK)))  # joins the unattributed :1
    assert new.sdk == OTHER_SDK
    assert new.attribution["source"] == "native-stack"


def test_idle_reset_stash_drained_by_first_flow_of_new_lifetime_is_direct():
    bus, collector = _wire_up()
    bus.emit(_make_datalog())
    bus.emit(_caller_stack())
    bus.emit(_caller_stack(sdk=dict(OTHER_SDK)))  # nothing unattributed -> stashed
    bus.emit(_make_datalog(timestamp=2000.0))     # idle-reset; :1 drains it
    new = collector.live_flows()[1]
    assert new.sdk == OTHER_SDK
    assert new.attribution["source"] == "native-stack"
    assert "mixed" not in new.attribution  # a new lifetime starts unmixed


def test_reused_conn_id_after_session_end_starts_a_new_lifetime():
    bus, collector = _wire_up_with_libraries()
    bus.emit(_make_datalog())
    bus.emit(_caller_stack())
    conn_id = collector.live_flows()[0].connection_id
    _end_session(bus, conn_id)
    bus.emit(_make_datalog(timestamp=1001.0))   # same tuple + sid -> same conn_id
    new = collector.live_flows()[1]
    assert new.connection_id == conn_id and new.sdk is None
    assert collector._is_first_flow_of_connection(new)


def _assert_untouched_by(flow, sdk):
    attribution = flow.attribution or {}
    assert flow.sdk != sdk
    assert attribution.get("originator") != sdk
    assert "mixed" not in attribution


def test_tuple_join_to_new_lifetime_leaves_previous_lifetime_flows_alone():
    """A stack joined (by tuple) to the second lifetime of a reused conn_id must
    not give the first lifetime's flows its SDK, nor mark them mixed."""
    bus, collector, old, new = _idle_reset_after_attributed_flow()
    bus.emit(_caller_stack(sdk=dict(OTHER_SDK)))   # joins :1 (lifetime 2)
    with collector._lock:                          # a 2nd stack on lifetime 2
        collector._attribute_connection(new.connection_id, _stashed(SIGNAL_SDK), [])
    assert new.sdk == OTHER_SDK and new.attribution["mixed"] is True
    assert old.sdk == FB_SDK and old.attribution["originator"] == FB_SDK
    _assert_untouched_by(old, OTHER_SDK)


def test_cr_join_to_new_lifetime_leaves_unattributed_previous_lifetime_alone():
    """First lifetime got no stack; an idle gap starts a second lifetime of the
    same cr-keyed conn_id and its stack joins by client_random -- the old flow
    stays bare."""
    bus, collector = _wire_up()
    bus.emit(_cr_datalog())
    bus.emit(_cr_datalog(timestamp=2000.0))        # > IDLE_THRESHOLD: lifetime 2
    old, new = collector.live_flows()
    assert old.connection_id == new.connection_id
    bus.emit(_cr_stack(sdk=dict(OTHER_SDK)))
    assert new.sdk == OTHER_SDK
    assert old.sdk is None and old.caller_stack is None
    _assert_untouched_by(old, OTHER_SDK)


def test_tuple_join_to_previous_lifetime_flow_leaves_current_lifetime_alone():
    """The tuple join picks the earliest unattributed flow; when that is a
    previous lifetime's flow the stack stays there, not on the live lifetime."""
    bus, collector = _wire_up()
    bus.emit(_make_datalog())
    bus.emit(_make_datalog(timestamp=2000.0))      # > IDLE_THRESHOLD: lifetime 2
    old, new = collector.live_flows()
    assert old.connection_id == new.connection_id
    bus.emit(_caller_stack(sdk=dict(OTHER_SDK)))   # earliest unattributed: old
    assert old.sdk == OTHER_SDK
    assert new.sdk is None and new.caller_stack is None
    assert new.connection_id not in collector._connection_attributions


def test_lifetime_first_seq_is_cleared_with_flow_seq():
    _bus, collector, _old, new = _idle_reset_after_attributed_flow()
    assert collector._lifetime_first_seq[new.connection_id] == 1
    collector.clear()
    assert collector._lifetime_first_seq == {}


# ---------------------------------------------------------------------------
# A stash drained at a later flow's birth that makes the connection mixed
# ---------------------------------------------------------------------------

def test_stash_drain_turning_connection_mixed_marks_every_present_flow():
    bus, collector = _wire_up()
    events = _record_events(collector)
    bus.emit(_make_datalog())
    bus.emit(_caller_stack())                        # joins :0 (FB)
    bus.emit(_read_response(1000.5))                 # :0 completes
    bus.emit(_caller_stack(sdk=dict(OTHER_SDK)))     # stashed on the tuple
    events.clear()
    bus.emit(_make_datalog(timestamp=1001.0))        # :1 born, drains it
    first, newborn = collector.live_flows()
    assert _mixed_connection_ids(collector) == {first.connection_id}
    assert newborn.attribution["mixed"] is True
    assert first.attribution["mixed"] is True
    assert ("updated", first.flow_id) in [(str(t.value), f) for t, f in events]
    assert collector._staged_updates == []


# ---------------------------------------------------------------------------
# Module paths: keyed by module AND library name, case-insensitively
# ---------------------------------------------------------------------------

def test_module_path_recorded_under_library_name_case_insensitively():
    from friTap.events import LibraryDetectedEvent
    bus, collector = _wire_up_with_libraries()
    bus.emit(LibraryDetectedEvent(library="LibCronet.143.0.so", module="cronet-module",
                                  path=GMS_CRONET_PATH))
    assert set(collector._module_paths) == {"libcronet.143.0.so", "cronet-module"}
    bus.emit(_lib_datalog("libcronet.143.0.so"))
    assert collector.live_flows()[0].attribution["transport"]["kind"] == "gms-cronet"


# ---------------------------------------------------------------------------
# Late information re-classifies the stamped transport
# ---------------------------------------------------------------------------

def test_late_module_path_reclassifies_matching_flows_only():
    from friTap.events import LibraryDetectedEvent
    bus, collector = _wire_up_with_libraries()
    events = _record_events(collector)
    bus.emit(_lib_datalog("libcronet.143.0.so"))
    bus.emit(_lib_datalog("libssl.so", dst_addr="203.0.113.7"))
    cronet, other = collector.live_flows()
    assert cronet.attribution["transport"]["kind"] == "cronet"
    events.clear()
    bus.emit(LibraryDetectedEvent(library="", module="libcronet.143.0.so",
                                  path=GMS_CRONET_PATH))
    assert cronet.attribution["transport"] == {
        "module": "libcronet.143.0.so", "kind": "gms-cronet"}
    assert other.attribution["transport"]["kind"] == "other"
    assert [(str(t.value), f) for t, f in events] == [("updated", cronet.flow_id)]


def test_unchanged_kind_queues_no_update():
    from friTap.events import LibraryDetectedEvent
    bus, collector = _wire_up_with_libraries()
    events = _record_events(collector)
    bus.emit(_lib_datalog("libssl.so"))
    events.clear()
    bus.emit(LibraryDetectedEvent(library="", module="libssl.so", path="/system/lib64/libssl.so"))
    collector.set_capture_target("com.example.app")
    assert events == []


def test_capture_target_change_reclassifies_and_keeps_originator():
    bus, collector = _wire_up_with_libraries(target="com.fritap.attributionfixture")
    events = _record_events(collector)
    bus.emit(_lib_cr_datalog("libmonochrome_64.so"))
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    flow = collector.live_flows()[0]
    assert flow.attribution["transport"]["kind"] == "webview"
    events.clear()
    collector.set_capture_target("com.android.chrome")
    assert flow.attribution["transport"]["kind"] == "chrome"
    assert flow.attribution["originator"] == FB_SDK
    assert flow.attribution["source"] == "native-stack"
    from friTap.flow.attribution import direct_attribution
    assert flow.attribution["confidence"] == direct_attribution(FB_SDK, "chrome")["confidence"]
    assert [(str(t.value), f) for t, f in events] == [("updated", flow.flow_id)]


def test_reclassification_recomputes_only_native_stack_confidence(monkeypatch):
    import friTap.flow.collector as collector_module
    bus, collector = _wire_up_with_libraries(target="com.fritap.attributionfixture")
    bus.emit(_lib_cr_datalog("libmonochrome_64.so"))
    conn_id = collector.live_flows()[0].connection_id
    sibling = _inject_flow(collector, f"{conn_id}:5", conn_id)
    sibling.tls.library = "libmonochrome_64.so"
    collector._stamp_transport_attribution(sibling)
    bus.emit(_cr_stack(sdk=dict(FB_SDK)))
    first = collector.live_flows()[0]
    assert sibling.attribution["source"] == "connection-fallback"

    def fake_direct(sdk, kind):
        return {"originator": dict(sdk), "source": "native-stack",
                "confidence": "high" if kind == "chrome" else "medium"}
    monkeypatch.setattr(collector_module, "direct_attribution", fake_direct)
    collector.set_capture_target("com.android.chrome")
    assert first.attribution["confidence"] == "high"
    assert sibling.attribution["transport"]["kind"] == "chrome"
    assert sibling.attribution["confidence"] == "low"
    assert sibling.attribution["source"] == "connection-fallback"


# ---------------------------------------------------------------------------
# Numeric-PID targets: the resolved process name classifies the transport
# ---------------------------------------------------------------------------

def test_pid_target_with_resolved_process_name_is_chrome():
    bus, collector = _wire_up_with_libraries(target="12345")
    bus.emit(_lib_datalog("libmonochrome_64.so"))
    flow = collector.live_flows()[0]
    assert flow.attribution["transport"]["kind"] == "webview"
    assert flow.process_name == "12345"
    collector.set_capture_target("12345", process_name="com.android.chrome")
    assert flow.attribution["transport"]["kind"] == "chrome"
    assert collector._capture_target == "12345"
    assert collector._process_name == "com.android.chrome"
    assert collector._package_name == "com.android.chrome"


def test_pid_target_with_friendly_name_has_no_package():
    _bus, collector = _wire_up_with_libraries()
    collector.set_capture_target("12345", process_name="Chrome")
    assert collector._process_name == "Chrome"
    assert collector._package_name == ""


def test_tui_passes_picker_name_only_for_pid_targets():
    from types import SimpleNamespace

    from friTap.tui.capture_controller import _pid_target_process_name
    assert _pid_target_process_name(
        SimpleNamespace(target="4242", target_display="Chrome")) == "Chrome"
    assert _pid_target_process_name(
        SimpleNamespace(target="com.android.chrome", target_display="Chrome")) is None
    assert _pid_target_process_name(SimpleNamespace(target="4242", target_display="")) is None
    assert _pid_target_process_name(SimpleNamespace(target="")) is None
