"""Regression coverage for two FlowCollector bugs.

BUG #4 — TLS metadata dropped on handshake-before-data ordering.
    SESSION_STARTED normally arrives BEFORE the first SSL_read/write data event.
    At that moment no flow exists for the connection, so _stamp_tls_metadata had
    nothing to stamp and the TLS columns stayed empty even though the agent did
    report SNI/ALPN/version/cipher. The fix caches the session TLS fields per
    connection_id and backfills them when the flow is later created.

    Note: tests/unit/test_session_metadata_stamping.py already covers the
    data-before-STARTED ordering; this file adds the missing handshake-FIRST case.

BUG #5 — flush() never emitted COMPLETED, so end-of-capture flows were never
    scanned. The end-of-capture path (legacy._finalize_live_scan) calls flush()
    expecting still-active flows to "complete and get enqueued" via the COMPLETED
    FlowEvent. flush() now emits COMPLETED for every flow it transitions
    ACTIVE -> COMPLETE.
"""

from friTap.connection_index import resolve_connection_key
from friTap.events import (
    SESSION_STARTED,
    DatalogEvent,
    EventBus,
    FlowEvent,
    SessionEvent,
)
from friTap.flow.collector import FlowCollector
from friTap.flow.models import FlowEventType, FlowState

SRC_ADDR = "10.0.0.2"
SRC_PORT = 51000
DST_ADDR = "93.184.216.34"
DST_PORT = 443
CLIENT_RANDOM = "cd" * 32  # 64 hex chars


def _conn_id(client_random=CLIENT_RANDOM, ssl_session_id=""):
    return resolve_connection_key(
        SRC_ADDR, SRC_PORT, DST_ADDR, DST_PORT,
        session_token=ssl_session_id, client_random=client_random,
    )


def _make_datalog(client_random="", ssl_session_id="", timestamp=1000.0):
    return DatalogEvent(
        data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        function="SSL_write",
        direction="write",
        src_addr=SRC_ADDR,
        src_port=SRC_PORT,
        dst_addr=DST_ADDR,
        dst_port=DST_PORT,
        ssl_session_id=ssl_session_id,
        client_random=client_random,
        timestamp=timestamp,
    )


def _make_session_started(client_random="", ssl_session_id="",
                          server_name="example.com",
                          protocol_version="TLS 1.3", alpn="h2",
                          cipher_suite="TLS_AES_128_GCM_SHA256"):
    return SessionEvent(
        event_type=SESSION_STARTED,
        connection_id=_conn_id(client_random, ssl_session_id),
        client_random=client_random,
        session_id=ssl_session_id,
        server_name=server_name,
        protocol_version=protocol_version,
        alpn=alpn,
        cipher_suite=cipher_suite,
        src_addr=SRC_ADDR,
        src_port=SRC_PORT,
        dst_addr=DST_ADDR,
        dst_port=DST_PORT,
    )


def _wire_up():
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    bus.subscribe(SessionEvent, collector.on_session_event)
    return bus, collector


# ---------------------------------------------------------------------------
# BUG #4 — handshake BEFORE data
# ---------------------------------------------------------------------------

def test_session_started_before_data_backfills_tls_on_new_flow():
    """SESSION_STARTED arrives first (no flow yet), THEN the data event creates
    the flow. The cached TLS fields must be backfilled onto the new flow."""
    bus, collector = _wire_up()

    # 1. Handshake metadata arrives first — no flow exists yet.
    bus.emit(_make_session_started(client_random=CLIENT_RANDOM))
    assert collector.get_flows() == []  # nothing created by the session event

    # 2. The first data event creates the flow.
    bus.emit(_make_datalog(client_random=CLIENT_RANDOM))

    flows = collector.get_flows()
    assert len(flows) == 1
    flow = flows[0]
    assert flow.tls.sni == "example.com"
    assert flow.tls.version == "TLS 1.3"
    assert flow.tls.alpn == "h2"
    assert flow.tls.cipher == "TLS_AES_128_GCM_SHA256"


def test_session_started_before_data_via_session_token():
    """Same handshake-first proof through the sid: tier (no client_random)."""
    bus, collector = _wire_up()
    session_id = "FEEDFACE" * 4

    bus.emit(_make_session_started(ssl_session_id=session_id,
                                   server_name="api.example.com"))
    assert collector.get_flows() == []

    bus.emit(_make_datalog(ssl_session_id=session_id))

    flow = collector.get_flows()[0]
    assert flow.tls.sni == "api.example.com"
    assert flow.connection_id == f"sid:tls:{session_id}"


def test_cached_tls_does_not_clobber_existing_flow_fields():
    """Backfill only fills EMPTY fields; a value already on the flow wins."""
    bus, collector = _wire_up()

    # Data first creates the flow, then a STARTED stamps it directly.
    bus.emit(_make_datalog(client_random=CLIENT_RANDOM))
    bus.emit(_make_session_started(client_random=CLIENT_RANDOM,
                                   server_name="first.example.com"))
    flow = collector.get_flows()[0]
    assert flow.tls.sni == "first.example.com"


# ---------------------------------------------------------------------------
# BUG #5 — flush() emits COMPLETED for still-active flows
# ---------------------------------------------------------------------------

def test_flush_emits_completed_for_active_flow():
    """flush() must emit a COMPLETED FlowEvent for a flow still ACTIVE at
    capture end so the passive-analysis worker can pick it up."""
    bus, collector = _wire_up()

    completed_events = []
    bus.subscribe(
        FlowEvent,
        lambda ev: completed_events.append(ev)
        if ev.flow_event_type == FlowEventType.COMPLETED else None,
    )

    bus.emit(_make_datalog(client_random=CLIENT_RANDOM))
    # The flow is still ACTIVE — no SESSION_ENDED, no idle gap.
    active = collector.get_flows()
    assert len(active) == 1
    assert active[0].state == FlowState.ACTIVE
    assert completed_events == []  # nothing completed yet

    collector.flush()

    assert len(completed_events) == 1
    ev = completed_events[0]
    assert ev.flow.flow_id == active[0].flow_id
    assert ev.flow.state == FlowState.COMPLETE


def test_flush_via_callback_also_notifies_completed():
    """The subscribe() callback path receives COMPLETED too (used by the TUI)."""
    bus, collector = _wire_up()

    notified = []
    collector.subscribe(lambda flow, event_type: notified.append((event_type, flow.flow_id)))

    bus.emit(_make_datalog(client_random=CLIENT_RANDOM))
    flow_id = collector.get_flows()[0].flow_id

    collector.flush()

    assert (FlowEventType.COMPLETED, flow_id) in notified


def test_flush_does_not_double_complete_already_finalized_flow():
    """A flow already COMPLETE (e.g. finalized by an idle gap) must NOT get a
    second COMPLETED from flush() — guard on FlowState.ACTIVE.

    Tracked by Flow object identity (id()): the idle-gap reset resets
    flow_sequence, so flow #2 happens to reuse flow #1's flow_id string even
    though they are distinct Flow objects.
    """
    bus, collector = _wire_up()

    completed_ids = []  # python id() of each completed Flow object
    bus.subscribe(
        FlowEvent,
        lambda ev: completed_ids.append(id(ev.flow))
        if ev.flow_event_type == FlowEventType.COMPLETED else None,
    )

    # First event creates flow #1. Second event > IDLE_THRESHOLD later forces
    # _finalize_connection on flow #1 (emitting its COMPLETED) and starts flow #2.
    bus.emit(_make_datalog(client_random=CLIENT_RANDOM, timestamp=1000.0))
    first_flow = collector.get_flows()[0]
    # get_flows() returns copies, so grab the live object for identity tracking.
    live_first = collector._flows[first_flow.flow_id]
    first_obj_id = id(live_first)
    bus.emit(_make_datalog(client_random=CLIENT_RANDOM, timestamp=1100.0))

    assert completed_ids == [first_obj_id]  # only flow #1 completed so far

    collector.flush()

    # flow #1 must not be completed a second time; flow #2 (still active) is.
    assert completed_ids.count(first_obj_id) == 1
    assert len(completed_ids) == 2


# ---------------------------------------------------------------------------
# #13 — package_name heuristic must only accept Android-package-shaped targets
# ---------------------------------------------------------------------------

def test_set_capture_target_package_name_classification():
    """set_capture_target() records package_name ONLY for Android-package-shaped
    targets, rejecting IPs, PIDs, paths and binary/file names."""
    collector = FlowCollector()

    # Accepts a real Android package — and always sets process_name.
    collector.set_capture_target("com.example.app")
    assert collector._package_name == "com.example.app"
    assert collector._process_name == "com.example.app"

    # Rejects IPs, bare PIDs, paths and binary/file names — process_name still set.
    for bad in ("10.0.0.1", "1234", "/proc/1/exe", "libssl.so", "app.exe"):
        collector.set_capture_target(bad)
        assert collector._package_name == "", f"{bad!r} wrongly treated as package"
        assert collector._process_name == bad


# --------------------------------------------------------------------------- #
# Offline opt-ins: flush(end_at_last_activity) and the event clock
# --------------------------------------------------------------------------- #


def test_flush_end_at_last_activity_uses_newest_chunk_time():
    collector = FlowCollector()
    first = _make_datalog(timestamp=1000.0)
    first.data = b"GET / HTTP/1.1\r\nHost: example.com\r\n"
    second = _make_datalog(timestamp=1005.0)
    second.data = b"\r\n"  # completes the same request
    collector.on_data(first)
    collector.on_data(second)
    collector.flush(end_at_last_activity=True)
    (flow,) = collector.get_flows()
    assert flow.started == 1000.0
    assert flow.ended == 1005.0


def test_flush_default_still_ends_at_wall_clock():
    collector = FlowCollector()
    collector.on_data(_make_datalog(timestamp=1000.0))
    collector.flush()
    (flow,) = collector.get_flows()
    assert flow.ended > 1e9 and flow.ended != 1000.0


def test_last_activity_falls_back_to_started():
    from friTap.flow.models import Flow

    flow = Flow(started=42.0)
    assert FlowCollector._last_activity_of(flow) == 42.0


def test_event_clock_tracks_newest_event_time():
    collector = FlowCollector()
    collector.use_event_clock(True)
    collector.on_data(_make_datalog(timestamp=1000.0))
    collector.on_data(_make_datalog(timestamp=900.0))  # older — clock stays
    assert collector._now() == 1000.0


def test_wall_clock_is_default():
    collector = FlowCollector()
    collector.on_data(_make_datalog(timestamp=1000.0))
    assert collector._now() > 1e9 + 1000


def test_event_clock_sweep_keeps_recent_connection_alive():
    """With pcap-era timestamps the wall-clock sweep finalizes every connection;
    the event clock only finalizes connections idle relative to the capture."""
    collector = FlowCollector()
    collector.use_event_clock(True)
    collector.on_data(_make_datalog(timestamp=1000.0))
    pending: list = []
    with collector._lock:
        collector._periodic_sweep(pending)
    assert pending == [] and len(collector._connections) == 1

    wall = FlowCollector()
    wall.on_data(_make_datalog(timestamp=1000.0))
    with wall._lock:
        wall._periodic_sweep(pending)
    assert len(wall._connections) == 0
