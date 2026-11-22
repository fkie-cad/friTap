"""Router plumbing of the frame-path QUIC STREAM chunk position.

WHY: a downstream writer rebuilds QUIC STREAM frames from DatalogEvent, so the
agent's ``stream_offset`` and ``fin`` must reach the event (and default safely
when an older agent or a non-frame hook omits them).
"""

from friTap.events import DatalogEvent, EventBus
from friTap.message_router import MessageRouter
from friTap.schemas.agent_messages import DatalogMessage


def _route(**extra) -> DatalogEvent:
    bus = EventBus()
    seen: list[DatalogEvent] = []
    bus.subscribe(DatalogEvent, seen.append)
    payload = {"contentType": "datalog", "function": "QuicConnection_OnStreamFrame",
               "direction": "read", "src_addr": "93.184.216.34", "src_port": 443,
               "dst_addr": "10.0.0.1", "dst_port": 5000, "ss_family": "AF_INET",
               "stream_id": 0, "quic_payload": "stream", "transport": "udp"}
    payload.update(extra)
    MessageRouter(bus).route(payload, b"abc")
    assert len(seen) == 1
    return seen[0]


def test_offset_and_fin_are_copied():
    event = _route(stream_offset=1200, fin=True)
    assert event.stream_offset == 1200
    assert event.fin is True


def test_offset_zero_is_kept():
    assert _route(stream_offset=0).stream_offset == 0


def test_defaults_when_absent():
    event = _route()
    assert event.stream_offset is None
    assert event.fin is False


def test_malformed_values_fall_back_to_defaults():
    event = _route(stream_offset="12", fin="true")
    assert event.stream_offset is None
    assert event.fin is False


def test_bool_is_not_an_offset():
    assert _route(stream_offset=True).stream_offset is None


def test_event_defaults():
    event = DatalogEvent()
    assert event.stream_offset is None
    assert event.fin is False


def test_schema_accepts_and_defaults():
    assert DatalogMessage().stream_offset is None
    assert DatalogMessage().fin is None
    msg = DatalogMessage(stream_offset=7, fin=True)
    assert (msg.stream_offset, msg.fin) == (7, True)
