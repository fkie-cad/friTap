"""FlowCollector: transport-pinned Telegram parsing, one flow per packet.

Every Secret-Chat (``telegram_e2e``) and cloud MTProto (``mtproto``) packet
becomes its own complete flow carrying the packet's REAL src/dst: a sent
packet fills ``request``, a received one ``response`` (forensic rows).
"""

import struct

from friTap.events import DatalogEvent
from friTap.flow.collector import IDLE_THRESHOLD, FlowCollector
from friTap.flow.models import FlowEventType, FlowState, FlowSummary
from tests.unit._tl_helpers import tl_str

DEVICE = ("192.168.0.66", 39398)
DC = ("149.154.167.41", 5222)
E2E_SID = "telegram_e2e:abcdef0123456789"

# decryptedMessageLayer (layer 151) wrapping decryptedMessage "Hi infected",
# captured from a real Secret Chat. Everything before the trailing TL string
# is the shared envelope; _e2e_blob swaps only the message text.
_HI_INFECTED_HEX = (
    "8917e31b0fc1a2e4f91e39178d0905d8cb6391229700000014000000390000007446cc91"
    "0000000036f216008c205efc000000000b486920696e666563746564"
)
_ENVELOPE = bytes.fromhex(_HI_INFECTED_HEX)[:-12]


def _e2e_blob(text: str) -> bytes:
    return _ENVELOPE + tl_str(text)


def _e2e_event(text: str, direction: str, ts: float) -> DatalogEvent:
    """A Secret-Chat event as offline conversion emits it (carrying packet 4-tuple)."""
    src, dst = (DEVICE, DC) if direction == "write" else (DC, DEVICE)
    return DatalogEvent(
        data=_e2e_blob(text), function="telegram_e2e_offline",
        direction=direction, src_addr=src[0], src_port=src[1],
        dst_addr=dst[0], dst_port=dst[1], ssl_session_id=E2E_SID,
        protocol="telegram_e2e", timestamp=ts,
    )


def _collect(*events) -> FlowCollector:
    collector = FlowCollector()
    collector.use_event_clock(True)
    for event in events:
        collector.on_data(event)
    return collector


def _flows(collector):
    return sorted(collector.live_flows(), key=lambda f: f.started)


def test_blob_fixture_matches_real_capture():
    assert _e2e_blob("Hi infected").hex() == _HI_INFECTED_HEX


def test_write_then_read_gives_two_single_packet_flows():
    collector = _collect(
        _e2e_event("Hi infected", "write", 1000.0),
        _e2e_event("hello folks", "read", 1005.0),
    )
    sent, received = _flows(collector)
    assert sent.request.body == b"Hi infected" and sent.response is None
    assert received.response.body == b"hello folks" and received.request is None
    assert sent.request.protocol == received.response.protocol == "Telegram-E2E"
    assert sent.request.method == "decryptedMessage"
    assert (sent.started, sent.ended) == (1000.0, 1000.0)
    assert (received.started, received.ended) == (1005.0, 1005.0)
    assert sent.state == received.state == FlowState.COMPLETE


def test_each_flow_holds_only_its_own_packet():
    collector = _collect(
        _e2e_event("Hi infected", "write", 1000.0),
        _e2e_event("hello folks", "read", 1005.0),
    )
    sent, received = _flows(collector)
    assert sent.request.raw == _e2e_blob("Hi infected")
    assert received.response.raw == _e2e_blob("hello folks")
    assert [(c.direction, c.data) for c in sent.chunks] == [
        ("write", _e2e_blob("Hi infected"))]
    assert [(c.direction, c.data) for c in received.chunks] == [
        ("read", _e2e_blob("hello folks"))]


def test_read_row_keeps_real_direction_dc_to_device():
    collector = _collect(_e2e_event("hello folks", "read", 1000.0))
    [flow] = _flows(collector)
    assert flow.request is None
    assert flow.response.body == b"hello folks"
    assert (flow.src_addr, flow.src_port) == DC
    assert (flow.dst_addr, flow.dst_port) == DEVICE
    assert (flow.local_addr, flow.local_port) == DEVICE
    assert (flow.remote_addr, flow.remote_port) == DC


def test_write_row_local_is_device():
    collector = _collect(_e2e_event("Hi infected", "write", 1000.0))
    [flow] = _flows(collector)
    assert (flow.src_addr, flow.src_port) == DEVICE
    assert (flow.local_addr, flow.local_port) == DEVICE
    assert (flow.remote_addr, flow.remote_port) == DC


def test_read_row_draws_literal_arrow():
    collector = _collect(
        _e2e_event("Hi infected", "write", 1000.0),
        _e2e_event("hello folks", "read", 1005.0),
    )
    sent, received = _flows(collector)
    assert sent.display_connection == "192.168.0.66:39398 \u2192 149.154.167.41:5222"
    assert received.display_connection == "149.154.167.41:5222 \u2192 192.168.0.66:39398"
    for flow in (sent, received):
        assert FlowSummary.from_flow(flow).display_connection == flow.display_connection


def test_write_write_read_gives_three_flows():
    collector = _collect(
        _e2e_event("first", "write", 1000.0),
        _e2e_event("second", "write", 1001.0),
        _e2e_event("reply", "read", 1002.0),
    )
    collector.flush(end_at_last_activity=True)
    first, second, reply = _flows(collector)
    assert first.request.body == b"first" and first.response is None
    assert [c.direction for c in first.chunks] == ["write"]
    assert second.request.body == b"second" and second.response is None
    assert reply.response.body == b"reply" and reply.request is None


def test_read_after_write_read_opens_its_own_flow():
    collector = _collect(
        _e2e_event("ping", "write", 1000.0),
        _e2e_event("pong", "read", 1001.0),
        _e2e_event("unsolicited", "read", 1002.0),
    )
    collector.flush(end_at_last_activity=True)
    _, pong, lone = _flows(collector)
    assert pong.response.body == b"pong"
    assert lone.request is None and lone.response.body == b"unsolicited"


def test_read_before_write_is_never_merged_at_flush():
    collector = _collect(
        _e2e_event("early reply", "read", 1000.0),
        _e2e_event("later send", "write", 1001.0),
    )
    collector.flush(end_at_last_activity=True)
    lone_response, lone_request = _flows(collector)
    assert lone_response.request is None
    assert lone_request.response is None


def test_packet_flows_unaffected_by_idle_gap():
    gap = IDLE_THRESHOLD + 3.0
    collector = _collect(
        _e2e_event("Hi infected", "write", 1000.0),
        _e2e_event("hello folks", "read", 1000.0 + gap),
    )
    sent, received = _flows(collector)
    assert sent.request.body == b"Hi infected"
    assert received.response.body == b"hello folks"
    assert received.started == received.ended == 1000.0 + gap


def test_packet_flows_unaffected_by_periodic_sweep(monkeypatch):
    import friTap.flow.collector as collector_mod

    monkeypatch.setattr(collector_mod, "_SWEEP_INTERVAL", 1)
    gap = 3 * IDLE_THRESHOLD
    # Unrelated traffic advances the event clock so the sweep sees the Secret
    # Chat idle for longer than its 2 x IDLE_THRESHOLD cut-off.
    other = _mtproto_event(_PING, "write", 1000.0 + gap)
    collector = _collect(
        _e2e_event("Hi infected", "write", 1000.0),
        other,
        _e2e_event("hello folks", "read", 1000.0 + gap + 1.0),
    )
    sent, received = [f for f in _flows(collector) if f.transport == "telegram_e2e"]
    assert sent.request.body == b"Hi infected"
    assert received.response.body == b"hello folks"
    assert all(len(f.chunks) == 1 for f in (sent, received))


def test_packet_flow_emits_created_then_completed():
    seen = []
    collector = FlowCollector()
    collector.subscribe(lambda flow, kind: seen.append((kind, flow.flow_id)))
    collector.on_data(_e2e_event("Hi infected", "write", 1000.0))
    assert [kind for kind, _ in seen] == [
        FlowEventType.CREATED, FlowEventType.COMPLETED]
    assert len({fid for _, fid in seen}) == 1


def test_e2e_never_misdetected_as_websocket():
    # "89 17" is a WebSocket FIN|PING header to a byte sniffer.
    collector = _collect(_e2e_event("Hi infected", "write", 1000.0))
    [flow] = _flows(collector)
    assert flow.request.protocol == "Telegram-E2E"
    assert flow.transport == "telegram_e2e"


# ---------------------------------------------------------------------------
# Cloud MTProto: one flow per record
# ---------------------------------------------------------------------------

_PING = struct.pack("<Iq", 0x7ABE77EC, 42)          # ping ping_id:long
_MSGS_ACK = struct.pack("<III", 0x62D6B459, 0x1CB5C415, 0)  # msgs_ack []


def _mtproto_event(data: bytes, direction: str, ts: float) -> DatalogEvent:
    src, dst = (DEVICE, DC) if direction == "write" else (DC, DEVICE)
    return DatalogEvent(
        data=data, function="mtproto_offline", direction=direction,
        src_addr=src[0], src_port=src[1], dst_addr=dst[0], dst_port=dst[1],
        protocol="mtproto", timestamp=ts,
    )


def test_mtproto_each_record_is_its_own_flow():
    collector = _collect(
        _mtproto_event(_MSGS_ACK, "write", 1000.0),
        _mtproto_event(_PING, "write", 1000.1),
        _mtproto_event(_MSGS_ACK, "read", 1000.2),
    )
    ack, ping, ack_in = _flows(collector)
    assert ack.request.protocol == "MTProto"
    assert ack.request.raw == _MSGS_ACK and ack.response is None
    assert ping.request.raw == _PING and ping.response is None
    assert ack_in.response.raw == _MSGS_ACK and ack_in.request is None
    assert [len(f.chunks) for f in (ack, ping, ack_in)] == [1, 1, 1]
    assert (ack_in.src_addr, ack_in.src_port) == DC
    assert (ack_in.local_addr, ack_in.local_port) == DEVICE
    assert all(f.state == FlowState.COMPLETE for f in (ack, ping, ack_in))


def test_mtproto_n_events_give_n_completed_flows():
    completed = []
    collector = FlowCollector()
    collector.use_event_clock(True)
    collector.subscribe(
        lambda flow, kind: kind == FlowEventType.COMPLETED and completed.append(flow))
    for i in range(7):
        direction = "write" if i % 2 == 0 else "read"
        collector.on_data(_mtproto_event(_PING, direction, 1000.0 + i))
    assert len(completed) == 7
    assert len({f.flow_id for f in completed}) == 7
    assert all(len(f.chunks) == 1 for f in completed)


def test_mtproto_grouped_method_is_best_ranked():
    from friTap.flow.collector import _merge_tl_records
    from friTap.parsers.base import ParseResult

    service = ParseResult(protocol="MTProto", method="msgs_ack", raw=b"a", body=b"a")
    rpc = ParseResult(protocol="MTProto", method="messages.getHistory", raw=b"b", body=b"b")
    merged = _merge_tl_records(service, rpc)
    assert merged.method == "messages.getHistory"
    assert (merged.raw, merged.body) == (b"ab", b"ab")
    assert _merge_tl_records(rpc, service).method == "messages.getHistory"


def test_display_connection_literal_direction_flag():
    from friTap.flow.display import display_connection
    from friTap.parsers.base import ParseResult

    response = ParseResult(protocol="MTProto", is_request=False)
    args = (None, response, DC[0], DC[1], DEVICE[0], DEVICE[1])
    assert display_connection(*args) == "149.154.167.41:5222 ← 192.168.0.66:39398"
    assert display_connection(*args, literal_direction=True) == (
        "149.154.167.41:5222 → 192.168.0.66:39398")


def test_tls_flow_local_remote_unchanged_on_read():
    event = DatalogEvent(
        data=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", function="SSL_read",
        direction="read", src_addr=DEVICE[0], src_port=DEVICE[1],
        dst_addr=DC[0], dst_port=DC[1], protocol="tls", timestamp=1000.0)
    [flow] = _flows(_collect(event))
    assert (flow.local_addr, flow.remote_addr) == (DEVICE[0], DC[0])
