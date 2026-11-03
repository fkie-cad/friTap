"""WP9: FlowCollector memory caps for attacker-controlled payload streams.

* per-flow retained chunk bytes are capped (MAX_FLOW_CHUNK_BYTES); bytes keep
  being counted and the flow is reported truncated;
* the live Signal raw buffer is capped (MAX_SIGNAL_RAW_BYTES); past it decoding
  stops for that connection direction instead of re-decrypting an ever-growing
  buffer on every event.
"""

from __future__ import annotations

from friTap.events import DatalogEvent, EventBus
from friTap.flow import collector as collector_mod
from friTap.flow.collector import FlowCollector, _ConnectionState
from friTap.flow.models import Flow, FlowChunk


def _chunk(size: int) -> FlowChunk:
    return FlowChunk(data=b"x" * size, direction="read", timestamp=1.0)


def test_append_chunk_within_cap_retains(monkeypatch):
    monkeypatch.setattr(collector_mod, "MAX_FLOW_CHUNK_BYTES", 10)
    collector = FlowCollector()
    flow = Flow(flow_id="f1")
    collector._append_chunk(flow, _chunk(4))
    collector._append_chunk(flow, _chunk(6))
    assert len(flow.chunks) == 2
    assert flow._total_bytes == 10
    assert collector.is_flow_truncated("f1") is False


def test_append_chunk_past_cap_counts_but_drops(monkeypatch):
    monkeypatch.setattr(collector_mod, "MAX_FLOW_CHUNK_BYTES", 10)
    collector = FlowCollector()
    flow = Flow(flow_id="f1")
    collector._append_chunk(flow, _chunk(8))
    collector._append_chunk(flow, _chunk(8))
    collector._append_chunk(flow, _chunk(1))  # also dropped once truncated
    assert len(flow.chunks) == 1
    assert flow._total_bytes == 17
    assert collector.is_flow_truncated("f1") is True


def test_cap_is_per_flow(monkeypatch):
    monkeypatch.setattr(collector_mod, "MAX_FLOW_CHUNK_BYTES", 10)
    collector = FlowCollector()
    a, b = Flow(flow_id="a"), Flow(flow_id="b")
    collector._append_chunk(a, _chunk(10))
    collector._append_chunk(b, _chunk(10))
    assert len(a.chunks) == len(b.chunks) == 1


def test_clear_resets_truncation(monkeypatch):
    monkeypatch.setattr(collector_mod, "MAX_FLOW_CHUNK_BYTES", 1)
    collector = FlowCollector()
    collector._append_chunk(Flow(flow_id="f1"), _chunk(2))
    collector.clear()
    assert collector.is_flow_truncated("f1") is False


def test_merge_carries_retained_state(monkeypatch):
    monkeypatch.setattr(collector_mod, "MAX_FLOW_CHUNK_BYTES", 1)
    collector = FlowCollector()
    collector._append_chunk(Flow(flow_id="resp"), _chunk(2))
    collector._merge_retained_bytes("req", "resp")
    assert collector.is_flow_truncated("req") is True
    assert collector.is_flow_truncated("resp") is False


# --------------------------------------------------------------------------- #
# live Signal buffer
# --------------------------------------------------------------------------- #

def test_signal_buffer_extends_under_cap(monkeypatch):
    monkeypatch.setattr(collector_mod, "MAX_SIGNAL_RAW_BYTES", 10)
    conn = _ConnectionState("c1")
    assert FlowCollector._extend_signal_buffer(conn, "read", b"abc") == bytearray(b"abc")
    assert FlowCollector._extend_signal_buffer(conn, "read", b"def") == bytearray(b"abcdef")


def test_signal_buffer_capped_releases_and_stops(monkeypatch):
    monkeypatch.setattr(collector_mod, "MAX_SIGNAL_RAW_BYTES", 10)
    conn = _ConnectionState("c1")
    FlowCollector._extend_signal_buffer(conn, "read", b"x" * 8)
    assert FlowCollector._extend_signal_buffer(conn, "read", b"x" * 8) is None
    assert conn.signal_raw["read"] == bytearray()
    assert FlowCollector._extend_signal_buffer(conn, "read", b"y") is None
    # The other direction is unaffected.
    assert FlowCollector._extend_signal_buffer(conn, "write", b"z") == bytearray(b"z")


class _RecordingDecryptor:
    has_keys = True

    def __init__(self):
        self.fed_sizes: list[int] = []

    def feed(self, stream_key, buffer, direction, **_kw):
        self.fed_sizes.append(len(buffer))
        return []


def _datalog(data: bytes) -> DatalogEvent:
    return DatalogEvent(
        data=data, function="SSL_read", direction="read",
        src_addr="10.0.0.1", src_port=443, dst_addr="10.0.0.2", dst_port=50000,
        timestamp=1.0,
    )


def test_collect_signal_stops_feeding_past_cap(monkeypatch):
    monkeypatch.setattr(collector_mod, "MAX_SIGNAL_RAW_BYTES", 10)
    collector = FlowCollector(event_bus=EventBus())
    decryptor = _RecordingDecryptor()
    collector._signal_decryptor = decryptor
    conn = _ConnectionState("c1")
    out: list = []
    for _ in range(4):
        collector._collect_signal_messages(conn, "read", _datalog(b"x" * 4), out)
    assert decryptor.fed_sizes == [4, 8]


def test_truncated_flag_set_on_flow(monkeypatch):
    monkeypatch.setattr(collector_mod, "MAX_FLOW_CHUNK_BYTES", 1)
    collector = FlowCollector()
    flow = Flow(flow_id="f1")
    assert flow.truncated is False
    collector._append_chunk(flow, _chunk(2))
    assert flow.truncated is True


def test_truncated_flag_roundtrips_through_tap():
    from friTap.flow.tap_format import decode_flow, encode_flow

    for value in (True, False):
        flow = Flow(flow_id="f1", truncated=value)
        decoded = decode_flow(encode_flow(flow))
        assert decoded.truncated is value
