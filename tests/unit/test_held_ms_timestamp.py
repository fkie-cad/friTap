"""``held_ms`` back-dates a datalog record the agent held before sending.

The host stamps records on receipt; QUIC bodies held while their stream id is
learned would otherwise carry a late timestamp.
"""

from __future__ import annotations

import pytest

from friTap import message_router as router_module
from friTap import pipeline as pipeline_module
from friTap.events import DatalogEvent, EventBus
from friTap.flow.collector import FlowCollector
from friTap.message_router import MessageRouter
from friTap.output.quic_pcap_bridge import QuicPcapBridge
from friTap.output.quic_synthetic import CLIENT, SyntheticOutput
from friTap.pipeline import NormalizeStage, PipelineContext, create_default_pipeline
from friTap.schemas.agent_messages import DatalogMessage
from friTap.sinks.pcapng import PcapngSink

NOW = 1_000.0


@pytest.fixture(autouse=True)
def _frozen_clock(monkeypatch):
    monkeypatch.setattr(pipeline_module.time, "time", lambda: NOW)


def _stamp(**fields) -> float:
    ctx = PipelineContext()
    NormalizeStage().process({"contentType": "datalog", "function": "x", **fields}, b"", ctx)
    return ctx.timestamp


def test_held_record_is_back_dated():
    assert _stamp(held_ms=1500) == pytest.approx(NOW - 1.5)


@pytest.mark.parametrize("fields", [{}, {"held_ms": None}, {"held_ms": 0}, {"held_ms": -5},
                                    {"held_ms": "100"}, {"held_ms": True}])
def test_absent_or_invalid_held_ms_keeps_receive_time(fields):
    assert _stamp(**fields) == NOW


def test_back_dating_never_goes_negative():
    assert _stamp(held_ms=10**12) == 0.0


def test_schema_accepts_optional_held_ms():
    assert DatalogMessage().held_ms is None
    assert DatalogMessage(held_ms=12).held_ms == 12


# --- packet writers keep the arrival time; flows keep the back-dated time -------
# Records reach the pcap in arrival order, so a back-dated packet time would
# land before packets written earlier (out of order in Wireshark).

HELD = {"held_ms": 1500}
REQUEST = b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"


def _datalog(**fields) -> dict:
    return {"contentType": "datalog", "function": "SSL_write", "ss_family": "AF_INET",
            "src_addr": 0x0A000002, "src_port": 51000, "dst_addr": 0x5DB8D822, "dst_port": 443,
            "ssl_session_id": "sess-1", **fields}


@pytest.fixture
def router_clock(monkeypatch):
    monkeypatch.setattr(router_module.time, "time", lambda: NOW)


class _Capture:
    def __init__(self):
        self.data = []

    def open(self): pass
    def on_keylog(self, event): pass
    def on_meta(self, event): pass
    def flush(self): pass
    def close(self): pass

    def on_data(self, event):
        self.data.append(event)


def _pipeline_events(*msgs):
    pipeline, sink = create_default_pipeline(filter_infrastructure=False, include_loopback=True), _Capture()
    pipeline.add_sink(sink)
    for msg in msgs:
        pipeline.push(msg, REQUEST)
    return sink.data


def test_pipeline_held_record_carries_both_times():
    (held, plain) = _pipeline_events(_datalog(**HELD), _datalog())
    assert (held.timestamp, held.received_at) == (pytest.approx(NOW - 1.5), NOW)
    assert (plain.timestamp, plain.received_at) == (NOW, None)


def _epb_times(tmp_path, events):
    sink, times = PcapngSink(str(tmp_path / "out.pcapng")), []
    sink.open()
    sink._write_packet_block = lambda packet, t_us: times.append(t_us)
    for event in events:
        sink.on_data(event)
    sink.close()
    return times


def test_pcapng_sink_stamps_the_arrival_time(tmp_path):
    held, plain = _pipeline_events(_datalog(**HELD), _datalog())
    assert _epb_times(tmp_path, [held, plain]) == [int(NOW * 1_000_000)] * 2


def _routed(payload: dict) -> DatalogEvent:
    events = []
    bus = EventBus()
    bus.subscribe(DatalogEvent, events.append)
    MessageRouter(bus).route(payload, REQUEST)
    return events[0]


def test_router_held_record_carries_both_times(router_clock):
    held, plain = _routed(_datalog(**HELD)), _routed(_datalog())
    assert (held.timestamp, held.received_at) == (pytest.approx(NOW - 1.5), NOW)
    assert (plain.timestamp, plain.received_at) == (NOW, None)


def test_flow_chunk_keeps_the_back_dated_time(router_clock):
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    MessageRouter(bus).route(_datalog(**HELD), REQUEST)
    collector.flush()
    chunks = [c for flow in collector.get_flows() for c in flow.chunks]
    assert chunks and all(c.timestamp == pytest.approx(NOW - 1.5) for c in chunks)


class _OneDatagramWriter:
    def __init__(self):
        self.now = []

    def feed_stream(self, *args):
        self.now.append(args[-1])
        return SyntheticOutput(packets=[(CLIENT, b"c1")])


def _quic_event(**times) -> DatalogEvent:
    return DatalogEvent(data=b"abc", direction="write", src_addr="10.0.0.2", src_addr_raw=0x0A000002,
                        src_port=41000, dst_addr="142.250.74.46", dst_addr_raw=0x8EFA4A2E, dst_port=443,
                        ssl_session_id="0x5eed", transport="udp", protocol="quic", stream_id=0,
                        quic_payload="stream", **times)


@pytest.mark.parametrize("times, written_at", [
    ({"timestamp": NOW - 1.5, "received_at": NOW}, NOW),
    ({"timestamp": NOW}, NOW),
])
def test_quic_synthetic_datagram_is_stamped_on_arrival(times, written_at):
    writer, written = _OneDatagramWriter(), []
    bridge = QuicPcapBridge(writer=writer, available=lambda: True, notice=[].append)
    bridge.route(_quic_event(**times), lambda record, timestamp=None: written.append((record, timestamp)),
                 lambda lines: None)
    assert writer.now == [written_at]
    (record, timestamp), = written
    assert timestamp == written_at and record.timestamp == written_at and record.received_at is None
