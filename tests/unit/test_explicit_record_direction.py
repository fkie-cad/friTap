"""Consumers honour a datalog record's explicit ``direction``.

QUIC records carry ``direction`` from the agent; their hook labels (e.g. the
Google QUICHE STREAM-frame hooks) are not listed in SSL_READ/SSL_WRITE. Every
writer must therefore use the explicit direction and fall back to the
function label only when it is absent.
"""

from __future__ import annotations

import io

import pytest

from friTap.constants import direction_label
from friTap.events import DatalogEvent
from friTap.message_router import MessageRouter
from friTap.output import pcapng_handler as pcapng_module
from friTap.output.live_wireshark_handler import LiveWiresharkHandler
from friTap.output.pcap_handler import PcapOutputHandler
from friTap.output.pcapng_handler import PcapngOutputHandler
from friTap.pipeline import NormalizeStage, PipelineContext
from friTap.schemas.canonical import Direction

UNKNOWN_IN_LABEL = "QuicConnection_OnStreamFrame"  # no read hint, not in SSL_READ


class _RecordingPcap:
    def __init__(self):
        self.functions = []

    def log_plaintext_payload(self, ss_family, function, *args, **kwargs):
        self.functions.append(function)


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _event(direction: str, function: str = UNKNOWN_IN_LABEL) -> DatalogEvent:
    return DatalogEvent(data=b"h3", function=function, direction=direction,
                        src_addr_raw=0x0A000001, src_port=443,
                        dst_addr_raw=0x0A000002, dst_port=50000)


@pytest.mark.parametrize("function,explicit,expected", [
    (UNKNOWN_IN_LABEL, "read", "SSL_read"),
    ("SSL_read", "write", "SSL_write"),
    ("SSL_read", None, "SSL_read"),
    ("custom_hook", "", "custom_hook"),
])
def test_direction_label(function, explicit, expected):
    assert direction_label(function, explicit) == expected


def test_pcapng_handler_uses_explicit_direction(monkeypatch):
    seen = []
    monkeypatch.setattr(pcapng_module, "build_framed_packets_from_fields",
                        lambda **kw: seen.append(kw["is_read"]) or [])
    handler = PcapngOutputHandler("unused.pcapng")
    handler._file = io.BytesIO()
    handler._write_epb(_event("read"))
    handler._write_epb(_event("", function="SSL_read"))
    assert seen == [True, True]


@pytest.mark.parametrize("handler_cls", [PcapOutputHandler, LiveWiresharkHandler])
def test_pcap_writers_pass_direction_canonical_label(handler_cls):
    pcap = _RecordingPcap()
    handler = handler_cls(pcap) if handler_cls is PcapOutputHandler else handler_cls()
    handler._pcap = pcap
    handler.on_data(_event("read"))
    handler.on_data(_event("write", function="SSL_read"))
    assert pcap.functions == ["SSL_read", "SSL_write"]


@pytest.mark.parametrize("explicit,expected", [("read", Direction.READ), (None, Direction.WRITE)])
def test_pipeline_normalize_honours_explicit_direction(explicit, expected):
    msg = {"contentType": "datalog", "function": UNKNOWN_IN_LABEL}
    if explicit:
        msg["direction"] = explicit
    ctx = PipelineContext()
    NormalizeStage().process(msg, b"", ctx)
    assert ctx.direction is expected


def test_router_passes_quic_payload_library_and_direction():
    bus = _Bus()
    MessageRouter(bus).route({
        "contentType": "datalog", "function": UNKNOWN_IN_LABEL, "direction": "read",
        "protocol": "tls", "stream_id": 0, "quic_payload": "stream",
        "library": "libmonochrome_64.so",
    }, b"\x01\x00")
    (event,) = bus.events
    assert (event.direction, event.quic_payload, event.library) == (
        "read", "stream", "libmonochrome_64.so")


def test_router_defaults_missing_quic_fields_to_empty():
    bus = _Bus()
    MessageRouter(bus).route({"contentType": "datalog", "function": "SSL_write"}, b"x")
    (event,) = bus.events
    assert (event.quic_payload, event.library) == ("", "")
