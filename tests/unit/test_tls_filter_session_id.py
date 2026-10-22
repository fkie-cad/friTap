"""The ``tls`` filter must not match flows just because they carry a session id.

Telegram Secret Chats reuse ``ssl_session_id`` as ``telegram_e2e:<chat id>``,
so a session id alone is no evidence of TLS. Real TLS still matches through
``transport == "tls"`` or a tls layer. The live collector must not attach a
stray TlsLayer (via ``flow.tls``) to non-TLS flows either.
"""

from __future__ import annotations

import pytest

from friTap.events import DatalogEvent, EventBus, LibraryDetectedEvent
from friTap.flow.collector import FlowCollector
from friTap.flow.layers import TelegramE2ELayer
from friTap.flow.models import Flow, FlowState, FlowSummary
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter
from tests.unit._display_filter_helpers import match as _match

E2E_SESSION_ID = "telegram_e2e:4242"


def _telegram_e2e_flow() -> Flow:
    flow = Flow(
        flow_id="e2e-1", connection_id=f"sid:{E2E_SESSION_ID}",
        transport="telegram_e2e", ssl_session_id=E2E_SESSION_ID,
        state=FlowState.COMPLETE,
    )
    flow.add_layer(TelegramE2ELayer(chat_id=4242, message_count=1))
    return flow


# -- Filter: Telegram Secret Chat flows ---------------------------------------

def test_telegram_e2e_flow_is_telegram_not_tls():
    flow = _telegram_e2e_flow()
    assert _match("telegram", flow)
    assert not _match("tls", flow)


def test_telegram_e2e_summary_is_telegram_not_tls():
    summary = FlowSummary.from_flow(_telegram_e2e_flow())
    assert _match("telegram", summary)
    assert not _match("tls", summary)


def test_telegram_e2e_tap_round_trip_is_telegram_not_tls(tmp_path):
    path = str(tmp_path / "e2e.tap")
    writer = TapWriter()
    writer.open(path, target="test")
    writer.write_flow(_telegram_e2e_flow())
    writer.close()

    with TapReader(path) as reader:
        (summary,) = reader.read_flow_summaries()
        flow = reader.read_flow(summary.flow_id)

    assert "telegram_e2e" in summary.protocols  # "telegram" is a filter alias
    assert "tls" not in summary.protocols
    assert _match("telegram", summary) and not _match("tls", summary)
    assert _match("telegram", flow) and not _match("tls", flow)


def test_tls_flow_round_trip_still_matches_tls(tmp_path):
    path = str(tmp_path / "tls.tap")
    writer = TapWriter()
    writer.open(path, target="test")
    writer.write_flow(Flow(flow_id="t-1", connection_id="c-1",
                           ssl_session_id="abcd", state=FlowState.COMPLETE))
    writer.close()

    with TapReader(path) as reader:
        (summary,) = reader.read_flow_summaries()
        flow = reader.read_flow(summary.flow_id)

    assert "tls" in summary.protocols
    assert _match("tls", summary) and _match("tls", flow)


# -- tls.session_id is TLS-only ------------------------------------------------

def test_tls_session_id_empty_for_telegram_e2e_flow_and_summary():
    flow = _telegram_e2e_flow()
    for obj in (flow, FlowSummary.from_flow(flow)):
        assert not _match("tls.session_id", obj)
        assert not _match('tls.session_id contains "telegram_e2e"', obj)
        assert not _match(f'tls.session_id == "{E2E_SESSION_ID}"', obj)


def test_tls_session_id_still_reported_for_tls_flow():
    flow = Flow(flow_id="t-2", connection_id="c-2", transport="tls",
                ssl_session_id="abcd", state=FlowState.COMPLETE)
    for obj in (flow, FlowSummary.from_flow(flow)):
        assert _match("tls.session_id", obj)
        assert _match('tls.session_id == "abcd"', obj)


# -- Live collector: library stamping only on TLS flows -----------------------

def _collector_with_library(library="OpenSSL") -> tuple[EventBus, FlowCollector]:
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    bus.subscribe(LibraryDetectedEvent, collector.on_library_detected)
    bus.emit(LibraryDetectedEvent(library=library))
    return bus, collector


def _emit_data(bus: EventBus, protocol: str, src_port: int) -> None:
    bus.emit(DatalogEvent(
        data=b"\x00\x01\x02\x03payload", function="hook", direction="write",
        src_addr="10.0.0.2", src_port=src_port,
        dst_addr="149.154.167.51", dst_port=443,
        protocol=protocol, timestamp=1000.0,
    ))


def _only_flow(collector: FlowCollector) -> Flow:
    (flow,) = collector.get_flows()
    return flow


@pytest.mark.parametrize("protocol", ["mtproto", "quic", "telegram_e2e"])
def test_live_non_tls_flow_gets_no_tls_layer_after_library_event(protocol):
    bus, collector = _collector_with_library()
    _emit_data(bus, protocol, src_port=51000)

    flow = _only_flow(collector)
    assert flow.transport == protocol
    assert flow.layer("tls") is None
    assert not _match("tls", flow)


def test_live_tls_flow_gets_detected_library():
    bus, collector = _collector_with_library("BoringSSL")
    _emit_data(bus, "tls", src_port=51001)

    flow = _only_flow(collector)
    tls = flow.layer("tls")
    assert tls is not None and tls.library == "BoringSSL"
    assert _match("tls", flow)
