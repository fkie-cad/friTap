"""eBPF producer outputs: handler selection, the eBPF pcap adapters and the router filter."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from friTap.config import FriTapConfig
from friTap.events import DatalogEvent, EventBus
from friTap.output import ebpf_pcap
from friTap.output.ebpf_pcap import EbpfFullCaptureOutputHandler, EbpfPcapOutputHandler
from friTap.output.factory import OutputHandlerFactory
from friTap.output.pcap_handler import PcapOutputHandler
from friTap.output.pcapng_handler import PcapngOutputHandler


def _config(**output):
    config = FriTapConfig(target="fixture", backend="ebpf")
    for name, value in output.items():
        setattr(config.output, name, value)
    return config


def _create(config):
    return OutputHandlerFactory.create_producer_handlers(
        config, {"session_info": {"backend": "ebpf"}}, logging.getLogger("test"), None)


# ------------------------------------------------- create_producer_handlers

def test_producer_handlers_empty_without_outputs():
    assert _create(_config()) == []


def test_producer_handlers_full_capture_wins_over_pcap(tmp_path):
    handlers = _create(_config(pcap=str(tmp_path / "c.pcap"), full_capture=True))
    assert [type(h) for h in handlers] == [EbpfFullCaptureOutputHandler]


def test_producer_handlers_plain_pcap(tmp_path):
    handlers = _create(_config(pcap=str(tmp_path / "c.pcap")))
    assert [type(h) for h in handlers] == [EbpfPcapOutputHandler]


def test_producer_handlers_tap_is_not_deferred_under_full_capture(tmp_path):
    from friTap.output.tap_handler import TapOutputHandler

    handlers = _create(_config(pcap=str(tmp_path / "c.pcap"), full_capture=True,
                               tap_output=str(tmp_path / "c.tap")))
    assert [type(h) for h in handlers] == [EbpfFullCaptureOutputHandler, TapOutputHandler]


def test_producer_handlers_wire_json(tmp_path):
    handlers = _create(_config(json_output=str(tmp_path / "c.jsonl")))
    assert len(handlers) == 1
    assert type(handlers[0]).__name__ == "JsonlOutputHandler"


# ---------------------------------------------------- EbpfPcapOutputHandler

@pytest.mark.parametrize("container, expected", [
    ("pcapng", PcapngOutputHandler), ("pcap", PcapOutputHandler)])
def test_pcap_writer_follows_factory_container_choice(monkeypatch, tmp_path, container, expected):
    monkeypatch.setattr("friTap.pcap.PCAP", MagicMock(name="PCAP"))
    output = SimpleNamespace(pcap=str(tmp_path / "c.out"), pcap_container=container)
    assert type(ebpf_pcap._build_pcap_writer(output)) is expected


class _RecordingWriter:
    def __init__(self):
        self.events = []
        self.closed = False

    def setup(self, bus):
        bus.subscribe(DatalogEvent, self.events.append)

    def close(self):
        self.closed = True


def _handler(monkeypatch):
    writer = _RecordingWriter()
    monkeypatch.setattr(ebpf_pcap, "_build_pcap_writer", lambda output: writer)
    handler = EbpfPcapOutputHandler(SimpleNamespace(pcap="x.pcap", pcap_container="pcap"))
    bus = EventBus()
    handler.setup(bus)
    return handler, bus, writer


def test_ebpf_pcap_pins_synthetic_endpoints_per_connection(monkeypatch):
    handler, bus, writer = _handler(monkeypatch)
    for direction in ("write", "read", "write"):
        bus.emit(DatalogEvent(data=b"x", direction=direction, ssl_session_id="conn-1"))

    first_write, read, second_write = writer.events
    assert all(e.endpoints_synthetic for e in writer.events)
    assert (first_write.src_addr, first_write.src_port) == (second_write.src_addr, second_write.src_port)
    assert (read.src_addr, read.src_port) == (first_write.dst_addr, first_write.dst_port)


def test_ebpf_pcap_resolves_each_connection_once(monkeypatch):
    handler, bus, writer = _handler(monkeypatch)
    calls = []
    real_resolve = handler._pinner.resolve
    monkeypatch.setattr(handler._pinner, "resolve",
                        lambda *args: calls.append(args) or real_resolve(*args))
    for _ in range(3):
        bus.emit(DatalogEvent(data=b"x", direction="write", ssl_session_id="conn-1"))
    assert calls == [("conn-1".encode().hex(), "tcp", False, None)]
    assert len(writer.events) == 3


def test_ebpf_pcap_distinct_connections_get_distinct_endpoints(monkeypatch):
    handler, bus, writer = _handler(monkeypatch)
    for sid in ("conn-1", "conn-2"):
        bus.emit(DatalogEvent(data=b"x", direction="write", ssl_session_id=sid))
    a, b = writer.events
    assert (a.src_addr, a.src_port) != (b.src_addr, b.src_port)


def test_ebpf_pcap_drops_records_without_session_and_closes_writer(monkeypatch):
    handler, bus, writer = _handler(monkeypatch)
    bus.emit(DatalogEvent(data=b"x", direction="write"))
    handler.close()
    assert writer.events == []
    assert writer.closed


def test_ebpf_pcap_close_before_setup_is_safe():
    EbpfPcapOutputHandler(SimpleNamespace(pcap="x.pcap", pcap_container="pcap")).close()


# --------------------------------------------- EbpfFullCaptureOutputHandler

def _output():
    return SimpleNamespace(pcap="c.pcap", include_loopback=False, filter_infrastructure=True,
                           pcap_container="pcap")


def _full_capture(monkeypatch, worker):
    pcap = MagicMock(full_capture_thread=worker)
    factory = MagicMock(return_value=pcap)
    monkeypatch.setattr("friTap.pcap.PCAP", factory)
    handler = EbpfFullCaptureOutputHandler(_output())
    handler.setup(EventBus())
    return handler, pcap, factory


def test_full_capture_starts_managed_worker_and_waits_for_ready(monkeypatch):
    worker = MagicMock(failure=None)
    worker.is_alive.return_value = False
    handler, pcap, factory = _full_capture(monkeypatch, worker)

    assert factory.call_args.kwargs["managed_full_capture"] is True
    worker.wait_until_ready.assert_called_once_with(5)
    handler.close()
    handler.close()  # second close is a no-op
    worker.join.assert_called_once_with(5)
    pcap.finalize_full_capture.assert_called_once()


def test_full_capture_close_raises_when_worker_hangs(monkeypatch):
    worker = MagicMock(failure=None)
    worker.is_alive.return_value = True
    handler, pcap, _ = _full_capture(monkeypatch, worker)
    with pytest.raises(RuntimeError, match="did not stop"):
        handler.close()
    pcap.finalize_full_capture.assert_not_called()


def test_full_capture_close_finalizes_then_reports_failure(monkeypatch):
    worker = MagicMock(failure=OSError("boom"))
    worker.is_alive.return_value = False
    handler, pcap, _ = _full_capture(monkeypatch, worker)
    with pytest.raises(RuntimeError, match="boom"):
        handler.close()
    pcap.finalize_full_capture.assert_called_once()


def test_full_capture_close_before_setup_is_safe():
    EbpfFullCaptureOutputHandler(_output()).close()


# ----------------------------------------- MessageRouter.install_display_filter

def _router():
    from friTap.message_router import MessageRouter
    return MessageRouter(EventBus())


def test_install_display_filter_ignores_empty_expression():
    router, logger = _router(), MagicMock()
    router.install_display_filter(None, logger)
    router.install_display_filter("", logger)
    assert router._data_filter is None
    logger.warning.assert_not_called()


def test_install_display_filter_sets_engine():
    router, logger = _router(), MagicMock()
    router.install_display_filter("tcp.port == 443", logger)
    assert router._data_filter is not None
    logger.info.assert_called_once()


def test_install_display_filter_warns_on_rejected_expression():
    router, logger = _router(), MagicMock()
    router.install_display_filter("tcp.port ==", logger)
    assert router._data_filter is None
    logger.warning.assert_called_once()


def test_install_display_filter_warns_on_builder_error(monkeypatch):
    def explode(expression):
        raise ValueError("bad")

    monkeypatch.setattr("friTap.filter.pipeline_filter.build_headless_filter", explode)
    router, logger = _router(), MagicMock()
    router.install_display_filter("tcp", logger)
    assert router._data_filter is None
    logger.warning.assert_called_once()
