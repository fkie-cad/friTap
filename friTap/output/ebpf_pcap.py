"""Adapt endpoint-less eBPF plaintext records to the standard PCAP writers."""

from dataclasses import replace
from functools import lru_cache

from ..constants import DIRECTION_READ, SSL_READ, SSL_WRITE
from ..endpoint_pinner import EndpointPinner
from ..events import DatalogEvent, EventBus
from .base import OutputHandler

#: Connections whose synthetic endpoints stay cached (resolution is deterministic).
_ENDPOINT_CACHE_SIZE = 4096


def _build_pcap_writer(output):
    """The -p writer the shared factory selects (pcap or pcapng) for *output*."""
    from .factory import _pcap_handler_class
    from .pcapng_handler import PcapngOutputHandler

    handler_cls = _pcap_handler_class(output)
    if handler_cls is PcapngOutputHandler:
        return PcapngOutputHandler(output.pcap)
    from ..pcap import PCAP
    from ..pcap_utility import PCAP_FORMAT_PCAP

    pcap = PCAP(output.pcap, SSL_READ, SSL_WRITE, False, False, pcap_format=PCAP_FORMAT_PCAP)
    return handler_cls(pcap)


class EbpfPcapOutputHandler(OutputHandler):
    consumes_plaintext = True

    def __init__(self, output):
        self._output = output
        self._bus = EventBus()
        self._pinner = EndpointPinner()
        self._writer = None
        self._resolve_endpoints = lru_cache(maxsize=_ENDPOINT_CACHE_SIZE)(self._resolve_uncached)

    def setup(self, event_bus: EventBus) -> None:
        self._writer = _build_pcap_writer(self._output)
        self._writer.setup(self._bus)
        event_bus.subscribe(DatalogEvent, self._write)

    def _resolve_uncached(self, ssl_session_id: str, transport: str, is_read: bool):
        pinner_key = ssl_session_id.encode().hex()
        return self._pinner.resolve(pinner_key, transport, is_read, None)

    def _write(self, event: DatalogEvent) -> None:
        if not event.ssl_session_id:
            return
        endpoints = self._resolve_endpoints(
            event.ssl_session_id, event.transport, event.direction == DIRECTION_READ)
        if endpoints is not None:
            event = replace(event, src_addr=endpoints.src_addr, dst_addr=endpoints.dst_addr,
                            src_port=endpoints.src_port, dst_port=endpoints.dst_port,
                            src_addr_raw=endpoints.src_addr_raw, dst_addr_raw=endpoints.dst_addr_raw,
                            ss_family=endpoints.ss_family, endpoints_synthetic=True)
        self._bus.emit(event)

    def close(self) -> None:
        if self._writer is not None:
            self._writer.close()


class EbpfFullCaptureOutputHandler(OutputHandler):
    """Own the existing local full-capture worker for a producer session."""

    def __init__(self, output):
        self._output = output
        self._pcap = None

    def setup(self, event_bus: EventBus) -> None:
        from ..pcap import PCAP

        output = self._output
        self._pcap = PCAP(
            output.pcap, SSL_READ, SSL_WRITE, True, False,
            include_loopback=output.include_loopback,
            filter_infrastructure=output.filter_infrastructure,
            pcap_format=output.pcap_container, managed_full_capture=True,
        )
        self._pcap.full_capture_thread.wait_until_ready(5)

    def close(self) -> None:
        if self._pcap is None:
            return
        pcap, self._pcap = self._pcap, None
        worker = pcap.full_capture_thread
        worker.join(5)
        if worker.is_alive():
            raise RuntimeError("Full packet capture worker did not stop")
        pcap.finalize_full_capture()
        if worker.failure is not None:
            raise RuntimeError(f"Full packet capture failed: {worker.failure}")
