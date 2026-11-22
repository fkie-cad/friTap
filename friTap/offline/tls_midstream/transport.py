"""Per-direction mid-stream TLS record extraction from a pcap.

With no handshake tshark has no keys to follow, so raw TCP is reassembled
(:mod:`friTap.offline.net.tcp_reassembly`) and each direction's run split into
TLS records. Mirrors :func:`friTap.offline.rc4.transport.standalone_rc4_streams`
without importing it. Per-direction ``degraded`` / ``has_start_gap`` flags let a
caller report an incomplete stream; a direction not starting on a record
boundary is resynced to the first plausible header and flagged ``resynced``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from ..tls.records import find_record_boundary, parse_records, plausible_record_header

# Client->server is "write", server->client is "read" (as in rc4.transport).
WRITE = "write"
READ = "read"


@dataclass
class MidstreamTlsStream:
    """One conversation's TLS records, per direction.

    ``records`` maps ``"write"`` / ``"read"`` to ``(content_type, header5, fragment)``
    records. ``degraded`` / ``start_gap`` mirror the reassembler's flags; ``resynced``
    marks a direction whose records began at the first plausible boundary.
"""

    client_addr: Tuple[str, int]
    server_addr: Tuple[str, int]
    ss_family: str  # "AF_INET" | "AF_INET6"
    records: Dict[str, List[Tuple[int, bytes, bytes]]] = field(default_factory=dict)
    degraded: Dict[str, bool] = field(default_factory=dict)
    start_gap: Dict[str, bool] = field(default_factory=dict)
    resynced: Dict[str, bool] = field(default_factory=dict)


def _direction_bytes(half) -> bytes:
    """One direction's usable byte run: past a start gap when one exists."""
    data = half.contiguous_bytes()
    if not data and half.has_start_gap:
        data = half.bytes_after_start_gap()
    return data


def _records_with_resync(
    data: bytes,
) -> Tuple[List[Tuple[int, bytes, bytes]], bool]:
    """Parse *data* into ``(records, resynced)``; if it does not start on a plausible header, skip to the first boundary and validate headers."""
    if plausible_record_header(data, 0):
        return parse_records(data), False
    boundary: Optional[int] = find_record_boundary(data)
    if boundary is None:
        return [], True
    return parse_records(data[boundary:], validate=True), True


def midstream_tls_streams(
    pcap_path: str,
    *,
    server_ports: Tuple[int, ...] = (443,),
) -> Iterator[MidstreamTlsStream]:
    """Yield one :class:`MidstreamTlsStream` per raw-TCP conversation (parsed with :func:`friTap.offline.tls.records.parse_records`); empty conversations are skipped."""
    from ..net.tcp_reassembly import reassemble_pcap

    pairs = reassemble_pcap(pcap_path, server_ports=server_ports)
    for pair in pairs.values():
        halves = ((WRITE, pair.client), (READ, pair.server))
        runs = [(name, half, _direction_bytes(half)) for name, half in halves]
        if not any(data for _name, _half, data in runs):
            continue

        stream = MidstreamTlsStream(
            client_addr=pair.client_addr,
            server_addr=pair.server_addr,
            ss_family=pair.ss_family,
        )
        for name, half, data in runs:
            if not data:
                continue
            stream.records[name], stream.resynced[name] = _records_with_resync(data)
            stream.degraded[name] = half.degraded
            stream.start_gap[name] = half.has_start_gap
        yield stream
