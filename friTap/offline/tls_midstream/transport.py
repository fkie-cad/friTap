"""Per-direction mid-stream TLS record extraction from a pcap.

A mid-stream TLS 1.3 capture has no handshake, so there are no tshark keys to
follow and no ServerHello to name the stream's endpoints or suite. This module
therefore reassembles raw TCP directly (reusing the shared sequence-indexed
reassembler in :mod:`friTap.offline.net.tcp_reassembly`) and splits each
direction's contiguous byte run into TLS records with the RC4 module's pure
record parser. It mirrors
:func:`friTap.offline.rc4.transport.standalone_rc4_streams` but composes
``reassemble_pcap`` here directly rather than importing from ``rc4/transport`` so
this package stays isolated.

Each yielded stream carries per-direction ``degraded`` / ``has_start_gap`` flags
copied from the reassembler so a caller can REPORT an incomplete stream instead
of emitting garbage plaintext. A direction whose bytes do not begin on a record
boundary (the capture started mid-record, or a start gap swallowed the opening
bytes) is RESYNCED to the first plausible record header and flagged ``resynced``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from ..tls.records import find_record_boundary, parse_records, plausible_record_header

# Client->server is "write", server->client is "read" (same convention as the
# RC4 transport module).
WRITE = "write"
READ = "read"


@dataclass
class MidstreamTlsStream:
    """One conversation's TLS records, per direction.

    ``records`` maps ``"write"`` (client->server) / ``"read"`` (server->client)
    to that direction's parsed ``(content_type, header5, fragment)`` records.
    ``degraded`` / ``start_gap`` mirror the reassembler's per-direction flags so
    a caller can report a truncated stream rather than decrypt garbage.
    ``resynced`` marks a direction whose records were found by skipping to the
    first plausible record boundary.
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
    """Parse *data* into records, resyncing when it does not start on a header.

    A run that begins with a plausible record header is parsed exactly as before
    (length-only framing). Otherwise the capture started inside a record: skip to
    the first plausible record boundary and parse from there with header
    validation. Returns ``(records, resynced)``.
    """
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
    """Yield one :class:`MidstreamTlsStream` per raw-TCP conversation in ``pcap_path``.

    Each direction's reassembled contiguous bytes are split into TLS records via
    :func:`friTap.offline.tls.records.parse_records` (resynced to the first
    plausible record header when the run starts mid-record). Conversations with no
    bytes in either direction are skipped.
    """
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
