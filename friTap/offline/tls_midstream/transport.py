"""Per-direction mid-stream TLS record extraction from a pcap.

A mid-stream TLS 1.3 capture has no handshake, so there are no tshark keys to
follow and no ServerHello to name the stream's endpoints or suite. This module
therefore reassembles raw TCP directly (reusing the MTProto sequence-indexed
reassembler) and splits each direction's contiguous byte run into TLS records
with the RC4 module's pure record parser. It mirrors
:func:`friTap.offline.rc4.transport.standalone_rc4_streams` but composes
``reassemble_pcap`` here directly rather than importing from ``rc4/transport`` so
this package stays isolated.

Each yielded stream carries per-direction ``degraded`` / ``has_start_gap`` flags
copied from the reassembler so a caller can REPORT an incomplete stream instead
of emitting garbage plaintext.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Tuple

from ..rc4.crypto import parse_records

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
    """

    client_addr: Tuple[str, int]
    server_addr: Tuple[str, int]
    ss_family: str  # "AF_INET" | "AF_INET6"
    records: Dict[str, List[Tuple[int, bytes, bytes]]] = field(default_factory=dict)
    degraded: Dict[str, bool] = field(default_factory=dict)
    start_gap: Dict[str, bool] = field(default_factory=dict)


def midstream_tls_streams(
    pcap_path: str,
    *,
    server_ports: Tuple[int, ...] = (443,),
) -> Iterator[MidstreamTlsStream]:
    """Yield one :class:`MidstreamTlsStream` per raw-TCP conversation in ``pcap_path``.

    Each direction's reassembled contiguous bytes are split into TLS records via
    :func:`friTap.offline.rc4.crypto.parse_records`. Conversations with no bytes
    in either direction are skipped.
    """
    from ..mtproto.reassembly import reassemble_pcap

    pairs = reassemble_pcap(pcap_path, server_ports=server_ports)
    for pair in pairs.values():
        client_bytes = pair.client.contiguous_bytes()
        server_bytes = pair.server.contiguous_bytes()
        if not client_bytes and not server_bytes:
            continue

        records: Dict[str, List[Tuple[int, bytes, bytes]]] = {}
        degraded: Dict[str, bool] = {}
        start_gap: Dict[str, bool] = {}
        if client_bytes:
            records[WRITE] = parse_records(client_bytes)
            degraded[WRITE] = pair.client.degraded
            start_gap[WRITE] = pair.client.has_start_gap
        if server_bytes:
            records[READ] = parse_records(server_bytes)
            degraded[READ] = pair.server.degraded
            start_gap[READ] = pair.server.has_start_gap

        yield MidstreamTlsStream(
            client_addr=pair.client_addr,
            server_addr=pair.server_addr,
            ss_family=pair.ss_family,
            records=records,
            degraded=degraded,
            start_gap=start_gap,
        )
