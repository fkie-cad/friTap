"""Per-direction RC4 ciphertext extraction for both offline modes.

RC4 is a stream cipher: each direction's keystream runs continuously from the
first byte, so this module hands the orchestrator ONE contiguous ciphertext blob
per direction (client->server = ``"write"``, server->client = ``"read"``).

  * **Nested (RC4-in-TLS)** — :func:`nested_rc4_streams` reuses the EXACT tshark
    helpers the Signal emitter uses (``list_tls_streams`` + ``follow_tls_stream``
    from :mod:`friTap.offline.tshark`) to obtain tshark's DECRYPTED TLS plaintext,
    which is itself the RC4 ciphertext. No new tshark invocation is invented.

  * **Standalone (RC4-over-raw-TCP)** — :func:`standalone_rc4_streams` reuses the
    MTProto path's sequence-indexed TCP reassembler
    (:func:`friTap.offline.mtproto.reassembly.reassemble_pcap`), which anchors on
    the first sequence number and exposes only a strictly in-order byte run —
    exactly what a position-dependent stream cipher needs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, Iterator, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Rc4Stream:
    """One conversation's RC4 ciphertext, per direction.

    ``directions`` maps ``"write"`` (client->server) / ``"read"``
    (server->client) to that direction's contiguous ciphertext bytes.
    """

    client_addr: Tuple[str, int]
    server_addr: Tuple[str, int]
    ss_family: str  # "AF_INET" | "AF_INET6"
    directions: Dict[str, bytes] = field(default_factory=dict)
    # Optional per-direction TLS provenance (``direction -> [TlsPlaintextSpan]``)
    # whose joined ``data`` equals ``directions[direction]``; empty when the
    # stream came from a source without frame information.
    spans: Dict[str, list] = field(default_factory=dict)


def _client_server_from_spans(by_direction: Dict[str, list]
                              ) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    """(client, server) addressing from the first span of a known direction:
    a ``"write"`` span is sent BY the client, a ``"read"`` span TO it."""
    if by_direction.get("write"):
        span = by_direction["write"][0]
        return (span.src_addr, span.src_port), (span.dst_addr, span.dst_port)
    span = by_direction["read"][0]
    return (span.dst_addr, span.dst_port), (span.src_addr, span.src_port)


def rc4_streams_from_spans(tls_spans: Dict[str, Dict[str, list]]
                           ) -> Iterator[Rc4Stream]:
    """Yield one :class:`Rc4Stream` per connection of a TLS span store.

    Same shape as :func:`nested_rc4_streams` (joined per-direction blobs of the
    decrypted TLS plaintext = the nested RC4 ciphertext), but built from the
    single-pass span store (:mod:`friTap.offline.tls_spans`) instead of a second
    tshark run, and carrying the spans so each byte keeps its frame provenance.
    """
    for by_direction in tls_spans.values():
        kept = {d: list(s) for d, s in by_direction.items()
                if d in ("write", "read") and s}
        if not kept:
            continue
        client_addr, server_addr = _client_server_from_spans(kept)
        yield Rc4Stream(
            client_addr=client_addr,
            server_addr=server_addr,
            ss_family="AF_INET6" if ":" in client_addr[0] else "AF_INET",
            directions={d: b"".join(sp.data for sp in s) for d, s in kept.items()},
            spans=kept,
        )


def nested_rc4_streams(
    pcap_path: str,
    tls_keylog_path: str,
    *,
    tshark_bin: Optional[str] = None,
    tls_ports: Tuple[int, ...] = (),
) -> Iterator[Rc4Stream]:
    """Yield one :class:`Rc4Stream` per TLS stream, its bytes being tshark's
    DECRYPTED TLS plaintext (the RC4 ciphertext nested inside TLS)."""
    from ..tshark import find_tshark, follow_tls_stream, list_tls_streams

    bin_path = tshark_bin or find_tshark(None)
    ports = tls_ports or (443,)
    stream_ids = list_tls_streams(bin_path, pcap_path, tls_keylog_path, tls_ports=ports)

    for stream_id in stream_ids:
        endpoints, segments = follow_tls_stream(
            bin_path, pcap_path, stream_id, tls_keylog_path, tls_ports=ports,
        )
        if not segments:
            continue
        client_addr, client_port, server_addr, server_port = endpoints
        ss_family = "AF_INET6" if ":" in client_addr else "AF_INET"
        by_direction: Dict[str, bytearray] = {"write": bytearray(), "read": bytearray()}
        for direction, data in segments:
            by_direction.setdefault(direction, bytearray()).extend(data)
        yield Rc4Stream(
            client_addr=(client_addr, client_port),
            server_addr=(server_addr, server_port),
            ss_family=ss_family,
            directions={d: bytes(b) for d, b in by_direction.items() if b},
        )


def standalone_rc4_streams(
    pcap_path: str,
    *,
    server_ports: Tuple[int, ...] = (443, 80),
) -> Iterator[Rc4Stream]:
    """Yield one :class:`Rc4Stream` per raw-TCP conversation, its bytes being the
    reassembled per-direction TCP payload (the RC4 ciphertext over plain TCP)."""
    from ..mtproto.reassembly import reassemble_pcap

    pairs = reassemble_pcap(pcap_path, server_ports=server_ports)
    for pair in pairs.values():
        client_bytes = pair.client.contiguous_bytes()
        server_bytes = pair.server.contiguous_bytes()
        if not client_bytes and not server_bytes:
            continue
        directions: Dict[str, bytes] = {}
        if client_bytes:
            directions["write"] = client_bytes
        if server_bytes:
            directions["read"] = server_bytes
        yield Rc4Stream(
            client_addr=pair.client_addr,
            server_addr=pair.server_addr,
            ss_family=pair.ss_family,
            directions=directions,
        )
