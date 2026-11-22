"""Keyless offline ingest: raw-payload ``-T ek`` packets to friTap events.

For an already-plaintext capture the application bytes are the raw transport
payload; genuinely encrypted streams are detected and skipped.
"""

from __future__ import annotations

from friTap.events import DatalogEvent

from .pipeline_api import (
    StreamDirectionTracker,
    coerce_float,
    coerce_int,
    ek_as_list,
    ek_field,
    ek_first,
    extract_addrs,
)
from .tshark import ENCRYPTED_RECORD_MARKERS, decode_hex


def _is_encrypted_record(layers: dict, proto_layers: list[str]) -> bool:
    """True when a keyless packet carries genuine cipher-text.

    The heuristic dissector tags any unparseable TCP/443 or UDP payload ``tls``/``quic``
    (even friTap's decrypted HTTP/2), so the protocol stack alone proves nothing. A
    genuinely encrypted stream also exposes a parsed cleartext record marker
    (``tls.record.content_type``, ``quic.header_form``), which is required before
    skipping; pairs live in :data:`~friTap.offline.tshark.ENCRYPTED_RECORD_MARKERS`.
"""
    return any(
        proto in proto_layers and ek_first(ek_field(layers, marker)) is not None
        for proto, marker in ENCRYPTED_RECORD_MARKERS
    )


def _plaintext_packet_to_events(
    pkt: dict,
    tracker: StreamDirectionTracker,
    encrypted_streams: set[str],
    encrypted_quic_streams: frozenset[str] = frozenset(),
) -> list[DatalogEvent]:
    """Translate one raw-payload ``-T ek`` packet dict into DatalogEvents.

    No keys: the app bytes are ``tcp.payload`` / ``udp.payload`` (mirrors
    :func:`~friTap.offline.pipeline_api.tls_packet_to_events`). Encrypted streams are
    recorded in *encrypted_streams* (for the "pass --keylog" hint) and skipped: a
    match of :func:`_is_encrypted_record`, or a ``udp.stream`` in *encrypted_quic_streams*
    (:func:`~friTap.offline.pcap_to_tap._detect_encrypted_quic_streams`).
"""
    layers = pkt.get("layers") or {}
    # Split the colon-separated stack ("eth:ethertype:ip:tcp:tls") so membership is exact, with no substring false-matches.
    proto_layers = str(ek_first(ek_field(layers, "frame.protocols")) or "").lower().split(":")

    timestamp = coerce_float(ek_first(ek_field(layers, "frame.time_epoch")))

    src_addr, dst_addr, ss_family = extract_addrs(layers)

    tcp_stream = ek_first(ek_field(layers, "tcp.stream"))
    if tcp_stream is not None:
        transport = "tcp"
        stream_key = f"tcp:{tcp_stream}"
        src_port = coerce_int(ek_first(ek_field(layers, "tcp.srcport")))
        dst_port = coerce_int(ek_first(ek_field(layers, "tcp.dstport")))
        payload_field = "tcp.payload"
    else:
        udp_stream = ek_first(ek_field(layers, "udp.stream"))
        transport = "udp"
        stream_key = f"udp:{udp_stream}"
        src_port = coerce_int(ek_first(ek_field(layers, "udp.srcport")))
        dst_port = coerce_int(ek_first(ek_field(layers, "udp.dstport")))
        payload_field = "udp.payload"

    # Encrypted streams need keys: record once and skip every packet on them (record marker here, or confirmed QUIC by the pre-scan).
    if stream_key in encrypted_quic_streams or _is_encrypted_record(layers, proto_layers):
        encrypted_streams.add(stream_key)
        return []

    payloads = ek_as_list(ek_field(layers, payload_field))
    data = b"".join(decode_hex(str(p)) for p in payloads)
    if not data:
        return []

    direction = tracker.direction_for(
        stream_key, src_addr, src_port, dst_addr, dst_port)

    return [DatalogEvent(
        timestamp=timestamp,
        data=data,
        function="tshark_offline",
        direction=direction,
        src_addr=src_addr,
        src_port=src_port,
        dst_addr=dst_addr,
        dst_port=dst_port,
        ss_family=ss_family,
        ssl_session_id="",
        transport=transport,
        stream_id=None,
    )]
