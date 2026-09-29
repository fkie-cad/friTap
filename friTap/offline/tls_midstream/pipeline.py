"""Bind mid-stream TLS 1.3 secret bundles to a pcap's raw TLS streams and emit
the recovered plaintext into the offline conversion pipeline.

Phase 2.3 (binding) + the emit side of 2.4 (classification): the BoringSSL
memscan engine writes a leak-safe JSONL sidecar of TLS 1.3 secret bundles for
flows whose ClientHello was never captured (see
:meth:`friTap.memory_scanning.engine.MemoryScanEngine.tls_midstream_manifest_entry`).
This module loads that sidecar, enumerates the pcap's raw TLS streams
(:func:`~friTap.offline.tls_midstream.transport.midstream_tls_streams`), and
trial-binds each bundle against each stream using the AEAD tag as a
zero-false-accept oracle (:func:`~friTap.offline.tls_midstream.crypto.pick_suite`):
``CLIENT_TRAFFIC_SECRET_0`` on the client->server (``"write"``) direction,
``SERVER_TRAFFIC_SECRET_0`` on the server->client (``"read"``) direction. A
bundle that decrypts a direction binds to the stream AND fixes that direction's
cipher suite and starting record sequence number in one step.

Each bound direction's application_data is decrypted
(:func:`~friTap.offline.tls_midstream.crypto.decrypt_stream_from`), turned into a
:class:`~friTap.events.DatalogEvent` identical in shape to the tshark single-pass
path (:func:`friTap.offline.pcap_to_tap._tls_packet_to_events`), and emitted
through the same ``EventBus`` while its plaintext is recorded as a
:class:`~friTap.offline.tls_spans.TlsPlaintextSpan`
(:func:`~friTap.offline.tls_spans.record_tls_span`). Every downstream consumer
(the collector, the ``.tap`` writer, a TLS-riding decoder) therefore sees it
exactly as if tshark had decrypted a handshake-anchored flow.

All cryptographic / transport primitives are IMPORTED READ-ONLY; this module
only wires them into the offline conversion.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import List, Optional, Set, Tuple

from friTap.connection_index import canonical_4tuple
from friTap.events import DatalogEvent
from friTap.offline.rc4.crypto import inner_content_type
from friTap.offline.tls_spans import record_tls_span

from .crypto import APPLICATION_DATA, decrypt_stream_from, pick_suite
from .transport import READ, WRITE, MidstreamTlsStream, midstream_tls_streams

logger = logging.getLogger(__name__)

# The display protocol stamped onto a flow that bound only via a mid-stream
# secret (no captured handshake). Surfaces through Flow.display_protocol when no
# richer inner protocol (e.g. Signal) was parsed on top of the plaintext.
MIDSTREAM_PROTOCOL_LABEL = "TLS(midstream)"

# TLS 1.3 handshake outer content-type. A reassembled stream that BEGINS with a
# handshake record carries its own ClientHello/ServerHello, so tshark can follow
# and decrypt it from the NSS keylog — it is not a mid-stream flow and we leave
# it to the normal single-pass path (avoids a duplicate flow).
_HANDSHAKE_CONTENT_TYPE = 0x16


@dataclass(frozen=True)
class _DirectionBinding:
    """One direction's recovered decryption parameters."""

    secret_hex: str
    suite: str
    start_seq: int


@dataclass(frozen=True)
class StreamBinding:
    """A secret bundle bound to a mid-stream TLS stream (one or both directions)."""

    stream: MidstreamTlsStream
    write: Optional[_DirectionBinding] = None
    read: Optional[_DirectionBinding] = None


def _valid_bundle(obj) -> bool:
    """True when *obj* is a secret bundle carrying at least one traffic secret."""
    return isinstance(obj, dict) and bool(
        obj.get("client_traffic_secret_0") or obj.get("server_traffic_secret_0")
    )


def load_secret_bundles(path: str) -> List[dict]:
    """Load the JSONL secret-bundle sidecar at *path* (``[]`` on any error).

    Each non-empty line is one bundle object (see the engine sidecar schema).
    Malformed lines and bundles missing both traffic secrets are skipped; a bad
    or absent file yields an empty list so the stage is simply a no-op.
    """
    bundles: List[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if _valid_bundle(obj):
                    bundles.append(obj)
    except OSError:
        return []
    return bundles


def _has_leading_handshake(records: List[Tuple[int, bytes, bytes]]) -> bool:
    """True when the stream's first record is a TLS handshake (captured ClientHello)."""
    return bool(records) and records[0][0] == _HANDSHAKE_CONTENT_TYPE


def _bind_direction(
    secret_hex: str, records: List[Tuple[int, bytes, bytes]]
) -> Optional[_DirectionBinding]:
    """Trial-bind *secret_hex* to one direction's *records*, or ``None``.

    The AEAD tag is a zero-false-accept oracle: a wrong secret never recovers a
    suite/seq, so a returned binding is a genuine match.
    """
    if not secret_hex or not records:
        return None
    picked = pick_suite(secret_hex, records)
    if picked is None:
        return None
    suite, start_seq = picked
    return _DirectionBinding(secret_hex, suite, start_seq)


def bind_stream(
    stream: MidstreamTlsStream, bundles: List[dict]
) -> Optional[StreamBinding]:
    """Bind the first *bundle* that decrypts a direction of *stream*, or ``None``.

    ``CLIENT_TRAFFIC_SECRET_0`` is tried on the ``"write"`` (client->server)
    direction and ``SERVER_TRAFFIC_SECRET_0`` on the ``"read"`` (server->client)
    direction. A stream that begins with a captured handshake is skipped (the
    normal tshark single pass already decrypts it).
    """
    write_records = stream.records.get(WRITE)
    read_records = stream.records.get(READ)
    if _has_leading_handshake(write_records or []) or _has_leading_handshake(
        read_records or []
    ):
        return None
    for bundle in bundles:
        write_bind = _bind_direction(
            bundle.get("client_traffic_secret_0", ""), write_records or []
        )
        read_bind = _bind_direction(
            bundle.get("server_traffic_secret_0", ""), read_records or []
        )
        if write_bind or read_bind:
            return StreamBinding(stream, write_bind, read_bind)
    return None


def _app_content(plaintext: bytes) -> Optional[bytes]:
    """Application_data content of one decrypted inner plaintext, or ``None``.

    TLS 1.3 inner plaintext is ``content || content_type || zeros`` (RFC 8446
    sec 5.2). Only application_data (0x17) records carry app bytes; post-handshake
    handshake (0x16) / alert (0x15) records are dropped from the byte stream.
    """
    if inner_content_type(plaintext) != APPLICATION_DATA:
        return None
    end = len(plaintext) - 1
    while end >= 0 and plaintext[end] == 0:
        end -= 1
    return plaintext[:end]  # everything before the content-type byte


def _direction_plaintext(
    binding: _DirectionBinding, records: List[Tuple[int, bytes, bytes]]
) -> bytes:
    """Decrypt one direction and join its application_data content in order."""
    parts: List[bytes] = []
    for plaintext in decrypt_stream_from(
        binding.secret_hex, binding.suite, records, binding.start_seq
    ):
        content = _app_content(plaintext)
        if content:
            parts.append(content)
    return b"".join(parts)


def _make_event(
    stream: MidstreamTlsStream, direction: str, data: bytes, base_ts: float
) -> DatalogEvent:
    """Build a DatalogEvent shaped exactly like the tshark single-pass TLS path."""
    if direction == WRITE:
        (src_addr, src_port), (dst_addr, dst_port) = (
            stream.client_addr,
            stream.server_addr,
        )
    else:
        (src_addr, src_port), (dst_addr, dst_port) = (
            stream.server_addr,
            stream.client_addr,
        )
    return DatalogEvent(
        timestamp=base_ts,
        data=data,
        function="tls_midstream",
        direction=direction,
        src_addr=src_addr,
        src_port=src_port,
        dst_addr=dst_addr,
        dst_port=dst_port,
        ss_family=stream.ss_family,
        ssl_session_id="",
        transport="tcp",
        stream_id=None,
        protocol="tls",
    )


def _emit_binding(binding: StreamBinding, *, bus, state, result, base_ts: float) -> bool:
    """Emit each bound direction's plaintext as a span + DatalogEvent.

    Returns True when at least one non-empty direction was emitted.
    """
    emitted = False
    for direction, dbind in ((WRITE, binding.write), (READ, binding.read)):
        if dbind is None:
            continue
        records = binding.stream.records.get(direction) or []
        data = _direction_plaintext(dbind, records)
        if not data:
            continue
        event = _make_event(binding.stream, direction, data, base_ts)
        record_tls_span(state.tls_spans, {}, event)
        bus.emit(event)
        result.decrypted_packet_count += 1
        emitted = True
    return emitted


def run_midstream_tls_stage(
    pcap_path: str,
    sidecar_path: str,
    *,
    bus,
    state,
    result,
    base_ts: float = 0.0,
    server_ports: Tuple[int, ...] = (443,),
) -> Set[str]:
    """Bind the sidecar's secret bundles to *pcap_path*'s mid-stream TLS streams.

    Loads the secret bundles, enumerates the raw TLS streams, and for each stream
    that a bundle binds, emits the recovered plaintext through *bus* (recording a
    span in ``state.tls_spans``). Returns the set of :func:`canonical_4tuple`
    keys of the bound flows so the caller can relabel them ``TLS(midstream)``.
    A missing/empty sidecar (or an enumeration failure) is a no-op returning an
    empty set — the stage never aborts the surrounding conversion.
    """
    bundles = load_secret_bundles(sidecar_path)
    if not bundles:
        return set()
    try:
        streams = list(midstream_tls_streams(pcap_path, server_ports=server_ports))
    except Exception:  # noqa: BLE001 - a reassembly failure must not break convert
        logger.debug(
            "mid-stream TLS enumeration failed for %r", pcap_path, exc_info=True
        )
        return set()

    bound_keys: Set[str] = set()
    for stream in streams:
        binding = bind_stream(stream, bundles)
        if binding is None:
            continue
        state.ensure_open()
        if _emit_binding(binding, bus=bus, state=state, result=result, base_ts=base_ts):
            bound_keys.add(
                canonical_4tuple(
                    stream.client_addr[0],
                    stream.client_addr[1],
                    stream.server_addr[0],
                    stream.server_addr[1],
                )
            )
            result.stream_count += 1
    return bound_keys
