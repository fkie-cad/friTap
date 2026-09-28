#!/usr/bin/env python3

"""RC4 offline decryptor: dual-mode emitter + registry entry (PUBLIC).

RC4 appears in two shapes in the wild, and ONE registry entry covers both:

  * **standalone** — RC4 is the outer cipher directly over raw TCP, and
  * **nested RC4-in-TLS** — plaintext -> RC4 -> TLS 1.3 -> socket.

The entry registers with ``requires_tls_strip=False`` so it runs as an
*independent* emitter (like MTProto), which — per the offline driver contract —
STILL receives the TLS ``--keylog`` path (``tls_keylog_path``). The emitter
branches on that single fact:

  * ``tls_keylog_path`` present  -> NESTED: let tshark strip TLS first (via the
    SAME ``list_tls_streams``/``follow_tls_stream`` helpers the Signal emitter
    uses), then strip RC4 from the decrypted TLS plaintext;
  * ``tls_keylog_path`` absent   -> STANDALONE: strip RC4 straight off the
    reassembled raw-TCP payloads.

Each recovered directional payload becomes one ``DatalogEvent(protocol="rc4")``
fed through the SAME collector/writer path; the collector types the flow as
``rc4`` and :class:`~friTap.flow.layers.Rc4Layer` renders the decrypted chunks.
"""

from __future__ import annotations

import logging
import os

from friTap.events import DatalogEvent, EventBus
from friTap.offline.pcap_to_tap import ConvertResult, _WriterState
from friTap.offline.registry import OfflineDecryptorEntry

logger = logging.getLogger(__name__)


def _candidates_from_scan_source():
    """Mine RC4 candidate keys from the CLI-supplied memory scan source, if any.

    The source (a .dmp/.bin dump or a live pid/name) was stashed by this package's
    ``handle_offline_cli_extras``. Returns a de-duplicated ``[(source, key), ...]``
    list, or ``[]`` when no source was given or it could not be read. Never raises:
    a bad dump/pid is logged and treated as "no candidates" so the conversion still
    runs (falling back to keylog keys / in-band candidate bytes).
    """
    from . import get_rc4_scan_source

    src = get_rc4_scan_source()
    if not src:
        return []
    try:
        from .decrypt import materialize_candidates
        from .memreader import open_reader, reader_candidates

        reader = open_reader(
            dump=src.get("dump"), pid=src.get("pid"),
            name=src.get("name"), all_pages=bool(src.get("all_pages")),
        )
        if reader is None:
            return []
        return materialize_candidates(reader_candidates(reader))
    except Exception as exc:  # noqa: BLE001 - a bad scan source must not abort convert
        logger.warning("RC4: could not read memory scan source (%s); "
                       "continuing without dump-derived candidates", exc)
        return []


def _span_streams_kwargs(state, nested: bool) -> dict:
    """``{"streams": ...}`` built from the TLS single pass's span store, else ``{}``.

    Nested RC4 reuses the single-pass TLS plaintext (with per-frame provenance)
    instead of a second tshark run; without spans the tshark path is unchanged.
    """
    spans = getattr(state, "tls_spans", None)
    if not nested or not spans:
        return {}
    from friTap.offline.rc4.transport import rc4_streams_from_spans
    return {"streams": rc4_streams_from_spans(spans)}


def _rc4_session_id(msg) -> str:
    """Per-connection session token (``rc4:<canonical 4-tuple>``).

    Like the Telegram E2E token, it keys RC4 events onto their OWN flow (the
    collector's ``sid:`` tier) instead of the ``net:`` 4-tuple flow the outer TLS
    plaintext of the same connection lands in.
    """
    from friTap.connection_index import canonical_4tuple

    return "rc4:" + canonical_4tuple(msg.src_addr, msg.src_port,
                                     msg.dst_addr, msg.dst_port)


def _rc4_datalog_event(msg) -> DatalogEvent:
    """The ``protocol="rc4"`` DatalogEvent for one decrypted message.

    Carries the pcap capture time when the message has one (else the event's
    default clock, as before) and the per-connection RC4 session token.
    """
    from friTap.offline.pcap_to_tap import _event_ts_kwargs

    return DatalogEvent(
        data=msg.message,
        function="rc4_offline",
        direction=msg.direction,
        src_addr=msg.src_addr,
        src_port=msg.src_port,
        dst_addr=msg.dst_addr,
        dst_port=msg.dst_port,
        ss_family=msg.ss_family,
        ssl_session_id=_rc4_session_id(msg),
        transport="tcp",
        protocol="rc4",
        **_event_ts_kwargs(getattr(msg, "timestamp", 0.0) or 0.0),
    )


def _rc4_framing(msg) -> str:
    """``"u32be-length"`` for a length-prefixed record, else ``"continuous"``."""
    return "u32be-length" if getattr(msg, "frame_header_len", 0) else "continuous"


def _rc4_record(msg, data: bytes) -> dict:
    """Provenance record of one decrypted message (see ``Rc4Layer.records``),
    plus the key identity/framing and the private ``_chunk_key`` scope tag."""
    from friTap.offline.pcap_to_tap import _chunk_key

    return {
        "direction": msg.direction,
        "length": len(msg.message),
        "tls_frames": list(getattr(msg, "tls_frames", ()) or ()),
        "timestamp": getattr(msg, "timestamp", 0.0) or 0.0,
        "cipher_offset": getattr(msg, "cipher_offset", 0),
        "frame_header_len": getattr(msg, "frame_header_len", 0),
        "source": msg.source,
        "key_len": len(msg.key or b""),
        "framing": _rc4_framing(msg),
        "_chunk_key": _chunk_key(msg.direction, data),
    }


def _record_rc4_provenance(state, key: str, msg, data: bytes) -> None:
    """Append *msg*'s provenance record under connection *key*.

    No-op for writer-state stand-ins without an ``rc4_provenance`` store.
    """
    store = getattr(state, "rc4_provenance", None)
    if store is None:
        return
    store.setdefault(key, []).append(_rc4_record(msg, data))


def _emit_rc4_streams(
    pcap_path: str,
    rc4_keylog: str,
    tls_keylog_path: str | None,
    *,
    tshark_bin: str,
    tls_ports: tuple[int, ...],
    bus: EventBus,
    state: "_WriterState",
    result: ConvertResult,
) -> None:
    """Decrypt RC4 (standalone or nested-in-TLS) and emit DatalogEvents.

    NESTED vs STANDALONE is decided solely by whether a usable TLS keylog is
    present: with one, tshark peels TLS first and RC4 is stripped from the
    decrypted TLS plaintext; without one, RC4 is stripped from raw TCP. The
    candidate RC4 keys come from *rc4_keylog*; when it yields none, the
    trial-decrypt path falls back to keys recovered from candidate bytes in the
    ciphertext itself (see :func:`iter_decrypted_messages`).
    """
    from friTap.connection_index import canonical_4tuple
    from friTap.offline.pcap_to_tap import _open_at_capture_time
    from friTap.offline.rc4.decrypt import Rc4Stats, iter_decrypted_messages
    from friTap.offline.rc4.keylog import load_rc4_keylog

    # Keylog keys come first so they keep priority in trial ordering.
    candidates = load_rc4_keylog(rc4_keylog)
    # A managed-RC4 key (a passphrase in the client's own byte arrays) is not on
    # the wire and not in a keylog unless the live agent recovered it. When the
    # user points us at the client's memory (--rc4-scan-dump/--rc4-scan-pid/-name),
    # mine candidate keys from it and append them, so the key whose output looks
    # like plaintext is recovered here exactly as the live agent recovers it.
    scan_candidates = _candidates_from_scan_source()
    if scan_candidates:
        logger.info("RC4: mined %d candidate key(s) from the memory scan source",
                    len(scan_candidates))
        candidates = candidates + scan_candidates
    if not candidates:
        logger.warning(
            "RC4 keylog %s has no usable RC4_KEY lines and no memory scan source; "
            "will rely on in-band candidate-byte key recovery only", rc4_keylog,
        )

    nested = bool(tls_keylog_path) and os.path.isfile(tls_keylog_path)
    if tls_keylog_path and not nested:
        logger.warning(
            "TLS keylog %s not found; treating RC4 as standalone (raw TCP)",
            tls_keylog_path,
        )

    stats = Rc4Stats()
    for msg in iter_decrypted_messages(
        pcap_path, candidates,
        tls_keylog_path=tls_keylog_path if nested else None,
        tshark_bin=tshark_bin, tls_ports=tls_ports,
        stats=stats,
        **_span_streams_kwargs(state, nested),
    ):
        ev = _rc4_datalog_event(msg)
        # Keep the recovering key's provenance keyed by the perspective-independent
        # 4-tuple (tagged with the chunk key so it can be scoped to the flow the
        # collector put the chunk in); the decrypted BYTES already ride the chunks.
        _record_rc4_provenance(state, canonical_4tuple(
            msg.src_addr, msg.src_port, msg.dst_addr, msg.dst_port), msg, ev.data)
        _open_at_capture_time(state, msg.timestamp or 0.0)
        result.decrypted_packet_count += 1
        bus.emit(ev)

    result.record_protocol(
        "rc4",
        messages=stats.messages,
        streams=stats.streams,
        undecryptable=stats.records_undecryptable,
        degraded=stats.streams_degraded,
    )


def _rc4_offline_emitter(
    *, pcap_path, proto_keylog, tls_keylog_path, tshark_bin, tls_ports,
    bus, state, result,
) -> None:
    """Normalized adapter around :func:`_emit_rc4_streams`.

    Registered as an INDEPENDENT emitter (``requires_tls_strip=False``) so it runs
    on every conversion and still receives ``tls_keylog_path`` for the nested case.
    """
    _emit_rc4_streams(
        pcap_path, proto_keylog, tls_keylog_path,
        tshark_bin=tshark_bin, tls_ports=tls_ports,
        bus=bus, state=state, result=result,
    )


def build_rc4_offline_decryptor_entry() -> OfflineDecryptorEntry:
    """Build the RC4 :class:`OfflineDecryptorEntry` (one entry, both modes)."""
    from friTap.flow.layers import Rc4Layer

    return OfflineDecryptorEntry(
        protocol_name="rc4",
        cli_flag="--rc4-keylog",
        cli_dest="rc4_keylog",
        requires_tls_strip=False,
        # Nested RC4 rides the TLS plaintext: its flows (and the TLS flows they
        # may absorb) are held back until the post-collection RC4-in-TLS attach.
        nests_in_tls=True,
        emitter=_rc4_offline_emitter,
        layer_cls=Rc4Layer,
        counter_prefix="rc4",
        cli_help=(
            "friTap RC4 keylog (RC4_KEY lines) for RC4-encrypted traffic. ONE flag "
            "covers both shapes: standalone RC4 over raw TCP, and nested RC4-in-TLS "
            "(pass TOGETHER with --keylog to strip the outer TLS first). Decrypted "
            "by friTap's own RC4 decryptor, not tshark."
        ),
    )
