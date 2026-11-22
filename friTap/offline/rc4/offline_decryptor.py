#!/usr/bin/env python3

"""RC4 offline decryptor: dual-mode emitter + registry entry (PUBLIC).

One registry entry covers standalone RC4 over raw TCP and nested RC4-in-TLS.

It registers with ``requires_tls_strip=False`` (an independent emitter, like
MTProto), which still receives ``tls_keylog_path``. With it, tshark strips TLS
first and RC4 is stripped from the TLS plaintext (nested); without it, RC4 is
stripped from the reassembled raw TCP payloads (standalone).

Each recovered directional payload becomes one ``DatalogEvent(protocol="rc4")``
through the normal collector/writer path; :class:`~friTap.flow.layers.Rc4Layer`
renders the decrypted chunks.
"""

from __future__ import annotations

import logging
import os

from friTap.events import DatalogEvent, EventBus
from friTap.offline.pipeline_api import ConvertResult, WriterState, protocol_state_of
from friTap.offline.registry import OfflineDecryptorEntry

from .state import RC4_STATE

logger = logging.getLogger(__name__)


def _candidates_from_scan_source():
    """Mine RC4 candidate keys from the CLI-supplied memory scan source, if any.

    The source (dump or live pid/name) is stashed by ``handle_offline_cli_extras``.
    Returns de-duplicated candidates, or ``[]`` when there is no source or it is
    unreadable. Never raises, so the conversion still runs.
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
    instead of a second tshark run.
    """
    spans = getattr(state, "tls_spans", None)
    if not nested or not spans:
        return {}
    from friTap.offline.rc4.transport import rc4_streams_from_spans
    return {"streams": rc4_streams_from_spans(spans)}


def _rc4_datalog_event(msg) -> DatalogEvent:
    """The ``protocol="rc4"`` DatalogEvent for one decrypted message.

    Carries the pcap capture time when the message has one. No session token:
    ``protocol="rc4"`` alone keys it onto its own ``net:rc4:<4-tuple>`` flow,
    apart from the ``net:`` flow of the connection's outer TLS plaintext.
    """
    from friTap.offline.pipeline_api import event_ts_kwargs

    return DatalogEvent(
        data=msg.message,
        function="rc4_offline",
        direction=msg.direction,
        src_addr=msg.src_addr,
        src_port=msg.src_port,
        dst_addr=msg.dst_addr,
        dst_port=msg.dst_port,
        ss_family=msg.ss_family,
        transport="tcp",
        protocol="rc4",
        **event_ts_kwargs(getattr(msg, "timestamp", 0.0) or 0.0),
    )


def _rc4_framing(msg) -> str:
    """``"u32be-length"`` for a length-prefixed record, else ``"continuous"``."""
    return "u32be-length" if getattr(msg, "frame_header_len", 0) else "continuous"


def _rc4_record(msg, data: bytes) -> dict:
    """Provenance record of one decrypted message (see ``Rc4Layer.records``),
    plus the key identity/framing and the private ``_chunk_key`` scope tag."""
    from friTap.offline.pipeline_api import chunk_key

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
        "_chunk_key": chunk_key(msg.direction, data),
    }


def _record_rc4_provenance(state, key: str, msg, data: bytes) -> None:
    """Append *msg*'s provenance record under connection *key*.

    No-op for writer-state stand-ins without an ``rc4_provenance`` store.
    """
    store = getattr(protocol_state_of(state, RC4_STATE), "rc4_provenance", None)
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
    state: "WriterState",
    result: ConvertResult,
) -> None:
    """Decrypt RC4 (standalone or nested-in-TLS) and emit DatalogEvents.

    Nested vs standalone depends only on whether a usable TLS keylog file exists.
    Candidate keys come from *rc4_keylog* (plus the memory scan source); with
    none, trial-decrypt falls back to candidate bytes in the ciphertext (see
    :func:`iter_decrypted_messages`).
    """
    from friTap.connection_index import canonical_4tuple
    from friTap.offline.pipeline_api import open_at_capture_time
    from friTap.offline.rc4.decrypt import Rc4Stats, iter_decrypted_messages
    from friTap.offline.rc4.keylog import load_rc4_keylog

    # Keylog keys come first so they keep priority in trial ordering.
    candidates = load_rc4_keylog(rc4_keylog)
    # Keys mined from the client's memory (--rc4-scan-*) rank after keylog keys.
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
        # Keyed by the perspective-independent 4-tuple; the chunk key scopes it to
        # the flow the collector put the chunk in.
        _record_rc4_provenance(state, canonical_4tuple(
            msg.src_addr, msg.src_port, msg.dst_addr, msg.dst_port), msg, ev.data)
        open_at_capture_time(state, msg.timestamp or 0.0)
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
    """Registry emitter adapter around :func:`_emit_rc4_streams`."""
    _emit_rc4_streams(
        pcap_path, proto_keylog, tls_keylog_path,
        tshark_bin=tshark_bin, tls_ports=tls_ports,
        bus=bus, state=state, result=result,
    )


# Attach-hook order: RC4-in-TLS runs before the Telegram attach (30).
RC4_ATTACH_ORDER = 20


def build_rc4_offline_decryptor_entry() -> OfflineDecryptorEntry:
    """Build the RC4 :class:`OfflineDecryptorEntry` (one entry, both modes)."""
    from friTap.flow.layers import Rc4Layer

    from .tls_attach import attach_rc4_post_collection

    return OfflineDecryptorEntry(
        protocol_name="rc4",
        cli_flag="--rc4-keylog",
        cli_dest="rc4_keylog",
        requires_tls_strip=False,
        # Nested RC4 rides the TLS plaintext: its flows (and the TLS flows they
        # may absorb) are held back until the post-collection RC4-in-TLS attach.
        nests_in_tls=True,
        emitter=_rc4_offline_emitter,
        # Post-collection [TLS, RC4] fold; runs after the TLS-riding layering and
        # before the Telegram attach (see RC4_ATTACH_ORDER).
        attach=attach_rc4_post_collection,
        attach_order=RC4_ATTACH_ORDER,
        layer_cls=Rc4Layer,
        counter_prefix="rc4",
        cli_help=(
            "friTap RC4 keylog (RC4_KEY lines) for RC4-encrypted traffic. ONE flag "
            "covers both shapes: standalone RC4 over raw TCP, and nested RC4-in-TLS "
            "(pass TOGETHER with --keylog to strip the outer TLS first). Decrypted "
            "by friTap's own RC4 decryptor, not tshark."
        ),
    )
