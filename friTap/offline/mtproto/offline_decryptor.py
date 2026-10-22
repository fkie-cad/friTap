#!/usr/bin/env python3

"""MTProto/Telegram offline decryptor: emitters + registry entries.

Holds the Telegram-specific EMIT side of the offline conversion that was
historically inlined in ``friTap.offline.pcap_to_tap``: the parsed-message
side-channel accumulators, the keylog loading, the per-conversion
:class:`~friTap.offline.mtproto.packet_meta.RecordLedger` / cross-reference
bookkeeping, the cloud + Secret-Chat record emitters and the two
:class:`~friTap.offline.registry.OfflineDecryptorEntry` factories
(``mtproto`` and ``telegram``).

The package self-registers both entries at import (see
``friTap/offline/mtproto/__init__.py``), exactly like the Signal package. The
crypto backend and the TL parsers are imported lazily inside the emitters, so
importing this module stays cheap. The code keeps its original behavior
verbatim; only its enclosing module moved.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Sequence

from friTap.events import DatalogEvent, EventBus
from friTap.offline.pipeline_api import (
    ConvertResult,
    WriterState,
    _strip_private_keys,
    chunk_key,
    event_ts_kwargs,
    open_at_capture_time,
    protocol_state_of,
    unique_keylog_paths,
)

from .state import TELEGRAM_STATE
from .transport import DEFAULT_OBF_MAX_BLOCKS

if TYPE_CHECKING:
    # Type-only import: the factories import it lazily inside their bodies.
    from friTap.offline.registry import OfflineDecryptorEntry

logger = logging.getLogger(__name__)


def _parsed_mtproto_to_dicts(
    parsed_messages, direction: str, fallback_ts: float = 0.0,
) -> list:
    """Turn :class:`ParsedMtprotoMessage` objects into JSON-native dicts.

    Mirrors the per-message dict shape the Signal path stores (so flow_detail's
    generic ``_render_layer_parsed`` understands it). The TL parser yields no
    timestamp/sender for outbound text; a missing TL ``date`` falls back to
    *fallback_ts* (the carrying record's capture time, 0.0 = unknown).
    Per-message ``direction`` means who authored the message (TL ``out``: a
    server->client echo of our own message is still "write"), not which way
    the carrying packet travelled; the row/chunk direction is untouched.
    """
    return [
        {
            "sender": str(p.sender_id) if p.sender_id else "",
            "direction": "write" if getattr(p, "outgoing", False) else direction,
            "out": bool(getattr(p, "outgoing", False)),
            "timestamp": p.timestamp or fallback_ts,
            "kind": p.kind,
            "body": p.body,
            "method": getattr(p, "method", "") or "",
            "attachments": bool(p.has_media),
            "quote": False,
            "reaction": False,
            "peer_id": p.peer_id,
            "user_id": getattr(p, "user_id", 0) or 0,
        }
        for p in parsed_messages
    ]


def _user_dedup_key(item: dict):
    """Identity key for de-duplicating kind="user" rows within a flow.

    Prefers the Telegram user id (stable across the several RPC results that
    return the same identity); falls back to the rendered body when no id is
    available. Returns ``None`` for non-user items (never deduped).
    """
    if item.get("kind") != "user":
        return None
    uid = item.get("user_id") or 0
    if uid:
        return ("id", uid)
    return ("body", item.get("body", ""))


def _tag_chunk_key(dicts: list, chunk_key: str) -> list:
    """Stamp *chunk_key* onto every dict of one record (no-op when empty)."""
    if chunk_key:
        for item in dicts:
            item["_chunk_key"] = chunk_key
    return dicts


def _append_mtproto_dicts_deduped(entry: dict, dicts: list) -> list:
    """Append parsed dicts to *entry* while collapsing duplicate user identities.

    The same user often appears in multiple RPC results within one flow (e.g.
    "db Forscher" returned by several queries). Each distinct ``kind="user"``
    identity is emitted only ONCE per flow, keyed by :func:`_user_dedup_key`.
    Text/chat/service items are NEVER deduped — they pass through untouched.
    Returns the dicts actually appended (the record's messages for the ledger).
    """
    seen = entry.setdefault("_user_keys", set())
    appended: list = []
    for item in dicts:
        key = _user_dedup_key(item)
        if key is not None:
            # Scoped per record when chunk-tagged, so a user repeated in a LATER
            # flow of the same connection survives until per-flow dedup.
            key = (item.get("_chunk_key", ""), key)
            if key in seen:
                continue
            seen.add(key)
        entry["messages"].append(item)
        appended.append(item)
    return appended


def _mark_seen(entry: dict, identity) -> bool:
    """Record *identity* in *entry*'s private ``_seen`` set.

    Returns True when it was already present (the caller should skip). The
    ``_seen`` set lives on the accumulating side-channel entry next to
    ``_user_keys``; only ``messages`` is folded onto the flow layer, so neither
    private key reaches the .tap.
    """
    return _already_emitted(entry.setdefault("_seen", set()), identity)


def _accumulate_mtproto_messages(
    meta: dict, key: str, tl_bytes: bytes, direction: str, msg_id: int = 0,
    capture_ts: float = 0.0, chunk_key: str = "",
) -> list:
    """Parse a cloud MTProto record's TL bytes and append to the side-channel.

    Tolerant by delegation: the parser never raises (degrades to no messages),
    so this can never break the conversion. A known *msg_id* makes the call
    idempotent: the same (msg_id, direction) record is accumulated only once.
    A *chunk_key* (see :func:`~friTap.offline.pipeline_api.chunk_key`) tags every parsed message of the
    record so the attach pass can scope messages to their own flow. Returns
    the dicts accumulated for THIS record (empty when nothing was added).
    """
    from friTap.offline.mtproto.content import parse_mtproto_message

    parsed = parse_mtproto_message(tl_bytes)
    if not parsed:
        return []
    entry = meta.setdefault(key, {"messages": []})
    if msg_id and _mark_seen(entry, ("msg", msg_id, direction)):
        return []
    dicts = _parsed_mtproto_to_dicts(parsed, direction, fallback_ts=capture_ts)
    return _append_mtproto_dicts_deduped(entry, _tag_chunk_key(dicts, chunk_key))


def _secret_chat_identity(parsed, direction: str, msg_key_hex: str):
    """Identity of one parsed E2E message within its per-fingerprint entry.

    Prefers the blob's msg_key (unique per encrypted packet), so two DISTINCT
    packets that reuse a ``random_id`` still each get their messages (the
    Message tab de-duplicates by ``random_id`` for display). Falls back to the
    sender-chosen ``random_id``, then to (body, direction) when neither is known.
    """
    if msg_key_hex:
        return ("mk", msg_key_hex)
    random_id = getattr(parsed, "random_id", 0) or 0
    if random_id:
        return ("rid", random_id)
    return ("body", parsed.body, direction)


def _accumulate_secret_chat_messages(
    meta: dict, key: str, tl_bytes: bytes, direction: str, chat_id: int,
    msg_key_hex: str = "", capture_ts: float = 0.0, chunk_key: str = "",
) -> list:
    """Parse a Secret-Chat E2E record's TL bytes and append to the side-channel.

    Idempotent per message: each E2E message is accumulated once per
    fingerprint entry, keyed by :func:`_secret_chat_identity`. E2E dicts carry
    ``random_id`` in addition to the shared cloud dict shape. A known
    *capture_ts* always wins as the E2E ``timestamp`` (Secret-Chat TL carries no
    trustworthy date of its own). *chunk_key* tags the record's messages as in
    :func:`_accumulate_mtproto_messages`, and the record's dicts are returned.
    """
    from friTap.offline.mtproto.content import parse_secret_chat_message

    parsed = parse_secret_chat_message(tl_bytes)
    if not parsed:
        return []
    entry = meta.setdefault(key, {"chat_id": chat_id, "messages": []})
    fresh = [
        p for p in parsed
        if not _mark_seen(entry, _secret_chat_identity(p, direction, msg_key_hex))
    ]
    dicts = _parsed_mtproto_to_dicts(fresh, direction, fallback_ts=capture_ts)
    for item, p in zip(dicts, fresh):
        item["random_id"] = getattr(p, "random_id", 0) or 0
        if capture_ts > 0:
            item["timestamp"] = capture_ts
    entry["messages"].extend(_tag_chunk_key(dicts, chunk_key))
    return dicts


def _load_telegram_keys(paths: Sequence[str]):
    """Load and merge cloud, obfuscation and Secret-Chat keys from *paths*.

    Returns ``(auth_keymap, obf_keys, secret_keymap)``: the two dicts are
    merged (first file wins on a key collision), the obf-key list is
    concatenated without duplicates.
    """
    from friTap.offline.mtproto.e2e.keylog import load_secret_chat_keylog
    from friTap.offline.mtproto.keylog import (
        load_mtproto_keylog,
        load_mtproto_obf_keylog,
    )

    auth_keymap: dict = {}
    obf_keys: list = []
    secret_keymap: dict = {}
    for path in paths:
        for key_id, key in load_mtproto_keylog(path).items():
            auth_keymap.setdefault(key_id, key)
        obf_keys.extend(k for k in load_mtproto_obf_keylog(path) if k not in obf_keys)
        for fp, key in load_secret_chat_keylog(path).items():
            secret_keymap.setdefault(fp, key)
    return auth_keymap, obf_keys, secret_keymap


def _telegram_state(state):
    """The Telegram namespace of the writer *state* (a stand-in is its own)."""
    return protocol_state_of(state, TELEGRAM_STATE)


def _set_state_attr(state, name: str, value) -> None:
    """Set *state*.<name>; a state that refuses attributes is left untouched."""
    try:
        setattr(state, name, value)
    except AttributeError:
        pass


def _state_attr(state, name: str, factory):
    """*state*.<name>, created by *factory* and attached when missing or None.

    Minimal state stand-ins (tests) without the attribute get one attached; a
    state that refuses attributes gets a call-local value instead.
    """
    value = getattr(state, name, None)
    if value is None:
        value = factory()
        _set_state_attr(state, name, value)
    return value


def _telegram_emitted_set(state) -> set:
    """The per-conversion set of already-emitted Telegram record identities.

    Lives on the writer state (``telegram_emitted``) so it spans every decoder
    pass (see :func:`_state_attr` for stand-in states).
    """
    return _state_attr(_telegram_state(state), "telegram_emitted", set)


def _telegram_ledger(state):
    """The per-conversion :class:`RecordLedger` of emitted Telegram records.

    Lazily attached to the writer state like :func:`_telegram_emitted_set`, so
    minimal state stand-ins keep working; a state that refuses attributes gets
    a call-local ledger (the attach pass then falls back to scoping).
    """
    from friTap.offline.mtproto.packet_meta import RecordLedger

    return _state_attr(_telegram_state(state), "telegram_ledger", RecordLedger)


def _next_record_seq(state) -> int:
    """Next monotonic record number of this conversion (starting at 1)."""
    telegram_state = _telegram_state(state)
    seq = (getattr(telegram_state, "telegram_record_seq", 0) or 0) + 1
    _set_state_attr(telegram_state, "telegram_record_seq", seq)
    return seq


def _ledger_record(state, transport: str, chunk_key: str,
                   messages: list, envelope: dict) -> int:
    """Record one emitted Telegram packet (its messages + envelope) in the ledger.

    Returns the record's ``record_seq`` (used to key its cross-references).
    """
    record_seq = _next_record_seq(state)
    _telegram_ledger(state).add(transport, chunk_key, {
        "record_seq": record_seq,
        "transport": transport,
        "chunk_key": chunk_key,
        "messages": [_strip_private_keys(item) for item in messages or []],
        "envelope": envelope,
    })
    return record_seq


class _TelegramRefs:
    """Per-conversion cross-references, users and Secret-Chat hints by record_seq.

    Filled while records are emitted (one TL decode per cloud record; the tree
    itself is dropped) and consumed by :func:`_finalize_telegram_refs`.
    """

    def __init__(self) -> None:
        from friTap.offline.mtproto.crossref import CrossRefIndex

        self.index = CrossRefIndex()
        self.users_by_seq: dict = {}
        self.chat_nodes: list = []
        self.e2e_chats: dict = {}

    def add_cloud(self, record_seq: int, msg) -> None:
        """Decode one cloud record once: index its refs, keep its users/chat objects."""
        from friTap.offline.mtproto.crossref import REF_LIMITS, refs_from_tree
        from friTap.offline.mtproto.tl import decode_tl, iter_nodes
        from friTap.offline.mtproto.tl.users import extract_users, is_chat_related

        root = decode_tl(msg.message, domain="mtproto", limits=REF_LIMITS)
        self.index.add(refs_from_tree(
            root, record_seq=record_seq,
            auth_key_id=getattr(msg, "auth_key_id_hex", "") or "",
            direction=getattr(msg, "direction", "") or "",
            msg_id=getattr(msg, "msg_id", 0) or 0,
        ))
        users = extract_users(root)
        if users:
            self.users_by_seq[record_seq] = users
        self.chat_nodes.extend(n for n in iter_nodes(root) if is_chat_related(n))

    def add_e2e(self, record_seq: int, sc, carrier) -> None:
        """Register a Secret-Chat record and the cloud record carrying it."""
        self.index.add_e2e(record_seq, getattr(carrier, "auth_key_id_hex", "") or "",
                           getattr(carrier, "msg_id", 0) or 0)
        self.e2e_chats[record_seq] = (getattr(sc, "key_fingerprint_hex", "") or "",
                                      getattr(sc, "chat_id", 0) or 0,
                                      getattr(sc, "peer_user_id", 0) or 0)

    def directory(self) -> dict:
        """All users of the capture merged by id (later records win)."""
        from friTap.offline.mtproto.tl.users import merge_user_directory

        return merge_user_directory(
            user for seq in sorted(self.users_by_seq) for user in self.users_by_seq[seq]
        )


def _telegram_refs(state) -> "_TelegramRefs":
    """The per-conversion :class:`_TelegramRefs`, lazily attached to *state*."""
    return _state_attr(_telegram_state(state), "telegram_refs", _TelegramRefs)


def _collect_cloud_refs(state, record_seq: int, msg) -> None:
    """Index one cloud record's refs/users; never lets a failure stop the emit."""
    try:
        _telegram_refs(state).add_cloud(record_seq, msg)
    except Exception as exc:  # noqa: BLE001 - forensic extras must not break conversion
        logger.debug("Telegram cross-reference extraction failed for record %s: %s",
                     record_seq, exc)


def _already_emitted(seen: set, identity) -> bool:
    """True when *identity* was emitted before; otherwise record it.

    A falsy identity (unknown msg_id / msg_key) is never deduplicated.
    """
    if identity is None:
        return False
    if identity in seen:
        return True
    seen.add(identity)
    return False


def _cloud_identity(msg):
    """Emission identity of a decrypted cloud record, or None if msg_id unknown."""
    msg_id = getattr(msg, "msg_id", 0) or 0
    if not msg_id:
        return None
    return ("cloud", msg.auth_key_id_hex, msg_id, msg.direction)


def _secret_chat_emit_identity(sc):
    """Emission identity of a decrypted E2E message, or None if msg_key unknown."""
    msg_key_hex = getattr(sc, "msg_key_hex", "") or ""
    if not msg_key_hex:
        return None
    return ("e2e", sc.key_fingerprint_hex, msg_key_hex)


def _emit_mtproto_streams(
    pcap_path: str,
    mtproto_keylog: str,
    *,
    bus: EventBus,
    state: "WriterState",
    result: ConvertResult,
    extra_keylogs: Sequence[str] = (),
    obf_max_blocks: int = DEFAULT_OBF_MAX_BLOCKS,
) -> None:
    """Decrypt Telegram traffic from an ``.mtproto.keylog`` (cloud + Secret-Chat).

    The friTap memscan sidecar written by ``-ms mtproto`` carries BOTH
    ``MTPROTO_AUTH_KEY`` (cloud transport) and ``MTPROTO_E2E_KEY`` (Secret-Chat)
    lines, so ``--mtproto-keylog`` decrypts cloud AND E2E secret chats. Thin
    wrapper over :func:`_emit_telegram_like_streams`; cloud + E2E messages are
    counted under the ``mtproto`` protocol bucket.
    """
    _emit_telegram_like_streams(
        pcap_path, mtproto_keylog,
        counter_name="mtproto",
        cloud_function="mtproto_offline",
        bus=bus, state=state, result=result,
        keylogs=extra_keylogs,
        obf_max_blocks=obf_max_blocks,
    )


def _time_ordered(messages) -> list:
    """*messages* stably sorted by capture ``timestamp`` (ties keep yield order).

    Unknown (0.0) timestamps sort first, which keeps an all-unknown input in its
    original order.
    """
    return sorted(messages, key=lambda m: getattr(m, "timestamp", 0.0) or 0.0)


def _emit_telegram_like_streams(
    pcap_path: str,
    keylog: str,
    *,
    counter_name: str,
    cloud_function: str,
    bus: EventBus,
    state: "WriterState",
    result: ConvertResult,
    keylogs: Sequence[str] = (),
    obf_max_blocks: int = DEFAULT_OBF_MAX_BLOCKS,
) -> None:
    """Decrypt Telegram traffic (cloud + Secret-Chat) from ONE combined keylog.

    A friTap Telegram/MTProto keylog holds BOTH ``MTPROTO_AUTH_KEY`` (cloud
    transport) and ``MTPROTO_E2E_KEY`` (Secret-Chat) lines; the two loaders each
    read only their own label, so the same file feeds both decryptors. Unlike
    TLS/QUIC this does NOT use tshark — friTap's own decryptor reassembles the TCP
    streams and AES-IGE decrypts each record. For every decrypted cloud message we
    (a) emit it as a ``DatalogEvent(protocol="mtproto")`` flow, and (b) scan it for
    embedded Secret-Chat E2E blobs, emitting each decrypted one as a
    ``DatalogEvent(protocol="telegram_e2e")`` flow.

    *counter_name* selects the ``ConvertResult`` protocol bucket (so the same body
    serves both the ``--mtproto-keylog`` and ``--telegram-keylog`` flags), while
    *cloud_function* labels the emitted cloud events per caller (E2E events are
    always labelled ``telegram_e2e_offline``).

    *keylogs* optionally names further keylog files whose keys are merged with
    *keylog*'s, so one pass decrypts with the union (used when two registry
    entries of the same decoder family were given different files). Records
    already emitted during this conversion (see :func:`_telegram_emitted_set`)
    are skipped, so a repeated pass never duplicates flows or messages.

    Every emitted record is also queued in the state's :class:`RecordLedger`
    (see :func:`_ledger_record`) with its own messages, forensic envelope and a
    monotonic ``record_seq``, which :func:`_attach_telegram_meta` pops per flow.

    The optional crypto backend is imported lazily; a missing dependency logs a
    warning and skips decryption (the rest of the conversion is unaffected).
    """
    from friTap.offline.mtproto import MtprotoDependencyError
    from friTap.offline.mtproto.decrypt import MtprotoStats, iter_decrypted_messages
    from friTap.offline.mtproto.e2e.decrypt import iter_secret_chat_messages
    from friTap.offline.mtproto.e2e.records import SecretChatStats

    auth_keymap, obf_keys, secret_keymap = _load_telegram_keys(
        unique_keylog_paths(keylog, keylogs)
    )
    emitted = _telegram_emitted_set(state)
    if not auth_keymap and not secret_keymap:
        logger.warning(
            "Telegram keylog %s has no usable cloud (MTPROTO_AUTH_KEY) or "
            "Secret-Chat (MTPROTO_E2E_KEY) keys; skipping Telegram decryption",
            keylog,
        )
        return

    tstats = MtprotoStats()
    sstats = SecretChatStats()
    try:
        for msg in _time_ordered(iter_decrypted_messages(
            pcap_path, auth_keymap, stats=tstats, obf_keys=obf_keys,
            obf_max_blocks=obf_max_blocks,
        )):
            # A record an earlier pass already emitted (same auth key, msg_id and
            # direction) is skipped whole: its E2E blobs were handled then too.
            if _already_emitted(emitted, _cloud_identity(msg)):
                continue
            # (a) the decrypted cloud transport message itself.
            _emit_cloud_record(msg, cloud_function=cloud_function,
                               bus=bus, state=state, result=result)
            # (b) any Secret-Chat E2E blobs carried inside this cloud message.
            for sc in iter_secret_chat_messages([msg], secret_keymap, stats=sstats):
                if _already_emitted(emitted, _secret_chat_emit_identity(sc)):
                    continue
                _emit_e2e_record(sc, msg, bus=bus, state=state, result=result)
    except MtprotoDependencyError as exc:
        logger.warning("Telegram decryption skipped: %s", exc)
        return

    # Honest E2E diagnostic: an E2E (secret-chat) key was loaded but NO transport
    # auth key, so every transport record missed the keymap, the transport envelope
    # never decrypted, and the E2E blobs inside it were never reached. Report this
    # exactly rather than as a generic mid-connection/undecryptable failure.
    e2e_only = bool(secret_keymap) and not auth_keymap
    _record_telegram_stats(result, counter_name, tstats, sstats, e2e_only=e2e_only)


def _emit_cloud_record(msg, *, cloud_function: str, bus: EventBus,
                       state: "WriterState", result: ConvertResult) -> None:
    """Emit one decrypted cloud record as a ``protocol="mtproto"`` flow event.

    Its TL payload is parsed into displayable messages accumulated in the cloud
    side-channel keyed by the perspective-independent 4-tuple (folded onto the
    inner MtprotoLayer by :func:`_attach_telegram_meta`), and the record is
    queued in the ledger with its envelope and cross-references.
    """
    from friTap.connection_index import normalize_4tuple
    from friTap.offline.mtproto.packet_meta import build_cloud_envelope

    msg_ts = getattr(msg, "timestamp", 0.0) or 0.0
    cloud_ev = DatalogEvent(
        data=msg.message,
        function=cloud_function,
        direction=msg.direction,
        src_addr=msg.src_addr,
        src_port=msg.src_port,
        dst_addr=msg.dst_addr,
        dst_port=msg.dst_port,
        ss_family=msg.ss_family,
        transport="tcp",
        protocol="mtproto",
        **event_ts_kwargs(msg_ts),
    )
    cloud_key = normalize_4tuple(
        msg.src_addr, msg.src_port, msg.dst_addr, msg.dst_port
    )
    cloud_chunk_key = chunk_key(msg.direction, cloud_ev.data)
    cloud_dicts = _accumulate_mtproto_messages(
        _telegram_state(state).mtproto_meta, cloud_key, msg.message, msg.direction,
        msg_id=getattr(msg, "msg_id", 0) or 0,
        capture_ts=msg_ts,
        chunk_key=cloud_chunk_key,
    )
    cloud_seq = _ledger_record(state, "mtproto", cloud_chunk_key, cloud_dicts,
                               build_cloud_envelope(msg))
    _collect_cloud_refs(state, cloud_seq, msg)
    open_at_capture_time(state, msg_ts)
    result.decrypted_packet_count += 1
    bus.emit(cloud_ev)


def _emit_e2e_record(sc, carrier, *, bus: EventBus,
                     state: "WriterState", result: ConvertResult) -> None:
    """Emit one decrypted Secret-Chat message found inside cloud record *carrier*.

    Secret chats ride INSIDE the same TCP connection as the cloud transport, so
    they share the cloud flow's 4-tuple. The event carries a per-chat session
    token (``telegram_e2e:<fp>``) so the collector keys it onto its OWN
    ``telegram_e2e`` flow (via the ``sid:`` tier) instead of folding its bytes
    into the cloud flow's MTProto parser; its messages are accumulated under
    that same session id.
    """
    from friTap.offline.mtproto.packet_meta import build_e2e_envelope

    session_id = f"telegram_e2e:{sc.key_fingerprint_hex}"
    sc_ts = getattr(sc, "timestamp", 0.0) or getattr(carrier, "timestamp", 0.0) or 0.0
    e2e_ev = DatalogEvent(
        data=sc.message,
        function="telegram_e2e_offline",
        direction=sc.direction,
        src_addr=sc.src_addr,
        src_port=sc.src_port,
        dst_addr=sc.dst_addr,
        dst_port=sc.dst_port,
        ss_family=sc.ss_family,
        ssl_session_id=session_id,
        transport="tcp",
        protocol="telegram_e2e",
        **event_ts_kwargs(sc_ts),
    )
    e2e_chunk_key = chunk_key(sc.direction, e2e_ev.data)
    e2e_dicts = _accumulate_secret_chat_messages(
        _telegram_state(state).telegram_e2e_meta, session_id,
        sc.message, sc.direction, sc.chat_id,
        msg_key_hex=getattr(sc, "msg_key_hex", "") or "",
        capture_ts=sc_ts,
        chunk_key=e2e_chunk_key,
    )
    e2e_seq = _ledger_record(state, "telegram_e2e", e2e_chunk_key, e2e_dicts,
                             build_e2e_envelope(sc, carrier))
    _telegram_refs(state).add_e2e(e2e_seq, sc, carrier)
    open_at_capture_time(state, sc_ts)
    result.decrypted_packet_count += 1
    bus.emit(e2e_ev)


def _record_telegram_stats(result: ConvertResult, counter_name: str,
                           tstats, sstats, *, e2e_only: bool) -> None:
    """Record the cloud + Secret-Chat decryption stats under *counter_name*."""
    result.record_protocol(
        counter_name,
        messages=tstats.messages + sstats.messages,
        streams=tstats.streams,
        undecryptable=tstats.records_undecryptable + sstats.records_undecryptable,
        degraded=tstats.streams_degraded,
        degraded_non_mtproto=tstats.streams_degraded_non_mtproto,
        partial=tstats.streams_partial,
        recovered_via_obf=tstats.streams_recovered_via_obf,
        degraded_unrecovered=tstats.streams_degraded_unrecovered,
        short=tstats.streams_short,
        unsupported_framing=tstats.streams_unsupported_framing,
        e2e_only=e2e_only,
        unknown_key_ids=dict(tstats.unknown_key_ids),
    )


def _emit_telegram_streams(
    pcap_path: str,
    telegram_keylog: str,
    *,
    bus: EventBus,
    state: "WriterState",
    result: ConvertResult,
    extra_keylogs: Sequence[str] = (),
    obf_max_blocks: int = DEFAULT_OBF_MAX_BLOCKS,
) -> None:
    """Decrypt Telegram traffic (cloud + Secret-Chat) from ONE combined keylog.

    Thin wrapper over :func:`_emit_telegram_like_streams`; cloud + E2E messages
    are counted under the ``telegram`` protocol bucket. Behaviourally identical to
    ``--mtproto-keylog`` (both flags now decrypt cloud + E2E from the same combined
    keylog); the two entry points differ only in their summary counter name.
    """
    _emit_telegram_like_streams(
        pcap_path, telegram_keylog,
        counter_name="telegram",
        cloud_function="telegram_offline",
        bus=bus, state=state, result=result,
        keylogs=extra_keylogs,
        obf_max_blocks=obf_max_blocks,
    )


# --------------------------------------------------------------------------- #
# Offline-decryptor registry wiring
# --------------------------------------------------------------------------- #
#
# The MTProto/Telegram decryptors are exposed through the offline registry so
# ``convert_pcap_to_tap`` iterates the registry instead of hardcoding
# per-protocol if-blocks. The emitters above keep their original, expressive
# signatures; thin adapters below present the normalized
# :data:`~friTap.offline.registry.OfflineEmitter` shape.

def _mtproto_offline_emitter(
    *, pcap_path, proto_keylog, tls_keylog_path, tshark_bin, tls_ports,
    bus, state, result, extra_keylogs=(), obf_max_blocks=DEFAULT_OBF_MAX_BLOCKS,
) -> None:
    """Normalized adapter around :func:`_emit_mtproto_streams` (self-contained TCP)."""
    _emit_mtproto_streams(
        pcap_path, proto_keylog,
        bus=bus, state=state, result=result, extra_keylogs=extra_keylogs,
        obf_max_blocks=obf_max_blocks,
    )


def _telegram_offline_emitter(
    *, pcap_path, proto_keylog, tls_keylog_path, tshark_bin, tls_ports,
    bus, state, result, extra_keylogs=(), obf_max_blocks=DEFAULT_OBF_MAX_BLOCKS,
) -> None:
    """Normalized adapter around :func:`_emit_telegram_streams` (self-contained TCP)."""
    _emit_telegram_streams(
        pcap_path, proto_keylog,
        bus=bus, state=state, result=result, extra_keylogs=extra_keylogs,
        obf_max_blocks=obf_max_blocks,
    )


# Attach-hook order: the Telegram fold runs after the RC4-in-TLS attach (20).
TELEGRAM_ATTACH_ORDER = 30


def _telegram_attach_hook():
    """The shared post-collection attach hook (lazy: tap_attach imports us)."""
    from .tap_attach import attach_telegram_post_collection

    return attach_telegram_post_collection


def build_mtproto_offline_decryptor_entry() -> "OfflineDecryptorEntry":
    """Build the MTProto :class:`OfflineDecryptorEntry`.

    Named factory mirroring ``build_signal_offline_decryptor_entry`` (see
    :mod:`friTap.offline.signal.offline_decryptor`): the layer class and registry
    type are imported lazily so this is cheap to call at registration time.
    """
    from friTap.flow.layers import MtprotoLayer
    from friTap.offline.registry import OfflineDecryptorEntry

    return OfflineDecryptorEntry(
        protocol_name="mtproto",
        cli_flag="--mtproto-keylog",
        cli_dest="mtproto_keylog",
        requires_tls_strip=False,
        emitter=_mtproto_offline_emitter,
        layer_cls=MtprotoLayer,
        counter_prefix="mtproto",
        decoder_family="telegram",
        # The family's attach hook and resync default live on this member only.
        attach=_telegram_attach_hook(),
        attach_order=TELEGRAM_ATTACH_ORDER,
        messaging=True,
        resync_default=DEFAULT_OBF_MAX_BLOCKS,
        resync_param="obf_max_blocks",
        cli_help=(
            "friTap MTProto/Telegram keylog (MTPROTO_AUTH_KEY + MTPROTO_E2E_KEY "
            "lines, e.g. a .mtproto.keylog from -ms mtproto) — decrypts Telegram "
            "cloud chats AND Secret-Chat E2E. Decrypted by friTap's own decryptor "
            "(not tshark); distinct from --keylog."
        ),
    )


def build_telegram_offline_decryptor_entry() -> "OfflineDecryptorEntry":
    """Build the Telegram (cloud + Secret-Chat E2E) :class:`OfflineDecryptorEntry`.

    Named factory mirroring ``build_signal_offline_decryptor_entry``; lazy imports
    as above.
    """
    from friTap.flow.layers import TelegramE2ELayer
    from friTap.offline.registry import OfflineDecryptorEntry

    return OfflineDecryptorEntry(
        protocol_name="telegram",
        cli_flag="--telegram-keylog",
        cli_dest="telegram_keylog",
        requires_tls_strip=False,
        emitter=_telegram_offline_emitter,
        layer_cls=TelegramE2ELayer,
        counter_prefix="telegram",
        decoder_family="telegram",
        # Shares the mtproto entry's attach hook and resync default (declared
        # there); it takes the resync depth under the same keyword.
        messaging=True,
        resync_param="obf_max_blocks",
        cli_help=(
            "friTap Telegram keylog (combined MTProto cloud auth keys + Secret-Chat "
            "E2E keys) — decrypts cloud chats and secret chats."
        ),
    )
