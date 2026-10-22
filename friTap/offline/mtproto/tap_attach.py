#!/usr/bin/env python3

"""MTProto/Telegram attach pass: fold parsed metadata onto offline flows.

Holds the Telegram-specific ATTACH side of the offline conversion that was
historically inlined in ``friTap.offline.pcap_to_tap``: after the collection
pass, the parsed cloud / Secret-Chat messages accumulated by the emitters in
:mod:`friTap.offline.mtproto.offline_decryptor` (the per-record
:class:`~friTap.offline.mtproto.packet_meta.RecordLedger` first, the
side-channel scoping as fallback) are folded onto each flow's inner layer, and
the cross-references / users / Secret-Chat peer are finalized.

Generic helpers come from the public :mod:`friTap.offline.pipeline_api`. The
code keeps its original behavior verbatim; only its enclosing module moved.
"""

from __future__ import annotations

import logging

from friTap.flow.layer_pipeline import MESSAGE_TRANSPORTS
from friTap.offline.pipeline_api import (
    chunk_key,
    protocol_state_of,
    scope_messages_to_flow,
)

from .offline_decryptor import _append_mtproto_dicts_deduped
from .state import TELEGRAM_STATE

logger = logging.getLogger(__name__)


def _apply_mtproto_meta(layer, meta: dict | None) -> None:
    """Fold accumulated parsed Telegram messages onto an inner layer.

    Shared by the cloud ``MtprotoLayer`` and the Secret-Chat ``TelegramE2ELayer``
    (both expose ``messages``/``message_count``). No-op when *layer* or *meta* is
    absent, so a flow with no recovered messages keeps its empty-but-valid layer
    (degrades, never raises). Mirrors :func:`_apply_inner_meta`.
    """
    if layer is None or not meta:
        return
    messages = meta.get("messages", []) or []
    layer.messages = messages
    layer.message_count = len(messages)


def _scoped_cloud_meta(flow, meta: dict) -> dict:
    """Per-flow cloud entry: scoped messages, users re-deduped within the flow."""
    scoped: dict = {"messages": []}
    _append_mtproto_dicts_deduped(
        scoped, scope_messages_to_flow(flow, meta.get("messages"))
    )
    return {"messages": scoped["messages"]}


def _scoped_e2e_meta(flow, meta: dict) -> dict:
    """Per-flow Secret-Chat entry: public fields plus the flow's own messages."""
    scoped = {k: v for k, v in meta.items() if not k.startswith("_")}
    scoped["messages"] = scope_messages_to_flow(flow, meta.get("messages"))
    return scoped


def _single_chunk_key(flow) -> str:
    """:func:`chunk_key` of a one-chunk (per-packet) flow, else ``""``."""
    chunks = getattr(flow, "chunks", None) or []
    if len(chunks) != 1:
        return ""
    return chunk_key(getattr(chunks[0], "direction", ""), getattr(chunks[0], "data", b""))


def _apply_ledger_envelope(layer, envelope: dict) -> None:
    """Copy the envelope's identity fields onto the layer's typed attributes."""
    if getattr(layer, "NAME", "") == "mtproto":
        layer.transport = envelope.get("transport", "") or layer.transport
        layer.obfuscated = bool(envelope.get("obfuscated", layer.obfuscated))
        layer.dc_id = envelope.get("dc_id", 0) or layer.dc_id
        layer.auth_key_id = envelope.get("auth_key_id", "") or layer.auth_key_id
    else:
        layer.key_fingerprint = envelope.get("key_fingerprint", "") or layer.key_fingerprint
        layer.chat_id = envelope.get("chat_id", 0) or layer.chat_id


def _apply_ledger_record(layer, record: dict) -> None:
    """Fold one ledger record (messages + envelope + record_seq) onto *layer*."""
    messages = list(record.get("messages") or [])
    layer.messages = messages
    layer.message_count = len(messages)
    envelope = dict(record.get("envelope") or {})
    envelope["record_seq"] = record.get("record_seq", 0)
    layer.envelope = envelope
    _apply_ledger_envelope(layer, envelope)


def _meta_from_ledger(flow, ledger) -> bool:
    """Give a per-packet Telegram *flow* exactly its own ledger record.

    Pops the oldest record queued under the flow's transport and single chunk
    key; flows are walked in creation (= emission) order, so byte-identical
    packets are matched first-in-first-out. Returns False (caller falls back to
    side-channel scoping) when the flow is not one-chunk or no record is left.
    """
    inner_name = getattr(flow, "transport", "")
    chunk_key = _single_chunk_key(flow)
    record = ledger.take(inner_name, chunk_key) if chunk_key else None
    if record is None:
        logger.debug("No Telegram ledger record for flow %s (%s, key %r); "
                     "falling back to scoped metadata",
                     getattr(flow, "flow_id", "?"), inner_name, chunk_key)
        return False
    getattr(flow, inner_name)
    layer = flow.layer(inner_name)
    if layer is None:
        return False
    _apply_ledger_record(layer, record)
    return True


def _attach_scoped_meta(flow, mtproto_meta: dict | None,
                        telegram_e2e_meta: dict | None) -> None:
    """Fallback: fold the flow's scoped side-channel messages onto its layer."""
    from friTap.connection_index import normalize_4tuple

    inner_name = getattr(flow, "transport", "")
    if inner_name == "mtproto" and mtproto_meta:
        key = normalize_4tuple(
            flow.src_addr, flow.src_port, flow.dst_addr, flow.dst_port
        )
        meta = mtproto_meta.get(key)
        meta = _scoped_cloud_meta(flow, meta) if meta else None
    elif inner_name == "telegram_e2e" and telegram_e2e_meta:
        meta = telegram_e2e_meta.get(getattr(flow, "ssl_session_id", ""))
        meta = _scoped_e2e_meta(flow, meta) if meta else None
    else:
        return
    if not meta:
        return
    # Materialize the inner layer if the offline flow built it lazily
    # (``getattr`` triggers _create_layer, which appends the chunks-view
    # layer); then fold the parsed messages onto it.
    getattr(flow, inner_name)
    _apply_mtproto_meta(flow.layer(inner_name), meta)


def _attach_telegram_meta(
    flows,
    mtproto_meta: dict | None = None,
    telegram_e2e_meta: dict | None = None,
    ledger=None,
) -> None:
    """Fold parsed Telegram messages onto offline-decrypted MTProto/E2E flows.

    Unlike Signal, MTProto rides RAW TCP (no TLS to strip), so these flows are
    NOT processed by :func:`_attach_transport_metadata_layers`. This applies the
    side-channel parsed-message dicts accumulated by ``_emit_mtproto_streams`` /
    ``_emit_telegram_streams`` onto each flow's innermost decrypted layer:

      * cloud ``mtproto`` flows are keyed by the canonical 4-tuple (like Signal);
      * Secret-Chat ``telegram_e2e`` flows are keyed by their
        ``telegram_e2e:<fp>`` session id (several chats share one 4-tuple).

    Like the Signal pass it MUST run on the LIVE flow objects and BEFORE flush().
    Each flow receives only the messages whose record became one of ITS chunks
    (see :func:`scope_messages_to_flow`), so sibling exchange flows of one
    connection/chat no longer share one connection-wide message list.
    Flows with no recovered messages are left untouched (degrades, never raises).

    When a :class:`RecordLedger` is given (the emitter's per-record queue), it
    is tried FIRST: each per-packet flow gets exactly its own record's messages
    and forensic envelope (:func:`_meta_from_ledger`), which stays correct even
    for byte-identical packets. The scoping above is the per-flow fallback.
    """
    for flow in flows:
        if getattr(flow, "transport", "") not in MESSAGE_TRANSPORTS:
            continue
        if ledger and _meta_from_ledger(flow, ledger):
            continue
        _attach_scoped_meta(flow, mtproto_meta, telegram_e2e_meta)


def _flow_record_seq(flow) -> tuple:
    """``(layer, record_seq)`` of a per-packet Telegram flow, or ``(None, 0)``."""
    transport = getattr(flow, "transport", "")
    if transport not in MESSAGE_TRANSPORTS:
        return None, 0
    layer = flow.layer(transport)
    envelope = getattr(layer, "envelope", None) or {}
    return layer, int(envelope.get("record_seq", 0) or 0)


def _fill_flow_ids(value, seq_to_flow: dict) -> None:
    """Add ``flow_id`` next to every ``record_seq`` in a refs structure (in place)."""
    if isinstance(value, list):
        for item in value:
            _fill_flow_ids(item, seq_to_flow)
    elif isinstance(value, dict):
        flow_id = seq_to_flow.get(value.get("record_seq"))
        if flow_id is not None:
            value["flow_id"] = flow_id
        for item in value.values():
            if isinstance(item, (dict, list)):
                _fill_flow_ids(item, seq_to_flow)


def _message_user_ids(messages) -> list:
    """Non-zero user ids a flow's chat messages reference (sender / peer / user)."""
    ids = []
    for message in messages or []:
        for key in ("sender_id", "peer_id", "user_id"):
            value = message.get(key) if isinstance(message, dict) else None
            if isinstance(value, int) and value and value not in ids:
                ids.append(value)
    return ids


def _dedupe_users(users) -> list:
    seen, out = set(), []
    for user in users:
        if user and user.get("id") not in seen:
            seen.add(user.get("id"))
            out.append(user)
    return out


def _cloud_flow_users(layer, record_users: list, directory: dict) -> list:
    """Users decoded in this packet, plus self + users its chat messages reference."""
    from friTap.offline.mtproto.tl.users import self_user

    referenced = _message_user_ids(getattr(layer, "messages", None))
    extra = [directory.get(uid) for uid in referenced]
    if referenced:
        extra.insert(0, self_user(directory))
    return _dedupe_users(list(record_users) + extra)


def _apply_e2e_peer(layer, refs_state, record_seq: int, directory: dict) -> None:
    """Link the Secret-Chat peer and set ``layer.peer`` / ``layer.users``.

    Resolution priority: the keylog's ``peer_user_id`` (agent-read, confident) →
    a wire-confirmed ``encryptedChat*`` link → the heuristic fallback (tagged
    ``matched_by="heuristic"``) for chats that predate the capture.
    """
    from friTap.offline.mtproto.tl.users import (
        infer_secret_chat_peer,
        keylog_peer,
        link_secret_chat_peer,
        self_user,
    )

    fp_hex, chat_id, peer_user_id = refs_state.e2e_chats.get(record_seq, ("", 0, 0))
    if peer_user_id:
        peer = keylog_peer(peer_user_id, chat_id, directory)
    else:
        peer = link_secret_chat_peer(refs_state.chat_nodes, fp_hex, chat_id, directory)
        if not peer.get("user_id"):
            me = self_user(directory)
            peer = infer_secret_chat_peer(directory, me.get("id", 0) if me else 0, chat_id)
    layer.peer = peer
    layer.users = _dedupe_users([self_user(directory), peer.get("user")])


def _finalize_telegram_refs(flows, refs_state) -> None:
    """Write ``refs`` / ``users`` / ``peer`` onto every per-packet Telegram flow.

    Runs after :func:`_attach_telegram_meta` (which set ``envelope.record_seq``)
    on the LIVE flows, before flush. Referenced records gain their ``flow_id``.
    Degrades silently when no refs were collected (e.g. minimal test state).
    """
    if refs_state is None:
        return
    targets = [(flow, *_flow_record_seq(flow)) for flow in flows]
    targets = [(flow, layer, seq) for flow, layer, seq in targets if layer is not None and seq]
    seq_to_flow = {seq: flow.flow_id for flow, _layer, seq in targets}
    directory = refs_state.directory()
    for flow, layer, seq in targets:
        refs = refs_state.index.resolve(seq)
        _fill_flow_ids(refs, seq_to_flow)
        layer.refs = refs
        if flow.transport == "mtproto":
            layer.users = _cloud_flow_users(layer, refs_state.users_by_seq.get(seq, []), directory)
        else:
            _apply_e2e_peer(layer, refs_state, seq, directory)


def attach_telegram_post_collection(flows, state) -> None:
    """Registry attach hook: fold Telegram metadata, then finalize the refs.

    Folds the parsed MTProto/Secret-Chat messages onto their (raw-TCP,
    non-TLS-riding) LIVE flows, then writes the cross-references / users /
    Secret-Chat peer, which need every record's flow_id. Absorbs no flow.
    """
    flows = list(flows)
    telegram_state = protocol_state_of(state, TELEGRAM_STATE)
    _attach_telegram_meta(
        flows, telegram_state.mtproto_meta, telegram_state.telegram_e2e_meta,
        ledger=getattr(telegram_state, "telegram_ledger", None),
    )
    _finalize_telegram_refs(flows, getattr(telegram_state, "telegram_refs", None))
