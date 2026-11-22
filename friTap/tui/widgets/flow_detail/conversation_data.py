"""Flow-detail conversation model: gathering messages across sibling flows,
participants and peer identity (Signal, MTProto, Telegram Secret Chats).
"""

from __future__ import annotations

import re

from friTap.flow import telegram_conversation as _tconv
from friTap.flow.display import TELEGRAM_LAYER_NAMES

from .helpers import _safe_layer


class ConversationDataMixin:
    """Conversation model: message gathering, participants and peer identity."""

    @staticmethod
    def _is_mergeable_telegram_layer(flow, layer) -> bool:
        """Secret-Chat layers, and cloud MTProto layers carrying chat text,
        render the whole conversation merged across sibling flows."""
        name = getattr(layer, "name", "")
        if name == "telegram_e2e":
            return True
        return name == "mtproto" and _tconv.flow_has_chat_text(flow)

    # CHAT kinds form the visible message flow; bodies render in quotes.
    _CHAT_KINDS = frozenset({"text", "data", "message"})
    # Participant/identity kind (MTProto/E2E): shown in the header and the
    # Participants block, never as a flow row.
    _PARTICIPANT_KIND = "user"
    # Signal session-metadata kinds (plaintext WS/REST context), shown in a
    # "Session metadata" block. Other transport chatter stays in the
    # collapsed summary.
    _SESSION_META_KINDS = frozenset(
        {"rest", "profile", "device-list", "prekey", "ws-request"}
    )
    # Direction values meaning "sent by this device"; the message-dict
    # contract uses "write", other producers may use synonyms.
    _OUTBOUND_DIRECTIONS = _tconv.OUTBOUND_DIRECTIONS
    # Per-kind glyph for the Session-metadata rows.
    _META_ICONS = {"profile": "👤", "device-list": "📱", "prekey": "🔑",
                   "rest": "✉", "ws-request": "·"}
    # An E164 phone number: '+' then 6+ digits. Used to prefer a human phone
    # number over a UUID/PNI when labelling the conversation peer.
    _E164_RE = re.compile(r"^\+\d{6,}$")

    @classmethod
    def _is_outbound(cls, entry) -> bool:
        """True if a message dict is outbound (sent by this device)."""
        if entry.get("out") is True:
            return True
        return (entry.get("direction") or "") in cls._OUTBOUND_DIRECTIONS

    def _conversation_participants(self, layer, messages) -> list[dict]:
        """Derive conversation participants from a message-bearing layer.

        Returns a list of ``{"name", "detail", "is_self"}`` dicts, deduped:

        * MTProto/E2E — when the layer carries ``kind=="user"`` items, those
          ARE the participants. ``name`` = the body up to the first " (" or
          " ["; ``is_self`` when the relationship/body marks self (``[you]``);
          ``detail`` = the full body.
        * Signal/others — participants are the distinct non-empty ``sender``
          values among RECEIVED messages, plus a synthetic "you" iff there is
          any outgoing message. ``detail`` = the sender string.
        """
        users = [m for m in messages
                 if (m.get("kind") or "") == self._PARTICIPANT_KIND]
        if users:
            return self._participants_from_users(users)
        return self._participants_from_senders(messages)

    # Layers carrying structured Telegram identity metadata (users / peer).
    _TELEGRAM_META_LAYERS = TELEGRAM_LAYER_NAMES

    def _telegram_meta_layers(self, sources) -> list:
        """The Telegram layers (cloud + Secret-Chat) of every source flow."""
        return [lyr for src in sources for lyr in _tconv.telegram_layers_of(src)]

    def _structured_users_for(self, flow, layer, merge_siblings: bool,
                              sources=None) -> list:
        """Structured ``layer.users`` across *flow* (and siblings when merged).

        *sources* is the precomputed :meth:`_secret_chat_sources` result.
        """
        if getattr(layer, "name", "") not in self._TELEGRAM_META_LAYERS:
            return []
        if sources is None:
            sources = self._secret_chat_sources(flow, merge_siblings)
        return self._structured_users(sources)

    def _structured_users(self, sources) -> list:
        return [u for lyr in self._telegram_meta_layers(sources)
                for u in (getattr(lyr, "users", None) or []) if isinstance(u, dict)]

    def _structured_self_id(self, sources, users=None) -> int:
        """The capturing account's user id from structured users (0 if unknown).

        *users* is the precomputed :meth:`_structured_users` of *sources*.
        """
        if users is None:
            users = self._structured_users(sources)
        for user in users:
            if "self" in (user.get("flags") or []):
                return _tconv.as_int(user.get("id"))
        return 0

    def _secret_chat_peer(self, sources):
        """First linked Secret-Chat ``peer`` (a resolved user preferred)."""
        peers = [getattr(lyr, "peer", None) for lyr in self._telegram_meta_layers(sources)]
        peers = [p for p in peers if isinstance(p, dict) and p]
        return next((p for p in peers if p.get("user_id")), peers[0] if peers else None)

    def _cloud_chat_peer(self, messages, self_id: int):
        """The 1:1 cloud peer when all chat text shares one conversation key."""
        keys = _tconv.conversation_keys_of_entries(messages, self_id)
        if len(keys) != 1:
            return None
        peer_id = int(next(iter(keys)))
        return {"user_id": peer_id, "label": f"peer {peer_id}"}

    def _structured_participants(self, flow, layer, messages,
                                 merge_siblings: bool, sources=None, users=None):
        """Participants from structured users/peer, or None for old taps.

        Self renders by name (the header adds ``(you)``), then the peer's
        name or its label (``peer (unknown, chat_id X)``). A synthetic
        ``you`` stands in when outbound messages exist but self is unknown.
        """
        name = getattr(layer, "name", "")
        if name not in self._TELEGRAM_META_LAYERS:
            return None
        if sources is None:
            sources = self._secret_chat_sources(flow, merge_siblings)
        if users is None:
            users = self._structured_users(sources)
        if name == "telegram_e2e":
            peer = self._secret_chat_peer(sources)
        else:
            peer = self._cloud_chat_peer(messages, self._structured_self_id(sources, users))
        if not users and not (peer and name == "telegram_e2e"):
            return None
        participants = _tconv.participants_from_structured_users(users, peer)
        if not any(p.get("is_self") for p in participants) and any(
                self._is_outbound(m) for m in messages):
            participants.insert(0, {"name": "you", "detail": "you", "is_self": True})
        return participants or None

    def _participants_from_users(self, users) -> list[dict]:
        """Build participant dicts from MTProto/E2E ``kind=="user"`` items."""
        participants: list[dict] = []
        seen: set[str] = set()
        for entry in users:
            body = (entry.get("body") or "").strip()
            name = self._participant_name(body) or (entry.get("sender") or "?")
            if name in seen:
                continue
            seen.add(name)
            rel = (entry.get("relationship") or "")
            lowered = f"{rel} {body}".lower()
            is_self = "self" in lowered or "[you]" in lowered
            participants.append(
                {"name": name, "detail": body or name, "is_self": is_self}
            )
        return participants

    def _participants_from_senders(self, messages) -> list[dict]:
        """Build participant dicts from distinct senders (Signal etc.)."""
        participants: list[dict] = []
        seen: set[str] = set()
        has_outgoing = False
        for entry in messages:
            if self._is_outbound(entry):
                has_outgoing = True
                continue
            sender = (entry.get("sender") or "").strip()
            if sender and sender not in seen:
                seen.add(sender)
                participants.append(
                    {"name": sender, "detail": sender, "is_self": False}
                )
        if has_outgoing:
            participants.insert(0, {"name": "you", "detail": "you",
                                    "is_self": True})
        return participants

    def _resolve_peer_identity(self, messages) -> tuple[str, str]:
        """Best ``(display, kind)`` for the other party from the gathered messages.

        First hit wins: ``phone`` (inbound E164 sender), ``uuid`` (other
        inbound non-PNI sender, else a ``profile`` record's ``meta.uuid``),
        ``pni`` (``PNI:`` sender), else ``("", "unknown")``.
        """
        phone = sender_uuid = pni = profile_uuid = ""
        for m in messages:
            if not profile_uuid and (m.get("kind") or "") == "profile":
                profile_uuid = ((m.get("meta") or {}).get("uuid") or "").strip()
            if self._is_outbound(m):
                continue
            sender = (m.get("sender") or "").strip()
            if not sender:
                continue
            if not phone and self._E164_RE.match(sender):
                phone = sender
            elif sender.startswith("PNI:"):
                pni = pni or sender
            elif not sender_uuid:
                sender_uuid = sender

        if phone:
            return phone, "phone"
        if sender_uuid:
            return sender_uuid, "uuid"
        if profile_uuid:
            return profile_uuid, "uuid"
        if pni:
            return pni, "pni"
        return "", "unknown"

    @staticmethod
    def _participant_name(body: str) -> str:
        """Display name = body up to the first " (" or " [" marker."""
        name = body
        for marker in (" (", " ["):
            idx = name.find(marker)
            if idx >= 0:
                name = name[:idx]
        return name.strip()

    def _sender_id_to_name(self, messages, structured_users=None) -> dict:
        """Map stringified ``user_id`` -> display name for group chat rows.

        Keys are strings to match the message-dict ``sender`` field.
        Structured users seed the map; ``kind=="user"`` records fill the rest.
        """
        mapping: dict = _tconv.user_names_by_id(structured_users or [])
        for entry in messages:
            if (entry.get("kind") or "") != self._PARTICIPANT_KIND:
                continue
            uid = entry.get("user_id") or 0
            if not uid:
                continue
            name = self._participant_name(entry.get("body") or "")
            if name:
                mapping.setdefault(str(uid), name)
        return mapping

    @staticmethod
    def _sorted_by_time(messages: list) -> list:
        """Stable time-sort with carry-forward for zero-timestamp records.

        A record without a timestamp (receipts, typing) inherits the previous
        record's, and the original index breaks ties, so receipts stay next
        to their message instead of sinking to the top.
        """
        annotated = []
        last_ts = 0
        for idx, m in enumerate(messages):
            ts = m.get("timestamp") or 0
            try:
                ts = int(ts)
            except (TypeError, ValueError):
                ts = 0
            if ts > 0:
                last_ts = ts
                anchor = ts
            else:
                anchor = last_ts
            annotated.append((anchor, idx, m))
        annotated.sort(key=lambda t: (t[0], t[1]))
        return [m for _, _, m in annotated]

    def _gather_conversation_messages(self, flow, layer, merge_siblings: bool,
                                      sources=None, users=None) -> list:
        """Collect this flow's messages, optionally merged with sibling flows.

        De-dup is by flow (by flow_id, since siblings are ``copy.copy``
        snapshots), not by content, so two identical wire messages both
        survive. *sources* / *users* are precomputed by the caller.
        """

        if sources is None:
            sources = self._secret_chat_sources(flow, merge_siblings)
        if getattr(layer, "name", "") == "telegram_e2e":
            return self._gather_secret_chat_messages(flow, layer, merge_siblings, sources)
        if merge_siblings and getattr(layer, "name", "") == "mtproto":
            return self._gather_cloud_chat_messages(flow, layer, sources, users)
        messages = list(getattr(layer, "messages", None) or [])
        layer_name = getattr(layer, "name", "")
        for sib in sources[1:]:
            sib_layer = sib.layer(layer_name) if hasattr(sib, "layer") else None
            messages.extend(getattr(sib_layer, "messages", None) or [])
        return messages

    def _gather_cloud_chat_messages(self, flow, layer, sources=None, users=None) -> list:
        """This flow's messages plus its cloud siblings' chat text for the
        same conversation (and their identity records), deduped by identity.
        """
        if sources is None:
            sources = self._secret_chat_sources(flow, True)
        self_id = self._structured_self_id(sources, users)
        keys = _tconv.conversation_keys_of(flow, self_id)
        messages = list(getattr(layer, "messages", None) or [])
        for sib in sources[1:]:
            sib_layer = _safe_layer(sib, "mtproto")
            messages.extend(m for m in getattr(sib_layer, "messages", None) or []
                            if self._belongs_to_conversation(m, keys, self_id))
        return self._dedupe_by_message_identity(messages)

    def _belongs_to_conversation(self, entry, keys: set, self_id: int) -> bool:
        """A sibling entry joins the transcript when it is chat text of the
        same conversation, or an identity (``user``) record."""
        if (entry.get("kind") or "") == self._PARTICIPANT_KIND:
            return True
        return (_tconv.is_chat_text(entry)
                and _tconv.conversation_peer_key(entry, self_id) in keys)

    def _secret_chat_sources(self, flow, merge_siblings: bool) -> list:
        """The flow plus (when merging) each distinct sibling flow, flow first."""
        sources = [flow]
        if not merge_siblings:
            return sources
        seen_ids = {getattr(flow, "flow_id", id(flow))}
        for sib in getattr(self, "_conversation_siblings", None) or []:
            sib_id = getattr(sib, "flow_id", id(sib))
            if sib_id not in seen_ids:
                seen_ids.add(sib_id)
                sources.append(sib)
        return sources

    def _gather_secret_chat_messages(self, flow, layer, merge_siblings: bool,
                                     sources=None) -> list:
        """Secret-Chat messages across the chat's flows, deduped, times backfilled.

        A Secret Chat's messages can be repeated per flow (and legacy .tap
        files stored every message twice in two flows), so the union is
        collapsed by message identity. Messages lacking a timestamp inherit
        the pcap time of their source flow's matching-direction chunk.
        """
        if sources is None:
            sources = self._secret_chat_sources(flow, merge_siblings)
        source_of = {}
        messages = []
        for src in sources:
            src_layer = layer if src is flow else _safe_layer(src, "telegram_e2e")
            for m in getattr(src_layer, "messages", None) or []:
                source_of[id(m)] = src
                messages.append(m)
        unique = self._dedupe_by_message_identity(messages)
        return self._backfill_chunk_timestamps(unique, source_of)

    @staticmethod
    def _message_identity(entry) -> tuple:
        """Identity key: the TL random_id when non-zero, else direction/body/time."""
        try:
            random_id = int(entry.get("random_id") or 0)
        except (TypeError, ValueError):
            random_id = 0
        if random_id:
            return ("random_id", random_id)
        return ("content", entry.get("direction") or "",
                entry.get("body") or "", entry.get("timestamp") or 0)

    @classmethod
    def _dedupe_by_message_identity(cls, messages: list) -> list:
        """Drop repeated messages (same identity), keeping first occurrences in order."""
        seen = set()
        unique = []
        for m in messages:
            key = cls._message_identity(m)
            if key in seen:
                continue
            seen.add(key)
            unique.append(m)
        return unique

    def _backfill_chunk_timestamps(self, messages: list, source_of: dict) -> list:
        """Copy of *messages* where a missing timestamp takes its chunk's pcap time.

        The k-th message of a direction in a flow maps to that flow's k-th
        chunk of the same direction (clamped to the last one). Messages that
        already carry a timestamp are returned unchanged.
        """
        per_flow_index: dict = {}
        times_of: dict = {}  # (source, direction) -> chunk times, built once
        result = []
        for m in messages:
            if m.get("timestamp"):
                result.append(m)
                continue
            src = source_of.get(id(m))
            direction = "write" if self._is_outbound(m) else "read"
            key = (id(src), direction)
            idx = per_flow_index.get(key, 0)
            per_flow_index[key] = idx + 1
            if key not in times_of:
                times_of[key] = self._chunk_times(src, direction)
            ts = self._clamped_time(times_of[key], idx)
            result.append({**m, "timestamp": ts} if ts else m)
        return result

    @staticmethod
    def _chunk_times(flow, direction: str) -> list:
        """Non-zero timestamps of *flow*'s *direction* chunks, in chunk order."""
        return [ch.timestamp for ch in (getattr(flow, "chunks", None) or [])
                if ch.direction == direction and ch.timestamp]

    @staticmethod
    def _clamped_time(times: list, index: int) -> float:
        """``times[index]`` clamped to the last entry; 0.0 when *times* is empty."""
        return times[min(index, len(times) - 1)] if times else 0.0

    @classmethod
    def _nth_chunk_time(cls, flow, direction: str, index: int) -> float:
        """Timestamp of the *index*-th *direction* chunk (clamped), 0.0 if none."""
        return cls._clamped_time(cls._chunk_times(flow, direction), index)
