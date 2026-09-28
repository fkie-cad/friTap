"""Telegram conversation helpers for the Message tab (pure, UI-free).

Every MTProto / Secret-Chat packet is its own flow, so one chat is spread over
many flows. These helpers let the TUI reunite them and name the participants:

* :func:`conversation_peer_key` — which conversation a chat-text entry belongs to;
* :func:`flow_has_chat_text` — cheap test whether a flow (or summary) carries chat
  text, used to pre-filter sibling candidates;
* :func:`participants_from_structured_users` — participant dicts (the
  ``{"name", "detail", "is_self"}`` shape the Message tab renders) built from the
  structured ``layer.users`` / ``layer.peer`` metadata of newer taps.
"""

from __future__ import annotations

from typing import Iterable, List, Optional

from friTap.flow.display import TELEGRAM_LAYER_NAMES, _classify_method
from friTap.offline.mtproto.tl.users import merge_user_directory, self_user, user_label

#: Method rank that marks a chat operation (see ``display._classify_method``).
CHAT_METHOD_RANK = 4
#: Message-dict kind that carries chat text.
CHAT_TEXT_KIND = "text"
#: Layers whose ``messages`` may carry Telegram chat text.
_CHAT_LAYER_NAMES = TELEGRAM_LAYER_NAMES
#: Message-dict ``direction`` values meaning "sent by this device". The
#: decrypted message-dict contract uses "write"; other producers use synonyms.
OUTBOUND_DIRECTIONS = frozenset({"write", "outgoing", "sent"})
_OUTBOUND_DIRECTIONS = OUTBOUND_DIRECTIONS


def as_int(value) -> int:
    """``int(value)``, with ``0`` for empty or unparsable values."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


_as_int = as_int


def conversation_peer_key(entry: dict, self_id: int = 0) -> str:
    """Conversation key of a chat-text *entry*; ``""`` when it cannot be told.

    Outbound messages are keyed by their ``peer_id`` (the recipient). Inbound
    messages are keyed by ``peer_id`` when it names the chat (a group, or the
    private peer), else by the ``sender`` — also when ``peer_id`` is our own
    *self_id* (older layers address a private message to the receiver).
    """
    peer_id = as_int(entry.get("peer_id"))
    if (entry.get("direction") or "") in OUTBOUND_DIRECTIONS:
        return str(peer_id) if peer_id else ""
    sender = as_int(entry.get("sender"))
    if peer_id and peer_id != self_id:
        return str(peer_id)
    return str(sender) if sender else ""


def is_chat_text(entry) -> bool:
    """True for a message dict carrying non-empty chat text."""
    try:
        return (entry.get("kind") or "") == CHAT_TEXT_KIND and bool(entry.get("body"))
    except AttributeError:
        return False


def telegram_layers_of(flow) -> list:
    """*flow*'s present Telegram layers (cloud, then Secret-Chat); never raises."""
    lookup = getattr(flow, "layer", None)
    if not callable(lookup):
        return []
    layers = []
    for name in _CHAT_LAYER_NAMES:
        try:
            layer = lookup(name)
        except Exception:
            layer = None
        if layer is not None:
            layers.append(layer)
    return layers


def chat_text_entries(flow) -> list:
    """Chat-text message dicts of *flow*'s Telegram layers (empty when none)."""
    return [m for layer in telegram_layers_of(flow)
            for m in (getattr(layer, "messages", None) or []) if is_chat_text(m)]


def method_is_chat_ranked(summary_or_flow) -> bool:
    """True when the stored Method scalar ranks as a chat operation."""
    method = (getattr(summary_or_flow, "flow_method", "") or
              getattr(summary_or_flow, "method", "") or "")
    return _classify_method(str(method)) >= CHAT_METHOD_RANK


def flow_has_chat_text(summary_or_flow) -> bool:
    """Whether a flow carries chat text.

    A full flow (has layers) is judged by its layer messages; a summary (no
    layers) by its chat-ranked Method scalar — a cheap, permissive pre-filter.
    """
    if callable(getattr(summary_or_flow, "layer", None)):
        return bool(chat_text_entries(summary_or_flow))
    return method_is_chat_ranked(summary_or_flow)


def conversation_keys_of_entries(entries: Iterable, self_id: int = 0) -> set:
    """Distinct non-empty conversation keys of the chat-text dicts among *entries*."""
    keys = {conversation_peer_key(m, self_id) for m in entries if is_chat_text(m)}
    keys.discard("")
    return keys


def conversation_keys_of(flow, self_id: int = 0) -> set:
    """Distinct non-empty conversation keys of *flow*'s chat-text entries."""
    return conversation_keys_of_entries(chat_text_entries(flow), self_id)


# --------------------------------------------------------------------------- #
# Participants
# --------------------------------------------------------------------------- #

def _user_detail(user: dict, name: str, is_self: bool) -> str:
    """Participants-block line: ``name (you) @username · id N`` (unescaped)."""
    parts = [f"{name} (you)" if is_self else name]
    if user.get("username"):
        parts.append(f"@{user['username']}")
    if user.get("id"):
        parts.append(f"· id {user['id']}")
    return " ".join(parts)


def _participant(user: dict, is_self: bool) -> dict:
    name = user_label(user, as_int(user.get("id")))
    return {"name": name, "detail": _user_detail(user, name, is_self),
            "is_self": is_self, "user_id": as_int(user.get("id"))}


#: Appended to a peer resolved by heuristic (no wire ``encryptedChat*`` link), so
#: an inferred identity is never shown as a wire-confirmed one.
_INFERRED_SUFFIX = " (likely peer — inferred)"


def _mark_inferred(participant: dict, peer: dict) -> dict:
    """Append the inferred marker when the peer was resolved heuristically."""
    if peer.get("matched_by") == "heuristic":
        participant["name"] = f"{participant['name']}{_INFERRED_SUFFIX}"
        participant["detail"] = f"{participant['detail']}{_INFERRED_SUFFIX}"
        participant["inferred"] = True
    return participant


def _peer_participant(peer: dict, directory: dict) -> Optional[dict]:
    """The conversation peer: its known user, else its label (e.g. unknown chat)."""
    user = directory.get(as_int(peer.get("user_id"))) or peer.get("user")
    if user:
        return _mark_inferred(_participant(user, is_self=False), peer)
    label = str(peer.get("label") or "").strip()
    if not label:
        return None
    return _mark_inferred({"name": label, "detail": label, "is_self": False,
                           "user_id": as_int(peer.get("user_id"))}, peer)


def participants_from_structured_users(users: Iterable[dict], peer: Optional[dict] = None,
                                       self_first: bool = True) -> List[dict]:
    """Participant dicts from structured users (+ an optional conversation *peer*).

    With a *peer* the conversation is 1:1: the result is the self user (when
    known) plus the peer (its user, else its ``label``). Without one every
    distinct user is listed. *self_first* moves the self user to the front.
    """
    directory = merge_user_directory(u for u in (users or []) if isinstance(u, dict))
    me = self_user(directory)
    if peer:
        others = [p for p in (_peer_participant(peer, directory),) if p]
    else:
        others = [_participant(u, is_self=False) for u in directory.values() if u is not me]
    mine = [_participant(me, is_self=True)] if me else []
    return mine + others if self_first else others + mine


def user_names_by_id(users: Iterable[dict]) -> dict:
    """``{str(user_id): display name}`` for the structured *users*."""
    directory = merge_user_directory(u for u in (users or []) if isinstance(u, dict))
    return {str(uid): user_label(u, uid) for uid, u in directory.items()}
