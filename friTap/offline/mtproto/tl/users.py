"""Structured Telegram users and the Secret-Chat peer, from decoded TL trees.

:func:`extract_users` flattens every ``user`` constructor found anywhere in a
decoded tree into a JSON-native dict; :func:`merge_user_directory` folds the
users of a whole capture into one directory; :func:`link_secret_chat_peer`
finds the other participant of a Secret Chat from ``encryptedChat*`` objects.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Iterable, List, Optional

from .nodes import TlNode, iter_nodes

#: Constructor names treated as a full user object (old-layer aliases share "user").
USER_CTOR_NAMES = frozenset({"user"})

# Scalar user fields copied verbatim when present.
_SCALAR_FIELDS = ("access_hash", "first_name", "last_name", "username", "phone", "lang_code")

# Objects that may describe a Secret Chat (and its admin/participant ids).
_CHAT_CTORS = frozenset({"encryptedChat", "encryptedChatRequested", "encryptedChatWaiting"})
_CHAT_CARRIERS = frozenset({
    "updateEncryption", "messages.requestEncryption", "messages.acceptEncryption",
})


def _ctor_label(node: TlNode) -> str:
    return node.name if node.ctor_id is None else f"{node.name}#{node.ctor_id:08x}"


def _status(value: Any) -> Optional[dict]:
    """``{kind, was_online|expires}`` of a ``UserStatus`` node."""
    if not isinstance(value, TlNode):
        return None
    kind = value.name[len("userStatus"):].lower() if value.name.startswith("userStatus") else value.name
    status = {"kind": kind or value.name}
    for name in ("was_online", "expires"):
        if isinstance(value.value(name), int):
            status[name] = value.value(name)
    return status


def _flags(node: TlNode) -> List[str]:
    """Names of the set ``flags.N?true`` parameters (only set ones are decoded)."""
    return [f.name for f in node.fields if f.type == "true" and f.value is True]


def _has_photo(value: Any) -> bool:
    return isinstance(value, TlNode) and value.name not in ("", "userProfilePhotoEmpty")


def user_from_node(node: TlNode) -> dict:
    """One ``user`` node as a JSON-native dict (empty fields omitted)."""
    user: Dict[str, Any] = {"id": int(node.value("id", 0) or 0), "ctor": _ctor_label(node),
                            "flags": _flags(node)}
    for name in _SCALAR_FIELDS:
        value = node.value(name)
        if value not in (None, ""):
            user[name] = value
    status = _status(node.value("status"))
    if status:
        user["status"] = status
    user["has_photo"] = _has_photo(node.value("photo"))
    return user


def extract_users(node: Any) -> List[dict]:
    """Every user constructor below *node*, in tree order."""
    return [user_from_node(item) for item in iter_nodes(node)
            if item.name in USER_CTOR_NAMES and isinstance(item.value("id"), int)]


def _merge_user(old: dict, new: dict) -> dict:
    merged = dict(old)
    for key, value in new.items():
        if value not in (None, "", [], {}):
            merged[key] = value
    return merged


def merge_user_directory(users: Iterable[dict]) -> Dict[int, dict]:
    """Fold *users* (oldest first) into ``{id: user}``; newest non-empty field wins."""
    directory: Dict[int, dict] = {}
    for user in users:
        user_id = user.get("id")
        if not user_id:
            continue
        directory[user_id] = _merge_user(directory.get(user_id, {}), user)
    return directory


def self_user(directory: Dict[int, dict]) -> Optional[dict]:
    """The capturing account (the user flagged ``self``), if seen."""
    return next((u for u in directory.values() if "self" in (u.get("flags") or [])), None)


def user_label(user: Optional[dict], user_id: int = 0) -> str:
    """Human label: ``First Last``, else ``@username``, else ``user <id>``."""
    if user:
        name = " ".join(p for p in (user.get("first_name"), user.get("last_name")) if p)
        if name:
            return name
        if user.get("username"):
            return f"@{user['username']}"
        user_id = user_id or user.get("id", 0)
    return f"user {user_id}"


def _int32(value: int) -> int:
    return int(value) & 0xFFFFFFFF


def fingerprint_hex(key_fingerprint: int) -> str:
    """The keylog's fingerprint hex: the little-endian bytes of the TL ``long``."""
    return struct.pack("<q", key_fingerprint).hex()


def _chat_nodes(nodes: Iterable[Any]) -> List[TlNode]:
    found: List[TlNode] = []
    for root in nodes:
        found.extend(n for n in iter_nodes(root) if n.name in _CHAT_CTORS)
    return found


def _match_kind(node: TlNode, fp_hex: str, chat_id: int) -> str:
    """``"key_fingerprint"``/``"chat_id"`` when *node* is the chat, else ``""``."""
    fingerprint = node.value("key_fingerprint")
    if fp_hex and isinstance(fingerprint, int) and fingerprint_hex(fingerprint) == fp_hex.lower():
        return "key_fingerprint"
    node_chat = node.value("id")
    if node_chat is None and isinstance(node.value("peer"), TlNode):
        node_chat = node.value("peer").value("chat_id")
    if chat_id and isinstance(node_chat, int) and _int32(node_chat) == _int32(chat_id):
        return "chat_id"
    return ""


def _pick_peer_id(node: TlNode, self_id: int) -> int:
    ids = [node.value("admin_id"), node.value("participant_id")]
    others = [i for i in ids if isinstance(i, int) and i and i != self_id]
    return others[0] if others else 0


def _fallback_peer(chat_id: int) -> dict:
    return {"user_id": 0, "label": f"peer (unknown, chat_id {chat_id})", "chat_id": chat_id}


def _linked_peer(node: TlNode, matched_by: str, peer_id: int, chat_id: int,
                 directory: Dict[int, dict]) -> dict:
    user = directory.get(peer_id)
    peer = {"user_id": peer_id, "label": user_label(user, peer_id), "chat_id": chat_id,
            "matched_by": matched_by, "source": _ctor_label(node),
            "admin_id": node.value("admin_id"), "participant_id": node.value("participant_id")}
    if user:
        peer["user"] = user
    return peer


def link_secret_chat_peer(nodes: Iterable[Any], fp_hex: str, chat_id: int,
                          directory: Dict[int, dict]) -> dict:
    """The other participant of the Secret Chat with *fp_hex* / *chat_id*.

    Searches *nodes* (decoded trees) for ``encryptedChat*`` objects (also inside
    ``updateEncryption`` and request/accept-encryption calls) matching the
    little-endian key fingerprint or the (sign-normalised) chat id, and maps its
    admin/participant id that is not the capturing account onto *directory*.
    Falls back to ``{"user_id": 0, "label": "peer (unknown, chat_id X)"}``.
    """
    me = self_user(directory)
    self_id = me.get("id", 0) if me else 0
    for node in _chat_nodes(nodes):
        matched_by = _match_kind(node, fp_hex, chat_id)
        peer_id = _pick_peer_id(node, self_id) if matched_by else 0
        if peer_id:
            return _linked_peer(node, matched_by, peer_id, chat_id, directory)
    return _fallback_peer(chat_id)


#: Telegram service accounts that are never a Secret-Chat peer (777000 = "Telegram").
SERVICE_USER_IDS = frozenset({777000})


def _is_peer_candidate(user: dict, self_id: int, service_ids: frozenset) -> bool:
    """A directory user that could be the human on the other end of a Secret Chat."""
    user_id = user.get("id")
    if not user_id or user_id == self_id or user_id in service_ids:
        return False
    return "bot" not in (user.get("flags") or [])


def _candidate_score(user: dict) -> tuple:
    """Rank candidates: a named, reachable contact outranks a bare id."""
    has_name = bool(user.get("first_name") or user.get("last_name") or user.get("username"))
    return (
        1 if "contact" in (user.get("flags") or []) else 0,
        1 if user.get("phone") else 0,
        1 if user.get("access_hash") else 0,
        1 if has_name else 0,
    )


def infer_secret_chat_peer(directory: Dict[int, dict], self_id: int, chat_id: int,
                           service_ids: frozenset = SERVICE_USER_IDS) -> dict:
    """Best-guess Secret-Chat peer when no ``encryptedChat*`` object links the chat.

    The setup handshake (which carries ``admin_id``/``participant_id``) is only on
    the wire when the chat is created/accepted during the capture, so a pre-existing
    chat has nothing to link. As a fallback, pick the best non-self, non-service,
    non-bot user in the directory. The result is tagged ``matched_by="heuristic"``
    with ``confidence`` ``"single"`` (exactly one candidate) or ``"multiple"`` so it
    is never mistaken for a wire-confirmed link. No candidate returns the plain
    :func:`_fallback_peer`.
    """
    candidates = [u for u in directory.values()
                  if _is_peer_candidate(u, self_id, service_ids)]
    if not candidates:
        return _fallback_peer(chat_id)
    user = max(candidates, key=_candidate_score)
    return {"user_id": user["id"], "label": user_label(user, user["id"]),
            "chat_id": chat_id, "matched_by": "heuristic",
            "confidence": "single" if len(candidates) == 1 else "multiple",
            "user": user}


def keylog_peer(peer_user_id: int, chat_id: int, directory: Dict[int, dict]) -> dict:
    """Confident Secret-Chat peer from the keylog's ``peer_user_id`` (4th field).

    The agent read this id from the client's own ``EncryptedChat``, so it holds
    even for chats that predate the capture. Tagged ``matched_by="keylog"``; the
    user profile (name/phone) is attached when it is present in *directory*.
    """
    user = directory.get(peer_user_id)
    peer = {"user_id": peer_user_id, "label": user_label(user, peer_user_id),
            "chat_id": chat_id, "matched_by": "keylog"}
    if user:
        peer["user"] = user
    return peer


def is_chat_related(node: TlNode) -> bool:
    """True when *node* may help :func:`link_secret_chat_peer` (worth retaining)."""
    return node.name in _CHAT_CTORS or node.name in _CHAT_CARRIERS
