"""Parse decrypted MTProto/Telegram TL bytes into displayable chat messages.

The offline MTProto decryptor recovers the inner TL-serialized payload of each
record but historically handed it on as raw bytes, so the TUI could only show
hex. This module turns that blob into human-readable fields (message body, kind,
TL method/type name) by walking the relevant TL (Type Language) constructors,
mirroring the Signal chain (:mod:`friTap.offline.signal.content`).

Everything here is intentionally *tolerant*: it uses a small hand-rolled,
exception-safe TL reader and NEVER raises — malformed, truncated or unknown
input degrades to ``kind="unparsed"`` (or no item at all) so it can never break
decryption. A single transport message may yield SEVERAL parsed messages (e.g.
an ``updates`` or ``msg_container`` body fans out), so the public entry points
return *lists*.

Beyond the original outbound-text extraction this parser now surfaces:

  * ``User`` identities (kind ``"user"``, body ``Evil (@kneebel, +49...)``),
  * inbound chat ``message#`` objects (kind ``"text"``) inside updates and
    ``messages.messages`` / ``messagesSlice`` (getHistory) results,
  * service / container records (kind ``"service"`` / ``"ack"`` / ``"rpc"``)
    tagged with their TL ``method`` name,

and tags EVERY emitted item with a ``method`` (TL operation/type name) and a
``kind`` per the shared TUI contract.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Dict, List, Optional

# --------------------------------------------------------------------------- #
# TL constructor ids
# --------------------------------------------------------------------------- #
#
# A constructor id is the first uint32 (little-endian) of a boxed TL object.
#
# LAYER-VERSIONED WARNING: the message-BEARING constructors (sendMessage and the
# inbound update/Message ids) change their hash whenever the MTProto TL *layer*
# revs (new optional flags shift the CRC32 over the schema line). The ids below
# are pinned to the layer that was DEVICE-VERIFIED for the outbound path; if a
# future Telegram build moves them, parsing degrades to ``kind="unparsed"``
# rather than mis-reading bytes. The CORE CONTAINER ids (msg_container,
# rpc_result, gzip_packed, invokeWithLayer, invokeAfterMsg) and the InputPeer
# ids are stable across layers and safe to hardcode.

# --- Stable core containers (NOT layer-versioned) -------------------------- #
_MSG_CONTAINER = 0x73F1F8DC      # msg_container: count × {msg_id, seqno, len, body}
_RPC_RESULT = 0xF35C6D01         # rpc_result: req_msg_id:long, result:Object
_GZIP_PACKED = 0x3072CFA1        # gzip_packed: packed_data:bytes → zlib → Object
_INVOKE_WITH_LAYER = 0xDA9B0D0D  # invokeWithLayer: layer:int, query:Object
_INVOKE_AFTER_MSG = 0xCB9F372D   # invokeAfterMsg: msg_id:long, query:Object
_MSGS_ACK = 0x62D6B459           # msgs_ack: msg_ids:Vector<long> (no message body)
_VECTOR = 0x1CB5C415             # Vector<T>: count:int, items

# --- Service / system messages (stable; no chat body) ---------------------- #
_PONG = 0x347773C5                  # pong: msg_id:long, ping_id:long
_NEW_SESSION_CREATED = 0x9EC20908   # new_session_created: first_msg_id, unique_id, salt
_FUTURE_SALTS = 0xAE500895          # future_salts: req_msg_id, now, salts:Vector
_BAD_SERVER_SALT = 0xEDAB447B       # bad_server_salt
_BAD_MSG_NOTIFICATION = 0xA7EBA1FE  # bad_msg_notification
_MSGS_STATE_INFO = 0x04DEB57D       # msgs_state_info
_MSG_DETAILED_INFO = 0x276D3EC6     # msg_detailed_info
_MSG_NEW_DETAILED_INFO = 0x809DB6DF  # msg_new_detailed_info
_RPC_ERROR = 0x2144CA19             # rpc_error: error_code:int, error_message:string

# --- RPC result inner types (stable enough to name) ------------------------ #
# These let rpc_result name itself after the INNER result type.
_CONFIG = 0x232D5905                # config (verify per layer; named "config")
_BOOL_TRUE = 0x997275B5
_BOOL_FALSE = 0xBC799737

# --- InputPeer (stable; used to skip the `peer` field in sendMessage) ------ #
# Maps ctor → fixed byte length of the peer body that FOLLOWS the 4-byte ctor,
# or ``None`` for the recursive *FromMessage variants handled specially.
_INPUT_PEER_EMPTY = 0x7F3B18EA            # 0 bytes
_INPUT_PEER_SELF = 0x7DA07EC9             # 0 bytes
_INPUT_PEER_CHAT = 0x35A95CB9             # chat_id:long (8)
_INPUT_PEER_USER = 0xDDE8A54C             # user_id:long + access_hash:long (16) [verified]
_INPUT_PEER_CHANNEL = 0x27BCBBFC          # channel_id:long + access_hash:long (16)
_INPUT_PEER_USER_FROM_MSG = 0xA87B0A1C    # peer:InputPeer + msg_id:int + user_id:long
_INPUT_PEER_CHANNEL_FROM_MSG = 0xBD2A0840  # peer:InputPeer + msg_id:int + channel_id:long

_INPUT_PEER_FIXED_LEN = {
    _INPUT_PEER_EMPTY: 0,
    _INPUT_PEER_SELF: 0,
    _INPUT_PEER_CHAT: 8,
    _INPUT_PEER_USER: 16,
    _INPUT_PEER_CHANNEL: 16,
}

# --- Peer (the OUTPUT peer type; stable) ----------------------------------- #
_PEER_USER = 0x59511722        # peerUser: user_id:long
_PEER_CHAT = 0x36C6019A        # peerChat: chat_id:long
_PEER_CHANNEL = 0xA2A5371E     # peerChannel: channel_id:long
_PEER_FIXED_LEN = {_PEER_USER: 8, _PEER_CHAT: 8, _PEER_CHANNEL: 8}

# --- Outbound message-bearing constructors (LAYER-VERSIONED) --------------- #
# messages.sendMessage layout (device-verified at the captured layer):
#   ctor:int → flags:int32 → peer:InputPeer → [reply_to:InputReplyTo flags.0]
#   → message:string (EXTRACT) → random_id:long → optional fields (ignored).
_SEND_MESSAGE = 0xFEF48F62        # messages.sendMessage [verified]
# Accept these too if encountered (schema-derived, message at the same offset
# right after the peer-and-reply prefix is NOT identical, so only sendMessage
# proper is structurally parsed; the set documents the family).
_SEND_MESSAGE_IDS = {_SEND_MESSAGE}

# inputReplyToMessage (flags.0 of sendMessage); skipped best-effort.
_INPUT_REPLY_TO_MESSAGE = 0x22C0F6D5

# --- Inbound message-bearing constructors (LAYER-VERSIONED, schema-derived) -- #
_UPDATE_SHORT_MESSAGE = 0x313BC7F8       # flags, id, user_id:long, message:string, ...
_UPDATE_SHORT_CHAT_MESSAGE = 0x4D6DEEA5  # flags, id, from_id:long, chat_id:long, message, ...
_UPDATE_SHORT = 0x78D4DEC1               # update:Update, date:int (recurse update)
_UPDATES = 0x74AE4240                    # updates: ... updates:Vector<Update> ...
_UPDATES_COMBINED = 0x725B04C3           # updatesCombined: ... updates:Vector<Update> ...
_UPDATE_NEW_MESSAGE = 0x1F2B0AFD         # message:Message, pts:int, pts_count:int
_UPDATE_NEW_CHANNEL_MESSAGE = 0x62BA04D9  # message:Message, pts:int, pts_count:int
_UPDATE_EDIT_MESSAGE = 0xE40370A3        # message:Message, pts, pts_count
_UPDATE_EDIT_CHANNEL_MESSAGE = 0x1B3B4DF7  # message:Message, pts, pts_count

# messages.messages / messages.messagesSlice / channelMessages (getHistory results)
_MESSAGES_MESSAGES = 0x8C718E87          # messages:Vector<Message>, chats, users
_MESSAGES_SLICE = 0x3A54685E             # flags, count, ..., messages:Vector<Message>, ...
_CHANNEL_MESSAGES = 0xC776BA51           # flags, ..., messages:Vector<Message>, ...

# message#... is flag-heavy and layer-versioned; decoded best-effort only.
# Known recent layer ids for the full `message` constructor.
_MESSAGE_IDS_LAYER_VERSIONED = {
    0x96FDB04A, 0x38116EE0, 0xA66C7EFC, 0x2357BF25, 0x76BEC211, 0x85D6CBE2,
}
# messageService and messageEmpty (so we can recognise + skip cleanly).
_MESSAGE_EMPTY = 0x90A6CA84
_MESSAGE_SERVICE_IDS = {0x2B085862, 0xD3672C00}

# --- User objects (LAYER-VERSIONED) ---------------------------------------- #
# user#... ctor changes per layer; the spec captured 0x31774388. We keep a SET
# of known recent ids AND a tolerant fallback that scans TL-strings after
# id+access_hash regardless of the exact ctor.
_USER_IDS_LAYER_VERSIONED = {
    0x31774388, 0x8F97C628, 0x215C4438, 0x83314FCA, 0xD49A2697, 0x4B46C37E,
}
_USER_EMPTY = 0xD3BC4B7A

# --- UserStatus constructors ("last seen"; stable) ------------------------- #
# Reachable only when no photo (flags.5) sits before status (flags.6) in the
# User layout; see :func:`_parse_user_status`.
_USER_STATUS_EMPTY = 0x09D05049       # userStatusEmpty (no payload)
_USER_STATUS_ONLINE = 0xEDB93949      # userStatusOnline {expires:int}
_USER_STATUS_OFFLINE = 0x008C703F     # userStatusOffline {was_online:int}
_USER_STATUS_RECENTLY = 0x7B197DC8    # userStatusRecently (no payload)
_USER_STATUS_LAST_WEEK = 0x541A1D1A   # userStatusLastWeek (no payload)
_USER_STATUS_LAST_MONTH = 0x65899777  # userStatusLastMonth (no payload)
_USER_STATUS_IDS = {
    _USER_STATUS_EMPTY, _USER_STATUS_ONLINE, _USER_STATUS_OFFLINE,
    _USER_STATUS_RECENTLY, _USER_STATUS_LAST_WEEK, _USER_STATUS_LAST_MONTH,
}

# --- E2E (secret-chat) message-bearing constructors (LAYER-VERSIONED) ------ #
_DECRYPTED_MESSAGE_LAYER = 0x1BE31789    # layer:int, random_bytes, layer:int, in/out seq, msg:Object
# decryptedMessage variants by secret-chat layer: 0x204d3878 (layer 17),
# 0x36b091de (layer 45+), 0x91cc4674 (layer 73+). All share the leading
# flags/random_id/ttl/message prefix the parser extracts.
_DECRYPTED_MESSAGE_IDS = {0x91CC4674, 0x204D3878, 0x36B091DE}


# --------------------------------------------------------------------------- #
# Constructor → name table
# --------------------------------------------------------------------------- #
#
# Centralised map from constructor id to its TL operation/type name. This is the
# single source of truth for the per-item ``method`` tag. Entries marked
# LAYER-VERSIONED carry a hash that may shift between Telegram TL layers; the
# stable container/service ids do not.

_CTOR_NAMES: Dict[int, str] = {
    # Stable core containers
    _MSG_CONTAINER: "msg_container",
    _RPC_RESULT: "rpc_result",
    _GZIP_PACKED: "gzip_packed",
    _INVOKE_WITH_LAYER: "invokeWithLayer",
    _INVOKE_AFTER_MSG: "invokeAfterMsg",
    _VECTOR: "vector",
    # Stable service / system messages
    _MSGS_ACK: "msgs_ack",
    _PONG: "pong",
    _NEW_SESSION_CREATED: "new_session_created",
    _FUTURE_SALTS: "future_salts",
    _BAD_SERVER_SALT: "bad_server_salt",
    _BAD_MSG_NOTIFICATION: "bad_msg_notification",
    _MSGS_STATE_INFO: "msgs_state_info",
    _MSG_DETAILED_INFO: "msg_detailed_info",
    _MSG_NEW_DETAILED_INFO: "msg_new_detailed_info",
    _RPC_ERROR: "rpc_error",
    # RPC inner result types
    _CONFIG: "config",
    _BOOL_TRUE: "boolTrue",
    _BOOL_FALSE: "boolFalse",
    # getHistory result containers
    _MESSAGES_MESSAGES: "messages.messages",
    _MESSAGES_SLICE: "messages.messagesSlice",
    _CHANNEL_MESSAGES: "messages.channelMessages",
    # Outbound (LAYER-VERSIONED)
    _SEND_MESSAGE: "messages.sendMessage",
    # Inbound updates (LAYER-VERSIONED)
    _UPDATE_SHORT_MESSAGE: "updateShortMessage",
    _UPDATE_SHORT_CHAT_MESSAGE: "updateShortChatMessage",
    _UPDATE_SHORT: "updateShort",
    _UPDATES: "updates",
    _UPDATES_COMBINED: "updatesCombined",
    _UPDATE_NEW_MESSAGE: "updateNewMessage",
    _UPDATE_NEW_CHANNEL_MESSAGE: "updateNewChannelMessage",
    _UPDATE_EDIT_MESSAGE: "updateEditMessage",
    _UPDATE_EDIT_CHANNEL_MESSAGE: "updateEditChannelMessage",
    # Misc recognisable types
    _MESSAGE_EMPTY: "messageEmpty",
    _USER_EMPTY: "userEmpty",
}
# User ctors (LAYER-VERSIONED) all map to "user".
for _uid in _USER_IDS_LAYER_VERSIONED:
    _CTOR_NAMES[_uid] = "user"
# Full `message` ctors (LAYER-VERSIONED) all map to "message".
for _mid in _MESSAGE_IDS_LAYER_VERSIONED:
    _CTOR_NAMES[_mid] = "message"
for _mid in _MESSAGE_SERVICE_IDS:
    _CTOR_NAMES[_mid] = "messageService"


def ctor_name(ctor: int) -> str:
    """Return the TL operation/type name for *ctor*, or a hex fallback."""
    return _CTOR_NAMES.get(ctor, f"0x{ctor:08x}")


# Service constructors that, when met as a top-level / rpc_result object, are
# tagged kind="service" (acks get the more specific "ack" kind).
_SERVICE_CTORS = {
    _PONG, _NEW_SESSION_CREATED, _FUTURE_SALTS, _BAD_SERVER_SALT,
    _BAD_MSG_NOTIFICATION, _MSGS_STATE_INFO, _MSG_DETAILED_INFO,
    _MSG_NEW_DETAILED_INFO, _RPC_ERROR,
}


@dataclass
class ParsedMtprotoMessage:
    """A decoded MTProto message ready for display (mirrors ParsedContent)."""

    kind: str = "unparsed"
    body: str = ""
    timestamp: int = 0
    sender_id: int = 0
    peer_id: int = 0
    has_media: bool = False
    method: str = ""
    # User-only enrichment (empty/0 for non-user items). ``user_id`` mirrors
    # ``sender_id`` for users but is kept explicit so dedup can key on it without
    # confusing it with a chat sender. ``relationship`` is a sorted tuple of tags
    # like ("self",), ("contact", "mutual"). ``last_seen`` is a display suffix.
    user_id: int = 0
    relationship: tuple = ()
    last_seen: str = ""


class _Reader:
    """Exception-safe little-endian TL reader.

    Every accessor raises :class:`_TLError` on truncation; callers catch it and
    degrade to ``kind="unparsed"`` rather than letting it escape.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    @property
    def pos(self) -> int:
        return self._pos

    def seek(self, pos: int) -> None:
        self._pos = pos

    def _take(self, n: int) -> bytes:
        if n < 0 or self._pos + n > len(self._data):
            raise _TLError("read past end of TL buffer")
        chunk = self._data[self._pos:self._pos + n]
        self._pos += n
        return chunk

    def peek_uint32(self) -> int:
        if self._pos + 4 > len(self._data):
            raise _TLError("peek past end of TL buffer")
        return struct.unpack_from("<I", self._data, self._pos)[0]

    def uint32(self) -> int:
        return struct.unpack_from("<I", self._take(4))[0]

    def int32(self) -> int:
        return struct.unpack_from("<i", self._take(4))[0]

    def int64(self) -> int:
        return struct.unpack_from("<q", self._take(8))[0]

    def skip(self, n: int) -> None:
        self._take(n)

    def tl_bytes(self) -> bytes:
        """Read a TL string/bytes value (the length-prefixed, padded form)."""
        first = self._take(1)[0]
        if first < 254:
            length = first
            header = 1
        else:
            length = int.from_bytes(self._take(3), "little")
            header = 4
        data = self._take(length)
        # Pad so (header + length) is a multiple of 4.
        pad = (-(header + length)) % 4
        self._take(pad)
        return data

    def tl_string(self) -> str:
        return self.tl_bytes().decode("utf-8", "replace")


class _TLError(Exception):
    """Internal truncation/format error; never escapes the public parsers."""


# --------------------------------------------------------------------------- #
# Peer / reply-to skipping helpers
# --------------------------------------------------------------------------- #

def _skip_input_peer(reader: _Reader) -> None:
    """Consume one ``InputPeer`` from *reader*.

    Raises :class:`_TLError` for an unknown constructor so the caller can bail
    out of structured parsing for that record (per spec).
    """
    ctor = reader.uint32()
    if ctor in _INPUT_PEER_FIXED_LEN:
        reader.skip(_INPUT_PEER_FIXED_LEN[ctor])
        return
    if ctor in (_INPUT_PEER_USER_FROM_MSG, _INPUT_PEER_CHANNEL_FROM_MSG):
        _skip_input_peer(reader)   # peer:InputPeer
        reader.int32()             # msg_id:int
        reader.int64()             # user_id / channel_id:long
        return
    raise _TLError(f"unknown InputPeer constructor 0x{ctor:08x}")


def _read_peer(reader: _Reader) -> int:
    """Read a (stable) ``Peer`` and return its id, or raise on unknown ctor."""
    ctor = reader.uint32()
    if ctor in _PEER_FIXED_LEN:
        return reader.int64()
    raise _TLError(f"unknown Peer constructor 0x{ctor:08x}")


def _skip_input_reply_to(reader: _Reader) -> None:
    """Best-effort skip of an ``InputReplyTo`` (only inputReplyToMessage known)."""
    ctor = reader.uint32()
    if ctor != _INPUT_REPLY_TO_MESSAGE:
        raise _TLError(f"unknown InputReplyTo constructor 0x{ctor:08x}")
    flags2 = reader.uint32()
    reader.int32()  # reply_to_msg_id:int
    if flags2 & (1 << 0):
        reader.int32()              # top_msg_id:int
    if flags2 & (1 << 1):
        _skip_input_peer(reader)    # reply_to_peer_id:InputPeer
    if flags2 & (1 << 2):
        reader.tl_bytes()           # quote_text:string
    if flags2 & (1 << 3):
        _skip_vector_unknown(reader)  # quote_entities:Vector<MessageEntity>
    if flags2 & (1 << 4):
        reader.int32()              # quote_offset:int


def _skip_vector_unknown(reader: _Reader) -> None:
    """Best-effort skip of a ``Vector`` whose element layout is unknown.

    We cannot size unknown elements, so any Vector here forces a bail-out: the
    only safe action is to raise and let the record degrade to ``unparsed``.
    """
    ctor = reader.uint32()
    if ctor != _VECTOR:
        raise _TLError("expected Vector constructor")
    raise _TLError("cannot skip Vector of unknown element type")


# --------------------------------------------------------------------------- #
# Outbound: messages.sendMessage
# --------------------------------------------------------------------------- #

def _parse_send_message(reader: _Reader) -> Optional[ParsedMtprotoMessage]:
    """Parse a ``messages.sendMessage`` body (ctor already consumed)."""
    flags = reader.uint32()
    _skip_input_peer(reader)                  # peer:InputPeer
    if flags & (1 << 0):
        _skip_input_reply_to(reader)          # reply_to:InputReplyTo (flags.0)
    body = reader.tl_string()                 # message:string (EXTRACT)
    reader.int64()                            # random_id:long (sender is unknown
    #                                           for outbound, so left as 0)
    return ParsedMtprotoMessage(
        kind="text", body=body, method="messages.sendMessage",
    )


# --------------------------------------------------------------------------- #
# Inbound: updates / short messages
# --------------------------------------------------------------------------- #

def _parse_update_short_message(reader: _Reader) -> Optional[ParsedMtprotoMessage]:
    """updateShortMessage: flags, id, user_id:long, message:string, ..."""
    reader.uint32()                 # flags:int
    reader.int32()                  # id:int
    user_id = reader.int64()        # user_id:long
    body = reader.tl_string()       # message:string
    return ParsedMtprotoMessage(
        kind="text", body=body, peer_id=user_id, method="updateShortMessage",
    )


def _parse_update_short_chat_message(reader: _Reader) -> Optional[ParsedMtprotoMessage]:
    """updateShortChatMessage: flags, id, from_id:long, chat_id:long, message, ..."""
    reader.uint32()                 # flags:int
    reader.int32()                  # id:int
    from_id = reader.int64()        # from_id:long
    chat_id = reader.int64()        # chat_id:long
    body = reader.tl_string()       # message:string
    return ParsedMtprotoMessage(
        kind="text", body=body, sender_id=from_id, peer_id=chat_id,
        method="updateShortChatMessage",
    )


# --------------------------------------------------------------------------- #
# Inbound: full `message#` object (flag-heavy, layer-versioned, best-effort)
# --------------------------------------------------------------------------- #

def _parse_message_object(reader: _Reader, ctor: int) -> Optional[ParsedMtprotoMessage]:
    """Best-effort decode of a layer-versioned ``message`` object.

    The full ``message`` constructor is flag-heavy and shifts between layers, so
    we make a CONSERVATIVE attempt at the modern common prefix and degrade to
    ``kind="unparsed"`` (rather than mis-reading) on any inconsistency. Layout
    attempted (recent layers, message# ctor already consumed):

        flags:int32, [flags2:int32 when flags.34? — NOT present in classic],
        id:int32, [from_id:Peer  flags.8],
        peer_id:Peer, [saved_peer / fwd / via_bot ... — flag-gated, skipped],
        date:int32 (after the peer block), message:string ...

    Because the exact offset of ``message:string`` depends on many flag-gated
    fields we cannot size blindly, we use a tolerant heuristic: after reading the
    fixed leading fields we SCAN forward for the first plausible TL-string and
    take it as the body. Anything inconsistent → unparsed.
    """
    # messageEmpty / messageService carry no chat text.
    if ctor == _MESSAGE_EMPTY or ctor in _MESSAGE_SERVICE_IDS:
        return None

    flags = reader.uint32()                 # flags:int32
    msg_id = reader.int32()                  # id:int32
    sender_id = 0
    peer_id = 0
    timestamp = 0

    # from_id present when flags.8 set (Peer).
    try:
        if flags & (1 << 8):
            sender_id = _read_peer(reader)   # from_id:Peer
        # peer_id:Peer is mandatory.
        peer_id = _read_peer(reader)
    except _TLError:
        # Peer layout did not line up; fall back to a tolerant text scan from
        # just after id (drop what we tentatively consumed of the peers).
        return _scan_message_text(reader, msg_id, sender_id, peer_id, timestamp)

    # The remaining prefix (fwd_from / via_bot_id / reply_to / date) is heavily
    # flag-gated and layer-versioned. Rather than decode each, scan for the body.
    return _scan_message_text(reader, msg_id, sender_id, peer_id, timestamp)


# Max byte offsets to probe when scanning a message object for its body string.
# The body follows the peer/date prefix, so it is always near the front; bounding
# the scan keeps a large/garbage object from costing O(n²) probes.
_MESSAGE_SCAN_WINDOW = 512


def _scan_message_text(
    reader: _Reader, msg_id: int, sender_id: int, peer_id: int, timestamp: int,
) -> Optional[ParsedMtprotoMessage]:
    """Scan forward for the first plausible printable TL-string = message body.

    Conservative: only accepts a string that decodes to mostly-printable text of
    a reasonable length; otherwise returns ``unparsed`` (no mis-read body).
    """
    start = reader.pos
    # `date:int32` sits right before `message:string` in every layer of the full
    # message ctor; if the next 4 bytes look like a plausible unix-ish timestamp
    # take them as the date so sender/peer/date are correlated.
    try:
        maybe_date = reader.peek_uint32()
    except _TLError:
        maybe_date = 0
    if 1_000_000_000 <= maybe_date <= 4_000_000_000:
        reader.uint32()
        timestamp = maybe_date

    # Try to read the message string at the current position first.
    candidate = _try_read_text(reader)
    if candidate is not None:
        return ParsedMtprotoMessage(
            kind="text", body=candidate, sender_id=sender_id, peer_id=peer_id,
            timestamp=timestamp, method="message",
        )

    # Otherwise byte-scan for the first plausible TL-string. The body sits within
    # a handful of fields of the start (peer/date), so bound the scan to a small
    # window: this caps the worst-case O(n²) per-message cost on large/garbage
    # objects without missing a real body near the front.
    reader.seek(start)
    data_len = reader.remaining + reader.pos
    scan_end = min(data_len - 1, start + _MESSAGE_SCAN_WINDOW)
    for off in range(start, max(start, scan_end)):
        reader.seek(off)
        candidate = _try_read_text(reader)
        if candidate is not None:
            return ParsedMtprotoMessage(
                kind="text", body=candidate, sender_id=sender_id,
                peer_id=peer_id, timestamp=timestamp, method="message",
            )
    return ParsedMtprotoMessage(
        kind="unparsed", body="", sender_id=sender_id, peer_id=peer_id,
        method="message",
    )


def _try_read_text(reader: _Reader) -> Optional[str]:
    """Try to read a TL-string at the current pos and validate it as chat text.

    Returns the decoded text if it looks like a genuine message string (1+ chars,
    decodes cleanly to mostly-printable UTF-8), else ``None`` (pos is left
    undefined; callers reseek).
    """
    try:
        raw = reader.tl_bytes()
    except _TLError:
        return None
    if not raw or len(raw) > 4096:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    if printable / len(text) < 0.8:
        return None
    return text


# --------------------------------------------------------------------------- #
# User objects → kind="user"
# --------------------------------------------------------------------------- #

# user# flag bits (recent layer; LAYER-VERSIONED). Used by the flag-driven
# decoder; if the flags do not line up we fall back to the tolerant TL-string
# scan.
_USER_FLAG_HAS_ACCESS_HASH = 1 << 0
_USER_FLAG_HAS_FIRST_NAME = 1 << 1
_USER_FLAG_HAS_LAST_NAME = 1 << 2
_USER_FLAG_HAS_USERNAME = 1 << 3
_USER_FLAG_HAS_PHONE = 1 << 4
_USER_FLAG_HAS_PHOTO = 1 << 5    # UserProfilePhoto (complex) — BAIL after if set
_USER_FLAG_HAS_STATUS = 1 << 6   # UserStatus (last seen) — reachable iff no photo

# Relationship flag bits (device-verified): these annotate the body with tags.
_USER_FLAG_SELF = 1 << 10
_USER_FLAG_CONTACT = 1 << 11
_USER_FLAG_MUTUAL_CONTACT = 1 << 12
_USER_FLAG_DELETED = 1 << 13
_USER_FLAG_BOT = 1 << 14


def _user_relationship_tags(flags: int) -> tuple:
    """Return the relationship tags carried by *flags*, in display order.

    Verified bits: .10 self, .11 contact, .12 mutual_contact, .13 deleted,
    .14 bot. ``mutual`` implies ``contact`` so only ``mutual`` is shown when both
    are set, to keep the body terse.
    """
    tags = []
    if flags & _USER_FLAG_SELF:
        tags.append("you")
    if flags & _USER_FLAG_CONTACT:
        tags.append("contact")
    if flags & _USER_FLAG_MUTUAL_CONTACT:
        tags.append("mutual")
    if flags & _USER_FLAG_BOT:
        tags.append("bot")
    if flags & _USER_FLAG_DELETED:
        tags.append("deleted")
    return tuple(tags)


def _parse_user_status(reader: _Reader) -> str:
    """Read a ``UserStatus`` (ctor + payload) and return a "last seen" suffix.

    Returns "" when the next bytes are not a recognised UserStatus ctor (the
    position is restored so the caller does not desync). Never raises.
    """
    start = reader.pos
    try:
        ctor = reader.uint32()
    except _TLError:
        return ""
    if ctor == _USER_STATUS_ONLINE:
        try:
            expires = reader.int32()
        except _TLError:
            return "online"
        return f"online (until {expires})"
    if ctor == _USER_STATUS_OFFLINE:
        try:
            was_online = reader.int32()
        except _TLError:
            return "last seen recently"
        return f"last seen {was_online}"
    if ctor == _USER_STATUS_RECENTLY:
        return "last seen recently"
    if ctor == _USER_STATUS_LAST_WEEK:
        return "last seen within a week"
    if ctor == _USER_STATUS_LAST_MONTH:
        return "last seen within a month"
    if ctor == _USER_STATUS_EMPTY:
        return ""
    # Not a UserStatus we recognise: rewind so we don't consume foreign bytes.
    reader.seek(start)
    return ""


def _format_user_rich(
    first: str, last: str, username: str, phone: str,
    tags: tuple, last_seen: str,
) -> str:
    """Compose the rich, readable user summary used by the flag-driven decoder.

    Examples::

        db Forscher (@dbf, +4915738796832) [contact] [mutual] · last seen recently
        Evil kneebel (+4915155912510) [you]

    The ``@username`` is included only when present, the phone always shows a
    leading ``+``, empty parts are omitted, relationship tags are appended in
    ``[ ]`` and a UserStatus "last seen" is appended after ``·`` when known.
    """
    base = _format_user(first, last, username, phone)
    parts = [base] if base else []
    for tag in tags:
        parts.append(f"[{tag}]")
    body = " ".join(parts).strip()
    if last_seen:
        body = f"{body} · {last_seen}".strip(" ·") if body else last_seen
    return body


def _format_user(
    first: str, last: str, username: str, phone: str,
) -> str:
    """Compose a readable user summary, omitting missing parts.

    Examples: ``Evil (@kneebel, +4915155912510)``, ``db Forscher (+49...)``,
    ``(@kneebel)``.
    """
    name = " ".join(p for p in (first, last) if p).strip()
    extras = []
    if username:
        extras.append(f"@{username}")
    if phone:
        extras.append("+" + phone.lstrip("+"))
    suffix = f" ({', '.join(extras)})" if extras else ""
    return (name + suffix).strip()


def _classify_user_string(value: str) -> str:
    """Classify a stray TL-string from a User into phone/username/name."""
    stripped = value.strip()
    if not stripped:
        return "skip"
    digits = stripped.lstrip("+")
    if digits and all(ch.isdigit() for ch in digits) and len(digits) >= 6:
        return "phone"
    if " " not in stripped and all(
        ch.isalnum() or ch == "_" for ch in stripped
    ) and any(ch.isalpha() for ch in stripped):
        return "username"
    return "name"


def _parse_user_tolerant(reader: _Reader, ctor: int) -> Optional[ParsedMtprotoMessage]:
    """Parse a ``User`` object into a kind="user" item.

    First tries a PRECISE FLAG-DRIVEN read of the device-verified layer layout::

        flags:#  flags2:#  id:long  [access_hash:long .0]
        [first_name:string .1] [last_name:string .2] [username:string .3]
        [phone:string .4] [photo .5] [status:UserStatus .6] ...

    Fields appear strictly in ascending flag-bit order. Relationship bits
    (.10 self, .11 contact, .12 mutual, .13 deleted, .14 bot) annotate the body.
    If photo (.5) is present the following UserProfilePhoto struct is complex, so
    we parse identity up to phone and BAIL tolerantly (no status). When the flags
    produce an implausible result we fall back to a TOLERANT scan that reads
    consecutive TL-strings after id(+access_hash) and classifies each.
    """
    start = reader.pos
    # --- Attempt 1: precise flag-driven (device-verified layer layout) ------ #
    try:
        flags = reader.uint32()
        reader.uint32()            # flags2:int32 (recent layers)
        user_id = reader.int64()   # id:long
        if flags & _USER_FLAG_HAS_ACCESS_HASH:
            reader.int64()         # access_hash:long
        first = last = username = phone = ""
        if flags & _USER_FLAG_HAS_FIRST_NAME:
            first = reader.tl_string()
        if flags & _USER_FLAG_HAS_LAST_NAME:
            last = reader.tl_string()
        if flags & _USER_FLAG_HAS_USERNAME:
            username = reader.tl_string()
        if flags & _USER_FLAG_HAS_PHONE:
            phone = reader.tl_string()

        tags = _user_relationship_tags(flags)
        last_seen = ""
        # UserStatus (flags.6) is only reachable when no UserProfilePhoto
        # (flags.5) precedes it; that struct is complex, so we BAIL on photo.
        if (flags & _USER_FLAG_HAS_STATUS) and not (flags & _USER_FLAG_HAS_PHOTO):
            last_seen = _parse_user_status(reader)

        if _user_fields_plausible(first, last, username, phone):
            body = _format_user_rich(first, last, username, phone, tags, last_seen)
            if body:
                return ParsedMtprotoMessage(
                    kind="user", body=body, sender_id=user_id, user_id=user_id,
                    relationship=tags, last_seen=last_seen, method="user",
                )
    except _TLError:
        pass

    # --- Attempt 2: tolerant TL-string scan --------------------------------- #
    reader.seek(start)
    try:
        flags = reader.uint32()    # flags:int32
        reader.uint32()            # flags2:int32 (assume present; recent layers)
        user_id = reader.int64()   # id:long
        # access_hash rides under flag bit 0; gating it (like Attempt 1) avoids
        # eating 8 bytes of first_name for users that carry no access_hash.
        if flags & _USER_FLAG_HAS_ACCESS_HASH:
            reader.int64()         # access_hash:long
    except _TLError:
        return None

    first = last = username = phone = ""
    strings: List[str] = []
    for _ in range(8):  # bounded; a User has at most a handful of strings
        if reader.remaining <= 0:
            break
        try:
            value = reader.tl_string()
        except _TLError:
            break
        if value.strip():
            strings.append(value)
        # phone is unambiguous; once seen we have the trailing field.
        if phone:
            break
        if _classify_user_string(value) == "phone":
            phone = value
            break

    # Classify the non-phone strings: the first 1-2 are the name (first/last);
    # a trailing alnum/no-space token before the phone is the username. This
    # matches the spec's tolerant heuristic without trusting layer-versioned
    # flag bit positions.
    # ``phone``, when set, was already captured separately above and is excluded
    # from ``non_phone`` by the comprehension; the remaining tokens are name parts.
    non_phone = [s for s in strings if _classify_user_string(s) != "phone"]
    if len(non_phone) >= 1:
        first = non_phone[0]
    if len(non_phone) == 2:
        # second token: username if alnum/no-space, else last_name
        second = non_phone[1]
        if _classify_user_string(second) == "username":
            username = second
        else:
            last = second
    elif len(non_phone) >= 3:
        last = non_phone[1]
        if _classify_user_string(non_phone[2]) == "username":
            username = non_phone[2]
    body = _format_user(first, last, username, phone)
    if not body:
        return None
    return ParsedMtprotoMessage(
        kind="user", body=body, sender_id=user_id, user_id=user_id, method="user",
    )


def _user_fields_plausible(
    first: str, last: str, username: str, phone: str,
) -> bool:
    """Sanity-check flag-driven User fields before trusting them."""
    for name in (first, last):
        if name and not _mostly_printable(name):
            return False
    if username and (" " in username or not _mostly_printable(username)):
        return False
    if phone:
        digits = phone.lstrip("+")
        if not digits or not all(ch.isdigit() for ch in digits):
            return False
    return True


def _mostly_printable(text: str) -> bool:
    if not text:
        return True
    printable = sum(1 for ch in text if ch.isprintable())
    return printable / len(text) >= 0.8


# --------------------------------------------------------------------------- #
# Vector dispatch (Vector<User>, Vector<Message>, Vector<Update>)
# --------------------------------------------------------------------------- #

# Upper bound on a TL element count (Vector / msg_container). A hostile or
# misaligned record can decode a wildly large count; cap it so the parse loop
# can't spin on attacker-controlled input.
_MAX_TL_COUNT = 100_000

# Upper bound on the INFLATED size of a gzip_packed body. The packed bytes are
# peer-supplied wire data, so an unbounded zlib.decompress() is a decompression
# bomb: a few KB can expand to gigabytes and OOM the offline driver. 16 MiB is
# far above any real Telegram TL payload while keeping a hostile record cheap.
_MAX_GZIP_INFLATE = 16 * 1024 * 1024


def _parse_typed_vector(
    reader: _Reader, out: List[ParsedMtprotoMessage], depth: int,
) -> bool:
    """Parse a ``Vector`` of boxed objects, dispatching each element.

    Returns ``True`` if it consumed a vector. Each element is itself a boxed TL
    object (constructor + body), so we can recurse via :func:`_dispatch_object`.
    Tolerant: a single bad element ends the loop rather than discarding earlier
    siblings.
    """
    count = reader.int32()
    if count < 0 or count > _MAX_TL_COUNT:
        raise _TLError("implausible vector count")
    for _ in range(count):
        if reader.remaining < 4:
            break
        elem_ctor = reader.uint32()
        try:
            _dispatch_object(reader, elem_ctor, out, depth + 1)
        except _TLError:
            # Element layout unknown / misaligned: cannot size the rest of the
            # vector safely, so stop here (keep what we already collected).
            break
    return True


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #

def _dispatch(reader: _Reader, out: List[ParsedMtprotoMessage], depth: int) -> None:
    """Read ONE boxed TL object (ctor + body) and append any items to *out*."""
    if depth > 16:
        raise _TLError("TL recursion too deep")
    ctor = reader.uint32()
    _dispatch_object(reader, ctor, out, depth)


def _dispatch_object(
    reader: _Reader, ctor: int, out: List[ParsedMtprotoMessage], depth: int,
) -> None:
    """Dispatch a boxed object whose constructor *ctor* was already read.

    Recurses into the stable containers and the inbound update / getHistory
    wrappers; surfaces User identities, inbound/outbound text, and service
    records. A malformed branch raises :class:`_TLError`, swallowed upstream.
    """
    if depth > 16:
        raise _TLError("TL recursion too deep")

    if ctor == _MSG_CONTAINER:
        count = reader.int32()
        if count < 0 or count > _MAX_TL_COUNT:
            raise _TLError("implausible msg_container count")
        for _ in range(count):
            reader.int64()                  # msg_id:long
            reader.int32()                  # seqno:int
            length = reader.int32()         # len:int
            body = reader._take(length)     # body (raw TL object)
            _parse_into(body, out, depth + 1)
        return

    if ctor == _RPC_RESULT:
        reader.int64()                      # req_msg_id:long
        _parse_rpc_result(reader, out, depth + 1)
        return

    if ctor == _GZIP_PACKED:
        packed = reader.tl_bytes()
        # Bounded inflate: decompress at most _MAX_GZIP_INFLATE bytes. If the
        # decompressor still has unconsumed input, the output would exceed the
        # cap, so this is a (possibly malicious) oversized/bomb payload — reject
        # rather than inflating it unbounded into memory.
        try:
            dobj = zlib.decompressobj()
            inflated = dobj.decompress(packed, _MAX_GZIP_INFLATE)
            if dobj.unconsumed_tail:
                raise _TLError(
                    f"gzip_packed inflate exceeds {_MAX_GZIP_INFLATE} bytes"
                )
        except zlib.error as exc:
            raise _TLError("gzip_packed inflate failed") from exc
        _parse_into(inflated, out, depth + 1)
        return

    if ctor == _INVOKE_WITH_LAYER:
        reader.int32()                      # layer:int
        _dispatch(reader, out, depth + 1)   # query:Object
        return

    if ctor == _INVOKE_AFTER_MSG:
        reader.int64()                      # msg_id:long
        _dispatch(reader, out, depth + 1)   # query:Object
        return

    if ctor in _SEND_MESSAGE_IDS:
        msg = _parse_send_message(reader)
        if msg is not None:
            out.append(msg)
        return

    # --- Service / system records: tag and stop --------------------------- #
    if ctor == _MSGS_ACK:
        out.append(ParsedMtprotoMessage(kind="ack", body="", method="msgs_ack"))
        return
    if ctor in _SERVICE_CTORS:
        out.append(ParsedMtprotoMessage(
            kind="service", body="", method=ctor_name(ctor),
        ))
        return

    # --- Updates ---------------------------------------------------------- #
    if ctor == _UPDATE_SHORT_MESSAGE:
        msg = _parse_update_short_message(reader)
        if msg is not None:
            out.append(msg)
        return

    if ctor == _UPDATE_SHORT_CHAT_MESSAGE:
        msg = _parse_update_short_chat_message(reader)
        if msg is not None:
            out.append(msg)
        return

    if ctor == _UPDATE_SHORT:
        _dispatch(reader, out, depth + 1)   # update:Update (single), date:int after
        return

    if ctor in (
        _UPDATE_NEW_MESSAGE, _UPDATE_NEW_CHANNEL_MESSAGE,
        _UPDATE_EDIT_MESSAGE, _UPDATE_EDIT_CHANNEL_MESSAGE,
    ):
        inner = reader.uint32()             # message:Message ctor
        msg = _parse_message_object(reader, inner)
        if msg is not None:
            out.append(msg)
        return

    # updates / updatesCombined: ... updates:Vector<Update>, users:Vector<User>,
    # chats:Vector<Chat>, date:int, seq:int. The leading layout differs between
    # the two and is flag-free, but the trailing Vectors of Chat are not safely
    # skippable. We SCAN for the embedded Vector<Update> and Vector<User> by
    # searching for vector constructors, parsing each tolerantly.
    if ctor in (_UPDATES, _UPDATES_COMBINED):
        _scan_for_vectors(reader, out, depth + 1)
        return

    # getHistory results: messages:Vector<Message>, then chats/users vectors.
    if ctor in (_MESSAGES_MESSAGES, _MESSAGES_SLICE, _CHANNEL_MESSAGES):
        _scan_for_vectors(reader, out, depth + 1)
        return

    # A bare User object (rpc_result of users.getUsers element, etc.).
    if ctor in _USER_IDS_LAYER_VERSIONED:
        msg = _parse_user_tolerant(reader, ctor)
        if msg is not None:
            out.append(msg)
        return

    # A full `message` object encountered directly.
    if ctor in _MESSAGE_IDS_LAYER_VERSIONED:
        msg = _parse_message_object(reader, ctor)
        if msg is not None:
            out.append(msg)
        return

    # A bare Vector (e.g. rpc_result = Vector<User>).
    if ctor == _VECTOR:
        _parse_typed_vector(reader, out, depth)
        return

    # An unknown / non-message constructor: not an error, just nothing here.
    raise _TLError(f"no message in constructor 0x{ctor:08x}")


def _parse_rpc_result(
    reader: _Reader, out: List[ParsedMtprotoMessage], depth: int,
) -> None:
    """Parse the ``result:Object`` of an rpc_result, naming the method.

    The result's inner constructor names the rpc_result (e.g. a ``config`` ctor
    → method "config"; a ``Vector<User>`` / ``messages.messages`` → the users /
    messages method). We peek the inner ctor for the name, then dispatch it so
    Users / Messages inside are surfaced. If the inner object produced no items
    of its own we still emit a single kind="rpc" marker carrying the method, so
    the TUI can show that an RPC reply arrived.
    """
    try:
        inner_ctor = reader.peek_uint32()
    except _TLError:
        return
    method = _rpc_method_name(inner_ctor)
    before = len(out)
    result_start = reader.pos
    try:
        _dispatch(reader, out, depth)
    except _TLError:
        pass
    if len(out) == before:
        # The inner result type is unknown / not structurally decodable at this
        # layer (e.g. a contacts/peerSettings container that embeds the users we
        # care about in trailing Vectors). Tolerantly SCAN the result bytes for
        # Vector<User>/Vector<Message> so identities are still surfaced.
        scan = _Reader(reader._data)
        scan.seek(result_start)
        _scan_for_vectors(scan, out, depth + 1)
    if len(out) == before:
        # Still nothing: emit a single rpc marker with the method name.
        out.append(ParsedMtprotoMessage(kind="rpc", body="", method=method))
    else:
        # Stamp the rpc method onto produced items that lack a richer method.
        for item in out[before:]:
            if not item.method or item.method.startswith("0x"):
                item.method = method


def _rpc_method_name(inner_ctor: int) -> str:
    """Map an rpc_result's inner constructor to a method name."""
    if inner_ctor == _VECTOR:
        return "users"          # most boxed Vector results in this corpus are users
    if inner_ctor in _USER_IDS_LAYER_VERSIONED:
        return "users.getUsers"
    if inner_ctor == _CONFIG:
        return "config"
    if inner_ctor in (_MESSAGES_MESSAGES, _MESSAGES_SLICE, _CHANNEL_MESSAGES):
        return ctor_name(inner_ctor)
    name = _CTOR_NAMES.get(inner_ctor)
    if name:
        return name
    return "rpc_result"


def _scan_for_vectors(
    reader: _Reader, out: List[ParsedMtprotoMessage], depth: int,
) -> None:
    """Tolerantly surface Users / Messages from a wrapper with embedded Vectors.

    The exact field layout of ``updates`` / ``messages.messages`` is
    layer-versioned and carries Vectors of un-sizeable Chat objects, so rather
    than decode the full structure we SCAN the remaining bytes for ``Vector``
    constructors and try to parse each as a Vector of boxed objects (Users,
    Messages, Updates). Conservative: an element that does not line up ends that
    vector. This never raises (it is the wrapper's terminal handler).
    """
    data = reader._data
    base = reader.pos
    n = len(data)
    off = base
    while off + 4 <= n:
        if struct.unpack_from("<I", data, off)[0] == _VECTOR:
            sub = _Reader(data[off + 4:])
            try:
                _parse_typed_vector(sub, out, depth)
            except _TLError:
                off += 4
                continue
            # Advance past the bytes this vector consumed so its element data is
            # not re-scanned (and its elements re-emitted) as further "vectors".
            off += 4 + sub.pos
            continue
        off += 4


def _parse_into(tl_bytes: bytes, out: List[ParsedMtprotoMessage], depth: int) -> None:
    """Dispatch one TL object, swallowing a single object's parse failure.

    Container children are parsed independently: one undecodable child must not
    discard its siblings, so failures here are local (degrade to nothing for
    that child) rather than propagated.
    """
    try:
        _dispatch(_Reader(tl_bytes), out, depth)
    except _TLError:
        return
    except Exception:  # pragma: no cover - defensive belt-and-braces
        return


def parse_mtproto_message(tl_bytes: bytes) -> List[ParsedMtprotoMessage]:
    """Parse a decrypted cloud MTProto record's TL payload into messages.

    Tolerant by contract: returns ``[]`` when nothing readable is found and
    NEVER raises. A single record may yield several messages (a container fans
    out), so the result is a list.
    """
    if not tl_bytes:
        return []
    out: List[ParsedMtprotoMessage] = []
    _parse_into(tl_bytes, out, 0)
    return out


# --------------------------------------------------------------------------- #
# E2E (secret-chat)
# --------------------------------------------------------------------------- #

# decryptedMessage media detection (see _decrypted_has_media).
_DECRYPTED_MSG_L17 = 0x204D3878       # layer-17 form: no flags; media is a boxed object
_DECRYPTED_MSG_MEDIA_EMPTY = 0x089F5C4A  # decryptedMessageMediaEmpty (no media)
_DECRYPTED_MSG_MEDIA_FLAG = 1 << 9    # decryptedMessage.media flag bit (layer 45+/73+)


def _decrypted_has_media(reader: _Reader, ctor: int, flags: int) -> bool:
    """Report whether a ``decryptedMessage`` carries non-empty media.

    A ``decryptedMessage`` ALWAYS has trailing bytes after ``message`` (a media
    object, or further layer-versioned fields), so ``reader.remaining > 0`` would
    flag every text message as media. Instead:

      * layer-17 (``0x204d3878``, no flags): ``media`` is the next boxed
        ``DecryptedMessageMedia`` — peek it and treat
        ``decryptedMessageMediaEmpty`` as no media;
      * layer-45+/73+ (flag-bearing): ``media`` rides under flag bit 9.
    """
    if ctor == _DECRYPTED_MSG_L17:
        try:
            return reader.peek_uint32() != _DECRYPTED_MSG_MEDIA_EMPTY
        except _TLError:
            return False
    return bool(flags & _DECRYPTED_MSG_MEDIA_FLAG)


def _parse_decrypted_message(reader: _Reader, ctor: int) -> Optional[ParsedMtprotoMessage]:
    """decryptedMessage (ctor already consumed): reach ``message:string``.

    The layout's leading fields are layer-versioned: the layer-17 form
    (``0x204d3878``) is ``random_id:long, ttl:int, message:string, …`` while the
    layer-45+/73+ forms (``0x36b091de``/``0x91cc4674``) prepend a ``flags:int``.
    We extract ``message`` and report media presence via :func:`_decrypted_has_media`.
    """
    flags = 0
    if ctor != _DECRYPTED_MSG_L17:
        flags = reader.uint32()  # flags:int (layer 45+/73+ only)
    reader.int64()              # random_id:long
    reader.int32()              # ttl:int
    body = reader.tl_string()   # message:string (EXTRACT)
    return ParsedMtprotoMessage(
        kind="text", body=body, has_media=_decrypted_has_media(reader, ctor, flags),
        method="decryptedMessage",
    )


def parse_secret_chat_message(tl_bytes: bytes) -> List[ParsedMtprotoMessage]:
    """Parse a decrypted secret-chat E2E payload into messages.

    Reaches ``message:string`` via ``decryptedMessageLayer`` →
    ``decryptedMessage``. Tolerant: returns ``[]`` on any failure, never raises.
    """
    if not tl_bytes:
        return []
    try:
        reader = _Reader(tl_bytes)
        ctor = reader.uint32()
        if ctor == _DECRYPTED_MESSAGE_LAYER:
            reader.tl_bytes()       # random_bytes:bytes
            reader.int32()          # layer:int
            reader.int32()          # in_seq_no:int
            reader.int32()          # out_seq_no:int
            ctor = reader.uint32()  # message:DecryptedMessage ctor
        if ctor in _DECRYPTED_MESSAGE_IDS:
            msg = _parse_decrypted_message(reader, ctor)
            return [msg] if msg is not None else []
    except _TLError:
        return []
    except Exception:  # pragma: no cover - defensive
        return []
    return []
