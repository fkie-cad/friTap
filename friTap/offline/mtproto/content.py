"""Parse decrypted MTProto/Telegram TL bytes into displayable chat messages.

Walks the relevant TL constructors to extract body, kind and TL ``method``
name, mirroring :mod:`friTap.offline.signal.content`. The parser never raises:
malformed, truncated or unknown input degrades to ``kind="unparsed"`` (or no
item). One transport message can fan out into several items (``updates``,
``msg_container``), so the entry points return lists. Emitted kinds include
``user``, ``text`` (outbound and inbound ``message#``), ``service``, ``ack``
and ``rpc``; every item carries a ``method`` and ``kind``.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Dict, List, Optional

from friTap.parsers.decompress import (  # noqa: F401  (inflate_bounded: re-export)
    InflateLimitError,
    inflate_bounded,
    inflate_bounded_checked,
)

from .tl.decoder import (
    BOOL_FALSE_ID,
    BOOL_TRUE_ID,
    GZIP_PACKED_ID,
    GZIP_TRUNCATED_NOTE,
    MAX_INFLATE,
    MSG_CONTAINER_ID,
    RPC_RESULT_ID,
    VECTOR_ID,
    decode_tl_cached,
)
from .tl.nodes import TlNode, iter_nodes

# A constructor id is the first uint32 (little-endian) of a boxed TL object.
#
# Layer-versioned ids: the message-bearing constructors (sendMessage and the
# inbound update/Message ids) change hash whenever the TL layer revs (new
# optional flags shift the CRC32 over the schema line). They are pinned to the
# device-verified layer; a moved id degrades to ``kind="unparsed"`` instead of
# mis-reading bytes. The core container ids and the InputPeer ids are stable.

# Stable core containers.
_MSG_CONTAINER = MSG_CONTAINER_ID  # msg_container: count × {msg_id, seqno, len, body}
_RPC_RESULT = RPC_RESULT_ID       # rpc_result: req_msg_id:long, result:Object
_GZIP_PACKED = GZIP_PACKED_ID     # gzip_packed: packed_data:bytes → zlib → Object
_INVOKE_WITH_LAYER = 0xDA9B0D0D  # invokeWithLayer: layer:int, query:Object
_INVOKE_AFTER_MSG = 0xCB9F372D   # invokeAfterMsg: msg_id:long, query:Object
_MSGS_ACK = 0x62D6B459           # msgs_ack: msg_ids:Vector<long> (no message body)
_VECTOR = VECTOR_ID              # Vector<T>: count:int, items

# Service / system messages (stable; no chat body).
_PONG = 0x347773C5                  # pong: msg_id:long, ping_id:long
_NEW_SESSION_CREATED = 0x9EC20908   # new_session_created: first_msg_id, unique_id, salt
_FUTURE_SALTS = 0xAE500895          # future_salts: req_msg_id, now, salts:Vector
_BAD_SERVER_SALT = 0xEDAB447B       # bad_server_salt
_BAD_MSG_NOTIFICATION = 0xA7EBA1FE  # bad_msg_notification
_MSGS_STATE_INFO = 0x04DEB57D       # msgs_state_info
_MSG_DETAILED_INFO = 0x276D3EC6     # msg_detailed_info
_MSG_NEW_DETAILED_INFO = 0x809DB6DF  # msg_new_detailed_info
_RPC_ERROR = 0x2144CA19             # rpc_error: error_code:int, error_message:string

# RPC result inner types, so rpc_result can be named after its inner result.
_CONFIG = 0x232D5905                # config (verify per layer; named "config")
_BOOL_TRUE = BOOL_TRUE_ID
_BOOL_FALSE = BOOL_FALSE_ID

# InputPeer (stable; used to skip the `peer` field in sendMessage).
# Maps ctor → fixed byte length of the peer body that follows the 4-byte ctor,
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

# Peer (the output peer type; stable).
_PEER_USER = 0x59511722        # peerUser: user_id:long
_PEER_CHAT = 0x36C6019A        # peerChat: chat_id:long
_PEER_CHANNEL = 0xA2A5371E     # peerChannel: channel_id:long
_PEER_FIXED_LEN = {_PEER_USER: 8, _PEER_CHAT: 8, _PEER_CHANNEL: 8}

# Outbound message-bearing constructors (layer-versioned).
# messages.sendMessage layout (device-verified at the captured layer):
#   ctor:int → flags:int32 → peer:InputPeer → [reply_to:InputReplyTo flags.0]
#   → message:string → random_id:long → optional fields (ignored).
_SEND_MESSAGE = 0xFEF48F62        # messages.sendMessage [verified]
# Other send* variants do not share the message offset, so only sendMessage
# proper is structurally parsed.
_SEND_MESSAGE_IDS = {_SEND_MESSAGE}

# inputReplyToMessage (flags.0 of sendMessage); skipped best-effort.
_INPUT_REPLY_TO_MESSAGE = 0x22C0F6D5

# Inbound message-bearing constructors (layer-versioned, schema-derived).
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
# messageService and messageEmpty, recognised so they can be skipped cleanly.
_MESSAGE_EMPTY = 0x90A6CA84
_MESSAGE_SERVICE_IDS = {0x2B085862, 0xD3672C00}

# User objects (layer-versioned). Known recent ids plus a tolerant fallback that
# scans TL strings after id+access_hash regardless of the exact ctor.
# 0xB1B8CC83 is the current (TDLib telegram_api.tl) user, verified on a real
# Android capture: its flags/flags2/id/... layout parses via Attempt 1 below.
_USER_IDS_LAYER_VERSIONED = {
    0x31774388, 0x8F97C628, 0x215C4438, 0x83314FCA, 0xD49A2697, 0x4B46C37E,
    0xB1B8CC83,
}
_USER_EMPTY = 0xD3BC4B7A

# UserStatus constructors ("last seen"; stable).
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

# E2E (secret-chat) message-bearing constructors (layer-versioned).
_DECRYPTED_MESSAGE_LAYER = 0x1BE31789    # layer:int, random_bytes, layer:int, in/out seq, msg:Object
# decryptedMessage variants by secret-chat layer: 0x204d3878 (layer 17),
# 0x36b091de (layer 45+), 0x91cc4674 (layer 73+). All share the leading
# flags/random_id/ttl/message prefix the parser extracts.
_DECRYPTED_MESSAGE_IDS = {0x91CC4674, 0x204D3878, 0x36B091DE}


# Constructor id → TL operation/type name; single source of the ``method`` tag.

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
    # Outbound (layer-versioned)
    _SEND_MESSAGE: "messages.sendMessage",
    # Inbound updates (layer-versioned)
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
for _uid in _USER_IDS_LAYER_VERSIONED:
    _CTOR_NAMES[_uid] = "user"
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
    # Secret-Chat only: the sender-chosen ``random_id:long`` (signed TL int64)
    # identifying one E2E message; 0 for cloud messages / unknown.
    random_id: int = 0
    # TL ``out`` flag: the local user authored the message. Set even when it
    # arrives in a server->client echo (e.g. ``updateNewMessage``).
    outgoing: bool = False
    # Analyst-facing caveat, e.g. :data:`~.tl.decoder.GZIP_TRUNCATED_NOTE` when
    # the item was decoded from a truncated gzip_packed body; "" when none.
    note: str = ""


def _add_note(items: List[ParsedMtprotoMessage], note: str) -> None:
    """Append *note* to every item's ``note`` (``"; "``-joined, never twice)."""
    for item in items:
        if not item.note:
            item.note = note
        elif note not in item.note:
            item.note = f"{item.note}; {note}"


class _ParseBudget:
    """Per-message work and inflate budget shared by every reader of one parse.

    A hostile record can force superlinear work (Vector ctor ids at every
    offset, nested wrappers, gzip_packed bombs). One budget is shared by all
    sub-readers of a :func:`parse_mtproto_message` call to bound total cost.
    """

    __slots__ = ("work_left", "inflate_left", "gzip_depth", "gzip_truncated")

    def __init__(self) -> None:
        self.work_left = _MAX_PARSE_WORK
        self.inflate_left = _MAX_INFLATE_TOTAL
        self.gzip_depth = 0
        # gzip_packed bodies of this parse whose gzip stream was truncated.
        self.gzip_truncated = 0

    @property
    def exhausted(self) -> bool:
        return self.work_left <= 0

    def charge(self, units: int = 1) -> None:
        """Account *units* of work; raise :class:`_BudgetExceeded` when spent."""
        self.work_left -= units
        if self.work_left < 0:
            raise _BudgetExceeded("per-message TL parse budget exhausted")


class _Reader:
    """Exception-safe little-endian TL reader over ``data[pos:end]``.

    Accessors raise :class:`_TLError` on truncation; callers degrade to
    ``kind="unparsed"``. Sub-readers share the buffer (no copy) and budget.
    """

    def __init__(self, data: bytes, pos: int = 0, end: Optional[int] = None,
                 budget: Optional["_ParseBudget"] = None) -> None:
        self._data = data
        self._pos = pos
        self._end = len(data) if end is None else end
        self.budget = budget if budget is not None else _ParseBudget()

    def sub(self, pos: int, end: Optional[int] = None) -> "_Reader":
        """A reader over ``data[pos:end]`` sharing this reader's buffer and budget."""
        return _Reader(self._data, pos, self._end if end is None else end, self.budget)

    @property
    def remaining(self) -> int:
        return self._end - self._pos

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def end(self) -> int:
        return self._end

    def seek(self, pos: int) -> None:
        self._pos = pos

    def _take(self, n: int) -> bytes:
        if n < 0 or self._pos + n > self._end:
            raise _TLError("read past end of TL buffer")
        chunk = self._data[self._pos:self._pos + n]
        self._pos += n
        return chunk

    def peek_uint32(self) -> int:
        if self._pos + 4 > self._end:
            raise _TLError("peek past end of TL buffer")
        return struct.unpack_from("<I", self._data, self._pos)[0]

    def uint32(self) -> int:
        return struct.unpack_from("<I", self._take(4))[0]

    def int32(self) -> int:
        return struct.unpack_from("<i", self._take(4))[0]

    def int64(self) -> int:
        return struct.unpack_from("<q", self._take(8))[0]

    def skip(self, n: int) -> None:
        if n < 0 or self._pos + n > self._end:
            raise _TLError("read past end of TL buffer")
        self._pos += n

    def _tl_bytes_span(self) -> tuple:
        """``(start, length)`` of a TL string/bytes value; cursor moves past it."""
        first = self._take(1)[0]
        if first < 254:
            length = first
            header = 1
        else:
            length = int.from_bytes(self._take(3), "little")
            header = 4
        start = self._pos
        # Pad so (header + length) is a multiple of 4.
        self.skip(length + (-(header + length)) % 4)
        return start, length

    def tl_bytes(self) -> bytes:
        """Read a TL string/bytes value (the length-prefixed, padded form)."""
        start, length = self._tl_bytes_span()
        return self._data[start:start + length]

    def tl_string(self) -> str:
        return self.tl_bytes().decode("utf-8", "replace")


class _TLError(Exception):
    """Internal truncation/format error; never escapes the public parsers."""


class _BudgetExceeded(_TLError):
    """The per-message work budget is spent; parsing winds down cleanly."""


# Max nesting of the recursive ``inputPeer*FromMessage`` variants. Real peers
# nest once; a hostile chain must not recurse until the interpreter limit.
_MAX_INPUT_PEER_DEPTH = 3


def _skip_input_peer(reader: _Reader, depth: int = 0) -> None:
    """Consume one ``InputPeer``; raise :class:`_TLError` on an unknown ctor or
    a FromMessage chain deeper than :data:`_MAX_INPUT_PEER_DEPTH`."""
    if depth > _MAX_INPUT_PEER_DEPTH:
        raise _TLError("InputPeer nested too deep")
    ctor = reader.uint32()
    if ctor in _INPUT_PEER_FIXED_LEN:
        reader.skip(_INPUT_PEER_FIXED_LEN[ctor])
        return
    if ctor in (_INPUT_PEER_USER_FROM_MSG, _INPUT_PEER_CHANNEL_FROM_MSG):
        _skip_input_peer(reader, depth + 1)   # peer:InputPeer
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
    """Always raise: unknown elements cannot be sized, so the record degrades."""
    ctor = reader.uint32()
    if ctor != _VECTOR:
        raise _TLError("expected Vector constructor")
    raise _TLError("cannot skip Vector of unknown element type")


def _parse_send_message(reader: _Reader) -> Optional[ParsedMtprotoMessage]:
    """Parse a ``messages.sendMessage`` body (ctor already consumed)."""
    flags = reader.uint32()
    _skip_input_peer(reader)                  # peer:InputPeer
    if flags & (1 << 0):
        _skip_input_reply_to(reader)          # reply_to:InputReplyTo (flags.0)
    body = reader.tl_string()                 # message:string
    reader.int64()                            # random_id:long
    return ParsedMtprotoMessage(
        kind="text", body=body, method="messages.sendMessage",
    )


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


def _parse_message_object(reader: _Reader, ctor: int) -> Optional[ParsedMtprotoMessage]:
    """Best-effort decode of a layer-versioned ``message`` object (ctor consumed).

    Layout attempted::

        flags:int32, id:int32, [from_id:Peer flags.8], peer_id:Peer,
        [saved_peer / fwd / via_bot ... flag-gated, skipped],
        date:int32, message:string ...

    The body offset depends on flag-gated fields, so after the fixed prefix the
    first plausible TL string is taken as the body; otherwise ``unparsed``.
    """
    # messageEmpty / messageService carry no chat text.
    if ctor == _MESSAGE_EMPTY or ctor in _MESSAGE_SERVICE_IDS:
        return None

    flags = reader.uint32()                 # flags:int32
    msg_id = reader.int32()                  # id:int32
    sender_id = 0
    peer_id = 0
    timestamp = 0

    try:
        if flags & (1 << 8):
            sender_id = _read_peer(reader)   # from_id:Peer
        peer_id = _read_peer(reader)
    except _TLError:
        return _scan_message_text(reader, msg_id, sender_id, peer_id, timestamp)

    return _scan_message_text(reader, msg_id, sender_id, peer_id, timestamp)


# Max byte offsets to probe when scanning a message object for its body string.
# The body follows the peer/date prefix, so it is always near the front; bounding
# the scan keeps a large/garbage object from costing O(n²) probes.
_MESSAGE_SCAN_WINDOW = 512


def _scan_message_text(
    reader: _Reader, msg_id: int, sender_id: int, peer_id: int, timestamp: int,
) -> Optional[ParsedMtprotoMessage]:
    """Take the first mostly-printable TL string ahead as the body, else ``unparsed``."""
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

    candidate = _try_read_text(reader)
    if candidate is not None:
        return ParsedMtprotoMessage(
            kind="text", body=candidate, sender_id=sender_id, peer_id=peer_id,
            timestamp=timestamp, method="message",
        )

    # Byte-scan bounded by _MESSAGE_SCAN_WINDOW to cap the O(n²) worst case.
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
    """Read a TL string at pos and return it if it is mostly-printable UTF-8.

    Returns ``None`` otherwise; pos is then undefined and callers reseek.
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


# user# flag bits (recent layer; layer-versioned). If they do not line up the
# decoder falls back to the tolerant TL-string scan.
_USER_FLAG_HAS_ACCESS_HASH = 1 << 0
_USER_FLAG_HAS_FIRST_NAME = 1 << 1
_USER_FLAG_HAS_LAST_NAME = 1 << 2
_USER_FLAG_HAS_USERNAME = 1 << 3
_USER_FLAG_HAS_PHONE = 1 << 4
_USER_FLAG_HAS_PHOTO = 1 << 5    # UserProfilePhoto (complex); stop after phone if set
_USER_FLAG_HAS_STATUS = 1 << 6   # UserStatus (last seen); reachable iff no photo

# Relationship flag bits (device-verified): these annotate the body with tags.
_USER_FLAG_SELF = 1 << 10
_USER_FLAG_CONTACT = 1 << 11
_USER_FLAG_MUTUAL_CONTACT = 1 << 12
_USER_FLAG_DELETED = 1 << 13
_USER_FLAG_BOT = 1 << 14


def _user_relationship_tags(flags: int) -> tuple:
    """Return the relationship tags carried by *flags*, in display order."""
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
    """Read a ``UserStatus`` and return a "last seen" suffix; never raises.

    Returns "" and restores the position when the ctor is not a UserStatus.
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
    reader.seek(start)
    return ""


def _format_user_rich(
    first: str, last: str, username: str, phone: str,
    tags: tuple, last_seen: str,
) -> str:
    """Compose the user summary with ``[tag]`` suffixes and ``· last_seen``.

    Example: ``db Forscher (@dbf, +49157...) [contact] [mutual] · last seen recently``.
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
    """Compose ``first last (@username, +phone)``, omitting missing parts."""
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

    First a flag-driven read of the device-verified layout::

        flags:#  flags2:#  id:long  [access_hash:long .0]
        [first_name:string .1] [last_name:string .2] [username:string .3]
        [phone:string .4] [photo .5] [status:UserStatus .6] ...

    Fields follow ascending flag-bit order; bits .10-.14 are relationship tags.
    A photo (.5) stops the read after phone. An implausible result falls back to
    classifying consecutive TL strings after id(+access_hash).
    """
    start = reader.pos
    # Attempt 1: flag-driven.
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
        # UserStatus (.6) is reachable only when no UserProfilePhoto (.5) precedes it.
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

    # Attempt 2: tolerant TL-string scan.
    reader.seek(start)
    try:
        flags = reader.uint32()    # flags:int32
        reader.uint32()            # flags2:int32 (assume present; recent layers)
        user_id = reader.int64()   # id:long
        # Gate access_hash on flag bit 0, else 8 bytes of first_name are eaten.
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
        # phone is the trailing field.
        if phone:
            break
        if _classify_user_string(value) == "phone":
            phone = value
            break

    # The first 1-2 non-phone strings are the name; a trailing alnum/no-space
    # token is the username. Does not trust layer-versioned flag bits.
    non_phone = [s for s in strings if _classify_user_string(s) != "phone"]
    if len(non_phone) >= 1:
        first = non_phone[0]
    if len(non_phone) == 2:
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


# Cap on a TL element count (Vector / msg_container) so a hostile or misaligned
# count cannot spin the parse loop.
_MAX_TL_COUNT = 100_000

# Upper bound on the inflated size of a gzip_packed body (decompression-bomb
# guard; see :data:`~.tl.decoder.MAX_INFLATE`).
_MAX_GZIP_INFLATE = MAX_INFLATE

# Total inflated bytes across all gzip_packed bodies of one message: vectors,
# containers and nesting would otherwise multiply the per-body cap.
_MAX_INFLATE_TOTAL = 2 * MAX_INFLATE

# gzip_packed nested inside gzip_packed is legal but never deeper than this.
_MAX_GZIP_DEPTH = 2

# Per-message work budget (objects dispatched + Vector candidates probed). Far
# above any real record, it caps the tolerant hand path on hostile payloads.
_MAX_PARSE_WORK = 200_000


def _parse_typed_vector(
    reader: _Reader, out: List[ParsedMtprotoMessage], depth: int,
) -> bool:
    """Parse a ``Vector`` of boxed objects, dispatching each element.

    Returns ``True``. A bad element ends the loop but keeps earlier siblings.
    """
    count = reader.int32()
    if count < 0 or count > _MAX_TL_COUNT:
        raise _TLError("implausible vector count")
    for _ in range(count):
        if reader.remaining < 4 or reader.budget.exhausted:
            break
        elem_ctor = reader.uint32()
        try:
            _dispatch_object(reader, elem_ctor, out, depth + 1)
        except _TLError:
            # The rest of the vector cannot be sized safely.
            break
    return True


def _dispatch(reader: _Reader, out: List[ParsedMtprotoMessage], depth: int) -> None:
    """Read one boxed TL object (ctor + body) and append any items to *out*."""
    if depth > 16:
        raise _TLError("TL recursion too deep")
    ctor = reader.uint32()
    _dispatch_object(reader, ctor, out, depth)


def _dispatch_object(
    reader: _Reader, ctor: int, out: List[ParsedMtprotoMessage], depth: int,
) -> None:
    """Dispatch a boxed object whose *ctor* was already read; append items to *out*.

    Raises :class:`_TLError` on a malformed branch or a non-message ctor.
    """
    if depth > 16:
        raise _TLError("TL recursion too deep")
    reader.budget.charge()

    if ctor == _MSG_CONTAINER:
        _parse_container(reader, out, depth)
        return

    if ctor == _RPC_RESULT:
        reader.int64()                      # req_msg_id:long
        _parse_rpc_result(reader, out, depth + 1)
        return

    if ctor == _GZIP_PACKED:
        _parse_gzip_packed(reader, out, depth)
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

    # Service / system records: tag and stop.
    if ctor == _MSGS_ACK:
        out.append(ParsedMtprotoMessage(kind="ack", body="", method="msgs_ack"))
        return
    if ctor in _SERVICE_CTORS:
        out.append(ParsedMtprotoMessage(
            kind="service", body="", method=ctor_name(ctor),
        ))
        return

    # Inbound message-bearing updates and message# objects are emitted by
    # _inbound_messages_from_schema; the hand emitters (_parse_update_short_*,
    # _parse_message_object) are not dispatched here.

    # updates / updatesCombined: ... updates:Vector<Update>, users:Vector<User>,
    # chats:Vector<Chat>, date:int, seq:int. Chat vectors are not safely
    # skippable, so scan for the embedded Vector constructors instead.
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

    # A bare Vector (e.g. rpc_result = Vector<User>).
    if ctor == _VECTOR:
        _parse_typed_vector(reader, out, depth)
        return

    # Unknown / non-message constructor: nothing to emit.
    raise _TLError(f"no message in constructor 0x{ctor:08x}")


def _parse_container(
    reader: _Reader, out: List[ParsedMtprotoMessage], depth: int,
) -> None:
    """msg_container body (ctor consumed): count × {msg_id, seqno, len, body}.

    Each child body is parsed through an offset-bounded sub-reader (no copy).
    """
    count = reader.int32()
    if count < 0 or count > _MAX_TL_COUNT:
        raise _TLError("implausible msg_container count")
    for _ in range(count):
        reader.int64()                      # msg_id:long
        reader.int32()                      # seqno:int
        length = reader.int32()             # len:int
        start = reader.pos
        reader.skip(length)                 # body (raw TL object)
        _parse_region(reader.sub(start, start + length), out, depth + 1)


def _inflate_gzip_packed(reader: _Reader, packed: bytes) -> tuple[bytes, bool]:
    """Bounded inflate of one gzip_packed body: ``(inflated, complete)``.

    Inflates at most ``min(_MAX_GZIP_INFLATE, budget left)`` bytes and rejects
    larger (bomb) bodies. *complete* is False for a truncated gzip stream.
    """
    budget = reader.budget
    limit = min(_MAX_GZIP_INFLATE, budget.inflate_left)
    if limit <= 0:
        raise _TLError("gzip_packed total inflate budget exhausted")
    try:
        # Auto-detects the zlib or gzip header (Telegram sends real gzip).
        inflated, complete = inflate_bounded_checked(packed, limit)
    except InflateLimitError:
        # The rejected attempt still inflated *limit* bytes: charge them, so a
        # stream of oversized bodies cannot re-burn the same work forever.
        budget.inflate_left -= limit
        raise _TLError(f"gzip_packed inflate exceeds {limit} bytes") from None
    except zlib.error as exc:
        raise _TLError("gzip_packed inflate failed") from exc
    budget.inflate_left -= len(inflated)
    return inflated, complete


def _parse_gzip_packed(
    reader: _Reader, out: List[ParsedMtprotoMessage], depth: int,
) -> None:
    """gzip_packed body (ctor consumed): inflate and parse the inner object.

    Items decoded from a truncated gzip stream keep their partial content but
    carry :data:`~.tl.decoder.GZIP_TRUNCATED_NOTE`.
    """
    packed = reader.tl_bytes()
    budget = reader.budget
    if budget.gzip_depth >= _MAX_GZIP_DEPTH:
        raise _TLError("gzip_packed nested too deep")
    inflated, complete = _inflate_gzip_packed(reader, packed)
    before = len(out)
    budget.gzip_depth += 1
    try:
        _parse_region(_Reader(inflated, budget=budget), out, depth + 1)
    finally:
        budget.gzip_depth -= 1
    if not complete:
        budget.gzip_truncated += 1
        _add_note(out[before:], GZIP_TRUNCATED_NOTE)


def _parse_rpc_result(
    reader: _Reader, out: List[ParsedMtprotoMessage], depth: int,
) -> None:
    """Parse the ``result:Object`` of an rpc_result, named after its inner ctor.

    Falls back to a vector scan, then to a single kind="rpc" marker, so every
    RPC reply shows up.
    """
    try:
        inner_ctor = reader.peek_uint32()
    except _TLError:
        return
    method = _rpc_method_name(inner_ctor)
    before = len(out)
    truncated_before = reader.budget.gzip_truncated
    result_start = reader.pos
    try:
        _dispatch(reader, out, depth)
    except _TLError:
        pass
    if len(out) == before:
        # Unknown inner type (e.g. contacts/peerSettings with users in trailing
        # Vectors): scan for Vector<User>/Vector<Message>.
        scan = reader.sub(result_start)
        _scan_for_vectors(scan, out, depth + 1)
        reader.seek(max(reader.pos, scan.pos))
    if len(out) == before:
        truncated = reader.budget.gzip_truncated > truncated_before
        out.append(ParsedMtprotoMessage(
            kind="rpc", body="", method=method,
            note=GZIP_TRUNCATED_NOTE if truncated else "",
        ))
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


_VECTOR_BYTES = struct.pack("<I", _VECTOR)


def _next_vector_candidate(reader: _Reader, off: int, align_base: int) -> int:
    """Offset of the next 4-aligned (from *align_base*) Vector ctor id, or -1.

    Uses ``bytes.find`` to jump between matches instead of probing every
    offset, and charges one unit of work per aligned candidate.
    """
    data, end = reader._data, reader.end
    while True:
        hit = data.find(_VECTOR_BYTES, off, end)
        if hit < 0:
            return -1
        if (hit - align_base) % 4 == 0:
            reader.budget.charge()
            return hit
        off = hit + 1


def _scan_for_vectors(
    reader: _Reader, out: List[ParsedMtprotoMessage], depth: int,
) -> None:
    """Scan the remaining bytes for ``Vector`` ctors and parse each as boxed objects.

    Used for layer-versioned wrappers with un-sizeable Chat vectors; never raises.
    Leaves the reader at its end so an enclosing scan does not re-scan the same
    bytes; every candidate is charged to the per-message budget.
    """
    base = reader.pos
    off = align_base = base
    while not reader.budget.exhausted:
        try:
            off = _next_vector_candidate(reader, off, align_base)
        except _BudgetExceeded:
            break
        if off < 0:
            break
        sub = reader.sub(off + 4)
        try:
            _parse_typed_vector(sub, out, depth)
        except _TLError:
            off += 4
            continue
        # Advance past the bytes this vector consumed so its element data is
        # not re-scanned (and its elements re-emitted) as further "vectors".
        off = align_base = sub.pos
    reader.seek(reader.end)


def _parse_region(
    reader: _Reader, out: List[ParsedMtprotoMessage], depth: int,
) -> None:
    """Dispatch one TL object in *reader*'s region, swallowing its failure.

    Failures stay local so one undecodable container child keeps its siblings.
    """
    try:
        _dispatch(reader, out, depth)
    except _TLError:
        return
    except Exception:  # pragma: no cover - defensive belt-and-braces
        return


def _parse_into(tl_bytes: bytes, out: List[ParsedMtprotoMessage], depth: int) -> None:
    """Dispatch one TL object from *tl_bytes* with a fresh per-message budget."""
    _parse_region(_Reader(bytes(tl_bytes)), out, depth)


# Inbound chat text lives in flag-heavy, layer-versioned ``message#``
# constructors, so it comes from the schema decoder
# (:func:`~.tl.decoder.decode_tl_cached`) rather than the hand path above.

#: Schema predicate names (as :class:`TlNode.name` exposes them, without the
#: ``#id`` suffix) whose ``message:string`` is chat text. Others that carry a
#: ``message:string`` must not surface as chat: ``draftMessage`` (sent on every
#: keystroke on another device and in every getDialogs reply),
#: ``updateServiceNotification``, ``sponsoredMessage``, ``botInlineMessage*``,
#: ``messageActionCustomAction``, ``help.inviteText``, ``businessChatLink``.
_CHAT_MESSAGE_CTORS = frozenset({
    "message",
    "updateShortMessage",
    "updateShortChatMessage",
})


def _peer_node_id(peer) -> int:
    """First of a ``Peer`` node's user/chat/channel id fields, or 0."""
    if not isinstance(peer, TlNode):
        return 0
    for name in ("user_id", "chat_id", "channel_id"):
        value = peer.value(name)
        if isinstance(value, int):
            return value
    return 0


def _message_node_ids(node: TlNode) -> tuple:
    """Return ``(sender_id, peer_id)`` for a message-bearing constructor.

    ``updateShortMessage`` names only the private peer (``user_id``): an
    outgoing one (TL ``out``) has no explicit sender, an incoming one was sent
    by that peer. ``peer_id`` is the peer either way, so conversation keying
    does not depend on the direction.
    """
    if node.name == "updateShortMessage":
        user_id = node.value("user_id", 0)
        if node.value("out") is True:
            return 0, user_id
        return user_id, user_id
    if node.name == "updateShortChatMessage":
        return node.value("from_id", 0), node.value("chat_id", 0)
    return _peer_node_id(node.value("from_id")), _peer_node_id(node.value("peer_id"))


def _node_to_text(node: TlNode) -> Optional[ParsedMtprotoMessage]:
    """Project a message-bearing constructor node onto a text display record."""
    if node.kind != "constructor" or node.name not in _CHAT_MESSAGE_CTORS:
        return None
    text = node.value("message")
    if not isinstance(text, str) or not text:
        return None
    sender_id, peer_id = _message_node_ids(node)
    media = node.field("media")
    has_media = media is not None and getattr(media.value, "name", "") != "messageMediaEmpty"
    date = node.value("date", 0)
    return ParsedMtprotoMessage(
        kind="text", body=text, method=node.name,
        sender_id=sender_id, peer_id=peer_id,
        timestamp=date if isinstance(date, int) else 0, has_media=has_media,
        outgoing=node.value("out") is True,
    )


def _is_truncated_gzip(node: TlNode) -> bool:
    """True for a ``gzip_packed`` node decoded from a truncated gzip stream."""
    return node.kind == "gzip" and GZIP_TRUNCATED_NOTE in node.note


def _ids_under_truncated_gzip(root) -> set:
    """``id()`` of every node decoded from a truncated ``gzip_packed`` body."""
    return {
        id(inner)
        for gzip_node in iter_nodes(root) if _is_truncated_gzip(gzip_node)
        for inner in iter_nodes(gzip_node)
    }


def _inbound_messages_from_schema(tl_bytes: bytes) -> List[ParsedMtprotoMessage]:
    """Extract inbound chat text by walking the schema-decoded TL tree.

    Text decoded from a truncated gzip_packed body carries
    :data:`~.tl.decoder.GZIP_TRUNCATED_NOTE`.
    """
    try:
        root = decode_tl_cached(bytes(tl_bytes), "mtproto")
    except Exception:  # pragma: no cover - decode_tl_cached is itself tolerant
        return []
    partial_ids = _ids_under_truncated_gzip(root)
    out: List[ParsedMtprotoMessage] = []
    for node in iter_nodes(root):
        msg = _node_to_text(node)
        if msg is not None:
            if id(node) in partial_ids:
                msg.note = GZIP_TRUNCATED_NOTE
            out.append(msg)
    return out


def parse_mtproto_message(tl_bytes: bytes) -> List[ParsedMtprotoMessage]:
    """Parse a decrypted cloud MTProto record's TL payload into messages.

    Never raises; returns ``[]`` when nothing is readable. The hand path emits
    outbound sendMessage, users, service and container records; inbound text
    comes from :func:`_inbound_messages_from_schema`.
    """
    if not tl_bytes:
        return []
    out: List[ParsedMtprotoMessage] = []
    _parse_into(tl_bytes, out, 0)
    out.extend(_inbound_messages_from_schema(tl_bytes))
    return out


# decryptedMessage media detection (see _decrypted_has_media).
_DECRYPTED_MSG_L17 = 0x204D3878       # layer-17 form: no flags; media is a boxed object
_DECRYPTED_MSG_MEDIA_EMPTY = 0x089F5C4A  # decryptedMessageMediaEmpty (no media)
_DECRYPTED_MSG_MEDIA_FLAG = 1 << 9    # decryptedMessage.media flag bit (layer 45+/73+)


def _decrypted_has_media(reader: _Reader, ctor: int, flags: int) -> bool:
    """Report whether a ``decryptedMessage`` carries non-empty media.

    Trailing bytes always follow ``message``, so ``remaining > 0`` is no signal.
    Layer 17 (``0x204d3878``): peek the boxed media, empty ctor means none.
    Layer 45+/73+: media rides under flag bit 9.
    """
    if ctor == _DECRYPTED_MSG_L17:
        try:
            return reader.peek_uint32() != _DECRYPTED_MSG_MEDIA_EMPTY
        except _TLError:
            return False
    return bool(flags & _DECRYPTED_MSG_MEDIA_FLAG)


# decryptedMessageService: a secret-chat control message (no text) carrying one
# DecryptedMessageAction. Every id below was verified by recomputing the TL
# constructor hash (CRC32 of the normalised secret_api.tl schema line).
_DECRYPTED_MSG_SERVICE = 0x73164160   # layer 17+: random_id:long action:DecryptedMessageAction
_DECRYPTED_MSG_SERVICE8 = 0xAA48327D  # layer 8: random_id:long random_bytes:bytes action
_DECRYPTED_MESSAGE_SERVICE_IDS = {_DECRYPTED_MSG_SERVICE, _DECRYPTED_MSG_SERVICE8}

_DECRYPTED_ACTION_NAMES: Dict[int, str] = {
    0xA1733AEC: "decryptedMessageActionSetMessageTTL",
    0x0C4F40BE: "decryptedMessageActionReadMessages",
    0x65614304: "decryptedMessageActionDeleteMessages",
    0x8AC1F475: "decryptedMessageActionScreenshotMessages",
    0x6719E45C: "decryptedMessageActionFlushHistory",
    0x511110B0: "decryptedMessageActionResend",
    0xF3048883: "decryptedMessageActionNotifyLayer",
    0xCCB27641: "decryptedMessageActionTyping",
    0xF3C9611B: "decryptedMessageActionRequestKey",
    0x6FE1735B: "decryptedMessageActionAcceptKey",
    0xDD05EC6B: "decryptedMessageActionAbortKey",
    0xEC2E0B9B: "decryptedMessageActionCommitKey",
    0xA82FDD63: "decryptedMessageActionNoop",
}

_SECRET_CTOR_NAMES: Dict[int, str] = {
    _DECRYPTED_MESSAGE_LAYER: "decryptedMessageLayer",
    _DECRYPTED_MSG_SERVICE: "decryptedMessageService",
    _DECRYPTED_MSG_SERVICE8: "decryptedMessageService",
    _DECRYPTED_MSG_MEDIA_EMPTY: "decryptedMessageMediaEmpty",
    **{ctor: "decryptedMessage" for ctor in _DECRYPTED_MESSAGE_IDS},
}


def secret_ctor_name(ctor: int) -> str:
    """Return the secret-chat TL name for *ctor*, or a hex fallback."""
    return _SECRET_CTOR_NAMES.get(ctor) or _DECRYPTED_ACTION_NAMES.get(ctor) \
        or f"0x{ctor:08x}"


@dataclass
class SecretChatFields:
    """Every decoded field of one Secret-Chat plaintext, for display.

    ``ctor_name`` names the inner message (``decryptedMessage`` or
    ``decryptedMessageService``); the envelope fields (``layer``, seq numbers,
    ``random_bytes_len``) stay 0 for a bare message without a layer wrapper.
    """

    ctor_name: str = ""
    layer: int = 0
    in_seq_no: int = 0
    out_seq_no: int = 0
    random_bytes_len: int = 0
    flags: int = 0
    random_id: int = 0
    ttl: int = 0
    message: str = ""
    has_media: bool = False
    media_ctor: str = ""
    action: str = ""
    ctor: int = 0
    has_layer_envelope: bool = False


def _read_layer_envelope(reader: _Reader, fields: SecretChatFields) -> int:
    """decryptedMessageLayer body (ctor consumed) → the inner message ctor."""
    fields.random_bytes_len = len(reader.tl_bytes())  # random_bytes:bytes
    fields.layer = reader.int32()                      # layer:int
    fields.in_seq_no = reader.int32()                  # in_seq_no:int
    fields.out_seq_no = reader.int32()                 # out_seq_no:int
    fields.has_layer_envelope = True
    return reader.uint32()                             # message:DecryptedMessage


def _peek_media_ctor(reader: _Reader) -> str:
    """Name of the media object at the cursor, or "" when it is truncated."""
    try:
        return secret_ctor_name(reader.peek_uint32())
    except _TLError:
        return ""


def _read_decrypted_message_fields(
    reader: _Reader, ctor: int, fields: SecretChatFields,
) -> None:
    """decryptedMessage body (ctor consumed): flags?, random_id, ttl, message.

    The layer-17 form (``0x204d3878``) has no leading ``flags:int``; the
    layer-45+/73+ forms do. Media presence comes from :func:`_decrypted_has_media`.
    """
    if ctor != _DECRYPTED_MSG_L17:
        fields.flags = reader.uint32()   # flags:int (layer 45+/73+ only)
    fields.random_id = reader.int64()    # random_id:long (message identity)
    fields.ttl = reader.int32()          # ttl:int
    fields.message = reader.tl_string()  # message:string
    fields.has_media = _decrypted_has_media(reader, ctor, fields.flags)
    if fields.has_media:
        fields.media_ctor = _peek_media_ctor(reader)
    fields.ctor = ctor
    fields.ctor_name = "decryptedMessage"


def _read_decrypted_service_fields(
    reader: _Reader, ctor: int, fields: SecretChatFields,
) -> None:
    """decryptedMessageService body (ctor consumed): random_id, [random_bytes], action."""
    fields.random_id = reader.int64()     # random_id:long
    if ctor == _DECRYPTED_MSG_SERVICE8:
        reader.tl_bytes()                 # random_bytes:bytes (layer 8 only)
    fields.action = secret_ctor_name(reader.uint32())  # action:DecryptedMessageAction
    fields.ctor = ctor
    fields.ctor_name = "decryptedMessageService"


def _read_secret_chat_fields(reader: _Reader) -> Optional[SecretChatFields]:
    """Decode an optional layer envelope plus one inner message, or ``None``.

    Raises :class:`_TLError` on truncation; callers swallow it.
    """
    fields = SecretChatFields()
    ctor = reader.uint32()
    if ctor == _DECRYPTED_MESSAGE_LAYER:
        ctor = _read_layer_envelope(reader, fields)
    if ctor in _DECRYPTED_MESSAGE_IDS:
        _read_decrypted_message_fields(reader, ctor, fields)
        return fields
    if ctor in _DECRYPTED_MESSAGE_SERVICE_IDS:
        _read_decrypted_service_fields(reader, ctor, fields)
        return fields
    return None


def decode_secret_chat_fields(tl_bytes: bytes) -> Optional[SecretChatFields]:
    """Decode a Secret-Chat plaintext (layer-wrapped or bare) into its fields.

    Never raises; returns ``None`` for empty, truncated or unknown input.
    """
    if not tl_bytes:
        return None
    try:
        return _read_secret_chat_fields(_Reader(tl_bytes))
    except _TLError:
        return None
    except Exception:  # pragma: no cover - defensive
        return None


def _fields_to_parsed(fields: SecretChatFields) -> ParsedMtprotoMessage:
    """Project decoded Secret-Chat fields onto the shared display record."""
    if fields.ctor_name == "decryptedMessageService":
        return ParsedMtprotoMessage(
            kind="service", body=fields.action, method="decryptedMessageService",
            random_id=fields.random_id,
        )
    return ParsedMtprotoMessage(
        kind="text", body=fields.message, has_media=fields.has_media,
        method="decryptedMessage", random_id=fields.random_id,
    )


def _parse_decrypted_message(reader: _Reader, ctor: int) -> Optional[ParsedMtprotoMessage]:
    """decryptedMessage (ctor consumed) → display record.

    Layer 17 (``0x204d3878``) is ``random_id:long, ttl:int, message:string, …``;
    layer 45+/73+ (``0x36b091de``/``0x91cc4674``) prepends ``flags:int``.
    """
    fields = SecretChatFields()
    _read_decrypted_message_fields(reader, ctor, fields)
    return _fields_to_parsed(fields)


def parse_secret_chat_message(tl_bytes: bytes) -> List[ParsedMtprotoMessage]:
    """Parse a decrypted secret-chat E2E payload into messages.

    Reaches ``message:string`` via ``decryptedMessageLayer`` →
    ``decryptedMessage`` (or the action of a ``decryptedMessageService``, as
    kind ``"service"``). Returns ``[]`` on any failure, never raises.
    """
    fields = decode_secret_chat_fields(tl_bytes)
    return [_fields_to_parsed(fields)] if fields is not None else []
