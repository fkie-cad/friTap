"""Synthetic unit tests for the MTProto/Telegram TL message parser.

No real keys: every fixture is a hand-built TL byte string. The
``messages.sendMessage`` vector reproduces the DEVICE-VERIFIED outbound layout
from the parser spec (constructor ``0xfef48f62``). Coverage:

  * the verified ``sendMessage`` layout (with and without a reply_to prefix),
  * ``msg_container`` fan-out into several bodies,
  * ``gzip_packed`` unwrap,
  * ``updateShortMessage`` / ``updateShortChatMessage`` inbound paths,
  * an E2E ``decryptedMessageLayer`` → ``decryptedMessage``,
  * tolerance: malformed / unknown input degrades to no messages (never raises).
"""

from __future__ import annotations

import struct
import zlib

from friTap.offline.mtproto.content import (
    ctor_name,
    parse_mtproto_message,
    parse_secret_chat_message,
)

# --- TL serialization helpers (mirror the reader's expectations) ----------- #

_VECTOR = 0x1CB5C415
_MSG_CONTAINER = 0x73F1F8DC
_GZIP_PACKED = 0x3072CFA1
_SEND_MESSAGE = 0xFEF48F62
_INPUT_PEER_USER = 0xDDE8A54C
_INPUT_PEER_SELF = 0x7DA07EC9
_INPUT_REPLY_TO_MESSAGE = 0x22C0F6D5
_UPDATE_SHORT_MESSAGE = 0x313BC7F8
_UPDATE_SHORT_CHAT_MESSAGE = 0x4D6DEEA5
_DECRYPTED_MESSAGE_LAYER = 0x1BE31789
_DECRYPTED_MESSAGE_L73 = 0x91CC4674
_DECRYPTED_MESSAGE_L17 = 0x204D3878
_RPC_RESULT = 0xF35C6D01
_MSGS_ACK = 0x62D6B459
_PONG = 0x347773C5
_NEW_SESSION_CREATED = 0x9EC20908
_USER_VERIFIED = 0x31774388
_UPDATE_NEW_MESSAGE = 0x1F2B0AFD
_PEER_USER = 0x59511722


def _u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _i32(value: int) -> bytes:
    return struct.pack("<i", value)


def _i64(value: int) -> bytes:
    return struct.pack("<q", value)


def _tl_bytes(data: bytes) -> bytes:
    """Serialize *data* as a TL string/bytes value (length-prefixed + padded)."""
    if len(data) < 254:
        out = bytes([len(data)]) + data
        header = 1
    else:
        out = b"\xfe" + len(data).to_bytes(3, "little") + data
        header = 4
    out += b"\x00" * ((-(header + len(data))) % 4)
    return out


def _tl_str(text: str) -> bytes:
    return _tl_bytes(text.encode("utf-8"))


# --------------------------------------------------------------------------- #
# Outbound: messages.sendMessage (device-verified layout)
# --------------------------------------------------------------------------- #

def _verified_send_message() -> bytes:
    """The exact 60-byte device-verified outbound sendMessage from the spec."""
    return bytes.fromhex(
        "628ff4fe"                    # messages.sendMessage 0xfef48f62
        "80000000"                    # flags = 0x80 (reply_to ABSENT)
        "4ca5e8dd"                    # inputPeerUser 0xdde8a54c
        "bd5ac9ff01000000"            # user_id : long
        "cbb036088ffb25d0"            # access_hash : long
        "16"                          # message TL-string len = 22
        + "fritapP3CLOUD2026FRESH".encode("utf-8").hex()  # 22 bytes
        + "00"                        # padding
        + "80b47497f5cd6429"          # random_id : long
    )


def test_verified_send_message_layout():
    msgs = parse_mtproto_message(_verified_send_message())
    assert len(msgs) == 1
    assert msgs[0].kind == "text"
    assert msgs[0].body == "fritapP3CLOUD2026FRESH"


def test_send_message_with_reply_to():
    """sendMessage with the flags.0 inputReplyToMessage prefix is skipped."""
    reply_to = (
        _u32(_INPUT_REPLY_TO_MESSAGE)
        + _u32(0)            # flags2 = 0 (no optional reply_to fields)
        + _i32(12345)        # reply_to_msg_id
    )
    body = (
        _u32(_SEND_MESSAGE)
        + _u32(0x00000001)   # flags = reply_to present (bit0)
        + _u32(_INPUT_PEER_SELF)
        + reply_to
        + _tl_str("hello reply")
        + _i64(0x1122334455667788)
    )
    msgs = parse_mtproto_message(body)
    assert len(msgs) == 1
    assert msgs[0].body == "hello reply"


# --------------------------------------------------------------------------- #
# Containers
# --------------------------------------------------------------------------- #

def test_msg_container_fan_out():
    """A msg_container fans out into one parsed message per message-bearing body."""
    body_a = _verified_send_message()
    body_b = (
        _u32(_SEND_MESSAGE) + _u32(0x80) + _u32(_INPUT_PEER_SELF)
        + _tl_str("second message") + _i64(7)
    )
    container = _u32(_MSG_CONTAINER) + _i32(2)
    for i, body in enumerate((body_a, body_b)):
        container += _i64(1000 + i) + _i32(i) + _i32(len(body)) + body
    msgs = parse_mtproto_message(container)
    bodies = [m.body for m in msgs]
    assert bodies == ["fritapP3CLOUD2026FRESH", "second message"]


def test_gzip_packed_unwrap():
    """A gzip_packed body is inflated and the inner sendMessage parsed."""
    inner = _verified_send_message()
    packed = _u32(_GZIP_PACKED) + _tl_bytes(zlib.compress(inner))
    msgs = parse_mtproto_message(packed)
    assert len(msgs) == 1
    assert msgs[0].body == "fritapP3CLOUD2026FRESH"


def test_gzip_packed_inflate_is_bounded(monkeypatch):
    """C15: gzip_packed must inflate at most _MAX_GZIP_INFLATE bytes. A payload
    that would inflate past the cap is refused (decompression-bomb guard) rather
    than expanded into memory unbounded. Distinguished from the no-cap bug by
    using an inner that DOES parse under the normal cap but is refused once the
    cap is lowered below its inflated size."""
    import friTap.offline.mtproto.content as content

    inner = _verified_send_message()
    packed = _u32(_GZIP_PACKED) + _tl_bytes(zlib.compress(inner))
    # Normal cap: inflates and parses to the inner message.
    assert len(parse_mtproto_message(packed)) == 1
    # Cap below the inflated size: the inflate is refused, so nothing is parsed
    # (an unbounded zlib.decompress would still have inflated and parsed it).
    monkeypatch.setattr(content, "_MAX_GZIP_INFLATE", len(inner) - 1)
    assert parse_mtproto_message(packed) == []


# --------------------------------------------------------------------------- #
# Inbound updates
# --------------------------------------------------------------------------- #

def test_update_short_message():
    body = (
        _u32(_UPDATE_SHORT_MESSAGE)
        + _u32(0)            # flags
        + _i32(42)           # id
        + _i64(99887766)     # user_id
        + _tl_str("inbound hi")
        + _i32(1)            # pts (ignored)
    )
    msgs = parse_mtproto_message(body)
    assert len(msgs) == 1
    assert msgs[0].body == "inbound hi"
    assert msgs[0].peer_id == 99887766


def test_update_short_chat_message():
    body = (
        _u32(_UPDATE_SHORT_CHAT_MESSAGE)
        + _u32(0)            # flags
        + _i32(7)            # id
        + _i64(111)          # from_id
        + _i64(222)          # chat_id
        + _tl_str("group hi")
        + _i32(1)            # pts (ignored)
    )
    msgs = parse_mtproto_message(body)
    assert len(msgs) == 1
    assert msgs[0].body == "group hi"
    assert msgs[0].sender_id == 111
    assert msgs[0].peer_id == 222


# --------------------------------------------------------------------------- #
# E2E (secret chat)
# --------------------------------------------------------------------------- #

def test_decrypted_message_layer_73():
    inner = (
        _u32(_DECRYPTED_MESSAGE_L73)
        + _u32(0)            # flags
        + _i64(0xCAFE)       # random_id
        + _i32(0)            # ttl
        + _tl_str("secret hello")
    )
    blob = (
        _u32(_DECRYPTED_MESSAGE_LAYER)
        + _tl_bytes(b"\x00" * 16)   # random_bytes
        + _i32(73)                  # layer
        + _i32(0)                   # in_seq_no
        + _i32(0)                   # out_seq_no
        + inner
    )
    msgs = parse_secret_chat_message(blob)
    assert len(msgs) == 1
    assert msgs[0].body == "secret hello"


def test_decrypted_message_layer_17():
    """The layer-17 decryptedMessage has no leading flags field."""
    inner = (
        _u32(_DECRYPTED_MESSAGE_L17)
        + _i64(0xBEEF)       # random_id
        + _i32(0)            # ttl
        + _tl_str("old secret")
    )
    blob = (
        _u32(_DECRYPTED_MESSAGE_LAYER)
        + _tl_bytes(b"\x00" * 16)
        + _i32(17) + _i32(0) + _i32(0)
        + inner
    )
    msgs = parse_secret_chat_message(blob)
    assert len(msgs) == 1
    assert msgs[0].body == "old secret"


# --------------------------------------------------------------------------- #
# Tolerance: never raise; degrade to no messages
# --------------------------------------------------------------------------- #

def test_empty_input_returns_empty():
    assert parse_mtproto_message(b"") == []
    assert parse_secret_chat_message(b"") == []


def test_unknown_constructor_degrades():
    assert parse_mtproto_message(_u32(0xDEADBEEF) + b"\x00\x00\x00\x00") == []


def test_truncated_send_message_degrades():
    truncated = _verified_send_message()[:20]
    assert parse_mtproto_message(truncated) == []


def test_garbage_never_raises():
    for blob in (b"\xff", b"\x00\x01\x02\x03", bytes(range(40))):
        assert isinstance(parse_mtproto_message(blob), list)
        assert isinstance(parse_secret_chat_message(blob), list)


# --------------------------------------------------------------------------- #
# method / kind tagging
# --------------------------------------------------------------------------- #

def test_send_message_carries_method():
    msgs = parse_mtproto_message(_verified_send_message())
    assert msgs[0].method == "messages.sendMessage"
    assert msgs[0].kind == "text"


def test_ctor_name_lookup():
    assert ctor_name(_MSGS_ACK) == "msgs_ack"
    assert ctor_name(_PONG) == "pong"
    assert ctor_name(_USER_VERIFIED) == "user"
    assert ctor_name(0xDEADBEEF) == "0xdeadbeef"


# --------------------------------------------------------------------------- #
# Service records
# --------------------------------------------------------------------------- #

def test_msgs_ack_is_service_ack():
    # msgs_ack: msg_ids:Vector<long>
    body = (
        _u32(_MSGS_ACK) + _u32(_VECTOR) + _i32(2) + _i64(111) + _i64(222)
    )
    msgs = parse_mtproto_message(body)
    assert len(msgs) == 1
    assert msgs[0].kind == "ack"
    assert msgs[0].method == "msgs_ack"


def test_pong_is_service():
    body = _u32(_PONG) + _i64(0xABCD) + _i64(0x1234)
    msgs = parse_mtproto_message(body)
    assert len(msgs) == 1
    assert msgs[0].kind == "service"
    assert msgs[0].method == "pong"


def test_new_session_created_is_service():
    body = _u32(_NEW_SESSION_CREATED) + _i64(1) + _i64(2) + _i64(3)
    msgs = parse_mtproto_message(body)
    assert len(msgs) == 1
    assert msgs[0].kind == "service"
    assert msgs[0].method == "new_session_created"


# --------------------------------------------------------------------------- #
# User objects (device-verified layout from the spec)
# --------------------------------------------------------------------------- #

def _verified_user() -> bytes:
    """The exact device-verified User layout from REFINE_SPEC.md (msg#58/#60)."""
    hex_str = (
        "88437731"                          # user ctor 0x31774388 (LAYER-VERSIONED)
        "57040012"                          # flags
        "10000000"                          # flags2
        "e0eb841502000000"                  # id:long
        "11ec8f347b8d96d3"                  # access_hash:long
        "04" + "Evil".encode().hex() + "000000"          # first_name "Evil"
        + "07" + "kneebel".encode().hex()                # username "kneebel"
        + "0d" + "4915155912510".encode().hex() + "0000"  # phone "4915155912510"
    )
    return bytes.fromhex(hex_str)


def test_verified_user_layout():
    msgs = parse_mtproto_message(_verified_user())
    assert len(msgs) == 1
    assert msgs[0].kind == "user"
    assert msgs[0].method == "user"
    assert "kneebel" in msgs[0].body
    assert "4915155912510" in msgs[0].body


def test_user_in_rpc_result():
    """A User wrapped in rpc_result is surfaced as kind='user'."""
    body = _u32(_RPC_RESULT) + _i64(0x9999) + _verified_user()
    msgs = parse_mtproto_message(body)
    users = [m for m in msgs if m.kind == "user"]
    assert users, msgs
    assert "kneebel" in users[0].body


def test_user_in_vector():
    """Vector<User> (e.g. users.getUsers result) fans out into user items."""
    u = _verified_user()
    vec = _u32(_VECTOR) + _i32(1) + u
    body = _u32(_RPC_RESULT) + _i64(0x1) + vec
    msgs = parse_mtproto_message(body)
    users = [m for m in msgs if m.kind == "user"]
    assert users
    assert users[0].method in ("user", "users", "users.getUsers")
    assert "kneebel" in users[0].body


def test_user_tolerant_no_phone():
    """A User with only first_name + username still summarises (no phone).

    flags.0 (access_hash) is CLEAR, so the wire carries NO access_hash field —
    the parser must skip it (gated on the flag bit) and read first_name next.
    """
    body = (
        _u32(_USER_VERIFIED)
        + _u32(0x0000000A)   # flags: first_name(1) + username(3); NO access_hash(0)
        + _u32(0)            # flags2
        + _i64(123)          # id
        + _tl_str("Alice")   # first_name (no access_hash precedes it)
        + _tl_str("alice99")
    )
    msgs = parse_mtproto_message(body)
    users = [m for m in msgs if m.kind == "user"]
    assert users
    assert "Alice" in users[0].body or "alice99" in users[0].body


# --------------------------------------------------------------------------- #
# Inbound full message# object via updateNewMessage
# --------------------------------------------------------------------------- #

def test_inbound_message_via_update_new_message():
    """updateNewMessage → message# → best-effort text extraction."""
    message_ctor = 0x96FDB04A  # a known full-message ctor
    inner = (
        _u32(message_ctor)
        + _u32(0x00000100)              # flags: from_id present (bit8)
        + _i32(555)                     # id
        + _u32(_PEER_USER) + _i64(777)  # from_id:Peer
        + _u32(_PEER_USER) + _i64(888)  # peer_id:Peer
        + _i32(1700000000)              # date (plausible unix ts)
        + _tl_str("inbound full message")
    )
    body = (
        _u32(_UPDATE_NEW_MESSAGE)
        + inner
        + _i32(1) + _i32(1)             # pts, pts_count
    )
    msgs = parse_mtproto_message(body)
    texts = [m for m in msgs if m.kind == "text"]
    assert texts, msgs
    assert texts[0].body == "inbound full message"
    assert texts[0].method == "message"


def test_inbound_misaligned_message_degrades():
    """A message# whose body is garbage degrades, never mis-reads wildly."""
    message_ctor = 0x96FDB04A
    inner = _u32(message_ctor) + _u32(0) + _i32(1) + b"\xff\xff\xff\xff\x10\x20"
    body = _u32(_UPDATE_NEW_MESSAGE) + inner
    result = parse_mtproto_message(body)
    # Either nothing or an 'unparsed'/garbage item, but never an exception.
    assert isinstance(result, list)
    for m in result:
        assert m.kind in ("text", "unparsed")


# --------------------------------------------------------------------------- #
# Precise flag-based User decode (device-verified flag layouts)
# --------------------------------------------------------------------------- #

# UserStatus constructors.
_USER_STATUS_OFFLINE = 0x008C703F
_USER_STATUS_RECENTLY = 0x7B197DC8

# Verified relationship/identity flag bits.
_F_ACCESS_HASH = 1 << 0
_F_FIRST = 1 << 1
_F_LAST = 1 << 2
_F_USERNAME = 1 << 3
_F_PHONE = 1 << 4
_F_PHOTO = 1 << 5
_F_STATUS = 1 << 6
_F_SELF = 1 << 10
_F_CONTACT = 1 << 11
_F_MUTUAL = 1 << 12
_F_BOT = 1 << 14


def _make_user(flags: int, *, uid: int = 1000, access_hash: int = 7,
               first: str = "", last: str = "", username: str = "",
               phone: str = "", status_tail: bytes = b"") -> bytes:
    """Build a User#0x31774388 body in strict ascending-flag-bit field order."""
    out = _u32(_USER_VERIFIED) + _u32(flags) + _u32(0) + _i64(uid)
    if flags & _F_ACCESS_HASH:
        out += _i64(access_hash)
    if flags & _F_FIRST:
        out += _tl_str(first)
    if flags & _F_LAST:
        out += _tl_str(last)
    if flags & _F_USERNAME:
        out += _tl_str(username)
    if flags & _F_PHONE:
        out += _tl_str(phone)
    out += status_tail
    return out


def test_user_self_flag_layout():
    """flags 0x12000457: self + first/last/phone/status, NO username (Evil)."""
    user = _make_user(
        0x12000457, first="Evil", last="kneebel", phone="4915155912510",
        status_tail=_u32(_USER_STATUS_RECENTLY),
    )
    msgs = parse_mtproto_message(user)
    assert len(msgs) == 1
    item = msgs[0]
    assert item.kind == "user" and item.method == "user"
    assert "@" not in item.body                 # no username flag → no @handle
    assert "+4915155912510" in item.body
    assert "[you]" in item.body
    assert "you" in item.relationship
    assert "last seen recently" in item.body


def test_user_contact_mutual_flag_layout():
    """flags 0x2001857: contact + mutual + first/last/phone/status (db Forscher)."""
    user = _make_user(
        0x2001857, first="db", last="Forscher", phone="4915738796832",
        status_tail=_u32(_USER_STATUS_OFFLINE) + _i32(1700000000),
    )
    msgs = parse_mtproto_message(user)
    assert len(msgs) == 1
    item = msgs[0]
    assert item.kind == "user"
    assert "db Forscher" in item.body
    assert "+4915738796832" in item.body
    assert "[contact]" in item.body and "[mutual]" in item.body
    assert item.relationship == ("contact", "mutual")
    assert "last seen 1700000000" in item.body


def test_user_username_present():
    """A username flag (bit 3) renders an @handle in ascending field order."""
    user = _make_user(
        _F_ACCESS_HASH | _F_FIRST | _F_USERNAME | _F_PHONE,
        first="Alice", username="alice99", phone="491234567",
    )
    msgs = parse_mtproto_message(user)
    item = next(m for m in msgs if m.kind == "user")
    assert "Alice" in item.body
    assert "@alice99" in item.body
    assert "+491234567" in item.body


def test_user_username_absent_no_at():
    """No username flag → body must not invent an @handle."""
    user = _make_user(_F_ACCESS_HASH | _F_FIRST | _F_PHONE,
                      first="NoHandle", phone="490000000")
    item = next(m for m in parse_mtproto_message(user) if m.kind == "user")
    assert "@" not in item.body
    assert "NoHandle" in item.body


def test_user_bot_relationship_tag():
    user = _make_user(_F_ACCESS_HASH | _F_FIRST | _F_BOT, first="HelperBot")
    item = next(m for m in parse_mtproto_message(user) if m.kind == "user")
    assert "[bot]" in item.body
    assert "bot" in item.relationship


def test_user_status_online_suffix():
    user = _make_user(
        _F_ACCESS_HASH | _F_FIRST | _F_STATUS, first="OnlineGuy",
        status_tail=_u32(0xEDB93949) + _i32(1700001234),  # userStatusOnline
    )
    item = next(m for m in parse_mtproto_message(user) if m.kind == "user")
    assert "online" in item.body
    assert "·" in item.body


def test_user_photo_bails_before_status():
    """When photo (.5) is set we parse identity up to phone and skip status.

    The trailing bytes after phone are an (unparsed) photo struct; the parser
    must NOT treat them as a UserStatus, and must still surface the identity.
    """
    flags = _F_ACCESS_HASH | _F_FIRST | _F_PHONE | _F_PHOTO | _F_STATUS
    user = _make_user(flags, first="WithPhoto", phone="491111111",
                      status_tail=b"\xde\xad\xbe\xef\x01\x02\x03\x04")
    item = next(m for m in parse_mtproto_message(user) if m.kind == "user")
    assert "WithPhoto" in item.body
    assert "+491111111" in item.body
    assert item.last_seen == ""          # status not reached (photo in the way)


def test_user_id_captured_for_dedup():
    user = _make_user(_F_ACCESS_HASH | _F_FIRST, uid=424242, first="Ident")
    item = next(m for m in parse_mtproto_message(user) if m.kind == "user")
    assert item.user_id == 424242


def test_user_tolerant_fallback_min_user():
    """A min/unexpected user (no flags2-shaped layout) degrades to the scan.

    Here we feed a User whose flag bits do not describe the trailing strings
    (flags=0 but strings present); the precise pass yields nothing usable so the
    tolerant consecutive-string heuristic recovers the identity, never raising.
    flags.0 is clear, so there is NO access_hash on the wire — the fallback must
    skip it (gated on the flag) and read the first string as first_name.
    """
    body = (
        _u32(_USER_VERIFIED)
        + _u32(0)                # flags (precise read finds no fields; no access_hash)
        + _u32(0)                # flags2
        + _i64(555)              # id (no access_hash follows: flags.0 clear)
        + _tl_str("Fallback")
        + _tl_str("4915700000000")
    )
    msgs = parse_mtproto_message(body)
    users = [m for m in msgs if m.kind == "user"]
    assert users
    assert "Fallback" in users[0].body
    assert "4915700000000" in users[0].body


def test_user_tolerant_reads_access_hash_when_flagged():
    """The tolerant fallback CONSUMES access_hash when flags.0 is set.

    Complements the flags.0-clear cases (which must NOT read access_hash): the
    gate works both ways, so the name strings are read at the right offset.
    """
    body = (
        _u32(_USER_VERIFIED)
        + _u32(0x01)             # flags: access_hash(0) set, no name bits
        + _u32(0)                # flags2
        + _i64(777)              # id
        + _i64(0xABCDEF)         # access_hash (present because flags.0 set)
        + _tl_str("Zara")
        + _tl_str("4915799999999")
    )
    users = [m for m in parse_mtproto_message(body) if m.kind == "user"]
    assert users
    assert "Zara" in users[0].body


# --------------------------------------------------------------------------- #
# E2E decryptedMessage media detection (has_media)
# --------------------------------------------------------------------------- #

def _secret_chat_layer(inner: bytes) -> bytes:
    """Wrap a decryptedMessage (ctor + body) in a decryptedMessageLayer envelope."""
    return (
        _u32(_DECRYPTED_MESSAGE_LAYER)
        + _tl_bytes(b"\x00" * 16)   # random_bytes
        + _i32(73)                  # layer
        + _i32(0) + _i32(0)         # in_seq_no, out_seq_no
        + inner
    )


def test_decrypted_message_media_empty_is_not_media():
    """A layer-17 text message whose media is decryptedMessageMediaEmpty: no media.

    Regression for ``has_media = reader.remaining > 0``, which flagged EVERY text
    message as media (a decryptedMessage always has trailing bytes)."""
    inner = (
        _u32(_DECRYPTED_MESSAGE_L17)
        + _i64(1) + _i32(0) + _tl_str("hi")
        + _u32(0x089F5C4A)       # decryptedMessageMediaEmpty
    )
    msgs = parse_secret_chat_message(_secret_chat_layer(inner))
    assert msgs and msgs[0].body == "hi"
    assert msgs[0].has_media is False


def test_decrypted_message_real_media_is_media():
    inner = (
        _u32(_DECRYPTED_MESSAGE_L17)
        + _i64(1) + _i32(0) + _tl_str("hi")
        + _u32(0xDEADBEEF)       # a non-empty media constructor
    )
    msgs = parse_secret_chat_message(_secret_chat_layer(inner))
    assert msgs and msgs[0].has_media is True


def test_decrypted_message_flagged_media_from_flag_bit():
    """Flag-bearing layers report media from the flag bit, not trailing bytes."""
    no_media = _u32(_DECRYPTED_MESSAGE_L73) + _u32(0) + _i64(1) + _i32(0) + _tl_str("hi")
    assert parse_secret_chat_message(_secret_chat_layer(no_media))[0].has_media is False
    with_media = _u32(_DECRYPTED_MESSAGE_L73) + _u32(1 << 9) + _i64(1) + _i32(0) + _tl_str("hi")
    assert parse_secret_chat_message(_secret_chat_layer(with_media))[0].has_media is True


# --------------------------------------------------------------------------- #
# Vector scan advance + message-body scan window
# --------------------------------------------------------------------------- #

def test_scan_for_vectors_advances_and_terminates():
    """``_scan_for_vectors`` advances past a consumed vector (no re-scan / no loop).

    Two back-to-back empty vectors: the scanner must step past each vector's
    consumed bytes (magic + count) rather than re-walking them, and terminate."""
    from friTap.offline.mtproto import content as C
    data = _u32(_VECTOR) + _i32(0) + _u32(_VECTOR) + _i32(0)
    out = []
    C._scan_for_vectors(C._Reader(data), out, 0)
    assert out == []


def test_scan_message_text_window_caps_scan():
    """The body scan is bounded: a body within the window is found, beyond is not."""
    from friTap.offline.mtproto import content as C
    near = C._Reader(b"\x00" * 40 + _tl_str("near body"))
    msg_near = C._scan_message_text(near, 1, 0, 0, 0)
    assert msg_near.kind == "text" and "near body" in msg_near.body

    far = C._Reader(b"\x00" * 600 + _tl_str("late body"))
    msg_far = C._scan_message_text(far, 1, 0, 0, 0)
    assert msg_far.kind == "unparsed"   # beyond the scan window → not mis-read


def test_msg_container_rejects_implausible_count():
    """A msg_container with an out-of-range count is rejected (no spin on a
    hostile/garbage count), mirroring the Vector guard."""
    from friTap.offline.mtproto import content as C
    reader = C._Reader(_i32(500000) + b"\x00" * 32)  # count follows the ctor
    raised = False
    try:
        C._dispatch_object(reader, _MSG_CONTAINER, [], 0)
    except C._TLError:
        raised = True
    assert raised
    # And the public API degrades gracefully (returns a list, never hangs/raises).
    body = _u32(_MSG_CONTAINER) + _i32(500000) + b"\x00" * 32
    assert isinstance(parse_mtproto_message(body), list)
