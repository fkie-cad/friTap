"""Structured users and Secret-Chat peer linking (synthetic bytes only)."""

from __future__ import annotations

import struct

from friTap.offline.mtproto.tl import decode_tl
from friTap.offline.mtproto.tl.users import (
    extract_users,
    fingerprint_hex,
    infer_secret_chat_peer,
    keylog_peer,
    link_secret_chat_peer,
    merge_user_directory,
    self_user,
    user_label,
)
from tests.unit._tl_helpers import (
    USER,
    VECTOR,
    gzip_packed,
    i32,
    i64,
    rpc_result,
    synthetic_user,
    tl_bytes,
    tl_str,
    u32,
)

USER_STATUS_OFFLINE = 0x008C703F
USER_PROFILE_PHOTO = 0x82D1F706
ENCRYPTED_CHAT = 0x61F0D4C7
ENCRYPTED_CHAT_WAITING = 0x66B25953
UPDATE_ENCRYPTION = 0xB4A2E88D

SELF_ID = 123456789          # synthetic_user() id, flagged self
PEER_ID = 987654321
FP_INT = 0x6B2275A9796E6871   # little-endian bytes: 71686e79a975226b
FP_HEX = "71686e79a975226b"
CHAT_ID = -1355992074          # signed int32 as written in keylogs


def contact_user(user_id=PEER_ID, username="bob", photo=True) -> bytes:
    """user#b1b8cc83 with contact/mutual_contact/premium, username, photo, offline status."""
    flags = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 6) | (1 << 11) | (1 << 12) | (1 << 28)
    flags |= (1 << 5) if photo else 0
    body = u32(USER) + u32(flags) + u32(0) + i64(user_id) + i64(7) + tl_str("Bob")
    body += tl_str(username)
    if photo:
        body += u32(USER_PROFILE_PHOTO) + u32(0) + i64(55) + i32(2)
    return body + u32(USER_STATUS_OFFLINE) + i32(1_700_000_100)


def encrypted_chat(chat_id=CHAT_ID, admin=SELF_ID, participant=PEER_ID, fp=FP_INT) -> bytes:
    return (u32(ENCRYPTED_CHAT) + i32(chat_id) + i64(1) + i32(1_700_000_000)
            + i64(admin) + i64(participant) + tl_bytes(b"\x01" * 8) + i64(fp))


def directory():
    return merge_user_directory(extract_users(decode_tl(synthetic_user()))
                                + extract_users(decode_tl(contact_user())))


# --------------------------------------------------------------------------- #
# extract_users
# --------------------------------------------------------------------------- #

def test_self_user_fields_flags_and_status():
    [user] = extract_users(decode_tl(synthetic_user()))
    assert user["id"] == SELF_ID and user["access_hash"] == -42
    assert (user["first_name"], user["last_name"]) == ("Alice", "Example")
    assert user["phone"] == "15550000000"
    assert user["flags"] == ["self", "stories_unavailable"]
    assert user["status"] == {"kind": "online", "expires": 1700000000}
    assert user["has_photo"] is False
    assert user["ctor"] == "user#b1b8cc83"
    assert "username" not in user


def test_contact_user_flags_username_photo_offline():
    [user] = extract_users(decode_tl(contact_user()))
    assert user["flags"] == ["contact", "mutual_contact", "premium"]
    assert user["username"] == "bob"
    assert user["has_photo"] is True
    assert user["status"] == {"kind": "offline", "was_online": 1_700_000_100}


def test_users_found_inside_gzip_rpc_result_vector():
    vector = u32(VECTOR) + i32(2) + synthetic_user() + contact_user()
    users = extract_users(decode_tl(rpc_result(9, gzip_packed(vector))))
    assert [u["id"] for u in users] == [SELF_ID, PEER_ID]


def test_merge_directory_newest_non_empty_wins():
    old = {"id": 5, "first_name": "Old", "username": "keep", "flags": ["contact"]}
    new = {"id": 5, "first_name": "New", "username": "", "flags": []}
    merged = merge_user_directory([old, new, {"id": 0, "first_name": "ignored"}])
    assert merged == {5: {"id": 5, "first_name": "New", "username": "keep", "flags": ["contact"]}}


def test_self_user_and_labels():
    users = directory()
    assert self_user(users)["id"] == SELF_ID
    assert self_user({}) is None
    assert user_label(users[PEER_ID]) == "Bob"
    assert user_label({"id": 3, "username": "u"}) == "@u"
    assert user_label(None, 42) == "user 42"


# --------------------------------------------------------------------------- #
# link_secret_chat_peer
# --------------------------------------------------------------------------- #

def test_fingerprint_hex_is_little_endian():
    assert fingerprint_hex(FP_INT) == FP_HEX
    assert struct.pack(">q", FP_INT).hex() != FP_HEX


def test_link_by_fingerprint_maps_the_non_self_participant():
    nodes = [decode_tl(encrypted_chat(chat_id=1))]  # chat id does not match
    peer = link_secret_chat_peer(nodes, FP_HEX, CHAT_ID, directory())
    assert peer["user_id"] == PEER_ID and peer["label"] == "Bob"
    assert peer["matched_by"] == "key_fingerprint"
    assert peer["user"]["username"] == "bob"


def test_big_endian_fingerprint_does_not_match():
    nodes = [decode_tl(encrypted_chat(chat_id=1))]
    peer = link_secret_chat_peer(nodes, struct.pack(">q", FP_INT).hex(), CHAT_ID, directory())
    assert peer["user_id"] == 0


def test_link_by_chat_id_normalises_sign_and_self_as_participant():
    unsigned = CHAT_ID & 0xFFFFFFFF
    body = (u32(ENCRYPTED_CHAT_WAITING) + i32(CHAT_ID) + i64(1) + i32(1)
            + i64(PEER_ID) + i64(SELF_ID))  # peer is admin, self is participant
    update = u32(UPDATE_ENCRYPTION) + body + i32(2)
    peer = link_secret_chat_peer([decode_tl(update)], "", unsigned, directory())
    assert peer["user_id"] == PEER_ID and peer["matched_by"] == "chat_id"


def test_linked_peer_not_in_directory_gets_id_label():
    peer = link_secret_chat_peer([decode_tl(encrypted_chat(participant=555))], FP_HEX,
                                 CHAT_ID, directory())
    assert peer["user_id"] == 555 and peer["label"] == "user 555" and "user" not in peer


def test_fallback_when_nothing_matches():
    peer = link_secret_chat_peer([decode_tl(synthetic_user())], FP_HEX, CHAT_ID, directory())
    assert peer == {"user_id": 0, "label": f"peer (unknown, chat_id {CHAT_ID})",
                    "chat_id": CHAT_ID}


# --------------------------------------------------------------------------- #
# infer_secret_chat_peer (heuristic fallback for chats that predate the capture)
# --------------------------------------------------------------------------- #

_SELF = {"id": SELF_ID, "flags": ["self"], "first_name": "Me"}
_BOB = {"id": PEER_ID, "flags": ["contact", "mutual_contact"], "first_name": "Bob",
        "phone": "4915738796832", "access_hash": 7}


def _dir(*users) -> dict:
    return {u["id"]: u for u in users}


def test_infer_single_candidate_is_confident():
    peer = infer_secret_chat_peer(_dir(_SELF, _BOB), SELF_ID, CHAT_ID)
    assert peer["user_id"] == PEER_ID
    assert peer["matched_by"] == "heuristic"
    assert peer["confidence"] == "single"
    assert peer["label"] == "Bob"
    assert peer["user"]["id"] == PEER_ID and peer["chat_id"] == CHAT_ID


def test_infer_excludes_self_service_and_bot():
    service = {"id": 777000, "first_name": "Telegram"}
    bot = {"id": 555, "flags": ["bot"], "first_name": "SomeBot"}
    peer = infer_secret_chat_peer(_dir(_SELF, service, bot, _BOB), SELF_ID, CHAT_ID)
    assert peer["user_id"] == PEER_ID and peer["confidence"] == "single"


def test_infer_multiple_prefers_named_reachable_contact():
    bare = {"id": 42}  # no name / phone / contact flag
    peer = infer_secret_chat_peer(_dir(_SELF, bare, _BOB), SELF_ID, CHAT_ID)
    assert peer["user_id"] == PEER_ID  # Bob outranks the bare id
    assert peer["confidence"] == "multiple"


def test_infer_no_candidate_returns_plain_fallback():
    peer = infer_secret_chat_peer(_dir(_SELF), SELF_ID, CHAT_ID)
    assert peer == {"user_id": 0, "label": f"peer (unknown, chat_id {CHAT_ID})",
                    "chat_id": CHAT_ID}


# --------------------------------------------------------------------------- #
# keylog_peer (confident peer from the keylog's 4th field)
# --------------------------------------------------------------------------- #

def test_keylog_peer_attaches_profile_when_present():
    peer = keylog_peer(PEER_ID, CHAT_ID, _dir(_SELF, _BOB))
    assert peer["user_id"] == PEER_ID and peer["matched_by"] == "keylog"
    assert peer["label"] == "Bob" and peer["user"]["id"] == PEER_ID
    assert peer["chat_id"] == CHAT_ID


def test_keylog_peer_without_directory_entry_uses_id_label():
    peer = keylog_peer(555, CHAT_ID, _dir(_SELF))
    assert peer["user_id"] == 555 and peer["label"] == "user 555"
    assert peer["matched_by"] == "keylog" and "user" not in peer
