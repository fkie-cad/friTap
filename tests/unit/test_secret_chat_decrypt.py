"""Tests for the offline secret-chat (E2E) decrypt orchestrator.

We craft synthetic transport ``DecryptedMessage`` objects whose ``.message``
embeds a TL-``bytes``-framed E2E blob, then assert the orchestrator scans, peels,
and unframes them — and that unknown fingerprints are ignored.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("cryptography")  # secret-chat crypto needs an AES backend

from friTap.offline.mtproto import crypto
from friTap.offline.mtproto.e2e.decrypt import (
    iter_e2e_blobs,
    iter_secret_chat_messages,
)
from friTap.offline.mtproto.e2e.records import SecretChatStats
from friTap.offline.mtproto.records import DecryptedMessage
from friTap.protocols.mtproto_keylog_spec import MtprotoSecretChatKey


def _shared_key() -> bytes:
    return os.urandom(crypto.SECRET_CHAT_KEY_LEN)


def _tl_frame(blob: bytes) -> bytes:
    """Prepend the short-form TL ``bytes`` length byte (blobs here are < 254)."""
    assert len(blob) < 254
    return bytes([len(blob)]) + blob


def _transport_message(message: bytes) -> DecryptedMessage:
    return DecryptedMessage(
        src_addr="10.0.0.1",
        src_port=12345,
        dst_addr="149.154.167.51",
        dst_port=443,
        ss_family="AF_INET",
        direction="write",
        message=message,
        dc_id=2,
        transport="abridged",
        obfuscated=True,
        auth_key_id_hex="00" * 8,
    )


# --------------------------------------------------------------------------- #
# iter_e2e_blobs framing scan
# --------------------------------------------------------------------------- #


def test_iter_e2e_blobs_finds_framed_blob():
    key = _shared_key()
    fp = crypto.compute_secret_chat_fingerprint(key)
    blob = crypto.build_secret_chat_blob(key, b"hi", sender_is_creator=True)
    data = b"\xaa\xbb" + _tl_frame(blob) + b"\xcc\xdd"  # surrounded by noise
    found = list(iter_e2e_blobs(data, {fp}))
    assert found == [(fp, blob)]


def test_iter_e2e_blobs_ignores_unknown_fingerprint():
    key = _shared_key()
    blob = crypto.build_secret_chat_blob(key, b"hi", sender_is_creator=True)
    data = _tl_frame(blob)
    assert list(iter_e2e_blobs(data, {os.urandom(8)})) == []
    assert list(iter_e2e_blobs(data, set())) == []


# --------------------------------------------------------------------------- #
# iter_secret_chat_messages end-to-end
# --------------------------------------------------------------------------- #


def test_iter_secret_chat_messages_yields_payload():
    key = _shared_key()
    fp = crypto.compute_secret_chat_fingerprint(key)
    payload = b"\x01\x02\x03 decrypted secret chat payload"
    blob = crypto.build_secret_chat_blob(key, payload, sender_is_creator=False)
    tmsg = _transport_message(b"\xff" + _tl_frame(blob) + b"\x00\x00")

    keymap = {fp: MtprotoSecretChatKey(key_fingerprint=fp, shared_key=key, chat_id=7)}
    stats = SecretChatStats()
    out = list(iter_secret_chat_messages([tmsg], keymap, stats=stats))

    assert len(out) == 1
    msg = out[0]
    assert msg.message == payload
    assert msg.chat_id == 7
    assert msg.key_fingerprint_hex == fp.hex()
    assert msg.origin == "decrypted"
    # addr/port/family/direction copied from the carrying transport message
    assert msg.src_addr == "10.0.0.1"
    assert msg.dst_port == 443
    assert msg.ss_family == "AF_INET"
    assert msg.direction == "write"
    assert stats.messages == 1
    assert stats.blobs_seen == 1
    assert stats.records_undecryptable == 0


def test_iter_secret_chat_messages_ignores_unknown_fingerprint():
    key = _shared_key()
    blob = crypto.build_secret_chat_blob(key, b"secret", sender_is_creator=True)
    tmsg = _transport_message(_tl_frame(blob))

    other = _shared_key()
    other_fp = crypto.compute_secret_chat_fingerprint(other)
    keymap = {other_fp: MtprotoSecretChatKey(key_fingerprint=other_fp, shared_key=other)}
    stats = SecretChatStats()
    out = list(iter_secret_chat_messages([tmsg], keymap, stats=stats))

    assert out == []
    assert stats.blobs_seen == 0  # fingerprint never matched, so no blob seen


def test_iter_secret_chat_messages_counts_undecryptable():
    # A blob framed under a KNOWN fingerprint but encrypted with a different key:
    # the fingerprint matches (so it is "seen") yet msg_key verification fails.
    key = _shared_key()
    fp = crypto.compute_secret_chat_fingerprint(key)
    # Build a blob whose header carries fp but body is keyed by a foreign key.
    foreign = _shared_key()
    foreign_blob = bytearray(
        crypto.build_secret_chat_blob(foreign, b"x", sender_is_creator=True)
    )
    foreign_blob[:8] = fp  # rewrite the fingerprint header to a known one
    tmsg = _transport_message(_tl_frame(bytes(foreign_blob)))

    keymap = {fp: MtprotoSecretChatKey(key_fingerprint=fp, shared_key=key)}
    stats = SecretChatStats()
    out = list(iter_secret_chat_messages([tmsg], keymap, stats=stats))

    assert out == []
    assert stats.blobs_seen == 1
    assert stats.records_undecryptable == 1
