"""Golden end-to-end test: synthetic Telegram pcap + combined keylog -> .tap.

Hermetic — no device, no real Telegram traffic, no tshark (the tshark seams are
monkeypatched; Telegram decryption is friTap's own and works on the synthetic
pcap directly). Proves the combined ``telegram`` offline path: one keylog holding
BOTH an ``MTPROTO_AUTH_KEY`` (cloud) and an ``MTPROTO_E2E_KEY`` (Secret-Chat)
line decrypts the cloud transport stream AND the Secret-Chat E2E blob carried
inside it, producing a ``mtproto`` cloud flow and a ``telegram_e2e`` flow in the
.tap.

Built on top of the MTProto golden test's helpers: the cloud transport record's
inner message is itself a TL-``bytes``-framed Secret-Chat E2E blob, so the same
obfuscated-stream construction carries the secret chat.
"""

from __future__ import annotations

import os
import struct

import pytest

pytest.importorskip("cryptography")

from scapy.utils import wrpcap

import friTap.offline.pcap_to_tap as p2t
from friTap.flow.layers import TelegramE2ELayer
from friTap.flow.tap_reader import TapReader
from friTap.offline.mtproto import crypto
from friTap.protocols import mtproto_keylog_spec as spec

from ._mtproto_helpers import (
    CLIENT,
    SERVER,
    _build_init,
    _intermediate,
    _obfuscate,
    _patch_tshark,
    _seg,
)


def _tl_bytes(payload: bytes) -> bytes:
    """Frame *payload* as a TL ``bytes`` field (short form: single length byte).

    The Secret-Chat blob (header 24 + small body) stays < 254 bytes, so the
    short form applies; the E2E scanner reads exactly this framing.
    """
    assert len(payload) < 254
    return struct.pack("<B", len(payload)) + payload


def test_offline_telegram_golden(tmp_path, monkeypatch):
    _patch_tshark(monkeypatch)

    # --- Secret-Chat (E2E) layer: the per-chat shared key + its blob. ---
    shared_key = os.urandom(crypto.SECRET_CHAT_KEY_LEN)
    e2e_payload = b"secret chat hello"
    blob = crypto.build_secret_chat_blob(
        shared_key, e2e_payload, sender_is_creator=True)
    framed_blob = _tl_bytes(blob)

    # --- Cloud transport layer: the auth key carries the E2E blob as its body. ---
    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    msg_s2c = b"TG server->client reply"

    # client->server transport message body = the TL-bytes-framed E2E blob.
    rec_c2s = crypto.build_encrypted_record(auth_key, framed_blob, "write")
    rec_s2c = crypto.build_encrypted_record(auth_key, msg_s2c, "read")

    init = _build_init(b"\xee\xee\xee\xee")  # intermediate transport tag
    client_wire, server_wire = _obfuscate(
        init, _intermediate(rec_c2s), _intermediate(rec_s2c))

    pkts = [
        _seg(CLIENT, SERVER, 1000, b"", syn=True),
        _seg(CLIENT, SERVER, 1001, client_wire),
        _seg(SERVER, CLIENT, 5000, server_wire),
    ]
    pcap_path = str(tmp_path / "tg.pcapng")
    wrpcap(pcap_path, pkts)

    # --- Combined Telegram keylog: one cloud line + one E2E line. ---
    keylog_path = str(tmp_path / "tg.keys")
    cloud_line = spec.format_line(
        dc_id=2,
        auth_key_id=crypto.compute_auth_key_id(auth_key).hex(),
        auth_key=auth_key.hex(),
        key_type="temp",
    )
    e2e_line = spec.format_e2e_line(
        key_fingerprint=crypto.compute_secret_chat_fingerprint(shared_key).hex(),
        shared_key=shared_key.hex(),
        chat_id=7,
    )
    assert cloud_line is not None and e2e_line is not None
    with open(keylog_path, "w") as fh:
        fh.write(cloud_line + "\n" + e2e_line + "\n")

    tap_path = str(tmp_path / "tg.tap")
    result = p2t.convert_pcap_to_tap(
        pcap_path,
        protocol_keylogs={"telegram": keylog_path},
        tap_path=tap_path,
    )

    # Cloud + secret-chat messages both decrypted (2 cloud transport messages,
    # 1 embedded E2E message).
    assert result.per_protocol["telegram"]["messages"] == 3
    assert result.per_protocol["telegram"]["undecryptable"] == 0
    assert result.decrypted_packet_count == 3

    # The .tap round-trips both a cloud (mtproto) flow and a telegram_e2e flow.
    reader = TapReader(tap_path)
    reader.open()
    flows = reader.read_all_flows()

    e2e_flows = [f for f in flows if f.transport == "telegram_e2e"]
    assert e2e_flows, "expected at least one telegram_e2e flow"
    e2e_flow = e2e_flows[0]
    assert isinstance(e2e_flow.layer("telegram_e2e"), TelegramE2ELayer)
    e2e_blob = (e2e_flow.get_direction_bytes("write")
                + e2e_flow.get_direction_bytes("read"))
    assert e2e_payload in e2e_blob

    mtproto_flows = [f for f in flows if f.transport == "mtproto"]
    assert mtproto_flows, "expected at least one mtproto (cloud) flow"
    cloud_blob = b"".join(
        f.get_direction_bytes("write") + f.get_direction_bytes("read")
        for f in mtproto_flows
    )
    assert msg_s2c in cloud_blob
