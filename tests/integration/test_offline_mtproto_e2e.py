"""Golden end-to-end test: synthetic Telegram pcap + keylog -> decrypted .tap.

Hermetic — no device, no real Telegram traffic, no tshark (the tshark seams are
monkeypatched; MTProto decryption is friTap's own and works on the synthetic
pcap directly). Proves the full Phase-B path: convert_pcap_to_tap(mtproto_keylog=…)
decrypts the obfuscated MTProto stream into an MtprotoLayer flow in the .tap.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("cryptography")

from scapy.utils import wrpcap

import friTap.offline.pcap_to_tap as p2t
from friTap.flow.layers import MtprotoLayer
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
    _stamp_capture_times,
)


def test_offline_mtproto_golden(tmp_path, monkeypatch):
    _patch_tshark(monkeypatch)

    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    msg_c2s = b"TG client->server hello"
    msg_s2c = b"TG server->client reply"

    rec_c2s = crypto.build_encrypted_record(auth_key, msg_c2s, "write")
    rec_s2c = crypto.build_encrypted_record(auth_key, msg_s2c, "read")

    init = _build_init(b"\xee\xee\xee\xee")  # intermediate transport tag
    client_wire, server_wire = _obfuscate(init, _intermediate(rec_c2s), _intermediate(rec_s2c))

    # Build the pcap: SYN, client data (split + out-of-order + a retransmit), server reply.
    base_c, base_s = 1000, 5000
    half = len(client_wire) // 2
    pkts = [
        _seg(CLIENT, SERVER, base_c, b"", syn=True),
        # out-of-order: second half first, then first half, then retransmit first half
        _seg(CLIENT, SERVER, base_c + 1 + half, client_wire[half:]),
        _seg(CLIENT, SERVER, base_c + 1, client_wire[:half]),
        _seg(CLIENT, SERVER, base_c + 1, client_wire[:half]),  # retransmit (dup)
        _seg(SERVER, CLIENT, base_s, server_wire),
    ]
    pcap_path = str(tmp_path / "tg.pcapng")
    wrpcap(pcap_path, _stamp_capture_times(pkts))

    # Write the MTProto keylog.
    keylog_path = str(tmp_path / "tg.keys")
    line = spec.format_line(
        dc_id=2,
        auth_key_id=crypto.compute_auth_key_id(auth_key).hex(),
        auth_key=auth_key.hex(),
        key_type="temp",
    )
    assert line is not None
    with open(keylog_path, "w") as fh:
        fh.write(spec.HEADER_COMMENT + "\n" + line + "\n")

    tap_path = str(tmp_path / "tg.tap")
    result = p2t.convert_pcap_to_tap(pcap_path, mtproto_keylog=keylog_path, tap_path=tap_path)

    # Both directions decrypted.
    assert result.mtproto_messages == 2
    assert result.mtproto_records_undecryptable == 0
    assert result.decrypted_packet_count == 2
    assert result.flow_count >= 1

    # The .tap round-trips an MTProto flow carrying the decrypted message bytes.
    reader = TapReader(tap_path)
    reader.open()
    flows = reader.read_all_flows()
    mtproto_flows = [f for f in flows if f.transport == "mtproto"]
    # One flow per decrypted packet (T1), each with the packet's real direction.
    assert len(mtproto_flows) == 2
    sent, received = sorted(mtproto_flows, key=lambda f: f.started)
    for flow in (sent, received):
        assert isinstance(flow.mtproto, MtprotoLayer)
        assert len(flow.chunks) == 1
    assert msg_c2s in sent.get_direction_bytes("write")
    assert msg_s2c in received.get_direction_bytes("read")
    assert (received.src_addr, received.dst_addr) == (sent.dst_addr, sent.src_addr)


def test_offline_mtproto_wrong_key_undecryptable(tmp_path, monkeypatch):
    _patch_tshark(monkeypatch)

    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    rec = crypto.build_encrypted_record(auth_key, b"secret", "write")
    init = _build_init(b"\xee\xee\xee\xee")
    client_wire, _ = _obfuscate(init, _intermediate(rec), b"")

    pkts = [
        _seg(CLIENT, SERVER, 1000, b"", syn=True),
        _seg(CLIENT, SERVER, 1001, client_wire),
    ]
    pcap_path = str(tmp_path / "tg.pcapng")
    wrpcap(pcap_path, _stamp_capture_times(pkts))

    # Keylog with a DIFFERENT auth_key -> auth_key_id won't match -> undecryptable.
    wrong = os.urandom(crypto.AUTH_KEY_LEN)
    keylog_path = str(tmp_path / "tg.keys")
    with open(keylog_path, "w") as fh:
        fh.write(spec.format_line(
            dc_id=2,
            auth_key_id=crypto.compute_auth_key_id(wrong).hex(),
            auth_key=wrong.hex(),
        ) + "\n")

    result = p2t.convert_pcap_to_tap(
        pcap_path, mtproto_keylog=keylog_path, tap_path=str(tmp_path / "tg.tap"))
    assert result.mtproto_messages == 0
    assert result.mtproto_records_undecryptable >= 1


def test_stamp_capture_times_overrides_wall_clock_order():
    # Construction-time (wall-clock) stamps that run backwards with a >30 s gap:
    # exactly the order that split the golden flow in two before pinning.
    pkts = [_seg(CLIENT, SERVER, 1000 + i, b"x") for i in range(3)]
    for pkt, wall in zip(pkts, (3000.0, 2000.0, 1000.0)):
        pkt.time = wall

    stamped = _stamp_capture_times(pkts, start=10.0, step=0.5)

    assert stamped is pkts
    assert [float(p.time) for p in pkts] == [10.0, 10.5, 11.0]
