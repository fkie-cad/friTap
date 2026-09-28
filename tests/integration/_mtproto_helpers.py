"""Shared scaffolding for the hermetic MTProto / Telegram offline e2e tests.

Both ``test_offline_mtproto_e2e`` and ``test_offline_telegram_e2e`` build a
synthetic obfuscated MTProto stream over a fake TCP flow and run it through the
real ``convert_pcap_to_tap`` path with the tshark seams monkeypatched. The
stream-construction primitives are identical between the two, so they live here.
"""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

import friTap.offline.pcap_to_tap as p2t
from friTap.offline.mtproto.transport import derive_obfuscation_keys
from tests.unit._mtproto_helpers import aes_ctr as _ctr
from tests.unit._mtproto_helpers import (
    build_obf_init as _build_init,  # noqa: F401 - re-exported
)
from tests.unit._mtproto_helpers import (
    intermediate_frame as _intermediate,  # noqa: F401 - re-exported
)

CLIENT = ("10.0.0.5", 50000)
SERVER = ("149.154.167.51", 443)


def _obfuscate(init: bytes, client_payload: bytes, server_payload: bytes):
    key_out, iv_out, key_in, iv_in = derive_obfuscation_keys(init)
    out = _ctr(key_out, iv_out)
    out.update(init)  # advance over the 64 init bytes (they are on the wire as-is)
    client_wire = init + out.update(client_payload)
    server_wire = _ctr(key_in, iv_in).update(server_payload)
    return client_wire, server_wire


def _seg(src, dst, seq, payload, syn=False):
    return (
        IP(src=src[0], dst=dst[0])
        / TCP(sport=src[1], dport=dst[1], seq=seq, flags=("S" if syn else "PA"))
        / Raw(load=payload)
    )


CAPTURE_EPOCH = 1_700_000_000.0  # fixed, arbitrary capture start
CAPTURE_STEP = 0.001  # 1 ms between packets: strictly increasing, never idle


def _stamp_capture_times(pkts, start=CAPTURE_EPOCH, step=CAPTURE_STEP):
    """Give *pkts* deterministic, strictly increasing capture times, in list order.

    scapy stamps each packet with ``time.time()`` at construction, so without this
    the pcap timestamps come from the wall clock. The decrypted messages are
    time-ordered from them and the collector splits flows on them (a reply that
    sorts before its request, or a >30 s idle gap, yields a second flow), so a
    wall-clock step or a suspended process makes the golden tests flaky.
    """
    for index, pkt in enumerate(pkts):
        pkt.time = start + index * step
    return pkts


def _patch_tshark(monkeypatch):
    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "warn_if_outdated", lambda *a, **k: None)
    monkeypatch.setattr(p2t, "capture_has_dsb", lambda *a, **k: False)
    # SSH metadata pass shells out to tshark; no-op it for the hermetic run.
    monkeypatch.setattr(p2t, "_emit_ssh_connections", lambda *a, **k: None)
