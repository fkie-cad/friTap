"""Real-tshark integration test for the TLS 1.2 Schannel oracle.

Proves that the in-Python TLS 1.2 oracle produces exactly the same correlation as
the tshark-only path on a real multi-suite TLS 1.2 capture — including the CBC
connection (now decrypted in Python via the Encrypt-then-MAC path) and a resumed
session (a second client_random sharing the first's master).

The fixture (tests/fixtures/schannel_tls12.pcap + .keylog) is five real
Python-ssl TLS 1.2 connections: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, one
CBC suite, and a resumed AES-128-GCM session. Regenerate it with
``python dev/gen_tls12_fixture.py`` (no capture privileges needed).
"""
from __future__ import annotations

import os

import pytest

from friTap.offline import tshark as tshark_mod
from friTap.offline.schannel import correlate as sc
from friTap.offline.schannel import oracle as oc

_FIXTURE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures"))
_PCAP = os.path.join(_FIXTURE_DIR, "schannel_tls12.pcap")
_KEYLOG = os.path.join(_FIXTURE_DIR, "schannel_tls12.keylog")


def _fixtures_available() -> bool:
    try:
        tshark_mod.find_tshark()
    except RuntimeError:
        return False
    return os.path.isfile(_PCAP) and os.path.isfile(_KEYLOG)


pytestmark = pytest.mark.skipif(
    not _fixtures_available(),
    reason="real tshark binary or TLS 1.2 fixture unavailable",
)


def _masters() -> list[str]:
    out: list[str] = []
    for line in open(_KEYLOG, encoding="utf-8"):
        if line.startswith("CLIENT_RANDOM"):
            out.append(line.split()[2])
    return list(dict.fromkeys(out))


def test_oracle_matches_tshark_only():
    tshark = tshark_mod.find_tshark()
    masters = _masters()
    with_oracle = sc.correlate_tls12(tshark, _PCAP, masters)
    tshark_only = sc.correlate_tls12(tshark, _PCAP, masters, oracle=None)
    assert sorted(with_oracle) == sorted(tshark_only)
    # Every client_random (5: the four distinct connections plus the resumed one)
    # is paired, including the EtM CBC stream now decided in Python.
    assert len(with_oracle) == 5


def test_oracle_decides_every_stream_in_python():
    # The oracle now answers True for all five streams — the three AEAD suites,
    # the resumed AEAD session, and the Encrypt-then-MAC CBC connection — so
    # tshark is not needed for any of them.
    oracle = oc.TrialOracle.from_pcap(_PCAP)
    assert oracle is not None
    verdicts = []
    for line in open(_KEYLOG, encoding="utf-8"):
        if not line.startswith("CLIENT_RANDOM"):
            continue
        _, cr, master = line.split()
        verdicts.append(oracle.tls12_match(cr, master))
    assert verdicts.count(True) == 5      # 3 AEAD + 1 resumed AEAD + 1 EtM CBC
    assert verdicts.count(None) == 0      # nothing falls back to tshark
    assert False not in verdicts


def test_resumed_session_shares_master():
    # The resumed connection's client_random maps to the same master as the first
    # AES-128-GCM connection; both must correlate.
    masters = _masters()
    tshark = tshark_mod.find_tshark()
    lines = sc.correlate_tls12(tshark, _PCAP, masters)
    placed_masters = [ln.split()[2] for ln in lines]
    # A master shared by two client randoms appears on two lines.
    assert any(placed_masters.count(m) >= 2 for m in set(placed_masters))
