"""Real-capture MtE AES-CBC validation for the TLS 1.2 oracle.

The ``schannel_tls12`` fixture's only CBC connection negotiates Encrypt-then-MAC
(RFC 7366), so the classic MAC-then-encrypt (MtE) CBC path shipped validated only
by self-consistent unit vectors. This test closes that gap with a real,
multi-suite OpenSSL capture: ``tests/fixtures/dump_premaster.pcapng`` +
``premaster.txt`` — 73 TLS 1.2 cipher suites, two connections each (a full
handshake and a resumption sharing its master), keyed in NSS ``CLIENT_RANDOM``
master-secret format.

Two real-world properties make this capture valuable precisely because they are
awkward:

* It uses **legacy TLS record compression** (DEFLATE), so a correctly decrypted
  ``Finished`` is a compressed stream, not a ``0x14`` handshake byte. The oracle
  must therefore treat such a record as "cannot tell" (``None`` → defer to
  tshark), never "wrong master" (``False``) — otherwise a valid key would be
  silently excluded. We assert that distinction holds on real records: the right
  master authenticates (HMAC verifies) and yields ``None``, while a wrong master
  fails the HMAC and yields ``False``. Only a correct key block + CBC decrypt +
  padding strip + HMAC over the real record can produce that asymmetry, so it is
  an end-to-end check of the MtE path on real multi-suite data.
* Because the oracle defers every compressed stream, tshark still has to decrypt
  them — and must recover exactly as many as the tshark-only path (no master
  dropped). That end-to-end guard is the ``slow`` test below.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("cryptography")

from friTap.offline import tshark as tshark_mod
from friTap.offline.schannel import correlate as sc
from friTap.offline.schannel import oracle as oc

_FIXTURE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures"))
_PCAP = os.path.join(_FIXTURE_DIR, "dump_premaster.pcapng")
_KEYLOG = os.path.join(_FIXTURE_DIR, "premaster.txt")

# Every AES-CBC suite the keylog labels, across all key exchanges in the capture
# (RSA, DHE-DSS, DHE-RSA, ECDH/ECDHE with RSA or ECDSA auth) and all three MACs
# (SHA1 / SHA256 / SHA384). The record protection — hence what the peel must get
# right — depends only on the AES key length and MAC, so all 28 exercise the same
# small set of parameter tuples under real, independently keyed streams.
_SUPPORTED_CBC = {
    "AES128-SHA": 0x002F, "AES256-SHA": 0x0035,
    "AES128-SHA256": 0x003C, "AES256-SHA256": 0x003D,
    "DHE-DSS-AES128-SHA": 0x0032, "DHE-DSS-AES256-SHA": 0x0038,
    "DHE-DSS-AES128-SHA256": 0x0040, "DHE-DSS-AES256-SHA256": 0x006A,
    "DHE-RSA-AES128-SHA": 0x0033, "DHE-RSA-AES256-SHA": 0x0039,
    "DHE-RSA-AES128-SHA256": 0x0067, "DHE-RSA-AES256-SHA256": 0x006B,
    "ECDH-ECDSA-AES128-SHA": 0xC004, "ECDH-ECDSA-AES256-SHA": 0xC005,
    "ECDH-ECDSA-AES128-SHA256": 0xC025, "ECDH-ECDSA-AES256-SHA384": 0xC026,
    "ECDH-RSA-AES128-SHA": 0xC00E, "ECDH-RSA-AES256-SHA": 0xC00F,
    "ECDH-RSA-AES128-SHA256": 0xC029, "ECDH-RSA-AES256-SHA384": 0xC02A,
    "ECDHE-ECDSA-AES128-SHA": 0xC009, "ECDHE-ECDSA-AES256-SHA": 0xC00A,
    "ECDHE-ECDSA-AES128-SHA256": 0xC023, "ECDHE-ECDSA-AES256-SHA384": 0xC024,
    "ECDHE-RSA-AES128-SHA": 0xC013, "ECDHE-RSA-AES256-SHA": 0xC014,
    "ECDHE-RSA-AES128-SHA256": 0xC027, "ECDHE-RSA-AES256-SHA384": 0xC028,
}

# Legacy record ciphers friTap deliberately does not decrypt — they must defer to
# tshark (both the right and a wrong master give ``None``, never ``False``).
_UNSUPPORTED_LEGACY = ["DES-CBC3-SHA", "CAMELLIA256-SHA", "SEED-SHA", "RC4-SHA"]


def _fixtures_available() -> bool:
    return os.path.isfile(_PCAP) and os.path.isfile(_KEYLOG)


pytestmark = pytest.mark.skipif(
    not _fixtures_available(), reason="dump_premaster fixture unavailable")


def _keylog_by_suite() -> dict[str, list[tuple[str, str]]]:
    """``suite_label -> [(client_random, master), ...]`` from the keylog comments."""
    out: dict[str, list[tuple[str, str]]] = {}
    label = None
    for line in open(_KEYLOG, encoding="utf-8"):
        s = line.strip()
        if s.startswith("# Cipher Suite"):
            label = s.split("# Cipher Suite", 1)[1].strip()
        elif s.startswith("CLIENT_RANDOM"):
            _, cr, master = s.split()
            out.setdefault(label, []).append((cr, master))
    return out


def _flip(master: str) -> str:
    """A definitely-wrong master: the real one with its first byte inverted."""
    b = bytearray.fromhex(master)
    b[0] ^= 0xFF
    return b.hex()


@pytest.fixture(scope="module")
def oracle():
    o = oc.TrialOracle.from_pcap(_PCAP)
    if o is None:
        pytest.skip("oracle backend unavailable")
    return o


@pytest.fixture(scope="module")
def keylog():
    return _keylog_by_suite()


@pytest.mark.parametrize("label", sorted(_SUPPORTED_CBC))
def test_mte_cbc_record_authenticates_on_real_capture(oracle, keylog, label):
    """A real AES-CBC MtE record authenticates: right master None, wrong master False.

    The capture is DEFLATE-compressed, so a correct master cannot be confirmed as
    a Finished (``None``), but it still passes the record HMAC; a wrong master
    fails it (``False``). That asymmetry on a real, clean stream is only possible
    if the whole MtE CBC peel — ``cbc_key_block`` from the real master/randoms,
    AES-CBC decrypt, TLS padding strip, HMAC — is correct for this suite.
    """
    for cr, master in keylog[label]:
        # A wrong master yielding False means this is a clean, decryptable stream
        # (the HMAC ran and rejected it) rather than a stream the oracle skips.
        if oracle.tls12_match(cr, _flip(master)) is False:
            assert oracle.tls12_match(cr, master) is None
            return
    pytest.fail(f"no clean {label} stream found in the capture")


@pytest.mark.parametrize("label", _UNSUPPORTED_LEGACY)
def test_legacy_cipher_defers_to_tshark(oracle, keylog, label):
    """A non-AES record cipher is not decrypted in Python: a clean stream returns
    None for both the right and a wrong master (defer to tshark), never False —
    so these suites keep working via the fallback without a bogus exclusion."""
    for cr, master in keylog[label]:
        if oracle._clean_stream(cr) is not None:   # noqa: SLF001 - clean-stream check
            assert oracle.tls12_match(cr, master) is None
            assert oracle.tls12_match(cr, _flip(master)) is None
            return
    pytest.skip(f"no clean {label} stream in the capture")


def test_streams_are_tls12_mte_not_etm(oracle, keylog):
    """Spot-check that these really are TLS 1.2 MtE streams (not EtM, not 1.3).

    Complements the EtM coverage in test_schannel_tls12_correlate_e2e.py.
    """
    sh = None
    for cr, _ in keylog["ECDHE-RSA-AES128-SHA"]:
        stream = oracle._clean_stream(cr)   # noqa: SLF001 - internals spot-check
        if stream is not None:
            sh = stream.server_hello
            break
    assert sh is not None
    assert sh.version == 0x0303          # TLS 1.2
    assert sh.cipher_suite == 0xC013     # ECDHE_RSA_AES_128_CBC_SHA
    assert sh.uses_etm is False          # MAC-then-encrypt, the gap this closes


@pytest.mark.slow
def test_oracle_never_drops_a_valid_master(keylog):
    """End-to-end: deferring compressed streams to tshark loses no key.

    With the oracle, every stream here defers (``None``) because of compression,
    so tshark must recover all of them — and exactly the tshark-only set. Before
    the oracle treated an authenticated-but-unconfirmable record as ``None``, it
    returned ``False`` and these masters were excluded; this guards that fix.
    """
    try:
        tshark = tshark_mod.find_tshark()
    except RuntimeError:
        pytest.skip("real tshark binary unavailable")
    masters = list(dict.fromkeys(m for pairs in keylog.values() for _, m in pairs))
    with_oracle = sc.correlate_tls12(tshark, _PCAP, masters)
    tshark_only = sc.correlate_tls12(tshark, _PCAP, masters, oracle=None)
    assert sorted(with_oracle) == sorted(tshark_only)
    assert len(with_oracle) == 70
