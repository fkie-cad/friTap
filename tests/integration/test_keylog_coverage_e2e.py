#!/usr/bin/env python3

"""Real-tshark checks for keylog coverage and the re-pair rescue.

Uses the TLS 1.3 fixture of test_schannel_tls13_correlate_e2e.py
(tests/fixtures/schannel_tls13.pcap + .keylog):

  * the fixture keylog (correct client_random) fully covers the capture;
  * the same secrets under a bogus client_random cover nothing, and
    ``repair_keylog`` re-pairs them by trial decryption so the repaired keylog
    covers the handshake again.
"""

from __future__ import annotations

import os

import pytest

from friTap.offline import keylog_coverage as kc
from friTap.offline import tshark as tshark_mod
from friTap.offline.schannel import correlate as sc

_FIXTURE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures"))
_PCAP = os.path.join(_FIXTURE_DIR, "schannel_tls13.pcap")
_KEYLOG = os.path.join(_FIXTURE_DIR, "schannel_tls13.keylog")
_BOGUS_CR = "ab" * 32


def _fixtures_available() -> bool:
    try:
        tshark_mod.find_tshark()
    except RuntimeError:
        return False
    return os.path.isfile(_PCAP) and os.path.isfile(_KEYLOG)


pytestmark = pytest.mark.skipif(
    not _fixtures_available(),
    reason="real tshark binary or TLS 1.3 fixture unavailable",
)


def _bogus_keylog(tmp_path) -> str:
    """The fixture keylog with every client_random replaced (CRLF endings)."""
    lines = []
    for line in open(_KEYLOG, encoding="utf-8"):
        if line.strip() and not line.startswith("#"):
            label, _cr, secret = line.split()
            lines.append(f"{label} {_BOGUS_CR} {secret}\r\n")
    path = tmp_path / "keys_bogus.log"
    path.write_bytes("".join(lines).encode())
    return str(path)


def test_capture_handshake_is_read():
    capture = kc.read_capture_handshakes(tshark_mod.find_tshark(), _PCAP)
    assert len(capture.handshakes) == 1
    assert capture.handshakes[0].version == "TLS 1.3"
    assert capture.handshakes[0].sni == "localhost"


def test_correct_keylog_fully_covers():
    coverage = kc.check_keylog_coverage(tshark_mod.find_tshark(), _PCAP, _KEYLOG)
    assert (len(coverage.covered), coverage.total) == (1, 1)
    assert kc.describe(coverage)[0] == "ok"


def test_bogus_client_random_repaired_by_trial_decryption(tmp_path):
    tshark = tshark_mod.find_tshark()
    capture = kc.read_capture_handshakes(tshark, _PCAP)
    bogus = _bogus_keylog(tmp_path)

    before = kc.check_keylog_coverage(tshark, _PCAP, bogus, capture)
    assert len(before.covered) == 0
    assert kc.describe(before)[0] == "warning"

    result = kc.repair_keylog(tshark, _PCAP, bogus, capture=capture)
    assert result.repaired_path == str(tmp_path / "keys_bogus.repaired.keylog")
    assert result.matched_sessions == 1

    after = kc.check_keylog_coverage(tshark, _PCAP, result.repaired_path, capture)
    assert (len(after.covered), after.total) == (1, 1)
    # EXPORTER_SECRET has no decryptable signal; it rides along via its group.
    real_cr = capture.handshakes[0].client_random
    assert kc.keylog_client_randoms(result.repaired_path)[real_cr] == {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET",
    }
    # ... and it really decrypts application data (inner content_type 23).
    assert sc.streams_matching_filter(
        tshark, _PCAP, result.repaired_path, sc.TLS13_APP_DATA_SIGNAL) == {"0"}
