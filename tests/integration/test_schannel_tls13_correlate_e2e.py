#!/usr/bin/env python3

"""Real-tshark integration test locking the S1 fix on an actual TLS 1.3 capture.

S1: a recovered TLS 1.3 traffic secret must be trial-placed under its CORRECT
NSS label by decryption, using a signal that is only present after the AEAD tag
verifies — never `tls.app_data` (encrypted, always present) and never bare
`tls.record.content_type` (also present on the PLAINTEXT ClientHello/ServerHello).
The correct signal is the decrypted inner `tls.record.content_type==23`
(application_data). See friTap/offline/schannel/correlate.py::TLS13_PROBE_SIGNAL.

The fixture (tests/fixtures/schannel_tls13.pcap + .keylog) is a real Python-ssl
TLS 1.3 session with application data BOTH directions, so the keylog carries both
CLIENT_TRAFFIC_SECRET_0 and SERVER_TRAFFIC_SECRET_0. Regenerate it with
`python dev/gen_tls13_fixture.py` (no capture privileges needed — see that file).

This complements the tshark-free model test in
tests/unit/test_schannel_correlate.py (test_correlate_tls13_places_traffic_
secrets_under_correct_label): the model locks the orchestration logic; this locks
the real tshark field semantics the logic depends on.
"""

from __future__ import annotations

import os

import pytest

from friTap.offline import tshark as tshark_mod
from friTap.offline.schannel import correlate as sc

_FIXTURE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fixtures"))
_PCAP = os.path.join(_FIXTURE_DIR, "schannel_tls13.pcap")
_KEYLOG = os.path.join(_FIXTURE_DIR, "schannel_tls13.keylog")

# Labels that protect records and can therefore be confirmed by trial decryption.
# EXPORTER_SECRET protects no records, so it is never placed by decryption.
_DECRYPTABLE = {
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
}


def _fixtures_available() -> bool:
    try:
        tshark_mod.find_tshark()
    except RuntimeError:
        return False
    return os.path.isfile(_PCAP) and os.path.isfile(_KEYLOG)


def _ground_truth() -> dict[str, str]:
    """secret(hex) -> true NSS label, from the server's own keylog."""
    truth: dict[str, str] = {}
    for line in open(_KEYLOG, encoding="utf-8"):
        if not line.strip() or line.startswith("#"):
            continue
        label, _cr, secret = line.split()
        truth[secret] = label
    return truth


pytestmark = pytest.mark.skipif(
    not _fixtures_available(),
    reason="real tshark binary or TLS 1.3 fixture unavailable",
)


def test_correlate_tls13_places_every_secret_under_its_true_label(tmp_path):
    # Feed the recovered secrets as BARE hexes (labels stripped), exactly as the
    # mem-scan sidecar emits them unpaired. correlate_tls13 must re-derive each
    # label by trial decryption and land it on the ground-truth label — in
    # particular the CLIENT traffic secret under CLIENT_TRAFFIC_SECRET_0, NOT
    # SERVER_TRAFFIC_SECRET_0 (the S1 mislabel).
    tshark = tshark_mod.find_tshark()
    truth = _ground_truth()

    records = sc.parse_tls13_records("\n".join(truth) + "\n")
    lines = sc.correlate_tls13(tshark, _PCAP, records)

    placed = {ln.split()[2]: ln.split()[0] for ln in lines}
    for secret, true_label in truth.items():
        if true_label not in _DECRYPTABLE:
            continue
        assert placed.get(secret) == true_label, (
            f"secret for {true_label} was placed as {placed.get(secret)!r}"
        )


def test_produced_keylog_decrypts_both_directions(tmp_path):
    # The keylog correlate_tls13 produces must let tshark decrypt BOTH directions:
    # the client's GET request (CLIENT_TRAFFIC_SECRET_0) and the server's 200
    # response (SERVER_TRAFFIC_SECRET_0).
    tshark = tshark_mod.find_tshark()
    truth = _ground_truth()
    records = sc.parse_tls13_records("\n".join(truth) + "\n")
    lines = sc.correlate_tls13(tshark, _PCAP, records)

    keylog = tmp_path / "produced.keylog"
    keylog.write_text("".join(lines), encoding="utf-8")

    out = tshark_mod._run_capture([
        tshark, "-r", _PCAP,
        "-o", f"tls.keylog_file:{keylog}",
        "-o", "tls.ignore_ssl_mac_failed:FALSE",
        "-Y", "http", "-T", "fields",
        "-e", "http.request.method", "-e", "http.response.code",
    ])
    methods = {c.strip() for row in out.splitlines() for c in row.split("\t") if c.strip()}
    assert "GET" in methods       # client -> server app data decrypted
    assert "200" in methods       # server -> client app data decrypted
