#!/usr/bin/env python3

"""Writer/reader agreement for the mid-stream TLS secret-bundle sidecar.

Covers, without a device or a capture:

  * :meth:`MemoryScanEngine._bundle_record` / ``_write_tls_secret_bundle`` now
    accept a bundle carrying only ``client_random`` + one traffic secret (the
    offline consumer needs just one), instead of the old all-or-nothing gate;
  * the record written that way is accepted by the offline
    :func:`friTap.offline.tls_midstream.pipeline.load_secret_bundles` /
    ``_valid_bundle``, proving writer and reader agree;
  * :meth:`MemoryScanEngine.intended_tls_secret_bundle_path` equals what the
    PCAP manifest advertises once ``set_tls_midstream_secrets_path`` is called —
    i.e. writer path == reader path even in the no-keylog CWD-literal fallback.
"""

from __future__ import annotations

import json

from friTap.memory_scanning.engine import MemoryScanEngine
from friTap.offline.tls_midstream import pipeline
from friTap.pcap import PCAP

# 64-hex (32-byte) randoms and a 64-hex traffic secret; all lowercase hex.
_CLIENT_RANDOM = "aa" * 32
_CLIENT_SECRET = "bb" * 32


def test_bundle_record_accepts_client_only(tmp_path):
    """A client_random + client_traffic_secret_0 bundle is a valid record."""
    engine = MemoryScanEngine(
        tls_secret_bundle_path=str(tmp_path / "x.tls_midstream.secrets.jsonl"))
    record = engine._bundle_record({
        "client_random": _CLIENT_RANDOM,
        "client_traffic_secret_0": _CLIENT_SECRET,
        # No server_random, no server secret, no exporter_secret.
    })
    assert record is not None
    assert record["client_random"] == _CLIENT_RANDOM
    assert record["client_traffic_secret_0"] == _CLIENT_SECRET
    # Absent optional fields are recorded as '' (tolerated downstream).
    assert record["server_random"] == ""
    assert record["server_traffic_secret_0"] == ""
    assert record["exporter_secret"] == ""


def test_bundle_record_rejects_no_traffic_secret(tmp_path):
    """client_random with neither traffic secret cannot decrypt -> dropped."""
    engine = MemoryScanEngine(
        tls_secret_bundle_path=str(tmp_path / "x.tls_midstream.secrets.jsonl"))
    assert engine._bundle_record({"client_random": _CLIENT_RANDOM}) is None


def test_write_client_only_bundle_one_line_reader_accepts(tmp_path):
    """The client-only bundle writes exactly one JSONL line the reader accepts."""
    path = tmp_path / "cap.tls_midstream.secrets.jsonl"
    engine = MemoryScanEngine(tls_secret_bundle_path=str(path))
    try:
        engine._write_tls_secret_bundle({
            "client_random": _CLIENT_RANDOM,
            "client_traffic_secret_0": _CLIENT_SECRET,
        })
        # A duplicate must NOT add a second line (dedup intact).
        engine._write_tls_secret_bundle({
            "client_random": _CLIENT_RANDOM,
            "client_traffic_secret_0": _CLIENT_SECRET,
        })
    finally:
        engine._close_tls_secret_bundle()

    lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert pipeline._valid_bundle(obj)

    bundles = pipeline.load_secret_bundles(str(path))
    assert len(bundles) == 1
    assert bundles[0]["client_traffic_secret_0"] == _CLIENT_SECRET


def test_intended_path_matches_pcap_advertisement_fallback():
    """Writer path == reader path in the no-keylog CWD-literal fallback."""
    # No tls_secret_bundle_path handed in -> engine uses its literal fallback.
    engine = MemoryScanEngine()
    intended = engine.intended_tls_secret_bundle_path()
    assert intended  # deterministic, non-empty

    pcap = PCAP.__new__(PCAP)  # skip heavy __init__; exercise the setter only
    pcap._tls_midstream_secrets_path = None
    pcap.set_tls_midstream_secrets_path(intended)
    assert pcap._tls_midstream_secrets_path == intended
