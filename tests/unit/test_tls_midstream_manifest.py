#!/usr/bin/env python3

"""Manifest wiring for the mid-stream TLS secret-bundle sidecar (Phase 2.3).

Covers, without a device or a capture:

  * :func:`friTap.memory_scanning._sidecar_paths_for` registers the new
    ``tls_midstream_secrets`` sidecar path co-located with the memscan keylog;
  * :func:`friTap.memory_scanning.build_memory_scan_engine` forwards it to the
    engine ctor as ``tls_secret_bundle_path``;
  * ``PCAP._write_capture_manifest`` emits ``tls_midstream_secrets`` into
    ``<pcap>.fritap.json`` only when the sidecar file exists with content.
"""

from __future__ import annotations

import json
import logging
import types
from types import SimpleNamespace

from friTap import memory_scanning as ms
from friTap.pcap import PCAP


# --------------------------------------------------------------------------- #
# _sidecar_paths_for + build_memory_scan_engine
# --------------------------------------------------------------------------- #

def test_sidecar_paths_for_includes_tls_midstream_secrets():
    paths = ms._sidecar_paths_for("/tmp/Telegram_memscan.keylog")
    assert paths["tls_midstream_secrets"] == \
        "/tmp/Telegram_memscan.tls_midstream.secrets.jsonl"
    # Existing siblings are unchanged.
    assert paths["rc4"] == "/tmp/Telegram_memscan.rc4.keylog"
    assert paths["mtproto"] == "/tmp/Telegram_memscan.mtproto.keylog"


def test_build_engine_forwards_tls_secret_bundle_path(monkeypatch):
    expected = "/tmp/x_memscan.tls_midstream.secrets.jsonl"
    monkeypatch.setattr(
        ms, "memory_scan_sidecar_paths",
        lambda config: {"tls_midstream_secrets": expected},
    )
    cfg = SimpleNamespace(
        hooking=SimpleNamespace(
            memory_scan_patterns=None,
            memory_scan_interval=2.0,
            memory_scan_emit_unconfirmed=False,
            memory_scan_rc4_known_plaintext=None,
            memory_scan_rc4_ciphertext=None,
        ),
        protocols=[],
        install_lsass_hook=True,
    )
    engine = ms.build_memory_scan_engine(cfg)
    assert engine._tls_secret_bundle_path == expected


# --------------------------------------------------------------------------- #
# PCAP._write_capture_manifest emission
# --------------------------------------------------------------------------- #

def _make_stub(pcap_file_name):
    """Minimal stub exposing _write_capture_manifest bound to it (see
    test_pcap_server_port for the stub pattern)."""
    stub = types.SimpleNamespace()
    stub.pcap_file_name = pcap_file_name
    stub.logger = logging.getLogger("test_tls_midstream_manifest")
    stub._observed_server_ports = {"tcp": {443}, "udp": set()}
    stub.keylog_path = None
    stub.capture_protocol = "tls"
    stub.memory_scan_keylogs = {}
    stub._write_capture_manifest = PCAP._write_capture_manifest.__get__(stub)
    for name, attr in vars(PCAP).items():
        if isinstance(attr, staticmethod):
            setattr(stub, name, attr.__func__)
    return stub


def _load_manifest(pcap_path):
    with open(f"{pcap_path}.fritap.json", encoding="utf-8") as fh:
        return json.load(fh)


def test_manifest_emits_tls_midstream_secrets_when_present(tmp_path):
    pcap = tmp_path / "capture.pcap"
    memscan_keylog = tmp_path / "capture_memscan.keylog"
    sidecar = tmp_path / "capture_memscan.tls_midstream.secrets.jsonl"
    sidecar.write_text(json.dumps({"client_traffic_secret_0": "ab" * 32}) + "\n")

    stub = _make_stub(str(pcap))
    # The RAW mapping supplies the memscan-keylog stem the sidecar is derived from.
    stub.memory_scan_keylogs = {"tls": str(memscan_keylog)}
    stub._write_capture_manifest()

    manifest = _load_manifest(pcap)
    assert manifest["tls_midstream_secrets"] == str(sidecar)


def test_manifest_omits_tls_midstream_secrets_when_absent(tmp_path):
    pcap = tmp_path / "capture.pcap"
    memscan_keylog = tmp_path / "capture_memscan.keylog"

    stub = _make_stub(str(pcap))
    stub.memory_scan_keylogs = {"tls": str(memscan_keylog)}  # but no sidecar file
    stub._write_capture_manifest()

    assert "tls_midstream_secrets" not in _load_manifest(pcap)


def test_manifest_omits_when_sidecar_empty(tmp_path):
    pcap = tmp_path / "capture.pcap"
    memscan_keylog = tmp_path / "capture_memscan.keylog"
    (tmp_path / "capture_memscan.tls_midstream.secrets.jsonl").write_text("")

    stub = _make_stub(str(pcap))
    stub.memory_scan_keylogs = {"tls": str(memscan_keylog)}
    stub._write_capture_manifest()

    assert "tls_midstream_secrets" not in _load_manifest(pcap)
