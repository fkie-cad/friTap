#!/usr/bin/env python3

"""Offline CLI (``fritap --from-pcap``): TLS mid-stream secret-bundle wiring.

The bug these cover: the manifest key ``tls_midstream_secrets`` (a path to a
``*.tls_midstream.secrets.jsonl`` sidecar written by a memory scan) was applied
by the Python API (``convert_pcap_to_tap``) but silently dropped by the offline
CLI's ``merge_manifest`` — so the headless workflow got no mid-stream TLS
decryption. These tests exercise only the CLI wiring: ``merge_manifest``, the
new ``--tls-midstream-secrets`` flag, and that the value reaches
``convert_pcap_to_tap``. tshark and the conversion are monkeypatched.
"""

from __future__ import annotations

import argparse
import json

import pytest

from friTap.offline import cli
from friTap.offline.pcap_to_tap import ConvertResult


def _ns(**kw) -> argparse.Namespace:
    """A minimal argparse Namespace as ``_build_parser`` would produce."""
    base = dict(
        keylog=None, tls_ports=[], quic_ports=[], decode_as=[],
        tls_heuristic=False, tls_midstream_secrets=None, from_pcap="",
    )
    base.update(kw)
    return argparse.Namespace(**base)


# --------------------------------------------------------------------------- #
# merge_manifest: manifest value / flag override / absence
# --------------------------------------------------------------------------- #

def test_merge_manifest_carries_tls_midstream_secrets_from_manifest():
    sidecar = "/abs/cap_memscan.tls_midstream.secrets.jsonl"
    merged = cli.merge_manifest(
        _ns(from_pcap="/abs/cap.pcapng"),
        {"tls_midstream_secrets": sidecar},
    )
    assert merged["tls_midstream_secrets"] == sidecar


def test_merge_manifest_flag_overrides_manifest():
    merged = cli.merge_manifest(
        _ns(from_pcap="/abs/cap.pcapng",
            tls_midstream_secrets="/abs/explicit.jsonl"),
        {"tls_midstream_secrets": "/abs/from_manifest.jsonl"},
    )
    assert merged["tls_midstream_secrets"] == "/abs/explicit.jsonl"


def test_merge_manifest_absent_yields_none():
    merged = cli.merge_manifest(_ns(from_pcap="/abs/cap.pcapng"), {})
    assert merged["tls_midstream_secrets"] is None


def test_merge_manifest_resolves_relative_manifest_path_against_pcap_dir():
    merged = cli.merge_manifest(
        _ns(from_pcap="/data/caps/cap.pcapng"),
        {"tls_midstream_secrets": "cap_memscan.tls_midstream.secrets.jsonl"},
    )
    assert merged["tls_midstream_secrets"] == (
        "/data/caps/cap_memscan.tls_midstream.secrets.jsonl"
    )


# --------------------------------------------------------------------------- #
# --tls-midstream-secrets flag parsing + help
# --------------------------------------------------------------------------- #

def test_flag_defaults_to_none():
    args = cli._build_parser().parse_args(["--from-pcap", "x.pcapng"])
    assert args.tls_midstream_secrets is None


def test_flag_parses_value():
    args = cli._build_parser().parse_args(
        ["--from-pcap", "x.pcapng", "--tls-midstream-secrets", "/p/s.jsonl"])
    assert args.tls_midstream_secrets == "/p/s.jsonl"


def test_flag_is_documented_in_help():
    assert "--tls-midstream-secrets" in cli._build_parser().format_help()


# --------------------------------------------------------------------------- #
# End-to-end wiring: the value reaches convert_pcap_to_tap
# --------------------------------------------------------------------------- #

class _Calls(list):
    result = ConvertResult(tap_path="out.tap", decrypted_packet_count=1)


@pytest.fixture
def convert_calls(monkeypatch):
    """Stub tshark + conversion; record each convert_pcap_to_tap call's kwargs."""
    calls = _Calls()

    def fake_convert(pcap, **kwargs):
        calls.append(kwargs)
        return calls.result

    monkeypatch.setattr(cli, "find_tshark", lambda *_a, **_k: "/fake/tshark")
    monkeypatch.setattr(cli, "convert_pcap_to_tap", fake_convert)
    monkeypatch.setattr(cli, "_keylog_coverage", lambda *_a, **_k: None)
    return calls


def test_manifest_midstream_secrets_reaches_convert(tmp_path, convert_calls):
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    sidecar = tmp_path / "cap_memscan.tls_midstream.secrets.jsonl"
    sidecar.write_text(json.dumps({"client_traffic_secret_0": "ab" * 32}) + "\n")
    (tmp_path / "cap.pcapng.fritap.json").write_text(
        json.dumps({"tls_midstream_secrets": str(sidecar)}))

    rc = cli.run_offline_pcap_to_tap(
        ["--from-pcap", str(pcap), "--tap", str(tmp_path / "o.tap")])

    assert rc == 0
    assert convert_calls[0]["tls_midstream_secrets"] == str(sidecar)


def test_flag_overrides_manifest_at_convert(tmp_path, convert_calls):
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    explicit = tmp_path / "explicit.jsonl"
    explicit.write_text(json.dumps({"client_traffic_secret_0": "cd" * 32}) + "\n")
    (tmp_path / "cap.pcapng.fritap.json").write_text(
        json.dumps({"tls_midstream_secrets": str(tmp_path / "from_manifest.jsonl")}))

    rc = cli.run_offline_pcap_to_tap([
        "--from-pcap", str(pcap), "--tap", str(tmp_path / "o.tap"),
        "--tls-midstream-secrets", str(explicit),
    ])

    assert rc == 0
    assert convert_calls[0]["tls_midstream_secrets"] == str(explicit)


def test_absent_midstream_secrets_passes_none_to_convert(tmp_path, convert_calls):
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")

    rc = cli.run_offline_pcap_to_tap(
        ["--from-pcap", str(pcap), "--tap", str(tmp_path / "o.tap")])

    assert rc == 0
    assert convert_calls[0]["tls_midstream_secrets"] is None
