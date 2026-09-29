#!/usr/bin/env python3

"""Unit tests for the mid-stream TLS 1.3 binding/emit pipeline (Phase 2.3 + 2.4).

All synthetic: no device, no pcap, no repo-root files. Records are sealed with the
same ``cryptography`` AEAD backend the decrypter uses (mirroring
``test_tls_midstream_crypto``), so a round-trip through the binding stage proves
the whole chain: trial-bind the sidecar bundle to a stream via the AEAD tag,
recover suite + starting seq per direction, decrypt, and emit a DatalogEvent +
TlsPlaintextSpan shaped exactly like the tshark single-pass path.
"""

from __future__ import annotations

import json
import struct
from types import SimpleNamespace

import pytest

from friTap.connection_index import canonical_4tuple
from friTap.offline.pcap_to_tap import ConvertResult, _relabel_midstream_flows
from friTap.offline.rc4 import crypto as rc4_crypto
from friTap.offline.tls_midstream import pipeline as pl
from friTap.offline.tls_midstream.transport import READ, WRITE, MidstreamTlsStream

# Distinct secrets per direction so a direction mix-up is caught.
CLIENT_SECRET = "ab" * 32
SERVER_SECRET = "cd" * 32
SUITE = "TLS_AES_128_GCM_SHA256"
CLIENT_ADDR = ("10.0.0.2", 51000)
SERVER_ADDR = ("93.184.216.34", 443)


# --------------------------------------------------------------------------- #
# Synthetic TLS 1.3 record builder (same shape as test_tls_midstream_crypto)
# --------------------------------------------------------------------------- #

def _seal_record(secret_hex: str, seq: int, inner: bytes) -> tuple:
    """AEAD-seal one application_data inner plaintext into a parsed record tuple."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key, iv = rc4_crypto.derive_key_iv(bytes.fromhex(secret_hex), SUITE)
    plaintext = inner + b"\x17"  # inner content-type = application_data
    hdr = b"\x17\x03\x03" + struct.pack(">H", len(plaintext) + 16)
    fragment = AESGCM(key).encrypt(rc4_crypto.record_nonce(iv, seq), plaintext, hdr)
    return (0x17, hdr, fragment)


def _stream(records: dict) -> MidstreamTlsStream:
    return MidstreamTlsStream(
        client_addr=CLIENT_ADDR,
        server_addr=SERVER_ADDR,
        ss_family="AF_INET",
        records=records,
    )


def _bundle(**overrides) -> dict:
    payload = {
        "client_random": "00" * 32,
        "server_random": "11" * 32,
        "client_traffic_secret_0": CLIENT_SECRET,
        "server_traffic_secret_0": SERVER_SECRET,
        "exporter_secret": "22" * 32,
    }
    payload.update(overrides)
    return payload


class _FakeBus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


class _FakeState:
    def __init__(self):
        self.tls_spans = {}
        self.opened = False

    def ensure_open(self, *a, **k):
        self.opened = True


# --------------------------------------------------------------------------- #
# Binding (Phase 2.3)
# --------------------------------------------------------------------------- #

def test_bind_stream_matches_both_directions():
    pytest.importorskip("cryptography")
    stream = _stream({
        WRITE: [_seal_record(CLIENT_SECRET, 3, b"client hello app")],
        READ: [_seal_record(SERVER_SECRET, 5, b"server response")],
    })
    binding = pl.bind_stream(stream, [_bundle()])
    assert binding is not None
    assert binding.write is not None and binding.write.start_seq == 3
    assert binding.write.suite == SUITE
    assert binding.read is not None and binding.read.start_seq == 5


def test_bind_stream_wrong_secret_binds_nothing():
    pytest.importorskip("cryptography")
    stream = _stream({
        WRITE: [_seal_record(CLIENT_SECRET, 3, b"payload")],
        READ: [_seal_record(SERVER_SECRET, 3, b"payload")],
    })
    wrong = _bundle(client_traffic_secret_0="ee" * 32,
                    server_traffic_secret_0="ff" * 32)
    assert pl.bind_stream(stream, [wrong]) is None


def test_bind_stream_skips_captured_handshake():
    """A stream that begins with a handshake record is left to the tshark pass."""
    pytest.importorskip("cryptography")
    handshake_record = (0x16, b"\x16\x03\x03\x00\x04", b"\x01\x00\x00\x00")
    app_record = _seal_record(CLIENT_SECRET, 0, b"app after handshake")
    stream = _stream({WRITE: [handshake_record, app_record]})
    assert pl.bind_stream(stream, [_bundle()]) is None


# --------------------------------------------------------------------------- #
# Secret-bundle sidecar loading
# --------------------------------------------------------------------------- #

def test_load_secret_bundles_skips_malformed_and_incomplete(tmp_path):
    path = tmp_path / "s.tls_midstream.secrets.jsonl"
    lines = [
        json.dumps(_bundle()),
        "",                       # blank line
        "{not json",              # malformed
        json.dumps({"client_random": "00" * 32}),  # no traffic secret
    ]
    path.write_text("\n".join(lines) + "\n")
    bundles = pl.load_secret_bundles(str(path))
    assert len(bundles) == 1
    assert bundles[0]["client_traffic_secret_0"] == CLIENT_SECRET


def test_load_secret_bundles_missing_file_is_empty():
    assert pl.load_secret_bundles("/no/such/sidecar.jsonl") == []


# --------------------------------------------------------------------------- #
# Full stage: decrypt + emit spans/events (Phase 2.3) via monkeypatched enum
# --------------------------------------------------------------------------- #

def _run_stage(monkeypatch, stream, sidecar_path, base_ts=1000.0):
    monkeypatch.setattr(
        pl, "midstream_tls_streams",
        lambda pcap_path, server_ports=(443,): iter([stream]),
    )
    bus, state, result = _FakeBus(), _FakeState(), ConvertResult(tap_path="x.tap")
    keys = pl.run_midstream_tls_stage(
        "dummy.pcap", str(sidecar_path),
        bus=bus, state=state, result=result, base_ts=base_ts,
    )
    return keys, bus, state, result


def test_run_stage_decrypts_and_emits_spans(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    stream = _stream({
        WRITE: [_seal_record(CLIENT_SECRET, 3, b"GET / HTTP/1.1"),
                _seal_record(CLIENT_SECRET, 4, b"host: x")],
        READ: [_seal_record(SERVER_SECRET, 7, b"200 OK")],
    })
    sidecar = tmp_path / "m.tls_midstream.secrets.jsonl"
    sidecar.write_text(json.dumps(_bundle()) + "\n")

    keys, bus, state, result = _run_stage(monkeypatch, stream, sidecar)

    expected_key = canonical_4tuple(*CLIENT_ADDR, *SERVER_ADDR)
    assert keys == {expected_key}
    assert result.stream_count == 1
    assert result.decrypted_packet_count == 2  # one event per non-empty direction

    # DatalogEvents: joined app content per direction, protocol tls, correct dirs.
    by_dir = {ev.direction: ev for ev in bus.events}
    assert by_dir[WRITE].data == b"GET / HTTP/1.1host: x"
    assert by_dir[WRITE].protocol == "tls"
    assert (by_dir[WRITE].src_addr, by_dir[WRITE].src_port) == CLIENT_ADDR
    assert (by_dir[WRITE].dst_addr, by_dir[WRITE].dst_port) == SERVER_ADDR
    assert by_dir[READ].data == b"200 OK"
    assert (by_dir[READ].src_addr, by_dir[READ].src_port) == SERVER_ADDR
    assert by_dir[WRITE].timestamp == 1000.0

    # Spans recorded under the canonical key, per direction, joined == plaintext.
    spans = state.tls_spans[expected_key]
    assert b"".join(s.data for s in spans[WRITE]) == b"GET / HTTP/1.1host: x"
    assert b"".join(s.data for s in spans[READ]) == b"200 OK"


def test_run_stage_wrong_secret_emits_nothing(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    stream = _stream({WRITE: [_seal_record(CLIENT_SECRET, 3, b"secret data")]})
    sidecar = tmp_path / "m.tls_midstream.secrets.jsonl"
    sidecar.write_text(json.dumps(
        _bundle(client_traffic_secret_0="ee" * 32,
                server_traffic_secret_0="ff" * 32)) + "\n")

    keys, bus, state, result = _run_stage(monkeypatch, stream, sidecar)
    assert keys == set()
    assert bus.events == []
    assert result.decrypted_packet_count == 0


def test_run_stage_no_sidecar_is_noop(tmp_path, monkeypatch):
    # An empty sidecar returns before enumerating streams at all.
    called = SimpleNamespace(hit=False)

    def _boom(*a, **k):
        called.hit = True
        return iter([])

    monkeypatch.setattr(pl, "midstream_tls_streams", _boom)
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    bus, state, result = _FakeBus(), _FakeState(), ConvertResult(tap_path="x.tap")
    keys = pl.run_midstream_tls_stage(
        "dummy.pcap", str(empty), bus=bus, state=state, result=result)
    assert keys == set()
    assert called.hit is False


# --------------------------------------------------------------------------- #
# Classifier (Phase 2.4): relabel bound flows TLS(midstream)
# --------------------------------------------------------------------------- #

def _flow(src_addr, src_port, dst_addr, dst_port, detected=""):
    return SimpleNamespace(
        src_addr=src_addr, src_port=src_port,
        dst_addr=dst_addr, dst_port=dst_port,
        detected_protocol=detected,
    )


def test_relabel_bound_flow_gets_midstream_label():
    key = canonical_4tuple(*CLIENT_ADDR, *SERVER_ADDR)
    flow = _flow(*CLIENT_ADDR, *SERVER_ADDR)
    _relabel_midstream_flows([flow], {key})
    assert flow.detected_protocol == pl.MIDSTREAM_PROTOCOL_LABEL


def test_relabel_leaves_richer_protocol_untouched():
    key = canonical_4tuple(*CLIENT_ADDR, *SERVER_ADDR)
    flow = _flow(*CLIENT_ADDR, *SERVER_ADDR, detected="signal")
    _relabel_midstream_flows([flow], {key})
    assert flow.detected_protocol == "signal"


def test_relabel_ignores_unbound_flow():
    key = canonical_4tuple(*CLIENT_ADDR, *SERVER_ADDR)
    other = _flow("1.1.1.1", 100, "2.2.2.2", 200)
    _relabel_midstream_flows([other], {key})
    assert other.detected_protocol == ""
