#!/usr/bin/env python3

"""Robustness tests for mid-stream TLS 1.3 binding (Phase 2 step 2).

All synthetic: records are sealed with the same ``cryptography`` AEAD backend the
decrypter uses. Covers:

  * a first application_data record that fails (corrupt / foreign key) no longer
    leaves the whole direction unbound -- binding retries the next records;
  * a direction that starts INSIDE a record (mid-record capture start, or a TCP
    start gap) resyncs to the first plausible record header;
  * undecryptable records and a degraded (later-gap) stream are reported.
"""

from __future__ import annotations

import json
import struct

import pytest

from friTap.events import DatalogEvent
from friTap.offline.net.tcp_reassembly import TcpStreamPair
from friTap.offline.pcap_to_tap import ConvertResult
from friTap.offline.tls import records as tls_records
from friTap.offline.tls import stream as tls_stream
from friTap.offline.tls import tls13
from friTap.offline.tls_midstream import pipeline as pl
from friTap.offline.tls_midstream import transport as tr
from friTap.offline.tls_midstream.transport import READ, WRITE, MidstreamTlsStream

SECRET = "ab" * 32
OTHER_SECRET = "99" * 32
SUITE = "TLS_AES_128_GCM_SHA256"
CLIENT_ADDR = ("10.0.0.2", 51000)
SERVER_ADDR = ("93.184.216.34", 443)


def _seal(secret_hex: str, seq: int, inner: bytes) -> tuple:
    """AEAD-seal one application_data inner plaintext into a parsed record tuple."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key, iv = tls13.derive_key_iv(bytes.fromhex(secret_hex), SUITE)
    plaintext = inner + b"\x17"
    hdr = b"\x17\x03\x03" + struct.pack(">H", len(plaintext) + 16)
    fragment = AESGCM(key).encrypt(tls13.record_nonce(iv, seq), plaintext, hdr)
    return (0x17, hdr, fragment)


def _corrupt(record: tuple) -> tuple:
    ctype, hdr, frag = record
    return (ctype, hdr, bytes([frag[0] ^ 0xFF]) + frag[1:])


def _wire(records) -> bytes:
    return b"".join(hdr + frag for _c, hdr, frag in records)


def _stream(records: dict, **flags) -> MidstreamTlsStream:
    return MidstreamTlsStream(CLIENT_ADDR, SERVER_ADDR, "AF_INET",
                              records=records, **flags)


def _bundle() -> dict:
    return {"client_traffic_secret_0": SECRET, "server_traffic_secret_0": ""}


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


class _State:
    def __init__(self):
        self.tls_spans = {}

    def ensure_open(self, *a, **k):
        pass


def _run_stage(monkeypatch, tmp_path, stream):
    monkeypatch.setattr(pl, "midstream_tls_streams",
                        lambda pcap_path, server_ports=(443,): iter([stream]))
    sidecar = tmp_path / "m.tls_midstream.secrets.jsonl"
    sidecar.write_text(json.dumps(_bundle()) + "\n")
    bus, result = _Bus(), ConvertResult(tap_path="x.tap")
    keys = pl.run_midstream_tls_stage("x.pcap", str(sidecar), bus=bus,
                                      state=_State(), result=result)
    return keys, bus, result


# --------------------------------------------------------------------------- #
# (a) binding retries the first few application_data records
# --------------------------------------------------------------------------- #

def test_corrupted_first_record_still_binds_from_record_two(monkeypatch, tmp_path):
    pytest.importorskip("cryptography")
    recs = [_corrupt(_seal(SECRET, 10, b"lost")),
            _seal(SECRET, 11, b"hello "), _seal(SECRET, 12, b"world")]
    keys, bus, result = _run_stage(monkeypatch, tmp_path, _stream({WRITE: recs}))
    assert len(keys) == 1
    assert [ev.data for ev in bus.events
            if isinstance(ev, DatalogEvent)] == [b"hello world"]
    # The record skipped before the binding point is reported, not dropped silently.
    assert result.per_protocol["tls_midstream"]["undecryptable"] == 1
    assert result.per_protocol["tls_midstream"]["messages"] == 2


def test_foreign_key_first_record_binds_at_seq_zero():
    """A leading record under another secret does not consume this key's seq."""
    pytest.importorskip("cryptography")
    recs = [_seal(OTHER_SECRET, 50, b"old key"), _seal(SECRET, 0, b"new key")]
    binding = tls_stream.pick_binding(SECRET, recs, max_seq=8)
    assert binding == tls_stream.SeqBinding(SUITE, 1, 0)
    plaintexts = tls_stream.decrypt_stream_from(SECRET, SUITE, recs, 0, start_index=1)
    assert plaintexts == [b"new key\x17"]


def test_partner_direction_gets_deep_retry_once_stream_is_known():
    """Write binds on its first record; read's corrupt first record is retried."""
    pytest.importorskip("cryptography")
    bundle = {"client_traffic_secret_0": SECRET,
              "server_traffic_secret_0": OTHER_SECRET}
    stream = _stream({
        WRITE: [_seal(SECRET, 2, b"req")],
        READ: [_corrupt(_seal(OTHER_SECRET, 4, b"x")), _seal(OTHER_SECRET, 5, b"resp")],
    })
    binding = pl._bind_bundle_to_stream(bundle, stream)
    assert binding.write.start_seq == 2 and binding.write.record_index == 0
    assert binding.read.start_seq == 5 and binding.read.record_index == 1


def test_binding_gives_up_after_max_records():
    pytest.importorskip("cryptography")
    recs = [_corrupt(_seal(SECRET, i, b"x")) for i in range(4)] + [_seal(SECRET, 4, b"y")]
    assert tls_stream.pick_binding(SECRET, recs, max_seq=8) is None
    assert tls_stream.pick_binding(SECRET, recs, max_seq=8, max_records=5) == (
        tls_stream.SeqBinding(SUITE, 4, 4))


def test_legacy_recover_seq_and_pick_suite_keep_first_record_semantics():
    """recover_seq/pick_suite return the FIRST record's seq (decrypt_stream_from
    seeds record 0 with it), so they stay first-record-only."""
    pytest.importorskip("cryptography")
    recs = [_corrupt(_seal(SECRET, 3, b"x")), _seal(SECRET, 4, b"y")]
    assert tls_stream.recover_seq(SECRET, SUITE, recs, max_seq=8) is None
    assert tls_stream.pick_suite(SECRET, recs, max_seq=8) is None


def test_multi_record_binding_derives_key_once_per_suite(monkeypatch):
    """Trying several records must not multiply HKDF work (cipher cache per suite)."""
    tls13._prepared_cipher.cache_clear()
    calls = {"n": 0}
    original = tls13.derive_key_iv

    def counting(secret, suite):
        calls["n"] += 1
        return original(secret, suite)

    monkeypatch.setattr(tls13, "derive_key_iv", counting)
    recs = [(0x17, b"\x17\x03\x03\x00\x20", bytes([i]) * 32) for i in range(4)]
    assert tls_stream.pick_binding("00" * 32, recs, max_seq=50) is None
    assert calls["n"] <= len(tls13.SUITES)


# --------------------------------------------------------------------------- #
# (b) resync a direction that starts inside a record
# --------------------------------------------------------------------------- #

def _pair_from_segments(segments, *, syn_seq=None) -> TcpStreamPair:
    pair = TcpStreamPair(client_addr=CLIENT_ADDR, server_addr=SERVER_ADDR,
                         ss_family="AF_INET")
    if syn_seq is not None:
        pair.client.feed(syn_seq, b"", syn=True)
    for seq, payload in segments:
        pair.client.feed(seq, payload)
    return pair


def _streams_for(monkeypatch, pair):
    from friTap.offline.net import tcp_reassembly

    monkeypatch.setattr(tcp_reassembly, "reassemble_pcap",
                        lambda path, server_ports=(443,): {"k": pair})
    return list(tr.midstream_tls_streams("x.pcap"))


def test_stream_starting_mid_record_resyncs_and_decrypts(monkeypatch):
    pytest.importorskip("cryptography")
    recs = [_seal(SECRET, 20 + i, b"msg%d" % i) for i in range(4)]
    wire = _wire(recs)[7:]  # capture began 7 bytes into the first record
    (stream,) = _streams_for(monkeypatch, _pair_from_segments([(1000, wire)]))
    assert stream.resynced[WRITE] is True
    assert stream.records[WRITE] == recs[1:]
    binding = pl.bind_stream(stream, [_bundle()])
    assert binding is not None and binding.write.start_seq == 21
    assert pl._direction_plaintext(binding.write, stream.records[WRITE]) == b"msg1msg2msg3"


def test_start_gap_after_syn_resyncs_past_the_gap(monkeypatch):
    """SYN seen, first data segment lost: the bytes after the gap are recovered."""
    pytest.importorskip("cryptography")
    recs = [_seal(SECRET, i, b"part%d" % i) for i in range(3)]
    wire = _wire(recs)
    lost = 10
    pair = _pair_from_segments([(5001 + lost, wire[lost:])], syn_seq=5000)
    assert pair.client.has_start_gap and pair.client.contiguous_bytes() == b""
    (stream,) = _streams_for(monkeypatch, pair)
    assert stream.start_gap[WRITE] is True and stream.resynced[WRITE] is True
    assert stream.records[WRITE] == recs[1:]


def test_clean_stream_is_not_resynced(monkeypatch):
    pytest.importorskip("cryptography")
    recs = [_seal(SECRET, i, b"ok") for i in range(2)]
    (stream,) = _streams_for(monkeypatch, _pair_from_segments([(1, _wire(recs))]))
    assert stream.resynced[WRITE] is False
    assert stream.records[WRITE] == recs


def test_degraded_stream_is_reported(monkeypatch, tmp_path):
    pytest.importorskip("cryptography")
    recs = [_seal(SECRET, 5, b"before the gap")]
    stream = _stream({WRITE: recs}, degraded={WRITE: True}, start_gap={WRITE: False})
    keys, bus, result = _run_stage(monkeypatch, tmp_path, stream)
    assert len(keys) == 1
    assert result.per_protocol["tls_midstream"]["partial"] == 1


def test_clean_binding_records_no_stats_bucket(monkeypatch, tmp_path):
    pytest.importorskip("cryptography")
    stream = _stream({WRITE: [_seal(SECRET, 5, b"fine")]})
    _keys, _bus, result = _run_stage(monkeypatch, tmp_path, stream)
    assert "tls_midstream" not in result.per_protocol


# --------------------------------------------------------------------------- #
# (c) parse_records header validation + record-boundary search
# --------------------------------------------------------------------------- #

def test_parse_records_validate_stops_at_implausible_header():
    good = b"\x17\x03\x03\x00\x02ab"
    bad = b"\x42\x00\x00\x00\x01z"
    assert len(tls_records.parse_records(good + bad)) == 2          # default: unchanged
    assert tls_records.parse_records(good + bad, validate=True) == [
        (0x17, good[:5], b"ab")]


@pytest.mark.parametrize("header,ok", [
    (b"\x17\x03\x03\x00\x10", True),
    (b"\x16\x03\x01\x00\x10", True),
    (b"\x13\x03\x03\x00\x10", False),            # content type out of range
    (b"\x17\x02\x03\x00\x10", False),            # bad version
    (b"\x17\x03\x03" + struct.pack(">H", 2 ** 14 + 257), False),  # too long
    (b"\x17\x03\x03\x00\x00", False),            # empty fragment
])
def test_plausible_record_header(header, ok):
    assert tls_records.plausible_record_header(header, 0) is ok


def test_find_record_boundary():
    rec = b"\x17\x03\x03\x00\x03abc"
    assert tls_records.find_record_boundary(b"junk" + rec + rec) == 4
    assert tls_records.find_record_boundary(b"junk" + rec) == 4  # ends exactly
    assert tls_records.find_record_boundary(b"\x00" * 64) is None


# --------------------------------------------------------------------------- #
# (d) Phase 4: AEAD trial accounting (no timing, just what gets tried)
# --------------------------------------------------------------------------- #

def _count_trials(monkeypatch):
    """Patch the stream module's AEAD trial to record (suite, fragment) per call."""
    trials = []
    original = tls_stream.try_decrypt

    def counting(secret, suite, seq, aad, ciphertext):
        trials.append((suite, ciphertext))
        return original(secret, suite, seq, aad, ciphertext)

    monkeypatch.setattr(tls_stream, "try_decrypt", counting)
    return trials


def test_pick_binding_tries_only_suites_matching_secret_length(monkeypatch):
    pytest.importorskip("cryptography")
    trials = _count_trials(monkeypatch)
    recs = [(0x17, b"\x17\x03\x03\x00\x20", b"\x01" * 32)]
    assert tls_stream.pick_binding("00" * 48, recs, max_seq=3) is None
    assert {suite for suite, _frag in trials} == {"TLS_AES_256_GCM_SHA384"}


def test_first_record_skips_tried_records_but_keeps_true_index(monkeypatch):
    pytest.importorskip("cryptography")
    recs = [_corrupt(_seal(SECRET, 7, b"x")), _corrupt(_seal(SECRET, 8, b"y")),
            _seal(SECRET, 9, b"z")]
    trials = _count_trials(monkeypatch)
    binding = tls_stream.pick_binding(SECRET, recs, max_seq=10, first_record=1)
    assert binding == tls_stream.SeqBinding(SUITE, 2, 9)
    assert all(frag != recs[0][2] for _suite, frag in trials)


def test_second_pass_does_not_retry_record_zero(monkeypatch):
    """bind_stream's deep pass starts after the record the first pass rejected."""
    pytest.importorskip("cryptography")
    recs = [_corrupt(_seal(SECRET, 3, b"x")), _seal(SECRET, 4, b"y")]
    stream = _stream({WRITE: recs})
    trials = _count_trials(monkeypatch)
    binding = pl.bind_stream(stream, [_bundle()], max_seq=8)
    assert binding.write.record_index == 1 and binding.write.start_seq == 4
    record0_trials = sum(1 for _s, frag in trials if frag == recs[0][2])
    # Pass 1 alone sweeps record 0 once per length-matching suite (2 x 9 seqs).
    assert record0_trials == 2 * 9


def test_partner_deep_retry_uses_bound_suite_and_skips_record_zero(monkeypatch):
    pytest.importorskip("cryptography")
    bundle = {"client_traffic_secret_0": SECRET,
              "server_traffic_secret_0": OTHER_SECRET}
    read = [_corrupt(_seal(OTHER_SECRET, 4, b"x")), _seal(OTHER_SECRET, 5, b"resp")]
    stream = _stream({WRITE: [_seal(SECRET, 2, b"req")], READ: read})
    trials = _count_trials(monkeypatch)
    binding = pl._bind_bundle_to_stream(bundle, stream, max_seq=8)
    assert binding.read == pl._DirectionBinding(OTHER_SECRET, SUITE, 5, 1)
    read0 = [suite for suite, frag in trials if frag == read[0][2]]
    assert len(read0) == 2 * 9          # only the first-record pass touched it
    assert {suite for suite, frag in trials if frag == read[1][2]} == {SUITE}
