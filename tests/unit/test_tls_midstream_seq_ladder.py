#!/usr/bin/env python3

"""Exact iterative-deepening seq search for mid-stream TLS 1.3 binding (WS-C).

The stage used to sweep ``0..DEFAULT_MAX_SEQ`` for every wrong (bundle, stream)
pair. It now deepens the seq search window by window
(:func:`~friTap.offline.tls.stream.seq_windows`) and must still return exactly
what the old search returned. The reference below is a verbatim copy of the old
search (stream.py ``_record_seq`` / ``recover_binding`` / ``pick_binding`` and
pipeline.py ``_bind_direction`` / ``_bind_bundle_to_stream`` / ``_place_bundle``
plus the stage's pass loop), with only ``max_seq`` threaded through and the
emission replaced by a recorder. A randomized equivalence test with real AEAD
sealing compares the two placement sequences; targeted tests pin the trial
savings and the cases where the exactness argument needs care.
"""

from __future__ import annotations

import random
import struct
from itertools import islice

import pytest

pytest.importorskip("cryptography")

from friTap.offline.pcap_to_tap import ConvertResult  # noqa: E402
from friTap.offline.tls import stream as tls_stream  # noqa: E402
from friTap.offline.tls import tls13  # noqa: E402
from friTap.offline.tls_midstream import pipeline as pl  # noqa: E402
from friTap.offline.tls_midstream.transport import (  # noqa: E402
    READ,
    WRITE,
    MidstreamTlsStream,
)
from tests.unit.test_tls_midstream_binding import SUITE, _corrupt, _seal  # noqa: E402

CHACHA = "TLS_CHACHA20_POLY1305_SHA256"
CLIENT_SECRET = "ab" * 32
SERVER_SECRET = "cd" * 32
UNRELATED = ("11" * 32, "22" * 32)


# --------------------------------------------------------------------------- #
# Reference: verbatim copy of the pre-WS-C search
# --------------------------------------------------------------------------- #

def _ref_record_seq(secret, suite, hdr, frag, max_seq):
    for seq in range(max_seq + 1):
        plaintext = tls_stream.try_decrypt(secret, suite, seq, hdr, frag)
        if plaintext is not None and tls_stream.inner_content_type(plaintext) in \
                tls_stream._VALID_INNER_TYPES:
            return seq
    return None


def _ref_recover_binding(secret_hex, suite, records, max_seq, max_records, first_record=0):
    secret = bytes.fromhex(secret_hex)
    window = islice(tls_stream.iter_app_data_records(records), first_record, max_records)
    for index, (_ctype, hdr, frag) in enumerate(window, start=first_record):
        seq = _ref_record_seq(secret, suite, hdr, frag, max_seq)
        if seq is not None:
            return index, seq
    return None


def _ref_pick_binding(secret_hex, records, suites=None, max_seq=tls_stream.DEFAULT_MAX_SEQ,
                      max_records=tls_stream.DEFAULT_BIND_RECORDS, first_record=0):
    if suites is None:
        suites = tls_stream.suites_for_secret(bytes.fromhex(secret_hex))
    for suite in suites:
        found = _ref_recover_binding(secret_hex, suite, records, max_seq, max_records,
                                     first_record)
        if found is not None:
            return tls_stream.SeqBinding(suite, found[0], found[1])
    return None


def _ref_bind_direction(secret_hex, records, max_seq, max_records, first_record=0,
                        suites=None):
    if not secret_hex or not records:
        return None
    picked = _ref_pick_binding(secret_hex, records, suites=suites, max_seq=max_seq,
                               max_records=max_records, first_record=first_record)
    if picked is None:
        return None
    return pl._DirectionBinding(secret_hex, picked.suite, picked.seq, picked.record_index)


def _ref_bind_bundle_to_stream(bundle, stream, max_seq, max_records=1, first_record=0):
    directions = (
        (bundle.get("client_traffic_secret_0", ""), stream.records.get(WRITE) or []),
        (bundle.get("server_traffic_secret_0", ""), stream.records.get(READ) or []),
    )
    if any(pl._has_leading_handshake(records) for _secret, records in directions):
        return None
    binds = [_ref_bind_direction(secret, records, max_seq, max_records, first_record)
             for secret, records in directions]
    bound = next((bind for bind in binds if bind), None)
    if bound is None:
        return None
    deep = max(max_records, tls_stream.DEFAULT_BIND_RECORDS)
    binds = [bind or _ref_bind_direction(secret, records, max_seq, deep, max_records,
                                         suites=[bound.suite])
             for bind, (secret, records) in zip(binds, directions)]
    return pl.StreamBinding(stream, binds[0], binds[1])


def _ref_place_bundle(bundle, unclaimed, max_records, first_record, max_seq, emit):
    for idx, stream in enumerate(unclaimed):
        binding = _ref_bind_bundle_to_stream(bundle, stream, max_seq,
                                             max_records=max_records,
                                             first_record=first_record)
        if binding is None:
            continue
        emit(binding)
        del unclaimed[idx]
        return True
    return False


def _ref_stage(bundles, streams, max_seq, emit):
    unclaimed = list(streams)
    unplaced = list(bundles)
    first_record = 0
    for max_records in pl._BIND_PASSES:
        unplaced = [bundle for bundle in unplaced
                    if not _ref_place_bundle(bundle, unclaimed, max_records,
                                             first_record, max_seq, emit)]
        if not unplaced or not unclaimed:
            break
        first_record = max_records


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #

class _Bus:
    def emit(self, event):
        pass


class _State:
    def __init__(self):
        self.tls_spans = {}

    def ensure_open(self, *a, **k):
        pass


def _recorder(streams, placements):
    def emit(binding, **_kwargs):
        index = next(i for i, s in enumerate(streams) if s is binding.stream)
        placements.append((index, binding.write, binding.read))
        return True
    return emit


def _count_trials(monkeypatch):
    trials = []
    original = tls_stream.try_decrypt

    def counting(secret, suite, seq, aad, ciphertext):
        trials.append((suite, seq, ciphertext))
        return original(secret, suite, seq, aad, ciphertext)

    monkeypatch.setattr(tls_stream, "try_decrypt", counting)
    return trials


def _new_placements(monkeypatch, bundles, streams, max_seq=tls_stream.DEFAULT_MAX_SEQ):
    placements = []
    monkeypatch.setattr(pl, "load_secret_bundles", lambda path: list(bundles))
    monkeypatch.setattr(pl, "midstream_tls_streams",
                        lambda path, server_ports=(443,): iter(streams))
    monkeypatch.setattr(pl, "_emit_binding", _recorder(streams, placements))
    pl.run_midstream_tls_stage("x.pcap", "x.jsonl", bus=_Bus(), state=_State(),
                               result=ConvertResult(tap_path="x.tap"), max_seq=max_seq)
    return placements


def _ref_placements(bundles, streams, max_seq=tls_stream.DEFAULT_MAX_SEQ):
    placements = []
    _ref_stage(bundles, streams, max_seq, _recorder(streams, placements))
    return placements


def _stream(write=(), read=(), port=40000):
    return MidstreamTlsStream(("10.0.0.2", port), ("93.0.0.1", 443), "AF_INET",
                              records={WRITE: list(write), READ: list(read)})


def _bundle(client=CLIENT_SECRET, server=SERVER_SECRET):
    return {"client_traffic_secret_0": client, "server_traffic_secret_0": server}


# --------------------------------------------------------------------------- #
# Random case generator (real AEAD sealing)
# --------------------------------------------------------------------------- #

def _seal_suite(secret_hex, suite, seq, inner):
    if suite == SUITE:
        return _seal(secret_hex, seq, inner)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    key, iv = tls13.derive_key_iv(bytes.fromhex(secret_hex), suite)
    plaintext = inner + b"\x17"
    hdr = b"\x17\x03\x03" + struct.pack(">H", len(plaintext) + 16)
    return (0x17, hdr, ChaCha20Poly1305(key).encrypt(tls13.record_nonce(iv, seq),
                                                      plaintext, hdr))


def _secret(rng):
    return rng.getrandbits(256).to_bytes(32, "big").hex()


def _random_direction(rng, secret, suite):
    """One direction under *secret*: consecutive seqs from a random start, with
    corrupt leading records and an optional leading foreign-key record."""
    if rng.random() < 0.15:
        return []
    start = rng.choice((rng.randint(0, 6), rng.randint(0, 60), rng.randint(0, 330)))
    count = rng.randint(1, 6)
    records = [_seal_suite(secret, suite, start + i, rng.randbytes(rng.randint(1, 12)))
               for i in range(count)]
    for i in range(min(rng.choice((0, 0, 0, 1, 2, 3, 4)), count)):
        records[i] = _corrupt(records[i])
    if rng.random() < 0.15:
        records.insert(0, _seal_suite(_secret(rng), SUITE, rng.randint(0, 50), b"foreign"))
    return records


def _random_stream(rng, port, client, server, suite):
    records = {WRITE: _random_direction(rng, client, suite),
               READ: _random_direction(rng, server, suite)}
    if rng.random() < 0.1:
        records[rng.choice((WRITE, READ))].insert(
            0, (0x16, b"\x16\x03\x03\x00\x20", rng.randbytes(32)))
    return _stream(records[WRITE], records[READ], port)


def _random_copy(rng, stream, port):
    """A copy stream: the same ciphertext, possibly missing leading records or
    with its directions swapped."""
    write, read = (stream.records[d][rng.choice((0, 0, 1, 2, 3)):] for d in (WRITE, READ))
    if rng.random() < 0.25:
        write, read = read, write
    return _stream(write, read, port)


def _random_bundles(rng, sessions):
    bundles = [_bundle(client, server) for client, server, _suite in sessions]
    for bundle in bundles:
        roll = rng.random()
        if roll < 0.15:
            bundle["server_traffic_secret_0"] = ""
        elif roll < 0.3:
            bundle["client_traffic_secret_0"] = ""
    if len(bundles) > 1 and rng.random() < 0.4:          # mis-paired bundles
        a, b = rng.sample(bundles, 2)
        a["server_traffic_secret_0"], b["server_traffic_secret_0"] = (
            b["server_traffic_secret_0"], a["server_traffic_secret_0"])
    if rng.random() < 0.35:                              # exact duplicate
        bundles.append(dict(rng.choice(bundles)))
    if rng.random() < 0.2:                               # no stream at all
        bundles.append(_bundle(_secret(rng), _secret(rng)))
    rng.shuffle(bundles)
    return [bundle for bundle in bundles if pl._valid_bundle(bundle)]


def _random_sessions_case(rng):
    """``(bundles, streams, sessions)`` of one randomized capture."""
    sessions = [(_secret(rng), _secret(rng), rng.choice((SUITE, SUITE, CHACHA)))
                for _ in range(rng.randint(1, 4))]
    streams = [_random_stream(rng, 40000 + i, *session)
               for i, session in enumerate(sessions)]
    streams += [_random_stream(rng, 41000 + i, _secret(rng), _secret(rng), SUITE)
                for i in range(rng.randint(0, 2))]
    for i in range(rng.choice((0, 0, 1, 2))):
        streams.append(_random_copy(rng, rng.choice(streams), 42000 + i))
    rng.shuffle(streams)
    return _random_bundles(rng, sessions), streams, sessions


def _random_case(rng):
    bundles, streams, _sessions = _random_sessions_case(rng)
    return bundles, streams


def _random_disjoint_case(rng):
    """A random capture where some sessions ALSO appear under a second 4-tuple
    with records that overlap nothing (a NAT'd capture merged from both sides)."""
    bundles, streams, sessions = _random_sessions_case(rng)
    for i, (client, _server, suite) in enumerate(sessions):
        if rng.random() < 0.5:
            start = rng.choice((rng.randint(0, 6), rng.randint(0, 60), rng.randint(0, 330)))
            part = [_seal_suite(client, suite, start + j, b"nat%d" % j) for j in range(2)]
            streams.insert(rng.randint(0, len(streams)), _stream(part, [], 43000 + i))
    return bundles, streams


# --------------------------------------------------------------------------- #
# Equivalence
# --------------------------------------------------------------------------- #

# Chunk 0 (50 seeds) runs by default; the full 200 seeds run under `slow`.
@pytest.mark.parametrize(
    "chunk",
    [0] + [pytest.param(c, marks=pytest.mark.slow) for c in range(1, 4)],
)
def test_iterative_deepening_matches_reference_search(monkeypatch, chunk):
    """Placements (stream, write binding, read binding, order) are identical to
    the old full-range search on randomized captures, ladder shrunk to (3, 40)."""
    monkeypatch.setattr(tls_stream, "SEQ_LADDER", (3, 40))
    trials = _count_trials(monkeypatch)
    old_trials = new_trials = 0
    for seed in range(chunk * 50, chunk * 50 + 50):
        bundles, streams = _random_case(random.Random(seed))
        del trials[:]
        expected = _ref_placements(bundles, streams, max_seq=300)
        old_trials += len(trials)
        del trials[:]
        actual = _new_placements(monkeypatch, bundles, streams, max_seq=300)
        new_trials += len(trials)
        assert actual == expected, f"seed {seed}"
    assert new_trials < old_trials


# --------------------------------------------------------------------------- #
# Targeted cases
# --------------------------------------------------------------------------- #

def test_seq_windows_follow_the_ladder():
    assert list(tls_stream.seq_windows(100000)) == [(0, 64), (65, 4096), (4097, 100000)]
    assert list(tls_stream.seq_windows(300)) == [(0, 64), (65, 300)]
    assert list(tls_stream.seq_windows(4097)) == [(0, 64), (65, 4096), (4097, 4097)]
    assert list(tls_stream.seq_windows(65)) == [(0, 64), (65, 65)]
    assert list(tls_stream.seq_windows(64)) == [(0, 64)]
    assert list(tls_stream.seq_windows(10)) == [(0, 10)]


def test_pick_binding_min_seq_skips_lower_seqs():
    recs = [_seal(CLIENT_SECRET, 5, b"x")]
    assert tls_stream.pick_binding(CLIENT_SECRET, recs, max_seq=9, min_seq=6) is None
    assert tls_stream.pick_binding(CLIENT_SECRET, recs, max_seq=9, min_seq=5) == (
        tls_stream.SeqBinding(SUITE, 0, 5))


def test_wrong_earlier_stream_costs_only_the_first_window(monkeypatch):
    wrong = _stream([_seal(UNRELATED[0], 5, b"x")], [_seal(UNRELATED[1], 3, b"y")])
    right = _stream([_seal(CLIENT_SECRET, 5, b"a")], [_seal(SERVER_SECRET, 7, b"b")], 40001)
    trials = _count_trials(monkeypatch)
    placements = _new_placements(monkeypatch, [_bundle()], [wrong, right])
    assert placements == [(1, pl._DirectionBinding(CLIENT_SECRET, SUITE, 5, 0),
                           pl._DirectionBinding(SERVER_SECRET, SUITE, 7, 0))]
    wrong_frags = {rec[2] for rec in wrong.records[WRITE] + wrong.records[READ]}
    # 2 directions x 2 length-matching suites x seqs 0..64 (was 0..100000).
    assert sum(1 for _s, _q, frag in trials if frag in wrong_frags) == 2 * 2 * 65


def test_mis_paired_earlier_stream_at_high_seq_beats_later_stream_at_low_seq(monkeypatch):
    """The server secret binds the earlier stream at seq 200 (second window), the
    client secret the later stream at seq 3 (first window): the earlier wins."""
    earlier = _stream(read=[_seal(SERVER_SECRET, 200, b"late")])
    later = _stream(write=[_seal(CLIENT_SECRET, 3, b"early")], port=40001)
    streams = [earlier, later]
    expected = [(0, None, pl._DirectionBinding(SERVER_SECRET, SUITE, 200, 0))]
    assert _ref_placements([_bundle()], streams) == expected
    assert _new_placements(monkeypatch, [_bundle()], streams) == expected


def test_copy_stream_triggers_the_exact_fallback(monkeypatch):
    """An earlier partial copy of the winner binds through the winner's own
    secret at a later window; only the shared-ciphertext fallback finds it."""
    full = [_seal(CLIENT_SECRET, 3 + i, b"r%d" % i) for i in range(78)]  # seq 3..80
    copy, original = _stream(full[67:]), _stream(full, port=40001)        # copy: seq 70..80
    assert pl._shares_ciphertext(copy, original)
    streams, bundles = [copy, original], [_bundle(server="")]
    expected = [(0, pl._DirectionBinding(CLIENT_SECRET, SUITE, 70, 0), None)]
    assert _ref_placements(bundles, streams) == expected
    assert _new_placements(monkeypatch, bundles, streams) == expected


def test_duplicate_bundle_costs_no_trials_without_copy_streams(monkeypatch):
    stream = _stream([_seal(CLIENT_SECRET, 5, b"a")], [_seal(SERVER_SECRET, 7, b"b")])
    other = _stream([_seal(UNRELATED[0], 5, b"x")], port=40001)
    trials = _count_trials(monkeypatch)
    _new_placements(monkeypatch, [_bundle()], [stream, other])
    single = len(trials)
    del trials[:]
    assert len(_new_placements(monkeypatch, [_bundle(), _bundle()], [stream, other])) == 1
    assert len(trials) == single


def test_duplicate_bundle_still_binds_a_copy_stream(monkeypatch):
    stream = _stream([_seal(CLIENT_SECRET, 5, b"a")], [_seal(SERVER_SECRET, 7, b"b")])
    copy = _stream(stream.records[WRITE], stream.records[READ], port=40001)
    streams, bundles = [stream, copy], [_bundle(), _bundle()]
    expected = _ref_placements(bundles, streams)
    assert [index for index, _w, _r in expected] == [0, 1]
    assert _new_placements(monkeypatch, bundles, streams) == expected


def test_duplicate_of_partially_bound_bundle_is_not_skipped(monkeypatch):
    """The first copy binds only its client secret (the server secret lives on a
    later stream); the duplicate must still find that later stream."""
    first = _stream(write=[_seal(CLIENT_SECRET, 2, b"a")])
    second = _stream(read=[_seal(SERVER_SECRET, 9, b"b")], port=40001)
    streams, bundles = [first, second], [_bundle(), _bundle()]
    expected = _ref_placements(bundles, streams)
    assert [index for index, _w, _r in expected] == [0, 1]
    assert _new_placements(monkeypatch, bundles, streams) == expected


# --------------------------------------------------------------------------- #
# The one-stream-per-session assumption (documented inexactness)
# --------------------------------------------------------------------------- #

def _disjoint_parts():
    """One session's client direction split over two 4-tuples, no shared record:
    the later part (seq 100..) first in stream order, the earlier part second."""
    late = _stream([_seal(CLIENT_SECRET, 100 + i, b"L%d" % i) for i in range(3)])
    early = _stream([_seal(CLIENT_SECRET, 3 + i, b"E%d" % i) for i in range(3)], port=40001)
    assert not pl._shares_ciphertext(late, early)
    return [late, early]


@pytest.mark.xfail(strict=True, reason="one-stream-per-session assumption: a session "
                   "split over two 4-tuples without a shared record is not re-checked "
                   "through the winner's secret (see _BundleSearch)")
def test_disjoint_parts_of_one_session_match_reference(monkeypatch):
    streams, bundles = _disjoint_parts(), [_bundle(server="")]
    assert _new_placements(monkeypatch, bundles, streams) == _ref_placements(bundles, streams)


def test_disjoint_parts_still_bind_the_bundles_own_session(monkeypatch):
    """Even off the assumption, the AEAD oracle only ever binds the session."""
    streams, bundles = _disjoint_parts(), [_bundle(server="")]
    ((index, write, read),) = _new_placements(monkeypatch, bundles, streams)
    assert (index, write, read) == (1, pl._DirectionBinding(CLIENT_SECRET, SUITE, 3, 0), None)


def test_duplicate_of_one_sided_bundle_places_the_other_disjoint_part(monkeypatch):
    """A placement that bound one direction proves nothing, so the duplicate is
    searched and claims the session's other 4-tuple, as the full search does."""
    streams, bundles = _disjoint_parts(), [_bundle(server=""), _bundle(server="")]
    expected = _ref_placements(bundles, streams)
    actual = _new_placements(monkeypatch, bundles, streams)
    assert sorted(index for index, _w, _r in actual) == [0, 1]
    assert sorted(actual, key=lambda p: p[0]) == sorted(expected, key=lambda p: p[0])


def test_only_a_both_direction_placement_proves_its_secrets():
    stream = _stream([_seal(CLIENT_SECRET, 5, b"a")], [_seal(SERVER_SECRET, 7, b"b")])
    write = pl._DirectionBinding(CLIENT_SECRET, SUITE, 5, 0)
    read = pl._DirectionBinding(SERVER_SECRET, SUITE, 7, 0)
    placements = pl._Placements([stream])
    placements.record(_bundle(), pl.StreamBinding(stream, write, None))
    assert not placements.proven and not placements.is_duplicate(_bundle())
    placements.record(_bundle(), pl.StreamBinding(stream, write, read))
    assert placements.proven == {CLIENT_SECRET, SERVER_SECRET}
    assert placements.is_duplicate(_bundle()) and placements.is_duplicate(_bundle(server=""))


@pytest.mark.xfail(strict=True, reason="one-stream-per-session assumption (see "
                   "_BundleSearch): some seeds split a session over two 4-tuples")
def test_disjoint_session_parts_fuzz_matches_reference(monkeypatch):
    monkeypatch.setattr(tls_stream, "SEQ_LADDER", (3, 40))
    mismatches = []
    for seed in range(50):
        bundles, streams = _random_disjoint_case(random.Random(seed))
        expected = _ref_placements(bundles, streams, max_seq=300)
        if _new_placements(monkeypatch, bundles, streams, max_seq=300) != expected:
            mismatches.append(seed)
    assert not mismatches, f"seeds {mismatches}"
