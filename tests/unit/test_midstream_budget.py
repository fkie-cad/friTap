"""Bounded work for the mid-stream TLS stage's secret-bundle trial search.

The secret-bundle JSONL sidecar can be named by an untrusted capture manifest
and every bundle is trial-decrypted against every stream (a seq search of up to
``DEFAULT_MAX_SEQ``), so the stage bounds its work:

* bundles are de-duplicated by their secret material,
* at most ``MAX_SECRET_BUNDLES`` distinct bundles are loaded (warned),
* one run makes at most ``MIDSTREAM_TRIAL_BUDGET`` AEAD trial decryptions
  (:class:`~friTap.offline.tls.stream.TrialBudget`); when it runs out the
  search stops with one warning naming the streams left unsearched.
"""

from __future__ import annotations

import json
import logging

import pytest

pytest.importorskip("cryptography")

from friTap.offline.pcap_to_tap import ConvertResult  # noqa: E402
from friTap.offline.tls import stream as tls_stream  # noqa: E402
from friTap.offline.tls.stream import TrialBudget  # noqa: E402
from friTap.offline.tls_midstream import pipeline as pl  # noqa: E402
from friTap.offline.tls_midstream.transport import (  # noqa: E402
    READ,
    WRITE,
    MidstreamTlsStream,
)
from tests.unit.test_tls_midstream_binding import SUITE, _seal  # noqa: E402

CLIENT_SECRET = "ab" * 32
SERVER_SECRET = "cd" * 32
ORPHAN = ("11" * 32, "22" * 32)   # a bundle whose session is not in the capture
FOREIGN = ("33" * 32, "44" * 32)  # the session of a stream no bundle belongs to
MAX_SEQ = 300                     # keeps the full-range sweeps fast


def _bundle(client=CLIENT_SECRET, server=SERVER_SECRET, **extra) -> dict:
    return {"client_traffic_secret_0": client, "server_traffic_secret_0": server, **extra}


def _stream(client, server, port, seq=5) -> MidstreamTlsStream:
    return MidstreamTlsStream(
        ("10.0.0.2", port), ("93.0.0.1", 443), "AF_INET",
        records={WRITE: [_seal(client, seq, b"c")], READ: [_seal(server, seq + 2, b"s")]})


class _Bus:
    def emit(self, event):
        pass


class _State:
    def __init__(self):
        self.tls_spans = {}

    def ensure_open(self, *a, **k):
        pass


def _write_sidecar(tmp_path, bundles) -> str:
    path = tmp_path / "m.tls_midstream.secrets.jsonl"
    path.write_text("".join(json.dumps(b) + "\n" for b in bundles))
    return str(path)


def _count_trials(monkeypatch) -> list:
    trials = []
    original = tls_stream.try_decrypt

    def counting(secret, suite, seq, aad, ciphertext):
        trials.append(seq)
        return original(secret, suite, seq, aad, ciphertext)

    monkeypatch.setattr(tls_stream, "try_decrypt", counting)
    return trials


def _run(monkeypatch, tmp_path, bundles, streams, **kwargs):
    monkeypatch.setattr(pl, "midstream_tls_streams",
                        lambda path, server_ports=(443,): iter(streams))
    return pl.run_midstream_tls_stage(
        "x.pcap", _write_sidecar(tmp_path, bundles), bus=_Bus(), state=_State(),
        result=ConvertResult(tap_path="x.tap"), max_seq=MAX_SEQ, **kwargs)


def _budget_warnings(caplog) -> list:
    return [r.getMessage() for r in caplog.records if "trial budget" in r.getMessage()]


# --------------------------------------------------------------------------- #
# TrialBudget and the budgeted seq search
# --------------------------------------------------------------------------- #

def test_trial_budget_grants_until_exhausted():
    budget = TrialBudget(10)
    assert budget.grant(4) == 4 and not budget.exhausted
    budget.spend(4)
    assert budget.grant(6) == 6 and not budget.exhausted
    budget.spend(6)
    assert budget.grant(1) == 0 and budget.exhausted
    assert budget.used == 10


def test_record_seq_spends_only_the_trials_it_made():
    _ctype, hdr, frag = _seal(CLIENT_SECRET, 7, b"x")
    budget = TrialBudget(100)
    assert tls_stream._record_seq(bytes.fromhex(CLIENT_SECRET), SUITE, hdr, frag,
                                  50, min_seq=2, budget=budget) == 7
    assert budget.used == 6 and not budget.exhausted  # seqs 2..7


def test_record_seq_stops_at_the_budget():
    _ctype, hdr, frag = _seal(CLIENT_SECRET, 40, b"x")
    budget = TrialBudget(30)
    assert tls_stream._record_seq(bytes.fromhex(CLIENT_SECRET), SUITE, hdr, frag,
                                  100, budget=budget) is None
    assert budget.exhausted and budget.used == 30


def test_pick_binding_is_unchanged_under_an_ample_budget(monkeypatch):
    records = [_seal(CLIENT_SECRET, 9, b"a"), _seal(CLIENT_SECRET, 10, b"b")]
    trials = _count_trials(monkeypatch)
    unbudgeted = tls_stream.pick_binding(CLIENT_SECRET, records, max_seq=MAX_SEQ)
    unbudgeted_trials = len(trials)
    del trials[:]
    budget = TrialBudget(10_000)
    assert tls_stream.pick_binding(CLIENT_SECRET, records, max_seq=MAX_SEQ,
                                   budget=budget) == unbudgeted
    assert budget.used == len(trials) == unbudgeted_trials


def test_exhausted_budget_makes_no_trials(monkeypatch):
    budget = TrialBudget(0)
    budget.grant(1)
    trials = _count_trials(monkeypatch)
    assert tls_stream.pick_binding(CLIENT_SECRET, [_seal(CLIENT_SECRET, 0, b"a")],
                                   budget=budget) is None
    assert trials == []


# --------------------------------------------------------------------------- #
# Sidecar loading: dedup + bundle cap
# --------------------------------------------------------------------------- #

def test_duplicate_bundles_are_deduplicated_by_secret_material(tmp_path):
    first = _bundle(client_random="00" * 32)
    path = _write_sidecar(tmp_path, [
        first,
        _bundle(client_random="ff" * 32),                         # same secrets
        _bundle(CLIENT_SECRET.upper(), SERVER_SECRET.upper()),    # same, other case
        _bundle(*ORPHAN),
        _bundle(server=""),                                       # one secret only: distinct
        _bundle(*ORPHAN),
    ])
    assert pl.load_secret_bundles(path) == [first, _bundle(*ORPHAN), _bundle(server="")]


def test_duplicate_orphan_bundles_cost_no_extra_trials(monkeypatch, tmp_path):
    streams = [_stream(*FOREIGN, 40000), _stream(CLIENT_SECRET, SERVER_SECRET, 40001)]
    trials = _count_trials(monkeypatch)
    _run(monkeypatch, tmp_path, [_bundle(*ORPHAN), _bundle()], streams)
    single = len(trials)
    del trials[:]
    keys = _run(monkeypatch, tmp_path, [_bundle(*ORPHAN)] * 50 + [_bundle()], streams)
    assert len(keys) == 1 and len(trials) == single


def test_bundle_cap_is_enforced_with_one_warning(tmp_path, caplog):
    bundles = [_bundle(f"{i:064x}", "") for i in range(1, 6)]
    path = _write_sidecar(tmp_path, bundles)
    with caplog.at_level(logging.WARNING):
        assert pl.load_secret_bundles(path, max_bundles=3) == bundles[:3]
    capped = [r.getMessage() for r in caplog.records if "distinct secret bundles" in r.getMessage()]
    assert len(capped) == 1 and "only the first 3" in capped[0]


def test_default_bundle_cap(tmp_path, caplog):
    count = pl.MAX_SECRET_BUNDLES + 1
    path = _write_sidecar(tmp_path, [_bundle(f"{i:064x}", "") for i in range(1, count + 1)])
    with caplog.at_level(logging.WARNING):
        assert len(pl.load_secret_bundles(path)) == pl.MAX_SECRET_BUNDLES == 4096
    assert any("distinct secret bundles" in r.getMessage() for r in caplog.records)


def test_no_cap_warning_at_the_limit(tmp_path, caplog):
    path = _write_sidecar(tmp_path, [_bundle(f"{i:064x}", "") for i in range(1, 4)]
                          + [_bundle("01".zfill(64), "")])  # a duplicate past the limit
    with caplog.at_level(logging.WARNING):
        assert len(pl.load_secret_bundles(path, max_bundles=3)) == 3
    assert not any("distinct secret bundles" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- #
# The stage's global trial budget
# --------------------------------------------------------------------------- #

def test_trial_budget_stops_the_search_and_warns(monkeypatch, tmp_path, caplog):
    """An orphan bundle ahead of the right one burns the whole budget: the
    search stops (no trial past the budget) and ONE warning names the streams
    left unsearched; with an ample budget the right bundle binds."""
    streams = [_stream(*FOREIGN, 40000), _stream(CLIENT_SECRET, SERVER_SECRET, 40001)]
    bundles = [_bundle(*ORPHAN), _bundle()]
    assert len(_run(monkeypatch, tmp_path, bundles, streams)) == 1

    trials = _count_trials(monkeypatch)
    with caplog.at_level(logging.WARNING):
        keys = _run(monkeypatch, tmp_path, bundles, streams, trial_budget=1000)
    assert keys == set()
    assert len(trials) == 1000
    (warning,) = _budget_warnings(caplog)
    assert "after 1000 trial decryptions" in warning
    assert "2 unbound stream(s) stayed unsearched" in warning
    assert "2 secret bundle(s) left unplaced" in warning


def test_trial_budget_defaults_to_the_module_constant(monkeypatch, tmp_path, caplog):
    assert pl.MIDSTREAM_TRIAL_BUDGET == 5_000_000
    monkeypatch.setattr(pl, "MIDSTREAM_TRIAL_BUDGET", 200)
    streams = [_stream(*FOREIGN, 40000)]
    trials = _count_trials(monkeypatch)
    with caplog.at_level(logging.WARNING):
        _run(monkeypatch, tmp_path, [_bundle(*ORPHAN)], streams)
    assert len(trials) == 200
    assert len(_budget_warnings(caplog)) == 1


def test_default_budget_leaves_normal_results_unchanged(monkeypatch, tmp_path, caplog):
    streams = [_stream(*FOREIGN, 40000), _stream(CLIENT_SECRET, SERVER_SECRET, 40001),
               _stream("55" * 32, "66" * 32, 40002, seq=250)]
    bundles = [_bundle(*ORPHAN), _bundle(), _bundle("55" * 32, "66" * 32)]
    with caplog.at_level(logging.WARNING):
        default = _run(monkeypatch, tmp_path, bundles, streams)
    unlimited = _run(monkeypatch, tmp_path, bundles, streams, trial_budget=10 ** 12)
    assert default == unlimited and len(default) == 2
    assert not _budget_warnings(caplog)
