"""Unit tests for the Schannel in-Python trial oracle (friTap.offline.schannel.oracle).

The tri-state (True / False / None=ask-tshark) is checked with hand-built streams
(no pcap), and the correlator is checked to not touch tshark when the oracle
decides every stream (``streams_matching_filter`` is patched to raise).
"""
from __future__ import annotations

import pytest

from friTap.offline.schannel import correlate as sc
from friTap.offline.schannel import oracle as oc
from friTap.offline.schannel import unpaired as up
from friTap.offline.tls import records as rec


def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _server_hello(suite: int, *, selected_version=None, legacy=0x0303,
                  random=b"\x11" * 32) -> rec.ServerHelloInfo:
    exts = b""
    if selected_version is not None:
        ext_body = selected_version.to_bytes(2, "big")
        exts = (rec.EXT_SUPPORTED_VERSIONS.to_bytes(2, "big")
                + len(ext_body).to_bytes(2, "big") + ext_body)
    body = (legacy.to_bytes(2, "big") + random + b"\x00"
            + suite.to_bytes(2, "big") + b"\x00"
            + len(exts).to_bytes(2, "big") + exts)
    return rec.server_hello_info(_handshake(2, body))


def _stream(version_suite, selected_version=None, legacy=0x0303):
    sh = _server_hello(version_suite, selected_version=selected_version, legacy=legacy)
    return oc._Stream([], [], "aa" * 32, sh)


def _oracle_with(cr, streams):
    return oc.TrialOracle({cr: streams})


CR = "aa" * 32


def test_duplicate_client_random_is_none():
    s = _stream(0xC02F)
    oracle = _oracle_with(CR, [s, s])          # two conversations, same cr
    assert oracle.tls12_match(CR, "00" * 48) is None
    assert oracle.tls13_probe(CR, "SERVER_TRAFFIC_SECRET_0", "00" * 32) is None


def test_missing_client_random_is_none():
    oracle = oc.TrialOracle({})
    assert oracle.tls12_match(CR, "00" * 48) is None


def test_tls10_tls11_are_none():
    for legacy in (0x0301, 0x0302):
        oracle = _oracle_with(CR, [_stream(0xC02F, legacy=legacy)])
        assert oracle.tls12_match(CR, "00" * 48) is None
        assert oracle.tls13_probe(CR, "SERVER_TRAFFIC_SECRET_0", "00" * 32) is None


def test_unknown_tls12_suite_is_none():
    # A clean TLS 1.2 stream whose suite is neither AEAD nor a supported CBC
    # suite (3DES) → the oracle cannot decide, so tshark must.
    oracle = _oracle_with(CR, [_stream(0x000A)])   # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    assert oracle.tls12_match(CR, "00" * 48) is None


def test_supported_cbc_suite_is_routed_not_short_circuited():
    # A supported AES-CBC suite is no longer rejected at the suite gate: with no
    # post-CCS records to check it is a decidable "no" (False), distinguishing it
    # from an unsupported suite (None). This proves the CBC dispatch is reached.
    oracle = _oracle_with(CR, [_stream(0xC027)])   # ECDHE_RSA_AES128_CBC_SHA256
    assert oracle.tls12_match(CR, "00" * 48) is False


def test_tls13_connection_rejects_tls12_master():
    oracle = _oracle_with(CR, [_stream(0x1301, selected_version=0x0304)])
    assert oracle.tls12_match(CR, "00" * 48) is False


def test_tls12_connection_rejects_tls13_label():
    oracle = _oracle_with(CR, [_stream(0xC02F)])
    assert oracle.tls13_probe(CR, "SERVER_TRAFFIC_SECRET_0", "00" * 32) is False


def test_tls13_unknown_suite_is_none():
    oracle = _oracle_with(CR, [_stream(0x00FF, selected_version=0x0304)])
    assert oracle.tls13_probe(CR, "SERVER_TRAFFIC_SECRET_0", "00" * 32) is None


def test_tls13_secret_length_mismatch_is_false():
    # SHA-256 suite but a 48-byte (SHA-384) secret can never be its traffic secret.
    oracle = _oracle_with(CR, [_stream(0x1301, selected_version=0x0304)])
    assert oracle.tls13_probe(CR, "SERVER_TRAFFIC_SECRET_0", "00" * 48) is False


def test_exporter_label_not_handled_by_oracle():
    oracle = _oracle_with(CR, [_stream(0x1301, selected_version=0x0304)])
    assert oracle.tls13_probe(CR, "EXPORTER_SECRET", "00" * 32) is None


def test_env_disable(monkeypatch):
    monkeypatch.setenv(oc.ORACLE_ENV, "0")
    assert oc.TrialOracle.from_pcap("tests/fixtures/schannel_tls13.pcap") is None


def test_analyze_pair_degraded_is_skipped():
    class _R:
        degraded = True
        def contiguous_bytes(self):      # pragma: no cover - never reached
            return b""

    class _Pair:
        client = _R()
        server = _R()

    assert oc._analyze_pair(_Pair()) is None


def test_unpaired_group_column_parsed():
    s13 = "cc" * 32
    text = (f"schannel_tls13_secret {s13} - 772 group=conn7\n"
            f"schannel_tls13_secret {'dd' * 32} - 772 bareid\n"
            f"schannel_tls12_master {'aa' * 48} - 771\n")   # no 5th column → None
    records = up.parse_unpaired(text)
    by_secret = {r.secret: r for r in records}
    assert by_secret[s13].group == "conn7"
    assert by_secret["dd" * 32].group == "bareid"
    assert by_secret["aa" * 48].group is None
    assert up.tls13_groups(records) == {s13: "conn7", "dd" * 32: "bareid"}


class _FakeOracleAllTrue:
    """An oracle that decides every query True, so tshark must never be called."""

    def tls12_match(self, cr, master):
        return True

    def tls13_probe(self, cr, label, secret):
        return label == "SERVER_TRAFFIC_SECRET_0"


def _raise(*_a, **_k):  # pragma: no cover - only hit on a regression
    raise AssertionError("tshark must not run when the oracle decides every stream")


def test_correlate_tls12_no_tshark_when_oracle_decides_all(monkeypatch):
    monkeypatch.setattr(sc, "read_client_randoms", lambda *_a, **_k: {"0": "11" * 32})
    monkeypatch.setattr(sc, "streams_that_decrypted", _raise)
    lines = sc.correlate_tls12("tshark", "cap.pcapng", ["ab" * 48],
                               oracle=_FakeOracleAllTrue())
    assert lines == [f"CLIENT_RANDOM {'11' * 32} {'ab' * 48}\n"]


def test_correlate_tls13_no_tshark_when_oracle_decides_all(monkeypatch):
    monkeypatch.setattr(sc, "read_tls13_client_randoms",
                        lambda *_a, **_k: {"0": "11" * 32})
    monkeypatch.setattr(sc, "streams_matching_filter", _raise)
    records = [{"secret": "cd" * 32, "label": None, "group": None}]
    lines = sc.correlate_tls13("tshark", "cap.pcapng", records,
                               oracle=_FakeOracleAllTrue())
    assert lines == [f"SERVER_TRAFFIC_SECRET_0 {'11' * 32} {'cd' * 32}\n"]


class _FakeOracleByLabel:
    """Decides each (secret, label) from a map; everything else False."""

    def __init__(self, placements):
        self._p = placements  # {secret: label}

    def tls12_match(self, cr, master):       # pragma: no cover - unused
        return False

    def tls13_probe(self, cr, label, secret):
        return self._p.get(secret) == label


def test_exporter_placed_by_elimination(monkeypatch):
    cr = "11" * 32
    monkeypatch.setattr(sc, "read_tls13_client_randoms", lambda *_a, **_k: {"0": cr})
    monkeypatch.setattr(sc, "streams_matching_filter", _raise)
    labels = list(sc.TLS13_TRIAL_LABELS)
    secrets = {f"{i:02x}" * 32: lab for i, lab in enumerate(labels, 1)}
    exporter = "aa" * 32
    oracle = _FakeOracleByLabel(secrets)
    # Every secret carries the same group; the exporter is unlabeled and
    # undecryptable, so it is placed only by elimination once the four decryptable
    # labels are in.
    records = [{"secret": s, "label": None, "group": "g1"} for s in secrets]
    records.append({"secret": exporter, "label": None, "group": "g1"})
    lines = sc.correlate_tls13("tshark", "cap.pcapng", records, oracle=oracle)
    placed = {ln.split()[2]: ln.split()[0] for ln in lines}
    assert placed[exporter] == "EXPORTER_SECRET"
    for secret, label in secrets.items():
        assert placed[secret] == label


def test_exporter_placed_for_real_resident_group(monkeypatch):
    # The composition a REAL capture produces: only the two application traffic
    # secrets are resident and trial-decryptable (the handshake traffic secrets
    # are zeroized after the handshake), plus the unplaceable exporter. The
    # exporter must still be placed by elimination from this 3-member group —
    # this is the case the former all-four-labels gate silently failed.
    cr = "11" * 32
    monkeypatch.setattr(sc, "read_tls13_client_randoms", lambda *_a, **_k: {"0": cr})
    monkeypatch.setattr(sc, "streams_matching_filter", _raise)
    secrets = {"01" * 32: "SERVER_TRAFFIC_SECRET_0",
               "02" * 32: "CLIENT_TRAFFIC_SECRET_0"}
    exporter = "aa" * 32
    oracle = _FakeOracleByLabel(secrets)
    records = [{"secret": s, "label": None, "group": "g1"} for s in secrets]
    records.append({"secret": exporter, "label": None, "group": "g1"})
    lines = sc.correlate_tls13("tshark", "cap.pcapng", records, oracle=oracle)
    placed = {ln.split()[2]: ln.split()[0] for ln in lines}
    assert placed[exporter] == "EXPORTER_SECRET"
    assert placed["01" * 32] == "SERVER_TRAFFIC_SECRET_0"
    assert placed["02" * 32] == "CLIENT_TRAFFIC_SECRET_0"


def test_exporter_not_placed_without_full_group(monkeypatch):
    cr = "11" * 32
    monkeypatch.setattr(sc, "read_tls13_client_randoms", lambda *_a, **_k: {"0": cr})
    monkeypatch.setattr(sc, "streams_matching_filter", _raise)
    # Handshake-only labels present, neither application traffic secret → the gate
    # still refuses to place the exporter (no false positive).
    secrets = {"01" * 32: "SERVER_HANDSHAKE_TRAFFIC_SECRET",
               "02" * 32: "CLIENT_HANDSHAKE_TRAFFIC_SECRET"}
    exporter = "aa" * 32
    records = [{"secret": s, "label": None, "group": "g1"} for s in secrets]
    records.append({"secret": exporter, "label": None, "group": "g1"})
    lines = sc.correlate_tls13("tshark", "cap.pcapng", records,
                               oracle=_FakeOracleByLabel(secrets))
    placed = {ln.split()[2] for ln in lines}
    assert exporter not in placed


# --------------------------------------------------------------------------- #
# Group-scoped EXPORTER elimination
# --------------------------------------------------------------------------- #

def _four_label_secrets(start):
    return {f"{i:02x}" * 32: lab
            for i, lab in enumerate(sc.TLS13_TRIAL_LABELS, start)}


def test_exporter_elimination_requires_the_groups_own_labels(monkeypatch):
    # The connection's four labels were placed by secrets of ANOTHER group (g2);
    # g1's lone placed member does not make g1's leftover secret the exporter.
    cr = "11" * 32
    monkeypatch.setattr(sc, "read_tls13_client_randoms", lambda *_a, **_k: {"0": cr})
    monkeypatch.setattr(sc, "streams_matching_filter", _raise)
    g2 = _four_label_secrets(1)
    g1_member = "77" * 32
    oracle = _FakeOracleByLabel({**g2, g1_member: "SERVER_TRAFFIC_SECRET_0"})
    leftover = "aa" * 32
    records = [{"secret": s, "label": None, "group": "g2"} for s in g2]
    records += [{"secret": g1_member, "label": None, "group": "g1"},
                {"secret": leftover, "label": None, "group": "g1"}]
    lines = sc.correlate_tls13("tshark", "cap.pcapng", records, oracle=oracle)
    assert leftover not in {ln.split()[2] for ln in lines}


def test_exporter_hinted_secret_placed_by_elimination(monkeypatch):
    cr = "11" * 32
    monkeypatch.setattr(sc, "read_tls13_client_randoms", lambda *_a, **_k: {"0": cr})
    monkeypatch.setattr(sc, "streams_matching_filter", _raise)
    secrets = _four_label_secrets(1)
    exporter = "aa" * 32
    records = [{"secret": s, "label": None, "group": "g1"} for s in secrets]
    records.append({"secret": exporter, "label": "EXPORTER_SECRET", "group": "g1"})
    lines = sc.correlate_tls13("tshark", "cap.pcapng", records,
                               oracle=_FakeOracleByLabel(secrets))
    assert f"EXPORTER_SECRET {cr} {exporter}\n" in lines


class _FakeOracleByStream:
    """Decides (cr, label, secret) from {secret: (label, cr)}; else False."""

    def __init__(self, placements):
        self._p = placements

    def tls13_probe(self, cr, label, secret):
        return self._p.get(secret) == (label, cr)


def test_group_spread_over_two_connections_places_nothing(monkeypatch):
    cr0, cr1 = "11" * 32, "22" * 32
    monkeypatch.setattr(sc, "read_tls13_client_randoms",
                        lambda *_a, **_k: {"0": cr0, "1": cr1})
    monkeypatch.setattr(sc, "streams_matching_filter", _raise)
    a, b = "01" * 32, "02" * 32
    oracle = _FakeOracleByStream({a: ("SERVER_HANDSHAKE_TRAFFIC_SECRET", cr0),
                                  b: ("SERVER_HANDSHAKE_TRAFFIC_SECRET", cr1)})
    exporter = "aa" * 32
    records = [{"secret": a, "label": None, "group": "g"},
               {"secret": b, "label": None, "group": "g"},
               {"secret": exporter, "label": "EXPORTER_SECRET", "group": "g"}]
    lines = sc.correlate_tls13("tshark", "cap.pcapng", records, oracle=oracle)
    assert exporter not in {ln.split()[2] for ln in lines}


def test_correlate_unpaired_detailed_counts_unplaced(monkeypatch):
    cr = "11" * 32
    monkeypatch.setattr(sc, "read_tls13_client_randoms", lambda *_a, **_k: {"0": cr})
    monkeypatch.setattr(sc, "read_client_randoms", lambda *_a, **_k: {})
    monkeypatch.setattr(sc, "streams_matching_filter", _raise)
    placed = "01" * 32
    monkeypatch.setattr(sc, "_build_oracle", lambda *_a: _FakeOracleByLabel(
        {placed: "SERVER_TRAFFIC_SECRET_0"}))
    result = sc.correlate_unpaired_detailed(
        "tshark", "cap.pcapng", ["ab" * 48], [placed, "02" * 32])
    assert result.lines == [f"SERVER_TRAFFIC_SECRET_0 {cr} {placed}\n"]
    assert (result.unplaced_masters, result.unplaced_tls13) == (1, 1)


# --------------------------------------------------------------------------- #
# Oracle failures are "ask tshark", never a confident answer
# --------------------------------------------------------------------------- #

class _RaisingOracle:
    def tls12_match(self, cr, master):
        raise RuntimeError("boom")

    def tls13_probe(self, cr, label, secret):
        raise RuntimeError("boom")


def test_partition_by_oracle_treats_errors_as_undecided():
    def verdict(cr):
        if cr == "bad":
            raise RuntimeError("boom")
        return {"yes": True, "no": False}.get(cr)

    matched, undecided = sc._partition_by_oracle(
        {"0": "yes", "1": "no", "2": "bad", "3": "maybe"}, verdict)
    assert matched == ["0"]
    assert undecided == {"2": "bad", "3": "maybe"}
    assert sc._partition_by_oracle({"0": "x"}, None) == ([], {"0": "x"})


def test_raising_oracle_falls_back_to_tshark(monkeypatch):
    monkeypatch.setattr(sc, "read_client_randoms", lambda *_a, **_k: {"0": "11" * 32})
    monkeypatch.setattr(sc, "streams_that_decrypted", lambda *_a, **_k: {"0"})
    lines = sc.correlate_tls12("tshark", "cap.pcapng", ["ab" * 48],
                               oracle=_RaisingOracle())
    assert lines == [f"CLIENT_RANDOM {'11' * 32} {'ab' * 48}\n"]
    probed = []
    monkeypatch.setattr(sc, "probe_tls13_label",
                        lambda _t, _p, label, _s, crs: probed.append(label) or set())
    assert sc.place_tls13_secret("tshark", "cap.pcapng", "cd" * 32,
                                 {"0": "11" * 32}, oracle=_RaisingOracle()) == []
    assert probed == list(sc.TLS13_TRIAL_LABELS)


# --------------------------------------------------------------------------- #
# TLS 1.3 record-level behaviour (needs the AEAD backend)
# --------------------------------------------------------------------------- #

_SUITE13 = "TLS_AES_128_GCM_SHA256"


def _seal13(secret, seq, inner):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from friTap.offline.tls.tls13 import derive_key_iv, record_nonce

    key, iv = derive_key_iv(secret, _SUITE13)
    hdr = bytes([0x17, 3, 3]) + (len(inner) + 16).to_bytes(2, "big")
    return (0x17, hdr, AESGCM(key).encrypt(record_nonce(iv, seq), inner, hdr))


def _tls13_stream(server_records=(), client_records=(), offered_early_data=None):
    sh = _server_hello(0x1301, selected_version=0x0304)
    return oc._Stream(list(client_records), list(server_records), CR, sh,
                      offered_early_data)


def test_keyupdate_then_more_handshake_rolls_the_secret_once():
    pytest.importorskip("cryptography")
    from friTap.offline.tls.tls13 import next_traffic_secret

    sts0 = bytes(range(32))
    sts1 = next_traffic_secret(sts0, _SUITE13)
    records = [
        _seal13(sts0, 0, _handshake(24, b"\x00") + b"\x16"),       # KeyUpdate
        _seal13(sts1, 0, _handshake(4, b"\x00" * 12) + b"\x16"),   # NewSessionTicket
        _seal13(sts1, 1, b"hello\x17"),                            # app data
    ]
    oracle = _oracle_with(CR, [_tls13_stream(server_records=records)])
    assert oracle.tls13_probe(CR, "SERVER_TRAFFIC_SECRET_0", sts0.hex()) is True


def _junk_records(n):
    return [(0x17, bytes([0x17, 3, 3, 0, 32]), bytes(32)) for _ in range(n)]


def test_missing_anchor_is_false_only_when_the_search_was_exhaustive():
    pytest.importorskip("cryptography")
    secret = ("5a" * 32)
    few = _oracle_with(CR, [_tls13_stream(server_records=_junk_records(5))])
    assert few.tls13_probe(CR, "SERVER_TRAFFIC_SECRET_0", secret) is False
    many = _oracle_with(CR, [_tls13_stream(
        server_records=_junk_records(oc._MAX_ANCHOR_RECORDS + 1))])
    assert many.tls13_probe(CR, "SERVER_TRAFFIC_SECRET_0", secret) is None
    # The server handshake secret's anchor can only be record 0: conclusive.
    assert many.tls13_probe(CR, "SERVER_HANDSHAKE_TRAFFIC_SECRET", secret) is False


def test_client_handshake_anchor_window_depends_on_early_data():
    pytest.importorskip("cryptography")
    secret = ("5a" * 32)
    records = _junk_records(oc._MAX_ANCHOR_RECORDS + 1)
    for early, expected in ((False, False), (True, None), (None, None)):
        oracle = _oracle_with(CR, [_tls13_stream(client_records=records,
                                                 offered_early_data=early)])
        assert oracle.tls13_probe(
            CR, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", secret) is expected, early


def test_aead_backend_error_is_none(monkeypatch):
    pytest.importorskip("cryptography")

    def unsupported(*_a, **_k):
        raise RuntimeError("UnsupportedAlgorithm")

    monkeypatch.setattr(oc, "try_decrypt", unsupported)
    oracle = _oracle_with(CR, [_tls13_stream(server_records=_junk_records(3))])
    assert oracle.tls13_probe(CR, "SERVER_TRAFFIC_SECRET_0", "5a" * 32) is None


def test_tls12_backend_error_is_none(monkeypatch):
    pytest.importorskip("cryptography")
    from friTap.offline.tls import tls12

    sh = _server_hello(0xC02F)
    ccs = (0x14, bytes([0x14, 3, 3, 0, 1]), b"\x01")
    fin = (0x16, bytes([0x16, 3, 3, 0, 40]), bytes(40))
    stream = oc._Stream([ccs, fin], [ccs, fin], CR, sh)
    oracle = _oracle_with(CR, [stream])
    assert oracle.tls12_match(CR, "ab" * 48) is False       # tag failure: a real no

    def unsupported(*_a, **_k):
        raise RuntimeError("UnsupportedAlgorithm")

    monkeypatch.setattr(tls12, "_aead", unsupported)
    assert oracle.tls12_match(CR, "ab" * 48) is None
