"""Pure-logic tests for the offline Schannel correlation package.

Ports the tshark-free assertions from
``research/memory_scan_lsass/tests/test_schannel_correlate.py`` and
``.../test_sspi_correlate.py`` (parsing, grouping, keylog assembly, the entropy
gates and the two in-memory scanners), adds parser tests for the
``.schannel.unpaired`` sidecar format, and checks the decryptor's self-registration
(the ``--schannel-unpaired`` flag appears; the registry includes ``schannel``). The
trial-decryption orchestration needs a real pcap + tshark and is out of scope for a
unit test.
"""
from __future__ import annotations

import struct

import friTap.offline.pcap_to_tap  # noqa: F401 - side effect: registers built-ins + discovery
from friTap.offline.registry import get_offline_decryptor_registry
from friTap.offline.schannel import correlate as sc
from friTap.offline.schannel import pidmap as pm
from friTap.offline.schannel import sspi
from friTap.offline.schannel import unpaired as up

M1 = "aa" * 48          # a TLS 1.2 master / SHA-384-sized secret
M2 = "bb" * 48
S256 = "cc" * 32        # SHA-256-sized TLS 1.3 secret
CR1 = "11" * 32
CR2 = "22" * 32
SID1 = "abcd1234"


# --------------------------------------------------------------------------- #
# correlate.py — TLS 1.2 pure logic
# --------------------------------------------------------------------------- #

def test_parse_secrets_forms_and_dedup():
    text = f"""# comment
kind=schannel_tls12_master session_id={SID1} secret={M1}
kind=schannel_tls12_master session_id= secret={M2}
kind=schannel_tls12_master session_id= secret={M1}
{M2}
deadbeef
"""
    assert sc.parse_secrets(text) == [M1, M2]


def test_parse_session_map_drops_empty_ids():
    text = f"session_id={SID1} secret={M1}\nsession_id= secret={M2}\n"
    assert sc.parse_session_map(text) == {SID1: M1}


def test_parse_tshark_fields_pads():
    assert sc.parse_tshark_fields("0\t11:22\n1\n\n2\taa", 2) == \
        [["0", "11:22"], ["1", ""], ["2", "aa"]]


def test_client_randoms_from_rows():
    rows = [["0", ":".join(["11"] * 32)], ["0", ":".join(["99"] * 32)],
            ["1", "22" * 32], ["2", "short"]]
    assert sc.client_randoms_from_rows(rows) == {"0": CR1, "1": CR2}


def test_build_keylog():
    assert sc.build_keylog([CR1, CR2], M1) == \
        f"CLIENT_RANDOM {CR1} {M1}\nCLIENT_RANDOM {CR2} {M1}\n"


# --------------------------------------------------------------------------- #
# correlate.py — TLS 1.3 pure logic
# --------------------------------------------------------------------------- #

def test_parse_tls13_kv_labeled_grouped():
    text = (f"kind=schannel_tls13 group=7 label=SERVER_HANDSHAKE_TRAFFIC_SECRET secret={M1}\n"
            f"kind=schannel_tls13 group=7 label=EXPORTER_SECRET secret={S256}\n")
    recs = sc.parse_tls13_records(text)
    assert recs == [
        {"secret": M1, "label": "SERVER_HANDSHAKE_TRAFFIC_SECRET", "group": "7"},
        {"secret": S256, "label": "EXPORTER_SECRET", "group": "7"},
    ]


def test_parse_tls13_nss_triple_and_bare():
    text = (f"CLIENT_TRAFFIC_SECRET_0 {CR1} {S256}\n"   # NSS triple: cr ignored
            f"SERVER_TRAFFIC_SECRET_0 {M2}\n"           # label + secret
            f"{M1}\n"                                    # bare hex, unlabeled
            "notahexsecret\n")
    recs = sc.parse_tls13_records(text)
    assert recs == [
        {"secret": S256, "label": "CLIENT_TRAFFIC_SECRET_0", "group": None},
        {"secret": M2, "label": "SERVER_TRAFFIC_SECRET_0", "group": None},
        {"secret": M1, "label": None, "group": None},
    ]


def test_parse_tls13_rejects_bad_lengths_and_stale_labels():
    text = f"label=NOT_A_REAL_LABEL secret={M1}\nsecret=deadbeef\n"
    recs = sc.parse_tls13_records(text)
    assert recs == [{"secret": M1, "label": None, "group": None}]


def test_unique_secrets_order_preserved():
    recs = [{"secret": M1, "label": None, "group": None},
            {"secret": M1, "label": "X", "group": None},
            {"secret": S256, "label": None, "group": None}]
    assert sc.unique_secrets(recs) == [M1, S256]


def test_group_connection_map_rides_along():
    recs = [{"secret": M1, "label": "SERVER_HANDSHAKE_TRAFFIC_SECRET", "group": "7"},
            {"secret": S256, "label": "EXPORTER_SECRET", "group": "7"},
            {"secret": M2, "label": None, "group": None}]
    assert sc.group_connection_map(recs, {M1: "3"}) == {"7": "3"}


def test_build_tls13_probe_keylog():
    crs = {"0": CR1, "1": CR2}
    out = sc.build_tls13_probe_keylog("SERVER_HANDSHAKE_TRAFFIC_SECRET", crs, M1)
    assert out == (f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR1} {M1}\n"
                   f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR2} {M1}\n")


def test_records_from_secret_lists_adapts_unpaired_hexes():
    masters, recs = sc.records_from_secret_lists([M1, "bad", M2], [S256, "short"])
    assert masters == [M1, M2]
    assert recs == [{"secret": S256, "label": None, "group": None}]


# --------------------------------------------------------------------------- #
# unpaired.py — '.schannel.unpaired' sidecar parser
# --------------------------------------------------------------------------- #

def test_parse_unpaired_forms_kinds_and_versions():
    text = (
        "# kind secret session_id ssl_version\n"
        f"schannel_tls12_master {M1} - 771\n"
        f"schannel_tls13_secret {S256} - 772\n"
        f"schannel_tls13_secret {M2} - 772\n"
        "\n"
        "garbage line\n"
    )
    recs = up.parse_unpaired(text)
    assert [r.kind for r in recs] == [
        up.KIND_TLS12_MASTER, up.KIND_TLS13_SECRET, up.KIND_TLS13_SECRET]
    assert up.tls12_masters(recs) == [M1]
    assert up.tls13_secrets(recs) == [S256, M2]
    assert recs[0].is_tls12 and recs[1].is_tls13
    assert recs[0].ssl_version == up.SSL_VERSION_TLS12
    assert recs[1].ssl_version == up.SSL_VERSION_TLS13


def test_parse_unpaired_dedups_and_reads_session_id():
    text = (
        f"schannel_tls12_master {M1} {SID1} 771\n"
        f"schannel_tls12_master {M1} {SID1} 771\n"   # dup on (kind, secret)
        f"schannel_tls12_master {M2} - 771\n"
    )
    recs = up.parse_unpaired(text)
    assert len(recs) == 2
    assert recs[0].session_id == SID1 and recs[1].session_id is None
    assert up.session_map(recs) == {SID1: M1}


def test_parse_unpaired_rejects_bad_secret_lengths():
    text = (
        f"schannel_tls12_master {S256} - 771\n"   # 32B is not a valid TLS 1.2 master
        "schannel_tls13_secret deadbeef - 772\n"  # too short for a TLS 1.3 secret
        f"schannel_tls13_secret {S256} - 772\n"   # valid
    )
    recs = up.parse_unpaired(text)
    assert [r.secret for r in recs] == [S256]
    assert recs[0].is_tls13


# --------------------------------------------------------------------------- #
# sspi.py — entropy gates, intersection, keylog helpers, in-memory scanners
# --------------------------------------------------------------------------- #

S48 = bytes(range(1, 49)).hex()
S48B = bytes(range(50, 98)).hex()
CR = "aa" * 32


class _FakeSrc:
    """Minimal source over (va, bytes) chunks, mirroring MiniDump/LiveProcess."""

    def __init__(self, chunks):
        self.chunks = chunks

    def search(self, needle):
        out = []
        for va, data in self.chunks:
            i = 0
            while True:
                j = data.find(needle, i)
                if j == -1:
                    break
                out.append(va + j)
                i = j + 1
        return out

    def read_va(self, va, n):
        for base, data in self.chunks:
            if base <= va < base + len(data):
                off = va - base
                return data[off:off + n] if off + n <= len(data) else None
        return None


def test_entropy_and_looks_secret():
    assert sspi.zero_fraction(b"\x00\x00\x00\x00") == 1.0
    assert sspi.shannon(bytes(range(48))) > 4.0
    assert sspi.looks_secret(bytes(range(1, 49)))
    assert not sspi.looks_secret(b"\x00" * 48)
    assert not sspi.looks_secret(b"AAAA")
    assert not sspi.looks_secret(None)


def test_intersect():
    assert sspi.intersect({S48, S48B}, {S48, "cc" * 48}) == {S48}


def test_keylog_secret_map_and_lines():
    text = (f"CLIENT_TRAFFIC_SECRET_0 {CR} {S48}\n"
            f"# c\n"
            f"SERVER_TRAFFIC_SECRET_0 {CR} {S48B}\n")
    m = sspi.keylog_secret_map(text)
    assert m[S48] == ("CLIENT_TRAFFIC_SECRET_0", CR)
    out = sspi.build_keylog_lines(m, {S48})
    assert out == f"CLIENT_TRAFFIC_SECRET_0 {CR} {S48}\n"


def test_scan_tls13_reads_at_3lss_plus_0x6a():
    secret = bytes(range(1, 49))
    blob = bytearray(0x200)
    blob[0x100:0x104] = b"3lss"
    blob[0x100 + 0x6a:0x100 + 0x6a + 48] = secret
    src = _FakeSrc([(0x7ff00000000, bytes(blob))])
    assert sspi.scan_tls13(src) == {secret.hex()}


def test_scan_tls13_honours_custom_profile_offsets():
    # scan_tls13 is data-driven: the anchor tag, secret offset and candidate
    # lengths come from the profile's tls13_secret tier (mirroring scan_tls12),
    # so a recalibrated profile flows through instead of the hardcoded
    # 3lss/0x6a/[48,32]. A profile with a DIFFERENT tag/offset/length must be
    # honoured.
    secret = bytes(range(1, 33))  # 32-byte secret
    blob = bytearray(0x200)
    blob[0x100:0x104] = b"TAG!"
    blob[0x100 + 0x20:0x100 + 0x20 + 32] = secret
    src = _FakeSrc([(0x7ff00000000, bytes(blob))])
    profile = {"tiers": {"tls13_secret": {"anchor_tag": "TAG!", "secret_at": 0x20,
                                          "secret_lens": [32]}}}
    assert sspi.scan_tls13(src, profile) == {secret.hex()}
    # The default profile still resolves the shipped arm64 3lss+0x6a slot.
    assert profile["tiers"]["tls13_secret"]["secret_at"] == 0x20


def test_scan_tls12_via_needle():
    profile = {
        "needles": {"candidates": [{"rva": "0x10"}]},
        "tiers": {"tls12_master": {"needle_at": 16, "master_at": 28, "master_len": 48}},
    }
    base = 0x1000
    needle_value = base + 0x10
    master = bytes(range(1, 49))
    va0 = 0x7ff00000000
    off_needle = 0x80
    blob = bytearray(0x200)
    blob[off_needle:off_needle + 8] = struct.pack("<Q", needle_value)
    blob[off_needle + 12:off_needle + 12 + 48] = master
    src = _FakeSrc([(va0, bytes(blob))])
    assert sspi.scan_tls12(src, base, profile) == {master.hex()}


def test_load_profile_matches_real_offsets():
    p = sspi.load_profile()
    t = p["tiers"]["tls12_master"]
    assert t["needle_at"] == 16 and t["master_at"] == 28 and t["master_len"] == 48
    assert any(c["rva"] for c in p["needles"]["candidates"])


# --------------------------------------------------------------------------- #
# pidmap.py — the offline netstat/pcap/keylog join
# --------------------------------------------------------------------------- #

def test_canon_ip_folds_v6_loopback():
    assert pm.canon_ip("::1") == "127.0.0.1"
    assert pm.canon_ip("[::1]") == "127.0.0.1"
    assert pm.canon_ip(" 10.0.0.5 ") == "10.0.0.5"


def test_parse_stream_rows_keeps_client_endpoint():
    rows = [
        ["0", "127.0.0.1", "55000", "127.0.0.1", "8443", CR1],
        ["1", "127.0.0.1", "55001", "127.0.0.1", "8443", ("ab:" * 32)[:-1]],
        ["2", "127.0.0.1", "55002", "127.0.0.1", "8443", "tooShort"],
    ]
    got = pm.parse_stream_rows(rows)
    assert got[("127.0.0.1", "55000", "127.0.0.1", "8443")] == CR1
    assert got[("127.0.0.1", "55001", "127.0.0.1", "8443")] == "ab" * 32


def test_parse_keylog_by_cr_groups_labels():
    text = (f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {CR1} {S256}\n"
            f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR1} {'dd' * 32}\n"
            f"# comment\n"
            f"CLIENT_TRAFFIC_SECRET_0 {CR2} {'ee' * 48}\n")
    by = pm.parse_keylog_by_cr(text)
    assert by[CR1]["CLIENT_HANDSHAKE_TRAFFIC_SECRET"] == S256
    assert set(by[CR2]) == {"CLIENT_TRAFFIC_SECRET_0"}


def test_match_pid_full_tuple_and_fallbacks():
    conns = [{"pid": 42, "local_addr": "127.0.0.1", "local_port": "55000",
              "remote_addr": "127.0.0.1", "remote_port": "8443", "process": "pwsh"}]
    streams = {("127.0.0.1", "55000", "127.0.0.1", "8443"): CR1}
    out = pm.match_pid_to_cr(conns, streams)
    assert out[42]["client_random"] == CR1 and out[42]["matched_by"] == "4-tuple"


def test_match_pid_ambiguous_ports_not_matched():
    conns = [{"pid": 9, "local_addr": "0.0.0.0", "local_port": "5",
              "remote_addr": "9.9.9.9", "remote_port": "443", "process": ""}]
    streams = {("1.1.1.1", "5", "8.8.8.8", "443"): CR1,
               ("2.2.2.2", "5", "7.7.7.7", "443"): CR2}
    assert pm.match_pid_to_cr(conns, streams) == {}


def test_secrets_from_any_and_build_pid_keylog():
    text = (
        f"CLIENT_TRAFFIC_SECRET_0 {CR1} {S256}\n"
        f"kind=schannel_tls13_secret secret={'dd' * 48}\n"
        f"# comment {'ff' * 32}\n"
        f"{'ee' * 32}\n"
        "deadbeef\n"
    )
    got = pm.secrets_from_any(text)
    assert S256 in got and "dd" * 48 in got and "ee" * 32 in got
    assert "deadbeef" not in got
    out = pm.build_pid_keylog({42: {"client_random": CR1}},
                              {CR1: {"CLIENT_TRAFFIC_SECRET_0": S256}})
    assert out == f"CLIENT_TRAFFIC_SECRET_0 {CR1} {S256}\n"


# --------------------------------------------------------------------------- #
# Registration — the entry self-registers and the CLI flag is generated
# --------------------------------------------------------------------------- #

def test_schannel_entry_registered():
    reg = get_offline_decryptor_registry()
    assert "schannel" in reg.names()
    entry = reg.get("schannel")
    assert entry.cli_flag == "--schannel-unpaired"
    assert entry.cli_dest == "schannel_unpaired"
    assert entry.requires_tls_strip is False
    assert entry.protocol_name == "schannel"


def test_schannel_cli_flag_present():
    from friTap.offline.cli import _build_parser

    help_text = _build_parser().format_help()
    assert "--schannel-unpaired" in help_text


def test_derived_keylog_path():
    from friTap.offline.schannel.offline_decryptor import _derived_keylog_path

    assert _derived_keylog_path("keys.memscan.schannel.unpaired") == \
        "keys.memscan.schannel.nss.keylog"


# --------------------------------------------------------------------------- #
# S1 regression — TLS 1.3 traffic secrets must be placed under the CORRECT label
# via a DECRYPTION-GATED tshark field, never the always-present `tls.app_data`.
# These tests need no pcap/tshark: they model tshark's field semantics so they
# run everywhere and fail loudly if the probe map is reverted to `tls.app_data`.
# The real-tshark counterpart lives in
# tests/integration/test_schannel_tls13_correlate_e2e.py.
# --------------------------------------------------------------------------- #

def test_tls13_probe_signals_are_decryption_gated():
    # Constant-lock: the two traffic-secret probes must key off the decrypted
    # INNER *application_data* type (content_type==23) — the only signal that
    # requires a traffic secret to AEAD-decrypt an app record. They must NOT use
    # `tls.app_data` (encrypted payload, always present) NOR bare
    # `tls.record.content_type` (also present on the PLAINTEXT ClientHello/
    # ServerHello handshake records, type 22). The handshake probes use the
    # decryption-gated, encrypted-only handshake-type filters.
    # Anchored to a TLS 1.3 ciphertext record (opaque_type) because in TLS 1.2
    # content_type==23 is the OUTER plaintext type of every app record.
    app_data = "tls.record.opaque_type==23 && tls.record.content_type==23"
    assert sc.TLS13_PROBE_SIGNAL["SERVER_TRAFFIC_SECRET_0"] == app_data
    assert sc.TLS13_PROBE_SIGNAL["CLIENT_TRAFFIC_SECRET_0"] == app_data
    assert sc.TLS13_PROBE_SIGNAL["SERVER_HANDSHAKE_TRAFFIC_SECRET"] == "tls.handshake.type==8"
    assert sc.TLS13_PROBE_SIGNAL["CLIENT_HANDSHAKE_TRAFFIC_SECRET"] == "tls.handshake.type==20"
    # Guard the S1 traps: no probe may key off the ciphertext field, and no
    # traffic probe may use the bare (plaintext-polluted) content_type.
    assert "tls.app_data" not in set(sc.TLS13_PROBE_SIGNAL.values())
    assert "tls.record.content_type" not in set(sc.TLS13_PROBE_SIGNAL.values())


# Ground truth for the model: one TLS 1.3 connection (stream "0", client_random
# CR1) with a client- and a server-direction traffic secret.
_S1_SC = "cc" * 32   # true CLIENT_TRAFFIC_SECRET_0
_S1_SS = "dd" * 32   # true SERVER_TRAFFIC_SECRET_0
_S1_TRUE_LABEL = {
    _S1_SC: "CLIENT_TRAFFIC_SECRET_0",
    _S1_SS: "SERVER_TRAFFIC_SECRET_0",
}
_S1_CR_TO_STREAM = {CR1: "0"}


def _fake_streams_matching_filter(tshark_bin, pcap, keylog_path, display_filter):
    """Model tshark: read the probe keylog and apply field semantics.

    A probe keylog pairs ONE (label, secret) with every stream's client_random.
    We model the field kinds the S1 fix distinguishes:

      * `tls.app_data` — the ENCRYPTED payload, present on every app record; and
      * bare `tls.record.content_type` — present on the PLAINTEXT handshake
        records (ClientHello/ServerHello) regardless of any secret.
        Both match EVERY stream unconditionally, so neither can prove a
        (secret,label) pairing — the two S1 traps.
      * decryption-gated fields — `tls.record.content_type==23` (decrypted
        application_data) and `tls.handshake.type==8/==20` (encrypted-only
        handshake messages) — appear only once the AEAD tag verifies, so they
        match a stream ONLY when the probed secret genuinely is that label.
    """
    from pathlib import Path
    unconditional = {"tls.app_data", "tls.record.content_type"}
    matched = set()
    for line in Path(keylog_path).read_text().splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        label, cr, secret = parts
        stream = _S1_CR_TO_STREAM.get(cr)
        if stream is None:
            continue
        if display_filter in unconditional:
            matched.add(stream)  # always present — the traps
        elif _S1_TRUE_LABEL.get(secret) == label:
            matched.add(stream)  # decryption-gated: only the true label matches
    return matched


def test_correlate_tls13_places_traffic_secrets_under_correct_label(monkeypatch):
    # End-to-end orchestration over the model: bare (unlabeled) secrets, exactly
    # as the mem-scan sidecar emits them, must be re-labelled by trial decryption
    # and land under their TRUE label — the client secret under
    # CLIENT_TRAFFIC_SECRET_0, the server secret under SERVER_TRAFFIC_SECRET_0.
    monkeypatch.setattr(sc, "read_tls13_client_randoms", lambda *_a, **_k: {"0": CR1})
    monkeypatch.setattr(sc, "streams_matching_filter", _fake_streams_matching_filter)

    records = sc.parse_tls13_records(f"{_S1_SC}\n{_S1_SS}\n")
    lines = sc.correlate_tls13("tshark", "cap.pcapng", records)

    assert f"CLIENT_TRAFFIC_SECRET_0 {CR1} {_S1_SC}\n" in lines
    assert f"SERVER_TRAFFIC_SECRET_0 {CR1} {_S1_SS}\n" in lines
    # The client secret must NOT be mis-emitted as a server secret (the S1 bug).
    assert f"SERVER_TRAFFIC_SECRET_0 {CR1} {_S1_SC}\n" not in lines
    assert f"CLIENT_TRAFFIC_SECRET_0 {CR1} {_S1_SS}\n" not in lines


def test_place_tls13_secret_picks_the_true_label_not_the_first_trial(monkeypatch):
    # place_tls13_secret short-circuits on the first label whose probe hits. That
    # break is only correct because the probes are decryption-gated: a client
    # traffic secret must skip the earlier-tried SERVER_TRAFFIC_SECRET_0 label
    # (which, under the reverted `tls.app_data` probe, would match first & wrong).
    monkeypatch.setattr(sc, "streams_matching_filter", _fake_streams_matching_filter)
    hits = sc.place_tls13_secret("tshark", "cap.pcapng", _S1_SC, {"0": CR1})
    assert hits == [("CLIENT_TRAFFIC_SECRET_0", "0")]


def test_place_tls13_secret_ignores_streams_outside_the_probe(monkeypatch):
    # A probe filter can match a stream the probe keylog never covered (e.g. a
    # mid-stream TLS 1.2 connection with no ClientHello). Such a hit proves
    # nothing and used to crash correlate_tls13 with a KeyError.
    monkeypatch.setattr(sc, "streams_matching_filter", lambda *_a: {"4"})
    assert sc.place_tls13_secret("tshark", "cap.pcapng", _S1_SC, {"0": CR1}) == []
    monkeypatch.setattr(sc, "read_tls13_client_randoms", lambda *_a, **_k: {"0": CR1})
    records = sc.parse_tls13_records(f"{_S1_SC}\n")
    assert sc.correlate_tls13("tshark", "cap.pcapng", records) == []
