"""Tests for keylog/capture coverage, its description and the re-pair rescue."""

from __future__ import annotations

import os

import pytest

from friTap.offline import keylog_coverage as kc
from friTap.offline import keylog_suggest as ks

CR_A = "aa" * 32
CR_B = "bb" * 32
CR_C = "cc" * 32
CR_D = "dd" * 32
SECRET_48 = "11" * 48
SECRET_32 = "22" * 32


def _keylog(tmp_path, text: str, name: str = "keys.log", newline: str = "\n") -> str:
    path = tmp_path / name
    path.write_bytes(text.replace("\n", newline).encode())
    return str(path)


def _hs(stream: str, cr: str, sni: str = "", version: str = "TLS 1.3") -> kc.TlsHandshake:
    return kc.TlsHandshake(stream, cr, sni, version)


# --- keylog parsing ----------------------------------------------------------

def test_keylog_client_randoms_crlf_comments_and_labels(tmp_path):
    path = _keylog(tmp_path, (
        "# comment\n"
        "\n"
        f"CLIENT_RANDOM {CR_A.upper()} {SECRET_48}\n"
        f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {CR_B} {SECRET_32}\n"
        f"SERVER_TRAFFIC_SECRET_1 {CR_B} {SECRET_32}\n"
        f"EARLY_EXPORTER_SECRET {CR_C} {SECRET_32}\n"
        f"RSA {CR_D} {SECRET_32}\n"          # not a TLS NSS label
        f"CLIENT_RANDOM short {SECRET_48}\n"  # malformed client random
    ), newline="\r\n")
    assert kc.keylog_client_randoms(path) == {
        CR_A: {"CLIENT_RANDOM"},
        CR_B: {"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_1"},
        CR_C: {"EARLY_EXPORTER_SECRET"},
    }


def test_keylog_client_randoms_bounded_read_drops_cut_line(tmp_path):
    line = f"CLIENT_RANDOM {CR_A} {SECRET_48}\n"
    path = _keylog(tmp_path, line + f"CLIENT_RANDOM {CR_B} {SECRET_48}\n")
    assert kc.keylog_client_randoms(path, max_bytes=len(line) + 20) == {CR_A: {"CLIENT_RANDOM"}}


def test_keylog_client_randoms_missing_file_is_empty(tmp_path):
    assert kc.keylog_client_randoms(str(tmp_path / "nope.log")) == {}


def test_keylog_secrets_groups_pairs_per_client_random(tmp_path):
    path = _keylog(tmp_path, (
        f"CLIENT_TRAFFIC_SECRET_0 {CR_A} {SECRET_32}\n"
        f"CLIENT_TRAFFIC_SECRET_0 {CR_A} {SECRET_32}\n"
        f"EXPORTER_SECRET {CR_A} {SECRET_48}\n"
    ))
    assert kc.keylog_secrets(path) == {
        CR_A: [("CLIENT_TRAFFIC_SECRET_0", SECRET_32), ("EXPORTER_SECRET", SECRET_48)],
    }


def test_suggest_uses_shared_label_predicate():
    assert ks._is_tls_label("SERVER_HANDSHAKE_TRAFFIC_SECRET")
    assert ks._is_tls_label("EARLY_EXPORTER_SECRET")
    assert ks.is_nss_tls_label is kc.is_nss_tls_label
    assert not kc.is_nss_tls_label("RSA")


# --- capture reading -------------------------------------------------------

_ROWS_OUTPUT = "\n".join([
    # stream 4: mid-stream app data only
    "4\t\t\t\t\t",
    # stream 5: TLS 1.2 (client offered 1.3, server chose 1.2)
    f"5\t1\t{CR_A}\tlogin.live.com\t0x0304,0x0303\t0x0303",
    f"5\t2,11,22,12,14\t{CR_D}\t\t\t0x0303",
    # stream 7: TLS 1.3 (ServerHello selects 0x0304), colon-separated random
    f"7\t1\t{':'.join(CR_B[i:i + 2] for i in range(0, 64, 2))}\twww.howsmyssl.com\t0x0304\t0x0303",
    f"7\t2\t{CR_D}\t\t0x0304\t0x0303",
    # stream 9: ClientHello only, offering 1.3
    f"9\t1\t{CR_C}\tspeed.cloudflare.com\t0x0304\t0x0303",
    # non-TCP row is ignored
    "\t1\t" + CR_D + "\tquic.example\t0x0304\t0x0303",
]) + "\n"


def test_read_capture_handshakes_single_pass(monkeypatch):
    calls = []

    def fake_run_fields(tshark_bin, pcap, display_filter, fields, *, keylog=None):
        calls.append((display_filter, tuple(fields)))
        return _ROWS_OUTPUT

    monkeypatch.setattr("friTap.offline.schannel.correlate._run_fields", fake_run_fields)
    capture = kc.read_capture_handshakes("tshark", "x.pcap")
    assert len(calls) == 1
    assert capture.handshakes == (
        _hs("5", CR_A, "login.live.com", "TLS 1.2"),
        _hs("7", CR_B, "www.howsmyssl.com", "TLS 1.3"),
        _hs("9", CR_C, "speed.cloudflare.com", "TLS 1.3"),
    )
    assert capture.midstream_streams == ("4",)
    assert capture.client_randoms == {CR_A, CR_B, CR_C}


def test_read_capture_handshakes_tshark_failure_is_empty(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("tshark exploded")

    monkeypatch.setattr("friTap.offline.schannel.correlate._run_fields", boom)
    assert kc.read_capture_handshakes("tshark", "x.pcap") == kc.CaptureTls()


# --- assess / describe ------------------------------------------------------

_LSASS_LIKE = kc.CaptureTls(
    handshakes=(
        _hs("5", CR_A, "login.live.com", "TLS 1.2"),
        _hs("6", CR_B, "login.live.com", "TLS 1.2"),
        _hs("7", CR_C, "www.howsmyssl.com", "TLS 1.3"),
        _hs("8", CR_D, "speed.cloudflare.com", "TLS 1.3"),
    ),
    midstream_streams=("4",),
)


def test_describe_none_covered_after_capture():
    coverage = kc.assess_coverage(
        _LSASS_LIKE, {"ee" * 32: {"X"}, "ff" * 32: {"X"}},
        keylog_mtime=1_000.0 + 302, capture_window=(900.0, 1_000.0),
    )
    assert coverage.keylog_sessions == 2 and coverage.keylog_sessions_in_capture == 0
    assert coverage.written_after_capture_s == pytest.approx(302)
    assert kc.describe(coverage) == ("warning", [
        "TLS keylog matches 0 of 4 TLS handshakes in the capture (login.live.com ×2 TLS 1.2, "
        "www.howsmyssl.com TLS 1.3, speed.cloudflare.com TLS 1.3).",
        "None of the keylog's 2 sessions appear in this capture.",
        "The keylog was last written 5 min after the capture ended — its sessions likely "
        "happened after the capture stopped.",
        "1 connection started before the capture and can't be decrypted.",
    ])


def test_written_after_capture_only_when_after_window_end():
    before = kc.assess_coverage(_LSASS_LIKE, set(), keylog_mtime=800.0, capture_window=(900.0, 1_000.0))
    inside = kc.assess_coverage(_LSASS_LIKE, set(), keylog_mtime=950.0, capture_window=(900.0, 1_000.0))
    assert before.written_after_capture_s is None
    assert inside.written_after_capture_s is None


def test_describe_short_flush_after_capture_is_not_blamed():
    coverage = kc.assess_coverage(
        _LSASS_LIKE, {"ee" * 32}, keylog_mtime=1_010.0, capture_window=(900.0, 1_000.0))
    _severity, lines = kc.describe(coverage)
    assert not any("last written" in line for line in lines)
    assert "The keylog's only session does not appear in this capture." in lines


def test_describe_empty_keylog():
    _severity, lines = kc.describe(kc.assess_coverage(_LSASS_LIKE, {}))
    assert "The keylog contains no TLS sessions." in lines


def test_describe_partial_lists_uncovered_hosts():
    coverage = kc.assess_coverage(_LSASS_LIKE, {CR_A, CR_B})
    assert kc.describe(coverage) == ("info", [
        "TLS keylog matches 2 of 4 TLS handshakes in the capture; not covered: "
        "www.howsmyssl.com TLS 1.3, speed.cloudflare.com TLS 1.3.",
        "1 connection started before the capture and can't be decrypted.",
    ])


def test_describe_full_coverage():
    capture = kc.CaptureTls(handshakes=_LSASS_LIKE.handshakes)
    coverage = kc.assess_coverage(capture, {CR_A: {"L"}, CR_B: {"L"}, CR_C: {"L"}, CR_D: {"L"}})
    assert kc.describe(coverage) == ("ok", ["TLS keylog covers 4/4 TLS handshakes in the capture."])


def test_describe_uses_stream_when_sni_missing():
    capture = kc.CaptureTls(handshakes=(_hs("3", CR_A, "", ""),))
    _severity, lines = kc.describe(kc.assess_coverage(capture, set()))
    assert "(stream 3)" in lines[0] and "1 TLS handshake in" in lines[0]


def test_describe_midstream_only():
    capture = kc.CaptureTls(midstream_streams=("1", "2"))
    assert kc.describe(kc.assess_coverage(capture, {CR_A})) == ("warning", [
        "The capture contains no TLS handshakes to match the keylog against.",
        "2 connections started before the capture and can't be decrypted.",
    ])


def test_describe_no_tls_at_all():
    severity, lines = kc.describe(kc.assess_coverage(kc.CaptureTls(), {CR_A}))
    assert severity == "info" and "no TLS traffic" in lines[0]


def test_check_keylog_coverage_uses_file_times(tmp_path):
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"")
    os.utime(pcap, (1_000_000, 1_000_000))
    keylog = _keylog(tmp_path, f"CLIENT_RANDOM {CR_A} {SECRET_48}\n")
    os.utime(keylog, (1_000_000 + 3 * 3600, 1_000_000 + 3 * 3600))
    capture = kc.CaptureTls(handshakes=(_hs("1", CR_B, "h", "TLS 1.2"),))
    coverage = kc.check_keylog_coverage("tshark", str(pcap), keylog, capture)
    assert coverage.written_after_capture_s == pytest.approx(3 * 3600)
    assert "last written 3 h after" in kc.describe(coverage)[1][2]


# --- repair -------------------------------------------------------------------

def _patch_correlators(monkeypatch, tls12_lines=(), tls13_lines=()):
    seen = {}

    def fake_tls12(_tshark, _pcap, masters):
        seen["masters"] = list(masters)
        return list(tls12_lines)

    def fake_tls13(_tshark, _pcap, records):
        seen["records"] = list(records)
        return list(tls13_lines)

    monkeypatch.setattr("friTap.offline.schannel.correlate.correlate_tls12", fake_tls12)
    monkeypatch.setattr("friTap.offline.schannel.correlate.correlate_tls13", fake_tls13)
    return seen


_CAPTURE_AB = kc.CaptureTls(handshakes=(_hs("1", CR_A), _hs("2", CR_B)))


def test_repair_hit_writes_repaired_keylog(tmp_path, monkeypatch):
    keylog = _keylog(tmp_path, (
        f"CLIENT_RANDOM {CR_C} {SECRET_48}\n"
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_D} {SECRET_32}\n"
        f"EXPORTER_SECRET {CR_D} {'33' * 32}\n"
        f"CLIENT_RANDOM {CR_A} {'44' * 48}\n"   # already in the capture: not re-tried
    ), name="keys_x.log", newline="\r\n")
    seen = _patch_correlators(
        monkeypatch,
        tls12_lines=[f"CLIENT_RANDOM {CR_B} {SECRET_48}\n"],
        tls13_lines=[f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_A} {SECRET_32}\n"],
    )
    progress = []
    result = kc.repair_keylog("tshark", "x.pcap", keylog, capture=_CAPTURE_AB, progress=progress.append)

    assert seen["masters"] == [SECRET_48]
    assert [r["group"] for r in seen["records"]] == [CR_D, CR_D]
    assert seen["records"][0]["label"] == "SERVER_HANDSHAKE_TRAFFIC_SECRET"
    assert result.repaired_path == str(tmp_path / "keys_x.repaired.keylog")
    assert result.matched_sessions == 2 and result.tried_secrets == 3
    assert progress and "3 secrets" in progress[0]
    content = open(result.repaired_path, "rb").read().decode()
    assert "\r" not in content
    assert content.startswith(f"CLIENT_RANDOM {CR_C} {SECRET_48}\n")
    assert f"CLIENT_RANDOM {CR_B} {SECRET_48}\n" in content
    repaired_cov = kc.assess_coverage(_CAPTURE_AB, kc.keylog_client_randoms(result.repaired_path))
    assert len(repaired_cov.covered) == 2


def test_repair_miss_returns_message(tmp_path, monkeypatch):
    keylog = _keylog(tmp_path, f"CLIENT_TRAFFIC_SECRET_0 {CR_C} {SECRET_32}\n")
    _patch_correlators(monkeypatch)
    result = kc.repair_keylog("tshark", "x.pcap", keylog, capture=_CAPTURE_AB)
    assert result == kc.RepairResult(None, 0, 1, kc.NO_REPAIR_HITS_MESSAGE)
    assert not (tmp_path / "keys.repaired.keylog").exists()


def test_repair_nothing_to_try(tmp_path, monkeypatch):
    keylog = _keylog(tmp_path, f"CLIENT_RANDOM {CR_A} {SECRET_48}\n")
    seen = _patch_correlators(monkeypatch)
    result = kc.repair_keylog("tshark", "x.pcap", keylog, capture=_CAPTURE_AB)
    assert result.repaired_path is None and result.tried_secrets == 0 and not seen


def test_repair_correlator_crash_is_a_miss(tmp_path, monkeypatch):
    keylog = _keylog(tmp_path, f"CLIENT_RANDOM {CR_C} {SECRET_48}\n")

    def boom(*_args):
        raise RuntimeError("tshark gone")

    monkeypatch.setattr("friTap.offline.schannel.correlate.correlate_tls12", boom)
    result = kc.repair_keylog("tshark", "x.pcap", keylog, capture=_CAPTURE_AB)
    assert result.message == kc.NO_REPAIR_HITS_MESSAGE


def test_repair_honours_out_path(tmp_path, monkeypatch):
    keylog = _keylog(tmp_path, f"CLIENT_RANDOM {CR_C} {SECRET_48}\n")
    _patch_correlators(monkeypatch, tls12_lines=[f"CLIENT_RANDOM {CR_A} {SECRET_48}\n"])
    out = tmp_path / "sub" / "out.keylog"
    out.parent.mkdir()
    result = kc.repair_keylog("tshark", "x.pcap", keylog, capture=_CAPTURE_AB, out_path=str(out))
    assert result.repaired_path == str(out) and out.is_file()


# --- relabel (trial-decrypt over ALL secrets, incl. ??? and in-capture) -------

_S_A = "22" * 32   # really the handshake secret (written under a swapped label)
_S_B = "33" * 32   # really the app secret (written under a swapped label)
_S_C = "44" * 32   # a ??? line's secret (foreign / uncorrelated)


def test_relabel_inputs_keeps_qqq_and_in_capture(tmp_path):
    keylog = _keylog(tmp_path, (
        f"SERVER_TRAFFIC_SECRET_0 {CR_A} {_S_A}\n"          # in-capture, swapped label
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_A} {_S_B}\n"  # in-capture, swapped label
        f"CLIENT_HANDSHAKE_TRAFFIC_SECRET ??? {_S_C}\n"     # ??? client_random
        f"CLIENT_RANDOM {CR_C} {SECRET_48}\n"               # TLS 1.2 master
    ))
    masters, records = kc._relabel_inputs(keylog, kc.DEFAULT_MAX_KEYLOG_BYTES)
    assert masters == [SECRET_48]
    by_secret = {r["secret"]: r for r in records}
    # ??? line is kept, ungrouped (group=None) so trial decryption can place it
    assert by_secret[_S_C]["group"] is None
    assert by_secret[_S_C]["label"] == "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
    # in-capture secrets ride along on their (correct) client_random group
    assert by_secret[_S_A]["group"] == CR_A and by_secret[_S_B]["group"] == CR_A


def test_relabel_fixes_swap_drops_foreign_keeps_others(tmp_path, monkeypatch):
    keylog = _keylog(tmp_path, (
        f"SERVER_TRAFFIC_SECRET_0 {CR_A} {_S_A}\n"          # swapped: really HANDSHAKE
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_A} {_S_B}\n"  # swapped: really TRAFFIC_0
        f"CLIENT_HANDSHAKE_TRAFFIC_SECRET ??? {_S_C}\n"     # foreign ??? (unplaced)
        f"CLIENT_RANDOM {CR_C} {SECRET_48}\n"               # unrelated valid session
    ), name="raw.keylog")
    # trial decryption resolves the true labels for CR_A's two secrets:
    _patch_correlators(monkeypatch, tls13_lines=[
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_A} {_S_A}\n",
        f"SERVER_TRAFFIC_SECRET_0 {CR_A} {_S_B}\n",
    ])
    result = kc.relabel_keylog("tshark", "x.pcap", keylog)
    assert result.repaired_path == str(tmp_path / "raw.relabeled.keylog")
    content = open(result.repaired_path, encoding="utf-8").read().splitlines()
    # swapped originals are gone (their secrets were authoritatively placed)
    assert f"SERVER_TRAFFIC_SECRET_0 {CR_A} {_S_A}" not in content
    assert f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_A} {_S_B}" not in content
    # corrected lines present
    assert f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_A} {_S_A}" in content
    assert f"SERVER_TRAFFIC_SECRET_0 {CR_A} {_S_B}" in content
    # ??? foreign line dropped; unrelated valid session preserved
    assert not any("???" in ln for ln in content)
    assert f"CLIENT_RANDOM {CR_C} {SECRET_48}" in content


def test_relabel_noop_when_already_correct(tmp_path, monkeypatch):
    keylog = _keylog(tmp_path, f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_A} {_S_A}\n")
    _patch_correlators(monkeypatch, tls13_lines=[
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_A} {_S_A}\n"])
    result = kc.relabel_keylog("tshark", "x.pcap", keylog)
    assert result.repaired_path is None
    assert "nothing to relabel" in result.message
    assert not (tmp_path / "keys.relabeled.keylog").exists()


def test_relabel_counts_only_sessions_whose_lines_changed(tmp_path, monkeypatch):
    """R6: an already-correct session re-emitted by correlation is not "relabeled"."""
    keylog = _keylog(tmp_path, (
        f"SERVER_TRAFFIC_SECRET_0 {CR_A} {_S_A}\n"          # swapped: really HANDSHAKE
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_B} {_S_B}\n"  # already correct
    ))
    _patch_correlators(monkeypatch, tls13_lines=[
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_A} {_S_A}\n",
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {CR_B} {_S_B}\n",
    ])
    result = kc.relabel_keylog("tshark", "x.pcap", keylog)
    assert result.repaired_path is not None
    assert result.matched_sessions == 1
    assert "Relabeled 1 session " in result.message
