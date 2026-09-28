"""Offline CLI (``fritap --from-pcap``): keylog coverage explanation + ``--repair-keylog``.

tshark, the conversion and the coverage/repair engine are all monkeypatched, so
these tests exercise only the CLI wiring in ``friTap.offline.cli``.
"""

from __future__ import annotations

import pytest

from friTap.offline import cli
from friTap.offline import keylog_coverage as kc
from friTap.offline.pcap_to_tap import ConvertResult

_HS_A = kc.TlsHandshake(stream="0", client_random="aa" * 32, sni="a.example", version="TLS 1.3")
_HS_B = kc.TlsHandshake(stream="1", client_random="bb" * 32, sni="b.example", version="TLS 1.3")

_NO_COVERAGE = kc.Coverage(uncovered=(_HS_A,), keylog_sessions=4, keylog_sessions_in_capture=0)
_PARTIAL_COVERAGE = kc.Coverage(covered=(_HS_A,), uncovered=(_HS_B,), keylog_sessions=1,
                                keylog_sessions_in_capture=1)
_FULL_COVERAGE = kc.Coverage(covered=(_HS_A,), keylog_sessions=1, keylog_sessions_in_capture=1)


@pytest.fixture
def paths(tmp_path):
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00" * 8)
    keylog = tmp_path / "keys.log"
    keylog.write_text("CLIENT_RANDOM " + "cc" * 32 + " " + "dd" * 48 + "\n")
    return pcap, keylog, tmp_path


class _Calls(list):
    """Recorded convert kwargs plus the ``ConvertResult`` the stub returns."""

    result = ConvertResult(tap_path="out.tap")


@pytest.fixture
def convert_calls(monkeypatch):
    """Stub tshark + conversion; record every convert_pcap_to_tap call's kwargs."""
    calls = _Calls()

    def fake_convert(pcap, **kwargs):
        calls.append(kwargs)
        return calls.result

    monkeypatch.setattr(cli, "find_tshark", lambda *_a, **_k: "/fake/tshark")
    monkeypatch.setattr(cli, "convert_pcap_to_tap", fake_convert)
    return calls


def _stub_coverage(monkeypatch, coverage):
    seen: list[str] = []

    def fake_check(tshark_bin, pcap, keylog, capture=None):
        seen.append(keylog)
        return coverage

    monkeypatch.setattr(kc, "check_keylog_coverage", fake_check)
    return seen


def _run(pcap, keylog, tmp_path, *extra):
    return cli.run_offline_pcap_to_tap([
        "--from-pcap", str(pcap), "--keylog", str(keylog),
        "--tap", str(tmp_path / "o.tap"), *extra,
    ])


# -- flag parsing ------------------------------------------------------------

def test_repair_keylog_flag_defaults_off():
    args = cli._build_parser().parse_args(["--from-pcap", "x.pcapng"])
    assert args.repair_keylog is False


def test_repair_keylog_flag_parses():
    args = cli._build_parser().parse_args(["--from-pcap", "x.pcapng", "--repair-keylog"])
    assert args.repair_keylog is True


def test_repair_keylog_flag_is_documented_in_help():
    assert "--repair-keylog" in cli._build_parser().format_help()


# -- coverage explanation ----------------------------------------------------

def test_zero_decrypted_prints_coverage_lines_before_generic_hint(paths, convert_calls, monkeypatch, capsys):
    pcap, keylog, tmp_path = paths
    _stub_coverage(monkeypatch, _NO_COVERAGE)
    monkeypatch.setattr(kc, "describe", lambda cov: ("warning", ["LINE ONE", "LINE TWO"]))

    rc = _run(pcap, keylog, tmp_path)

    out = capsys.readouterr().out
    assert rc == 4
    assert "Warning: LINE ONE" in out
    assert "         LINE TWO" in out
    assert out.index("LINE ONE") < out.index("Warning: no application data")


def test_zero_decrypted_without_keylog_skips_coverage(paths, convert_calls, monkeypatch, capsys):
    pcap, _keylog, tmp_path = paths
    seen = _stub_coverage(monkeypatch, _NO_COVERAGE)

    rc = cli.run_offline_pcap_to_tap(["--from-pcap", str(pcap), "--tap", str(tmp_path / "o.tap")])

    assert rc == 4
    assert seen == []


def test_coverage_failure_never_changes_exit_code(paths, convert_calls, monkeypatch, capsys):
    pcap, keylog, tmp_path = paths

    def boom(*_a, **_k):
        raise RuntimeError("tshark exploded")

    monkeypatch.setattr(kc, "check_keylog_coverage", boom)
    assert _run(pcap, keylog, tmp_path) == 4


def test_partial_coverage_prints_one_line_note_on_success(paths, convert_calls, monkeypatch, capsys):
    pcap, keylog, tmp_path = paths
    convert_calls.result = ConvertResult(tap_path="o.tap", flow_count=1, decrypted_packet_count=5)
    _stub_coverage(monkeypatch, _PARTIAL_COVERAGE)

    rc = _run(pcap, keylog, tmp_path)

    out = capsys.readouterr().out
    assert rc == 0
    assert "Note: TLS keylog matches 1 of 2 TLS handshakes" in out


def test_full_coverage_prints_no_note_on_success(paths, convert_calls, monkeypatch, capsys):
    pcap, keylog, tmp_path = paths
    convert_calls.result = ConvertResult(tap_path="o.tap", flow_count=1, decrypted_packet_count=5)
    _stub_coverage(monkeypatch, _FULL_COVERAGE)

    assert _run(pcap, keylog, tmp_path) == 0
    assert "Note:" not in capsys.readouterr().out


# -- --repair-keylog ---------------------------------------------------------

def test_repair_success_swaps_keylog_passed_to_convert(paths, convert_calls, monkeypatch, capsys):
    pcap, keylog, tmp_path = paths
    repaired = str(tmp_path / "keys.repaired.keylog")
    (tmp_path / "keys.repaired.keylog").write_text(keylog.read_text())
    seen = _stub_coverage(monkeypatch, _NO_COVERAGE)
    monkeypatch.setattr(kc, "relabel_keylog", lambda *_a, **_k: kc.RepairResult(
        repaired, 1, 3, "Relabeled 1 session by trial decryption; wrote keys.relabeled.keylog."))

    _run(pcap, keylog, tmp_path, "--repair-keylog")

    out = capsys.readouterr().out
    assert convert_calls[0]["keylog_path"] == repaired
    assert "Relabeled 1 session" in out
    assert seen[-1] == repaired  # post-run coverage uses the relabeled keylog


def test_repair_no_hits_keeps_original_keylog(paths, convert_calls, monkeypatch, capsys):
    pcap, keylog, tmp_path = paths
    _stub_coverage(monkeypatch, _NO_COVERAGE)
    monkeypatch.setattr(kc, "relabel_keylog", lambda *_a, **_k: kc.RepairResult(
        None, 0, 3, kc.NO_REPAIR_HITS_MESSAGE))

    _run(pcap, keylog, tmp_path, "--repair-keylog")

    out = capsys.readouterr().out
    assert convert_calls[0]["keylog_path"] == str(keylog)
    assert kc.NO_REPAIR_HITS_MESSAGE in out


def test_repair_runs_even_when_keylog_fully_covers(paths, convert_calls, monkeypatch, capsys):
    # A swapped/mislabeled session is invisible to the coverage gate, so relabel
    # runs regardless of coverage; a no-op result keeps the original keylog.
    pcap, keylog, tmp_path = paths
    _stub_coverage(monkeypatch, _FULL_COVERAGE)
    called = []

    def fake_relabel(*a, **k):
        called.append(a)
        return kc.RepairResult(
            None, 0, 1, "Every secret already carries its correct label; nothing to relabel.")

    monkeypatch.setattr(kc, "relabel_keylog", fake_relabel)

    _run(pcap, keylog, tmp_path, "--repair-keylog")

    assert called != []  # relabel is attempted even under full coverage
    assert convert_calls[0]["keylog_path"] == str(keylog)
    assert "nothing to relabel" in capsys.readouterr().out


def test_repair_exception_keeps_original_keylog(paths, convert_calls, monkeypatch, capsys):
    pcap, keylog, tmp_path = paths
    _stub_coverage(monkeypatch, _NO_COVERAGE)

    def boom(*_a, **_k):
        raise RuntimeError("correlate blew up")

    monkeypatch.setattr(kc, "relabel_keylog", boom)
    _run(pcap, keylog, tmp_path, "--repair-keylog")
    assert convert_calls[0]["keylog_path"] == str(keylog)


def test_no_repair_without_flag(paths, convert_calls, monkeypatch):
    pcap, keylog, tmp_path = paths
    _stub_coverage(monkeypatch, _NO_COVERAGE)
    called = []
    monkeypatch.setattr(kc, "relabel_keylog", lambda *a, **k: called.append(a))

    _run(pcap, keylog, tmp_path)
    assert called == []
