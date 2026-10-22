"""Review-D fixes in the offline pcap -> tap path.

* every ``stream_packets`` loop closes the tshark generator, even on an early exit;
* the progress label names the decryptor's ``protocol_name``;
* manifest-relative keylog paths resolve against the manifest (CLI and API), and
  the API honours the manifest's ``keylogs`` map like the CLI;
* a run that wrote only metadata-only flows (SSH) exits 0, not 4;
* the "TLS keylog is not needed" note no longer ignores QUIC;
* the keyless QUIC detection pass is skipped on a UDP-free capture.
"""

from __future__ import annotations

import importlib
import json
from types import SimpleNamespace

import pytest

from friTap.offline import cli
from friTap.offline import keylog_coverage as kc
from friTap.offline.pipeline_api import ConvertResult

p2t = importlib.import_module("friTap.offline.pcap_to_tap")


# --------------------------------------------------------------------------- #
# 1. stream_packets generators are always closed
# --------------------------------------------------------------------------- #

class _TrackedPackets:
    """A ``stream_packets`` stand-in that records whether it was closed."""

    def __init__(self, packets):
        self.closed = False
        self._gen = self._run(list(packets))

    def _run(self, packets):
        try:
            yield from packets
        finally:
            self.closed = True

    def __iter__(self):
        return self._gen

    def close(self):
        self._gen.close()


def test_closing_packets_closes_on_exception():
    packets = _TrackedPackets([{"layers": {}}, {"layers": {}}])
    with pytest.raises(RuntimeError):
        with p2t._closing_packets(packets) as source:
            for _pkt in source:
                raise RuntimeError("consumer failed")
    assert packets.closed


def test_closing_packets_accepts_plain_list():
    with p2t._closing_packets([1, 2]) as source:
        assert list(source) == [1, 2]


def test_quic_detection_closes_generator_when_consumer_fails(monkeypatch):
    class _BadPacket:
        def get(self, _key):
            raise ValueError("bad row")

    packets = _TrackedPackets([_BadPacket(), {"layers": {}}])
    monkeypatch.setattr(p2t, "stream_packets", lambda _cmd: packets)

    streams = p2t._detect_encrypted_quic_streams(
        "tshark", "cap.pcap", quic_ports=(), extra_decode_as=(), heuristic=False)

    assert streams == frozenset()
    assert packets.closed


def test_plaintext_pass_closes_generator_when_emit_fails(monkeypatch):
    row = {"layers": {"frame.protocols": ["eth:ip:tcp"], "tcp.stream": ["0"],
                      "tcp.srcport": ["1234"], "tcp.dstport": ["80"],
                      "ip.src": ["10.0.0.1"], "ip.dst": ["10.0.0.2"],
                      "tcp.payload": ["4142"], "frame.time_epoch": ["1.0"]}}
    packets = _TrackedPackets([row, row])
    monkeypatch.setattr(p2t, "stream_packets", lambda _cmd: packets)

    class _FailingBus:
        def emit(self, _event):
            raise RuntimeError("bus down")

    with pytest.raises(RuntimeError):
        p2t._emit_plaintext_streams_singlepass(
            "tshark", "cap.pcap", extra_decode_as=(), heuristic=False,
            bus=_FailingBus(), state=SimpleNamespace(ensure_open=lambda *a: None),
            result=ConvertResult(tap_path="x.tap"),
            tracker=p2t._StreamDirectionTracker(server_ports=(80,)))
    assert packets.closed


# --------------------------------------------------------------------------- #
# 6. progress label
# --------------------------------------------------------------------------- #

def test_entry_display_name_uses_protocol_name():
    assert p2t._entry_display_name(SimpleNamespace(protocol_name="mtproto")) == "mtproto"
    assert p2t._entry_display_name(SimpleNamespace()) == "protocol"


def test_independent_decryptor_progress_names_protocol(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(p2t, "_run_independent_entry", lambda *a, **k: None)
    monkeypatch.setattr(p2t, "_resync_kwargs", lambda *a, **k: {})
    ctx = SimpleNamespace(
        independent_plan=[(SimpleNamespace(protocol_name="rc4"), {})],
        progress=seen.append, pcap_path="c.pcap", keylog_path=None,
        tshark_bin="tshark", tls_ports=(), bus=None, state=None, result=None,
        resync_search_depth=None)

    p2t._run_independent_decryptors(ctx)

    assert seen == ["Decrypting rc4…"]


# --------------------------------------------------------------------------- #
# 7. manifest-relative keylog paths (CLI + API)
# --------------------------------------------------------------------------- #

@pytest.fixture
def capture_dir(tmp_path, monkeypatch):
    """A capture dir with a manifest of RELATIVE keylog paths; CWD elsewhere."""
    caps = tmp_path / "caps"
    caps.mkdir()
    pcap = caps / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    for name in ("keys.log", "split.mtproto.log", "keys.memscan.mtproto.keylog",
                 "cap.schannel.unpaired"):
        (caps / name).write_text("# hdr\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    return caps, pcap


def _write_manifest(pcap, data):
    (pcap.parent / (pcap.name + ".fritap.json")).write_text(json.dumps(data))


def test_resolve_manifest_keylog_paths_resolves_every_keylog(capture_dir):
    caps, pcap = capture_dir
    manifest = {
        "keylog": "keys.log",
        "mtproto_keylog": "keys.log",
        "schannel_unpaired": "cap.schannel.unpaired",
        "keylogs": {"mtproto": "split.mtproto.log"},
        "memory_scan_keylogs": {"mtproto": "keys.memscan.mtproto.keylog"},
        "tls_ports": [443],
    }

    resolved = cli.resolve_manifest_keylog_paths(str(pcap), manifest)

    assert resolved["keylog"] == str(caps / "keys.log")
    assert resolved["mtproto_keylog"] == str(caps / "keys.log")
    assert resolved["schannel_unpaired"] == str(caps / "cap.schannel.unpaired")
    assert resolved["keylogs"] == {"mtproto": str(caps / "split.mtproto.log")}
    assert resolved["memory_scan_keylogs"] == {
        "mtproto": str(caps / "keys.memscan.mtproto.keylog")}
    assert resolved["tls_ports"] == [443]
    assert manifest["keylog"] == "keys.log"  # the input is not mutated


def test_resolve_manifest_keylog_paths_keeps_absolute_and_cwd_paths(capture_dir, tmp_path):
    _caps, pcap = capture_dir
    (tmp_path / "elsewhere" / "cwd.log").write_text("x")
    resolved = cli.resolve_manifest_keylog_paths(
        str(pcap), {"keylog": "/abs/keys.log", "mtproto_keylog": "cwd.log"})
    assert resolved["keylog"] == "/abs/keys.log"
    assert resolved["mtproto_keylog"] == "cwd.log"  # CWD fallback


def _ns(pcap, **kw):
    import argparse

    base = dict(from_pcap=str(pcap), keylog=None, tls_ports=[], quic_ports=[],
                decode_as=[], tls_heuristic=False)
    base.update(kw)
    return argparse.Namespace(**base)


def test_merge_manifest_resolves_relative_keylogs(capture_dir):
    caps, pcap = capture_dir
    manifest = {"keylog": "keys.log", "mtproto_keylog": "keys.log"}

    merged = cli.merge_manifest(_ns(pcap), manifest)

    assert merged["keylog_path"] == str(caps / "keys.log")
    assert merged["mtproto_keylog"] == str(caps / "keys.log")
    assert merged["protocol_keylogs"]["mtproto"] == str(caps / "keys.log")


def test_merge_manifest_resolves_keylogs_map(capture_dir):
    caps, pcap = capture_dir
    merged = cli.merge_manifest(_ns(pcap), {
        "mtproto_keylog": "keys.log", "keylogs": {"mtproto": "split.mtproto.log"}})
    assert merged["protocol_keylogs"]["mtproto"] == str(caps / "split.mtproto.log")


@pytest.fixture
def api_calls(monkeypatch):
    calls: list[dict] = []

    def fake_convert(pcap, **kwargs):
        calls.append(kwargs)
        return ConvertResult(tap_path="o.tap")

    monkeypatch.setattr(p2t, "convert_pcap_to_tap", fake_convert)
    return calls


def test_api_resolves_relative_manifest_keylogs(capture_dir, api_calls):
    caps, pcap = capture_dir
    _write_manifest(pcap, {"keylog": "keys.log", "mtproto_keylog": "keys.log"})

    p2t.pcap_to_tap(str(pcap))

    kwargs = api_calls[0]
    assert kwargs["keylog_path"] == str(caps / "keys.log")
    assert kwargs["mtproto_keylog"] == str(caps / "keys.log")
    assert kwargs["protocol_keylogs"]["mtproto"] == str(caps / "keys.log")


def test_api_honours_manifest_keylogs_map(capture_dir, api_calls):
    caps, pcap = capture_dir
    _write_manifest(pcap, {"mtproto_keylog": "keys.log",
                           "keylogs": {"mtproto": "split.mtproto.log"}})

    p2t.pcap_to_tap(str(pcap))

    assert api_calls[0]["protocol_keylogs"]["mtproto"] == str(caps / "split.mtproto.log")


def test_api_explicit_keylogs_beat_manifest_map(capture_dir, api_calls):
    _caps, pcap = capture_dir
    _write_manifest(pcap, {"keylogs": {"mtproto": "split.mtproto.log"}})

    p2t.pcap_to_tap(str(pcap), protocol_keylogs={"mtproto": "/x/explicit.log"})
    p2t.pcap_to_tap(str(pcap), mtproto_keylog="/x/legacy.log")

    assert api_calls[0]["protocol_keylogs"]["mtproto"] == "/x/explicit.log"
    assert not (api_calls[1]["protocol_keylogs"] or {}).get("mtproto")
    assert api_calls[1]["mtproto_keylog"] == "/x/legacy.log"


def test_api_without_manifest_passes_protocol_keylogs_through(tmp_path, api_calls):
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\x00")
    p2t.pcap_to_tap(str(pcap))
    assert api_calls[0]["protocol_keylogs"] is None


# --------------------------------------------------------------------------- #
# 9. exit code with metadata-only flows
# --------------------------------------------------------------------------- #

def _run_cli_with_result(monkeypatch, tmp_path, result):
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\x00")
    monkeypatch.setattr(cli, "find_tshark", lambda *_a, **_k: "/fake/tshark")
    monkeypatch.setattr(cli, "convert_pcap_to_tap", lambda *_a, **_k: result)
    monkeypatch.setattr(cli, "_keylog_coverage", lambda *_a, **_k: None)
    return cli.run_offline_pcap_to_tap(
        ["--from-pcap", str(pcap), "--tap", str(tmp_path / "o.tap")])


def test_metadata_only_flows_exit_zero(monkeypatch, tmp_path, capsys):
    rc = _run_cli_with_result(
        monkeypatch, tmp_path, ConvertResult(tap_path="o.tap", flow_count=1))
    assert rc == 0
    assert "metadata only" in capsys.readouterr().out


def test_no_flows_no_data_still_exits_four(monkeypatch, tmp_path):
    rc = _run_cli_with_result(monkeypatch, tmp_path, ConvertResult(tap_path="o.tap"))
    assert rc == 4


# --------------------------------------------------------------------------- #
# 10. QUIC-aware "keylog not needed" note
# --------------------------------------------------------------------------- #

def test_no_tls_note_does_not_dismiss_quic():
    severity, lines = kc.describe(kc.Coverage())
    assert severity == "info"
    assert "QUIC" in lines[0]
    assert "unless it carries QUIC" in lines[0]


# --------------------------------------------------------------------------- #
# 19. keyless QUIC detection skipped on UDP-free captures
# --------------------------------------------------------------------------- #

# The probe itself is tested in tests/unit/test_pcap_fast.py
# (capture_may_carry_udp); here only its use by the keyless passes.

@pytest.mark.parametrize("may_carry_udp, expect_detection", [(False, False), (True, True)])
def test_keyless_passes_skip_quic_detection_without_udp(
        monkeypatch, may_carry_udp, expect_detection):
    detections: list[str] = []
    passed: dict = {}
    monkeypatch.setattr(p2t, "_capture_may_carry_udp", lambda _p: may_carry_udp)
    monkeypatch.setattr(
        p2t, "_detect_encrypted_quic_streams",
        lambda *a, **k: detections.append("ran") or frozenset({"udp:1"}))
    monkeypatch.setattr(
        p2t, "_emit_plaintext_streams_singlepass",
        lambda *a, **k: passed.update(k))
    ctx = SimpleNamespace(tshark_bin="tshark", pcap_path="c.pcap", quic_ports=(),
                          tls_ports=(), extra_decode_as=(), heuristic=False,
                          bus=None, state=None, result=None)

    assert p2t._run_keyless_passes(ctx) == []

    assert bool(detections) is expect_detection
    expected = frozenset({"udp:1"}) if expect_detection else frozenset()
    assert passed["encrypted_quic_streams"] == expected



# --------------------------------------------------------------------------- #
# Explicitly named protocol keylog / sidecar that does not exist
# --------------------------------------------------------------------------- #

def _run_cli_with_flags(monkeypatch, tmp_path, *flags):
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\x00")
    conversions: list = []
    monkeypatch.setattr(cli, "find_tshark", lambda *_a, **_k: "/fake/tshark")
    monkeypatch.setattr(
        cli, "convert_pcap_to_tap",
        lambda *_a, **_k: conversions.append(_k) or ConvertResult(tap_path="o.tap", flow_count=1))
    monkeypatch.setattr(cli, "_keylog_coverage", lambda *_a, **_k: None)
    rc = cli.run_offline_pcap_to_tap(
        ["--from-pcap", str(pcap), "--tap", str(tmp_path / "o.tap"), *flags])
    return rc, conversions


def test_missing_schannel_unpaired_sidecar_exits_five(monkeypatch, tmp_path, capsys):
    missing = str(tmp_path / "typo.schannel.unpaired")
    rc, conversions = _run_cli_with_flags(
        monkeypatch, tmp_path, "--schannel-unpaired", missing)
    assert rc == 5
    assert conversions == []
    out = capsys.readouterr().out
    assert "--schannel-unpaired" in out and missing in out


def test_existing_schannel_unpaired_sidecar_converts(monkeypatch, tmp_path):
    sidecar = tmp_path / "real.schannel.unpaired"
    sidecar.write_text("")
    rc, conversions = _run_cli_with_flags(
        monkeypatch, tmp_path, "--schannel-unpaired", str(sidecar))
    assert rc == 0
    assert len(conversions) == 1


def test_missing_midstream_sidecar_exits_five(monkeypatch, tmp_path, capsys):
    rc, conversions = _run_cli_with_flags(
        monkeypatch, tmp_path, "--tls-midstream-secrets", str(tmp_path / "nope.jsonl"))
    assert rc == 5
    assert conversions == []
    assert "nope.jsonl" in capsys.readouterr().out


def test_api_warns_with_path_for_missing_protocol_keylog(monkeypatch, tmp_path):
    warnings: list = []
    monkeypatch.setattr(p2t.logger, "warning",
                        lambda msg, *args: warnings.append(msg % args))
    missing = str(tmp_path / "gone.schannel.unpaired")
    assert p2t._present_offline_entries({"schannel": missing}) == []
    assert any(missing in line for line in warnings)
