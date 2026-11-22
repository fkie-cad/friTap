"""Stage split of ``convert_pcap_to_tap``.

The conversion runs as named stages over one ``_ConversionContext``; each stage
is looked up on the module at call time, so a test (or a later refactor) can
replace one stage without touching the others.
"""

from __future__ import annotations

import contextlib

import pytest

import friTap.offline.pcap_to_tap as p2t
from friTap.offline.net import capture_cache
from friTap.offline.registry import (
    OfflineDecryptorEntry,
    get_offline_decryptor_registry,
)

STAGES = ("_run_midstream_stage", "_run_tshark_stage", "_run_tls_riding_decryptors",
          "_run_independent_decryptors", "_finalize_conversion")


def _entry(name: str, *, requires_tls_strip: bool = False) -> OfflineDecryptorEntry:
    return OfflineDecryptorEntry(
        protocol_name=name, cli_flag=f"--{name}-keylog", cli_dest=f"{name}_keylog",
        requires_tls_strip=requires_tls_strip, emitter=lambda **_kw: None,
        layer_cls=object, counter_prefix=name,
    )


@pytest.fixture
def capture(monkeypatch, tmp_path):
    monkeypatch.setattr(p2t, "find_tshark", lambda path=None: "tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda binary: None)
    monkeypatch.setattr(p2t, "warn_if_outdated", lambda version: None)
    monkeypatch.setattr(p2t, "capture_has_dsb", lambda path: False)
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"")
    return str(pcap), str(tmp_path / "out.tap")


def _record_stages(monkeypatch, calls: list) -> None:
    for name in STAGES:
        monkeypatch.setattr(p2t, name, lambda ctx, _n=name: calls.append(_n))


def _record_cache_scope(monkeypatch, calls: list) -> None:
    @contextlib.contextmanager
    def scope(path, expected_consumers=None):
        calls.append("enter_cache")
        yield None
        calls.append("exit_cache")

    monkeypatch.setattr(capture_cache, "capture_cache_scope", scope)


def test_stages_run_in_order_inside_the_capture_cache_scope(monkeypatch, capture):
    pcap, tap = capture
    calls = []
    _record_stages(monkeypatch, calls)
    _record_cache_scope(monkeypatch, calls)

    result = p2t.convert_pcap_to_tap(pcap, tap_path=tap)

    assert calls == ["enter_cache", *STAGES[:4], "exit_cache", STAGES[4]]
    assert result.tap_path == tap


def test_cache_scope_is_released_when_a_stage_raises(monkeypatch, capture):
    pcap, tap = capture
    calls = []
    _record_stages(monkeypatch, calls)
    _record_cache_scope(monkeypatch, calls)

    def boom(ctx):
        raise RuntimeError("tshark died")

    monkeypatch.setattr(p2t, "_run_tshark_stage", boom)
    with pytest.raises(RuntimeError, match="tshark died"):
        p2t.convert_pcap_to_tap(pcap, tap_path=tap)
    assert calls == ["enter_cache", "_run_midstream_stage"]


# --------------------------------------------------------------------------- #
# _run_tshark_stage: the keyed combined pass, else the keyless passes, then SSH
# --------------------------------------------------------------------------- #

def _record_tshark_helpers(monkeypatch, calls: list) -> None:
    def recorder(name, value=None):
        def helper(*_a, **_k):
            calls.append(name)
            return value
        return helper

    for name, value in (("_detect_encrypted_quic_streams", set()),
                        ("_emit_plaintext_streams_singlepass", None),
                        ("_emit_ssh_connections", None),
                        ("_run_keyed_combined_pass", []),
                        ("_add_ssh_synthetic_flows", None)):
        monkeypatch.setattr(p2t, name, recorder(name, value))


def _context(**fields) -> p2t._ConversionContext:
    ctx = p2t._ConversionContext(
        pcap_path="cap.pcap", keylog_path=None, tap_path="cap.tap", tls_ports=(),
        quic_ports=(), extra_decode_as=(), heuristic=False, capture_target="",
        resync_search_depth=None, tls_midstream_secrets=None, progress=None,
    )
    for name, value in fields.items():
        setattr(ctx, name, value)
    return ctx


def test_tshark_stage_with_keys_runs_one_combined_pass_then_ssh(monkeypatch):
    calls = []
    _record_tshark_helpers(monkeypatch, calls)
    p2t._run_tshark_stage(_context(has_keys=True))
    # TLS, QUIC and SSH share ONE tshark run; its SSH rows become flows last.
    assert calls == ["_run_keyed_combined_pass", "_add_ssh_synthetic_flows"]


def test_tshark_stage_without_keys_ingests_plaintext_then_ssh(monkeypatch):
    calls = []
    _record_tshark_helpers(monkeypatch, calls)
    p2t._run_tshark_stage(_context(has_keys=False))
    # The plaintext pass also carries the SSH rows (no separate SSH pass).
    assert calls == ["_detect_encrypted_quic_streams",
                     "_emit_plaintext_streams_singlepass", "_add_ssh_synthetic_flows"]


def test_tshark_stage_skips_plaintext_when_an_independent_decryptor_runs(monkeypatch):
    calls = []
    _record_tshark_helpers(monkeypatch, calls)
    p2t._run_tshark_stage(_context(has_keys=False, independent_entries=[_entry("x")]))
    assert calls == ["_emit_ssh_connections"]


# --------------------------------------------------------------------------- #
# Plan helpers
# --------------------------------------------------------------------------- #

def test_fold_protocol_keylogs_prefers_the_generic_map():
    folded = p2t._fold_protocol_keylogs(
        {"mtproto": "generic.log"},
        {"mtproto_keylog": "named.log", "signal_keylog": "s.log",
         "rc4_keylog": None, "keylog_dir": "x"})
    assert folded == {"mtproto": "generic.log", "signal": "s.log"}


def test_fold_protocol_keylogs_does_not_mutate_the_caller_map():
    caller = {"a": "a.log"}
    p2t._fold_protocol_keylogs(caller, {"b_keylog": "b.log"})
    assert caller == {"a": "a.log"}


def test_present_entries_follow_the_registry_and_skip_missing_files(monkeypatch, tmp_path):
    keylog = tmp_path / "k.log"
    keylog.write_text("K\n")
    registry = get_offline_decryptor_registry()
    monkeypatch.setattr(registry, "_entries", {
        "a": _entry("a"), "b": _entry("b"), "c": _entry("c")})
    warnings = []
    monkeypatch.setattr(p2t.logger, "warning", lambda *a, **k: warnings.append(a))

    present = p2t._present_offline_entries(
        {"a": str(keylog), "b": str(tmp_path / "missing.log")})

    assert [e.protocol_name for e in present] == ["a"]
    assert len(warnings) == 1


def test_prepare_splits_tls_riding_and_independent_entries(monkeypatch, capture, tmp_path):
    pcap, tap = capture
    keylog = tmp_path / "k.log"
    keylog.write_text("K\n")
    registry = get_offline_decryptor_registry()
    monkeypatch.setattr(registry, "_entries", {
        "rider": _entry("rider", requires_tls_strip=True), "raw": _entry("raw")})
    ctx = _context(pcap_path=pcap, tap_path=tap)

    p2t._prepare_conversion(ctx, {"rider": str(keylog)}, {"raw_keylog": str(keylog)},
                            None)

    assert [e.protocol_name for e in ctx.tls_strip_entries] == ["rider"]
    assert [e.protocol_name for e, _ in ctx.independent_plan] == ["raw"]
    assert ctx.has_keys is False and ctx.tshark_bin == "tshark"
    assert ctx.target == "cap.pcap"


def test_prepare_fails_loud_on_a_missing_keylog_before_finding_tshark(monkeypatch, capture):
    pcap, tap = capture
    monkeypatch.setattr(p2t, "find_tshark", lambda path=None: pytest.fail("tshark looked up"))
    ctx = _context(pcap_path=pcap, tap_path=tap, keylog_path="/no/such/keylog")
    with pytest.raises(p2t.NoDecryptionKeysError):
        p2t._prepare_conversion(ctx, None, {}, None)


# --------------------------------------------------------------------------- #
# Request-context sidecar (--attribute-sdk) replayed onto the offline flows
# --------------------------------------------------------------------------- #

FB_FRAMES = ["org.chromium.net.UrlRequest.start", "com.facebook.GraphRequest.execute"]
CAPTURE_T0 = 1_700_000_000.0
DEVICE = "10.0.0.2"
SERVER = "93.184.216.34"


def _context_row(req_id: str, url: str, t: float, event: str = "start", **extra) -> dict:
    import dataclasses

    from friTap.events import RequestContextEvent

    row = dataclasses.asdict(RequestContextEvent(
        event=event, req_id=req_id, url=url, method="GET", frames=list(FB_FRAMES),
        stack_kind="cronet", timestamp=t + 3600.0, t_ms=t * 1000.0, **extra))
    row.pop("_cancelled", None)
    return row


def _write_sidecar(path, rows, junk=()) -> str:
    import json

    lines = [json.dumps(row) for row in rows] + list(junk)
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def _tls_request(bus, port: int, path: str, host: str, t: float) -> None:
    from friTap.events import DatalogEvent
    from friTap.offline.pipeline_api import emit_tls_session_event

    emit_tls_session_event(bus, (DEVICE, port, SERVER, 443),
                           {"sni": host, "client_random": f"{port:064x}"})
    bus.emit(DatalogEvent(
        timestamp=t, data=f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(),
        function="tshark_offline", direction="write", src_addr=DEVICE, src_port=port,
        dst_addr=SERVER, dst_port=443))


def _quic_request(bus, port: int, path: str, host: str, t: float) -> None:
    from friTap.events import DatalogEvent
    from tests.unit._h3_helpers import headers_frame, qpack_encoder

    p2t._emit_quic_session_event(bus, {
        "src_addr": DEVICE, "src_port": port, "dst_addr": SERVER, "dst_port": 443,
        "version": "1", "sni": host, "alpn": "h3", "client_random": "cd" * 32})
    encoder, _ = qpack_encoder()
    _, frame = headers_frame(encoder, 0, [
        (b":method", b"GET"), (b":scheme", b"https"),
        (b":authority", host.encode()), (b":path", path.encode())])
    bus.emit(DatalogEvent(
        timestamp=t, data=frame, function="tshark_offline", direction="write",
        src_addr=DEVICE, src_port=port, dst_addr=SERVER, dst_port=443,
        transport="udp", protocol="quic", stream_id=0))


def _tls_then_late_quic(ctx) -> None:
    """The combined pass's order: all TLS first (up to capture end), QUIC last."""
    _tls_request(ctx.bus, 51000, "/tls", "tls.example", CAPTURE_T0 + 0.5)
    _tls_request(ctx.bus, 51001, "/end", "other.example", CAPTURE_T0 + 400.0)
    _quic_request(ctx.bus, 52000, "/quic", "quic.example", CAPTURE_T0 + 1.0)


@pytest.fixture
def replay_capture(monkeypatch, capture):
    from friTap.flow import collector as collector_module

    monkeypatch.setattr(collector_module, "_SWEEP_INTERVAL", 1)  # sweep on every event
    for name in ("_run_midstream_stage", "_run_tls_riding_decryptors",
                 "_run_independent_decryptors"):
        monkeypatch.setattr(p2t, name, lambda ctx: None)
    monkeypatch.setattr(p2t, "_run_tshark_stage", _tls_then_late_quic)
    return capture


def _tap_contents(tap: str) -> tuple[dict, dict]:
    from friTap.flow.tap_reader import TapReader

    with TapReader(tap) as reader:
        flows = {(f.transport, f.src_port): f for f in reader.read_all_flows()}
        records = {r["req_id"]: r for r in reader.iter_request_contexts()}
    return flows, records


def test_sidecar_contexts_attribute_tls_and_late_quic_flows(replay_capture, tmp_path):
    pcap, tap = replay_capture
    sidecar = _write_sidecar(tmp_path / "ctx.jsonl", [
        _context_row("q1", "https://quic.example/quic", CAPTURE_T0 + 0.9),
        _context_row("t1", "https://tls.example/tls", CAPTURE_T0 + 0.4),
        _context_row("t1", "https://tls.example/tls", CAPTURE_T0 + 0.6, event="end"),
    ], junk=["not json", "[1, 2]", '{"event": "start"}'])

    p2t.convert_pcap_to_tap(pcap, tap_path=tap, request_contexts=sidecar)

    flows, records = _tap_contents(tap)
    for key in (("tls", 51000), ("quic", 52000)):
        attribution = flows[key].attribution
        assert attribution["originator"]["sdk"] == "Facebook SDK", key
        assert attribution["source"] == "java-request"
    assert not (flows[("tls", 51001)].attribution or {}).get("originator")
    assert records["q1"]["matched_flow_ids"] == [flows[("quic", 52000)].flow_id]
    assert records["t1"]["matched_flow_ids"] == [flows[("tls", 51000)].flow_id]
    assert flows[("tls", 51000)].tls.client_random == f"{51000:064x}"
    assert flows[("quic", 52000)].quic.client_random == "cd" * 32


def test_contexts_use_the_agent_clock_when_t_ms_is_present(tmp_path):
    from friTap.offline.request_contexts import load_request_contexts

    with_t_ms = _context_row("a", "https://x.example/", CAPTURE_T0 + 5)
    without = dict(_context_row("b", "https://x.example/", CAPTURE_T0), t_ms=None,
                   timestamp=CAPTURE_T0 + 1)
    events = load_request_contexts(_write_sidecar(tmp_path / "c.jsonl", [with_t_ms, without]))
    assert [(e.req_id, e.timestamp) for e in events] == [
        ("b", CAPTURE_T0 + 1), ("a", CAPTURE_T0 + 5)]
    assert events[1].frames == FB_FRAMES


def test_unreadable_sidecar_is_ignored(replay_capture, tmp_path):
    pcap, tap = replay_capture
    p2t.convert_pcap_to_tap(pcap, tap_path=tap,
                            request_contexts=str(tmp_path / "missing.jsonl"))
    flows, records = _tap_contents(tap)
    assert records == {}
    assert not (flows[("quic", 52000)].attribution or {}).get("originator")


def test_manifest_request_contexts_sidecar_is_picked_up(replay_capture, tmp_path, monkeypatch):
    import json

    pcap, tap = replay_capture
    _write_sidecar(tmp_path / "cap.contexts.jsonl", [
        _context_row("q1", "https://quic.example/quic", CAPTURE_T0 + 0.9)])
    with open(f"{pcap}.fritap.json", "w", encoding="utf-8") as fh:
        json.dump({"request_contexts": "cap.contexts.jsonl"}, fh)
    monkeypatch.chdir(tmp_path.parent)  # the relative path belongs to the manifest

    p2t.pcap_to_tap(pcap, tap_path=tap, use_manifest=True)

    flows, records = _tap_contents(tap)
    assert records["q1"]["matched_flow_ids"] == [flows[("quic", 52000)].flow_id]


def test_explicit_request_contexts_win_over_the_manifest(replay_capture, tmp_path):
    import json

    pcap, tap = replay_capture
    explicit = _write_sidecar(tmp_path / "explicit.jsonl", [
        _context_row("mine", "https://quic.example/quic", CAPTURE_T0 + 0.9)])
    _write_sidecar(tmp_path / "manifest.jsonl", [
        _context_row("theirs", "https://quic.example/quic", CAPTURE_T0 + 0.9)])
    with open(f"{pcap}.fritap.json", "w", encoding="utf-8") as fh:
        json.dump({"request_contexts": str(tmp_path / "manifest.jsonl")}, fh)

    p2t.pcap_to_tap(pcap, tap_path=tap, request_contexts=explicit)

    assert set(_tap_contents(tap)[1]) == {"mine"}


def test_cli_manifest_merge_forwards_request_contexts(tmp_path):
    import argparse

    from friTap.offline.cli import merge_manifest

    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"")
    (tmp_path / "ctx.jsonl").write_text("")
    args = argparse.Namespace(from_pcap=str(pcap), tls_ports=[], quic_ports=[], keylog=None,
                              decode_as=[], tls_heuristic=False)
    merged = merge_manifest(args, {"request_contexts": "ctx.jsonl"})
    assert merged["request_contexts"] == str(tmp_path / "ctx.jsonl")


def test_malformed_sidecar_lines_are_skipped_with_one_warning(tmp_path, fritap_log_records):
    import logging

    from friTap.offline import request_contexts as rc

    records = fritap_log_records(rc.logger.name)
    bad_type = dict(_context_row("x", "https://x.example/", CAPTURE_T0), frames="oops",
                    tid="7", timestamp="soon", t_ms=None)
    events = rc.load_request_contexts(_write_sidecar(tmp_path / "c.jsonl", [
        _context_row("ok", "https://x.example/", CAPTURE_T0), bad_type,
    ], junk=["{", "null", '{"event": "nope", "req_id": "r"}', "x" * 300_000]))
    assert [e.req_id for e in events] == ["ok"]
    warnings = [r for r in records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "2 malformed" in warnings[0].getMessage()
