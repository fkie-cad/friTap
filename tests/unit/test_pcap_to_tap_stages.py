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
