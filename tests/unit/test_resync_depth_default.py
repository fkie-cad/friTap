#!/usr/bin/env python3

"""``resync_search_depth=None`` means "each offline decryptor uses its own default".

The public boundary (``convert_pcap_to_tap`` / ``pcap_to_tap``, the
``--resync-search-depth`` CLI flag and the TUI's advanced field) used to resolve
the default to one concrete number (the FIRST registered entry's
``resync_default``), so a decryptor's own default was never reached. Now an
absent value is ``None`` and the emitter is called WITHOUT ``obf_max_blocks``;
an explicit value (including ``0``) keeps the old mapping and accept-gate.
"""

from __future__ import annotations

import dataclasses
import inspect

import pytest

from friTap.offline import pcap_to_tap as p2t
from friTap.offline.mtproto.transport import DEFAULT_OBF_MAX_BLOCKS
from friTap.offline.registry import (
    OfflineDecryptorEntry,
    get_offline_decryptor_registry,
)

_PCAP = "tests/fixtures/schannel_tls13.pcap"


def _swap_emitter(monkeypatch, name: str, emitter) -> None:
    """Replace the registered *name* entry's emitter for this test only."""
    registry = get_offline_decryptor_registry()
    monkeypatch.setattr(registry, "_entries", dict(registry._entries))
    registry._entries[name] = dataclasses.replace(registry._entries[name], emitter=emitter)


def _convert(tmp_path, **kwargs) -> None:
    keylog = tmp_path / "x.mtproto.keylog"
    keylog.write_text("")
    p2t.convert_pcap_to_tap(
        _PCAP, tap_path=str(tmp_path / "out.tap"),
        protocol_keylogs={kwargs.pop("protocol", "mtproto"): str(keylog)}, **kwargs,
    )


def _mtproto_spy(calls: list):
    """An emitter that accepts obf_max_blocks and records the effective value."""
    def spy(*, obf_max_blocks=DEFAULT_OBF_MAX_BLOCKS, **kwargs):
        calls.append({"effective": obf_max_blocks, "kwargs": kwargs,
                      "passed": "obf_max_blocks" in kwargs})
    return spy


# (a) default: the emitter's own default applies ------------------------------

def test_default_does_not_pass_obf_max_blocks(monkeypatch, tmp_path):
    seen: list = []

    def spy(**kwargs):
        seen.append(kwargs)

    _swap_emitter(monkeypatch, "mtproto", spy)
    _convert(tmp_path)
    assert len(seen) == 1
    assert "obf_max_blocks" not in seen[0]


def test_default_effective_depth_is_mtproto_default(monkeypatch, tmp_path):
    calls: list = []
    _swap_emitter(monkeypatch, "mtproto", _mtproto_spy(calls))
    _convert(tmp_path)
    assert [c["effective"] for c in calls] == [4096]


def test_registered_mtproto_emitter_defaults_to_4096():
    emitter = get_offline_decryptor_registry().get("mtproto").emitter
    default = inspect.signature(emitter).parameters["obf_max_blocks"].default
    assert default == DEFAULT_OBF_MAX_BLOCKS == 4096


def test_signature_defaults_are_none():
    for fn in (p2t.convert_pcap_to_tap, p2t.pcap_to_tap):
        assert inspect.signature(fn).parameters["resync_search_depth"].default is None
    assert p2t.DEFAULT_RESYNC_SEARCH_DEPTH == 4096  # kept for display / back-compat


# (b) explicit values, including 0, are forwarded ------------------------------

@pytest.mark.parametrize("depth", [0, 123])
def test_explicit_depth_is_forwarded(monkeypatch, tmp_path, depth):
    seen: list = []
    _swap_emitter(monkeypatch, "mtproto", lambda **kw: seen.append(kw))
    _convert(tmp_path, resync_search_depth=depth)
    assert seen[0]["obf_max_blocks"] == depth


# (c) plugin emitter without obf_max_blocks ------------------------------------

@pytest.mark.parametrize("depth", [None, 0, 500])
def test_plugin_emitter_without_obf_max_blocks(monkeypatch, tmp_path, depth):
    seen: list = []

    def plugin_emitter(*, pcap_path, proto_keylog, tls_keylog_path, tshark_bin,
                       tls_ports, bus, state, result):
        seen.append(proto_keylog)

    registry = get_offline_decryptor_registry()
    monkeypatch.setattr(registry, "_entries", dict(registry._entries))
    registry._entries["plugproto"] = OfflineDecryptorEntry(
        protocol_name="plugproto", cli_flag="--plugproto-keylog",
        cli_dest="plugproto_keylog", requires_tls_strip=False,
        emitter=plugin_emitter, layer_cls=object, counter_prefix="plugproto",
    )
    _convert(tmp_path, protocol="plugproto", resync_search_depth=depth)
    assert len(seen) == 1


def test_run_independent_entry_none_safe():
    seen: list = []
    entry = type("E", (), {"emitter": staticmethod(lambda **kw: seen.append(kw))})
    p2t._run_independent_entry(entry, ["k.log"], pcap_path="p")
    assert seen == [{"proto_keylog": "k.log", "pcap_path": "p"}]


def test_pcap_to_tap_wrapper_forwards_none(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(p2t, "convert_pcap_to_tap",
                        lambda pcap, **kw: captured.update(kw))
    p2t.pcap_to_tap("x.pcap", use_manifest=False)
    assert captured["resync_search_depth"] is None


# (d) CLI ------------------------------------------------------------------------

def _resync_action():
    from friTap.offline.cli import _build_parser

    parser = _build_parser()
    return parser, next(a for a in parser._actions if a.dest == "resync_search_depth")


def test_cli_without_flag_is_none():
    parser, action = _resync_action()
    assert action.default is None
    assert parser.parse_args(["--from-pcap", "x.pcap"]).resync_search_depth is None


def test_cli_help_mentions_each_decryptor_default():
    _parser, action = _resync_action()
    assert "default: each decryptor's own (mtproto: 4096)" in action.help


def test_cli_explicit_value_still_validated():
    parser, _action = _resync_action()
    args = parser.parse_args(["--from-pcap", "x.pcap", "--resync-search-depth", "0"])
    assert args.resync_search_depth == 0
    with pytest.raises(SystemExit):
        parser.parse_args(["--from-pcap", "x.pcap", "--resync-search-depth", "-1"])


def test_cli_resync_defaults_dedup_by_family():
    from friTap.offline.cli import _resync_defaults_text

    def entry(name, family="", default=None):
        return OfflineDecryptorEntry(
            protocol_name=name, cli_flag=f"--{name}", cli_dest=name,
            requires_tls_strip=False, emitter=lambda **_: None, layer_cls=object,
            counter_prefix=name, decoder_family=family, resync_default=default,
        )

    entries = [entry("mtproto", "telegram", 4096), entry("telegram", "telegram", 9),
               entry("signal"), entry("plug", default=77)]
    assert _resync_defaults_text(entries) == "mtproto: 4096, plug: 77"


def test_merge_manifest_default_is_none():
    from types import SimpleNamespace

    from friTap.offline import cli

    args = SimpleNamespace(tls_ports=[], quic_ports=[], keylog=None, decode_as=[],
                           tls_heuristic=False)
    assert cli.merge_manifest(args, {})["resync_search_depth"] is None


# (e) TUI field helpers -----------------------------------------------------------

def test_tui_empty_field_is_none():
    from friTap.tui.modals.pcap_to_tap_modals import parse_resync_depth_field

    assert parse_resync_depth_field("") == (None, None)
    assert parse_resync_depth_field("   ") == (None, None)
    assert parse_resync_depth_field("0") == (0, None)
    assert parse_resync_depth_field(" 20000 ") == (20000, None)
    depth, error = parse_resync_depth_field("-5")
    assert depth is None and "resync search depth" in error


def test_tui_field_renders_empty_for_none():
    from friTap.tui.modals.pcap_to_tap_modals import resync_depth_field_text

    assert resync_depth_field_text(None) == ""
    assert resync_depth_field_text(0) == "0"
    assert resync_depth_field_text(4096) == "4096"


# (f) removed alias ----------------------------------------------------------------

def test_obf_max_blocks_lives_only_in_the_mtproto_transport():
    assert DEFAULT_OBF_MAX_BLOCKS == 4096
    assert not hasattr(p2t, "DEFAULT_OBF_MAX_BLOCKS")
    with pytest.raises(ImportError):
        from friTap.offline.pcap_to_tap import (
            DEFAULT_OBF_MAX_BLOCKS as _alias,  # noqa: F401
        )
