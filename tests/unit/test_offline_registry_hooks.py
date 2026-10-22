"""Registry-driven post-collection hooks and derived defaults of the offline core.

``convert_pcap_to_tap`` no longer hardcodes the RC4 / Telegram attach passes,
the messaging prefixes or the resync default: each comes from the
:class:`~friTap.offline.registry.OfflineDecryptorEntry` fields. These tests pin
the derived values to the historical literals and prove the extension point.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from friTap.offline import pcap_to_tap as p2t
from friTap.offline.mtproto.tap_attach import attach_telegram_post_collection
from friTap.offline.mtproto.transport import DEFAULT_OBF_MAX_BLOCKS
from friTap.offline.rc4.tls_attach import attach_rc4_post_collection
from friTap.offline.registry import (
    OfflineDecryptorEntry,
    attach_hooks,
    default_resync_search_depth,
    entry_family,
    get_offline_decryptor_registry,
    messaging_protocol_names,
)


def _entry(name: str, **fields) -> OfflineDecryptorEntry:
    return OfflineDecryptorEntry(
        protocol_name=name, cli_flag=f"--{name}-keylog", cli_dest=f"{name}_keylog",
        requires_tls_strip=False, emitter=lambda **_kw: None, layer_cls=object,
        counter_prefix=name, **fields,
    )


class _FakeCollector:
    def __init__(self, flows):
        self._flows = flows

    def live_flows(self):
        return list(self._flows)


def _empty_state():
    return SimpleNamespace(mtproto_meta=None, telegram_e2e_meta=None)


def test_builtin_attach_order_is_rc4_then_telegram():
    hooks = attach_hooks(get_offline_decryptor_registry().list())
    assert hooks == [attach_rc4_post_collection, attach_telegram_post_collection]


def test_telegram_family_declares_attach_and_resync_on_mtproto_only():
    registry = get_offline_decryptor_registry()
    mtproto, telegram = registry.get("mtproto"), registry.get("telegram")
    assert mtproto.attach is attach_telegram_post_collection
    assert mtproto.resync_default == DEFAULT_OBF_MAX_BLOCKS
    assert telegram.attach is None and telegram.resync_default is None
    assert entry_family(mtproto) == entry_family(telegram) == "telegram"


def test_telegram_family_takes_resync_depth_as_obf_max_blocks():
    registry = get_offline_decryptor_registry()
    assert registry.get("mtproto").resync_param == "obf_max_blocks"
    assert registry.get("telegram").resync_param == "obf_max_blocks"


def test_entries_without_midstream_recovery_declare_no_resync_param():
    registry = get_offline_decryptor_registry()
    others = [e for e in registry.list() if e.protocol_name not in ("mtproto", "telegram")]
    assert others and all(e.resync_param is None for e in others)
    assert _entry("plugin").resync_param is None


def test_attach_hooks_sort_by_order_then_registration():
    first, second, third = (lambda f, s: None), (lambda f, s: None), (lambda f, s: None)
    entries = [_entry("x", attach=third, attach_order=9),
               _entry("y", attach=first, attach_order=1),
               _entry("z", attach=second, attach_order=1)]
    assert attach_hooks(entries) == [first, second, third]


def test_messaging_prefixes_derived_equal_old_literal():
    # The historical literal, minus protocols this build does not ship.
    legacy = ("mtproto", "telegram", "signal")
    registered = set(get_offline_decryptor_registry().names())
    assert p2t.MESSAGING_PREFIXES == tuple(p for p in legacy if p in registered)
    assert p2t.MESSAGING_PREFIXES[:2] == ("mtproto", "telegram")
    assert messaging_protocol_names([_entry("q", messaging=True), _entry("r")]) == ("q",)


def test_resync_default_equals_obf_max_blocks():
    assert p2t.DEFAULT_RESYNC_SEARCH_DEPTH == DEFAULT_OBF_MAX_BLOCKS == 4096
    assert default_resync_search_depth([_entry("n")], fallback=7) == 7


def test_cli_resync_default_and_help_unchanged():
    from friTap.offline.cli import _build_parser

    parser = _build_parser()
    action = next(a for a in parser._actions if a.dest == "resync_search_depth")
    # None: each decryptor's own default, which the help text lists.
    assert action.default is None
    assert (f"obfuscated transport; default: each decryptor's own "
            f"(mtproto: {DEFAULT_OBF_MAX_BLOCKS}))." in action.help)


def test_third_party_attach_hook_is_called(monkeypatch):
    registry = get_offline_decryptor_registry()
    calls = []

    def plugin_attach(flows, state):
        calls.append((flows, state))
        return {"absorbed-1"}

    monkeypatch.setitem(registry._entries, "plugin",
                        _entry("plugin", attach=plugin_attach, attach_order=25))
    state = _empty_state()
    absorbed = p2t._run_registered_attaches(_FakeCollector([]), state)
    assert absorbed == {"absorbed-1"}
    assert calls == [([], state)]


def test_builtin_hooks_are_noops_without_state():
    assert p2t._run_registered_attaches(_FakeCollector([object()]), _empty_state()) == set()


@pytest.mark.parametrize("backend_ok, expected", [(True, 0), (False, 2)])
def test_mtproto_cli_dependency_hook(monkeypatch, backend_ok, expected):
    import friTap.offline.mtproto as mt

    monkeypatch.setattr(mt, "mtproto_backend_available", lambda: backend_ok)
    assert mt.offline_cli_dependency_warnings(None, None) == []
    lines = mt.offline_cli_dependency_warnings("k.log", None)
    assert len(lines) == expected
    if lines:
        assert lines == [f"Warning: {mt.MTPROTO_DEPENDENCY_HINT}",
                         "         MTProto streams in this capture will be skipped."]


def test_register_offline_decryptors_safely_registers_in_order(monkeypatch):
    import sys
    import types

    from friTap.offline.registry import register_offline_decryptors_safely

    registry = get_offline_decryptor_registry()
    module = types.ModuleType("fake_pkg.offline_decryptor")
    module.build_a = lambda: _entry("safe-a")
    module.build_b = lambda: _entry("safe-b")
    monkeypatch.setitem(sys.modules, "fake_pkg.offline_decryptor", module)
    monkeypatch.setattr(registry, "_entries", dict(registry._entries))
    register_offline_decryptors_safely("fake_pkg", ("build_a", "build_b"), "skipped")
    assert registry.names()[-2:] == ["safe-a", "safe-b"]


def test_register_offline_decryptors_safely_never_raises(monkeypatch):
    import logging

    from friTap.offline.registry import register_offline_decryptors_safely

    messages = []
    monkeypatch.setattr(logging.getLogger("no_such_pkg_xyz"), "debug",
                        lambda msg, **kw: messages.append((msg, kw.get("exc_info"))))
    register_offline_decryptors_safely("no_such_pkg_xyz", ("build",), "X skipped")
    assert messages == [("X skipped", True)]


def test_midstream_spans_hooks_are_registry_driven(monkeypatch):
    registry = get_offline_decryptor_registry()
    calls = []

    def plugin_hook(state, bound, keylogs, entries, *, bus, result):
        calls.append((state, bound, keylogs, entries, bus, result))

    monkeypatch.setattr(registry, "_entries", {
        "plugin": _entry("plugin", midstream_spans=plugin_hook),
        "plain": _entry("plain"),
    })
    p2t._bridge_bound_midstream_spans("st", {"k"}, {"plugin": "p"}, ["e"],
                                      bus="b", result="r")
    assert calls == [("st", {"k"}, {"plugin": "p"}, ["e"], "b", "r")]


def _bridge_with_hooks(monkeypatch, *hooks):
    """Run the bridge over plugin entries carrying *hooks*, in order."""
    registry = get_offline_decryptor_registry()
    monkeypatch.setattr(registry, "_entries", {
        f"p{i}": _entry(f"p{i}", midstream_spans=hook) for i, hook in enumerate(hooks)
    })
    p2t._bridge_bound_midstream_spans("st", {"k"}, {}, [], bus="b", result="r")


def _raising_hook(exc, module="friTap.offline.signal.offline_decryptor"):
    def hook(*_a, **_k):
        raise exc
    hook.__module__ = module
    return hook


def test_midstream_bridge_propagates_decode_failure(monkeypatch):
    with pytest.raises(RuntimeError, match="decode bug"):
        _bridge_with_hooks(monkeypatch, _raising_hook(RuntimeError("decode bug")))


def test_midstream_bridge_absent_component_is_silent_and_continues(monkeypatch):
    warnings, calls = [], []
    monkeypatch.setattr(p2t.logger, "warning", lambda *a, **k: warnings.append(a))
    absent = ModuleNotFoundError("gone", name="friTap.offline.signal.midstream")
    _bridge_with_hooks(monkeypatch, _raising_hook(absent),
                       lambda *a, **k: calls.append(a))
    assert warnings == [] and len(calls) == 1


def test_midstream_bridge_warns_on_unrelated_import_failure(monkeypatch):
    warnings, calls = [], []
    monkeypatch.setattr(p2t.logger, "warning", lambda *a, **k: warnings.append(a))
    _bridge_with_hooks(monkeypatch,
                       _raising_hook(ModuleNotFoundError("no dep", name="dep")),
                       lambda *a, **k: calls.append(a))
    assert len(warnings) == 1 and len(calls) == 1


@pytest.mark.parametrize("name", [
    "_attach_rc4_in_tls_layers", "_attach_telegram_meta", "_emit_mtproto_streams",
    "DEFAULT_OBF_MAX_BLOCKS",
])
def test_pcap_to_tap_no_longer_resolves_moved_protocol_names(name):
    # The lazy back-compat shim (module __getattr__/__dir__) is gone: protocol
    # names are imported from their own packages.
    assert "__getattr__" not in vars(p2t) and "__dir__" not in vars(p2t)
    assert not hasattr(p2t, name)
    assert name not in dir(p2t)


def test_fresh_import_registers_in_sorted_discovery_order():
    import importlib.util
    import subprocess
    import sys

    code = (
        "import friTap.offline.pcap_to_tap as p;"
        "from friTap.offline.registry import get_offline_decryptor_registry as g;"
        "print(g().names()[:5], p.DEFAULT_RESYNC_SEARCH_DEPTH)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, check=True).stdout.strip()
    # Signal E2E is private and stripped from the public build; it registers last
    # when present, so assert the public discovery order and append signal only if
    # the offline Signal package is importable in this build.
    expected_names = ["mtproto", "telegram", "rc4", "schannel"]
    if importlib.util.find_spec("friTap.offline.signal") is not None:
        expected_names.append("signal")
    assert out == f"{expected_names} 4096"
