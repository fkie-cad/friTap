#!/usr/bin/env python3

"""Tests for the generic protocol UI-visibility ("upcoming") mechanism.

A protocol handler may mark itself ``upcoming`` (implemented + CLI-selectable but
code-only — kept out of user-facing menus). The TUI protocol picker:
  * hardcodes only the always-PUBLIC built-ins (no private/upcoming name leaks);
  * surfaces any further registered protocol via the registry, EXCEPT those
    flagged ``upcoming``.

These tests are protocol-agnostic (no private protocol named here), so they live
in the public tree and exercise the generic seam with stub handlers.
"""

import pytest


def test_base_handler_upcoming_defaults_false():
    from friTap.protocols.tls_handler import TLSHandler
    assert TLSHandler().upcoming is False


def test_base_handler_category_and_description_defaults():
    from friTap.protocols.tls_handler import TLSHandler
    assert TLSHandler().category == "protocol"
    assert TLSHandler().description == ""


def test_rc4_is_custom_cipher():
    from friTap.protocols.registry import available_protocol_names
    if "rc4" not in available_protocol_names():
        pytest.skip("rc4 not available in this build")
    from friTap.protocols.rc4_handler import RC4Handler
    handler = RC4Handler()
    assert handler.category == "custom_cipher"
    assert handler.description == "RC4 stream cipher key extraction"


def test_custom_cipher_names_lists_only_custom_ciphers():
    from friTap.protocols.registry import available_protocol_names, custom_cipher_names
    names = custom_cipher_names()
    assert names == sorted(names)
    assert "tls" not in names and "ssh" not in names
    if "rc4" in available_protocol_names():
        assert "rc4" in names


def test_expand_custom_group_in_place_and_deduped(monkeypatch):
    from friTap.protocols import registry
    monkeypatch.setattr(registry, "custom_cipher_names", lambda: ["aes", "rc4"])
    assert registry.expand_custom_group(["tls", "custom", "rc4"]) == ["tls", "aes", "rc4"]
    assert registry.expand_custom_group(["rc4", "custom"]) == ["rc4", "aes"]


def test_expand_custom_group_queries_registry_once(monkeypatch):
    from friTap.protocols import registry
    calls = []

    def _names(**_):
        calls.append(1)
        return ["aes", "rc4"]

    monkeypatch.setattr(registry, "custom_cipher_names", _names)
    assert registry.expand_custom_group(["custom", "tls", "custom"]) == ["aes", "rc4", "tls"]
    assert len(calls) == 1
    # No `custom` token -> no registry query; explicit names skip it too.
    registry.expand_custom_group(["tls"])
    assert registry.expand_custom_group(["custom"], ["rc4"]) == ["rc4"]
    assert len(calls) == 1


def test_order_protocol_selection_uses_given_names(monkeypatch):
    from friTap.protocols import registry
    monkeypatch.setattr(
        registry, "custom_cipher_names",
        lambda **_: pytest.fail("must not query the registry when names are given"),
    )
    assert registry.order_protocol_selection(["rc4", "tls"], ["rc4"]) == ["tls", "rc4"]


class _BareHandler:
    """Duck-typed plugin handler without category/description/upcoming."""

    def __init__(self, name):
        self.name = name
        self.display_name = name.upper()


class _CipherHandler(_BareHandler):
    def __init__(self, name, upcoming=False):
        super().__init__(name)
        self.category = "custom_cipher"
        self.description = f"{name} cipher"
        self.upcoming = upcoming


def _patch_factories(monkeypatch, handlers):
    from friTap.protocols import registry
    monkeypatch.setattr(
        registry, "_all_handler_factories",
        lambda: {h.name: (lambda h=h: h) for h in handlers},
    )
    return registry


def test_custom_cipher_handlers_tolerate_duck_typed_handlers(monkeypatch):
    registry = _patch_factories(
        monkeypatch, [_BareHandler("plug"), _CipherHandler("rc4")]
    )
    assert registry.custom_cipher_names() == ["rc4"]


def test_custom_cipher_handlers_skip_upcoming(monkeypatch):
    registry = _patch_factories(
        monkeypatch,
        [_CipherHandler("rc4"), _CipherHandler("aes", upcoming=True), _BareHandler("tls")],
    )
    assert registry.custom_cipher_names() == ["rc4"]
    assert registry.custom_cipher_names(include_upcoming=True) == ["aes", "rc4"]
    assert registry.expand_custom_group(["tls", "custom"]) == ["tls", "rc4"]
    # An upcoming cipher chosen by name still orders as a custom cipher.
    assert registry.order_protocol_selection(["aes", "tls"]) == ["tls", "aes"]


def test_available_custom_ciphers_tolerates_missing_description(monkeypatch):
    handler = _BareHandler("xor")
    handler.category = "custom_cipher"
    _patch_factories(monkeypatch, [handler])
    from friTap.tui.modals.custom_cipher_modal import available_custom_ciphers
    entries = available_custom_ciphers()
    assert [(e.name, e.display_name, e.description) for e in entries] == [("xor", "XOR", "")]


def test_custom_cipher_handlers_are_sorted_custom_ciphers():
    from friTap.protocols.registry import custom_cipher_handlers, custom_cipher_names
    handlers = custom_cipher_handlers()
    assert all(h.category == "custom_cipher" for h in handlers)
    assert [h.name for h in handlers] == custom_cipher_names()


def test_order_protocol_selection_puts_custom_ciphers_last(monkeypatch):
    from friTap.protocols import registry
    monkeypatch.setattr(registry, "custom_cipher_names", lambda **_: ["aes", "rc4"])
    assert registry.order_protocol_selection(["rc4", "tls", "aes", "rc4"]) == ["tls", "rc4", "aes"]
    assert registry.order_protocol_selection(["rc4"]) == ["rc4"]
    assert registry.order_protocol_selection([]) == []


def test_builtin_modal_list_is_public_only():
    pytest.importorskip("textual")
    from friTap.tui.modals import protocol_modal
    names = {n for n, _ in protocol_modal._BUILTIN_PROTOCOLS}
    # Always-public built-ins only — no private/upcoming protocol is hardcoded.
    assert names == {"tls", "ssh", "mtproto", "telegram"}


class _StubHandler:
    def __init__(self, name, upcoming):
        self.name = name
        self.display_name = name.upper()
        self.upcoming = upcoming


class _StubRegistry:
    def __init__(self, handlers):
        self._handlers = handlers

    def get_all(self):
        return self._handlers


def test_modal_hides_upcoming_registered_protocol():
    pytest.importorskip("textual")
    from friTap.tui.modals.protocol_modal import ProtocolSelectModal

    reg = _StubRegistry([
        _StubHandler("plugin_visible", upcoming=False),
        _StubHandler("plugin_upcoming", upcoming=True),
    ])
    modal = ProtocolSelectModal(registry=reg)
    names = [name for name, _ in modal._protocol_entries]

    assert "plugin_visible" in names      # a normal registered plugin is shown
    assert "plugin_upcoming" not in names  # an upcoming protocol stays hidden
    assert "auto" in names                # auto-detect always present
    assert "tls" in names and "telegram" in names  # public built-ins present


def test_modal_labels_duck_typed_plugin_and_uses_given_ciphers():
    pytest.importorskip("textual")
    from friTap.tui.modals.custom_cipher_modal import CustomCipherEntry
    from friTap.tui.modals.protocol_modal import ProtocolSelectModal

    # _StubHandler has no category/description: shown as a plain plugin.
    reg = _StubRegistry([_StubHandler("plugin_bare", upcoming=False)])
    ciphers = [CustomCipherEntry("rc4", "RC4", "RC4 stream cipher key extraction")]
    entries = dict(ProtocolSelectModal(registry=reg, ciphers=ciphers)._protocol_entries)

    assert entries["plugin_bare"] == "PLUGIN_BARE (plugin)"
    assert entries["custom"] == "Custom Encryption — custom cipher key extraction"
    assert "RC4" not in entries["custom"]  # ciphers are picked in the follow-up modal
    # No ciphers -> no grouped "Custom Encryption" entry.
    assert "custom" not in dict(ProtocolSelectModal(registry=reg, ciphers=[])._protocol_entries)
