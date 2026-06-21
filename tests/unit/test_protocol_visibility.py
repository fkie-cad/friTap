#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
