#!/usr/bin/env python3

"""Tests for Foundation F1 — multi-protocol selection.

``--protocol`` accepts a SET of protocols (repeatable and/or comma-separated),
e.g. ``--protocol tls,signal`` or ``--protocol tls --protocol signal``. TLS and
a companion protocol are both active and independent. ``--protocol tls`` alone
behaves exactly as before (default ``["tls"]``).

These tests exercise the generic plumbing only (parsing/normalization, config
shape, keylog-formatter union). They name no ``rc4``-specific behaviour — that
is a later workstream. A combinable protocol is picked from the registry at
runtime (``tls`` + a non-exclusive companion) so the tests do not hardcode an
extension that a filtered build might omit.
"""

import argparse

import pytest

from friTap.friTap import _normalize_protocol_selection
from friTap.protocols.registry import available_protocol_names


def _parser():
    # A bare parser whose .error() raises SystemExit (argparse default) so the
    # rejection paths are observable as pytest.raises(SystemExit).
    return argparse.ArgumentParser(prog="fritap")


def _normalize(raw):
    return _normalize_protocol_selection(raw, _parser(), available_protocol_names())


def _combinable_companion():
    """Return a registered protocol name that may be combined with ``tls``.

    Excludes ``tls`` itself and the exclusive protocols (ssh/ipsec/mtproto).
    Returns ``None`` when the build ships no combinable companion.
    """
    exclusive = {"ssh", "ipsec", "mtproto"}
    for name in available_protocol_names():
        if name != "tls" and name not in exclusive:
            return name
    return None


# ---------------------------------------------------------------------------
# Parsing / normalization
# ---------------------------------------------------------------------------

def test_default_is_tls():
    # Flag absent -> effectively ["tls"], unchanged from the historical default.
    assert _normalize(None) == ["tls"]


def test_empty_tokens_collapse_to_default():
    # Only empties / whitespace -> default.
    assert _normalize(["", "  "]) == ["tls"]


def test_single_tls_unchanged():
    assert _normalize(["tls"]) == ["tls"]


def test_comma_separated_multiselect():
    companion = _combinable_companion()
    if companion is None:
        pytest.skip("build ships no combinable companion protocol")
    assert _normalize([f"tls,{companion}"]) == ["tls", companion]


def test_repeated_flag_multiselect():
    companion = _combinable_companion()
    if companion is None:
        pytest.skip("build ships no combinable companion protocol")
    assert _normalize(["tls", companion]) == ["tls", companion]


def _combinable_main_companion():
    """Like :func:`_combinable_companion` but never a custom cipher.

    Custom ciphers are re-ordered after the main protocols, so order-preservation
    is only observable between two non-custom protocols.
    """
    from friTap.protocols.registry import custom_cipher_names
    exclusive = {"ssh", "ipsec", "mtproto"} | set(custom_cipher_names())
    for name in available_protocol_names():
        if name != "tls" and name not in exclusive:
            return name
    return None


def test_order_preserving_and_deduped():
    companion = _combinable_main_companion()
    if companion is None:
        pytest.skip("build ships no combinable non-custom companion protocol")
    # Duplicates removed, first-seen order preserved.
    assert _normalize([f"{companion},tls,{companion}", "tls"]) == [companion, "tls"]


def test_whitespace_is_trimmed():
    companion = _combinable_companion()
    if companion is None:
        pytest.skip("build ships no combinable companion protocol")
    assert _normalize([f" tls , {companion} "]) == ["tls", companion]


# ---------------------------------------------------------------------------
# Validation: exclusivity and meta standalone
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exclusive", ["ssh", "mtproto"])
def test_exclusive_protocol_rejects_combination(exclusive):
    if exclusive not in available_protocol_names():
        pytest.skip(f"{exclusive} not available in this build")
    with pytest.raises(SystemExit):
        _normalize([f"{exclusive},tls"])


def test_exclusive_alone_is_ok():
    assert _normalize(["ssh"]) == ["ssh"]


@pytest.mark.parametrize("meta", ["all", "auto"])
def test_meta_alone_is_ok(meta):
    assert _normalize([meta]) == [meta]


@pytest.mark.parametrize("meta", ["all", "auto"])
def test_meta_rejects_combination(meta):
    with pytest.raises(SystemExit):
        _normalize([f"{meta},tls"])


def test_unknown_protocol_rejected():
    with pytest.raises(SystemExit):
        _normalize(["definitely_not_a_protocol"])


# ---------------------------------------------------------------------------
# Custom cipher group (`--protocol custom`)
# ---------------------------------------------------------------------------

def _require_rc4():
    if "rc4" not in available_protocol_names():
        pytest.skip("rc4 not available in this build")


def test_custom_expands_to_custom_ciphers():
    _require_rc4()
    assert _normalize(["custom"]) == ["rc4"]


def test_tls_plus_custom():
    _require_rc4()
    assert _normalize(["tls,custom"]) == ["tls", "rc4"]


def test_custom_first_still_puts_main_protocol_first():
    _require_rc4()
    # protocols[0] is the primary protocol, so the main protocol leads.
    assert _normalize(["custom,tls"]) == ["tls", "rc4"]


def test_custom_and_explicit_cipher_deduped():
    _require_rc4()
    assert _normalize(["custom,rc4", "tls"]) == ["tls", "rc4"]


def test_exclusive_combines_with_custom_cipher():
    _require_rc4()
    assert _normalize(["ssh,rc4"]) == ["ssh", "rc4"]
    assert _normalize(["custom", "ssh"]) == ["ssh", "rc4"]


def test_exclusive_still_rejects_non_custom_protocol():
    _require_rc4()
    with pytest.raises(SystemExit):
        _normalize(["ssh,tls,rc4"])


@pytest.mark.parametrize("meta", ["all", "auto"])
def test_custom_rejects_meta(meta):
    _require_rc4()
    with pytest.raises(SystemExit):
        _normalize([f"custom,{meta}"])


def test_custom_without_ciphers_errors(monkeypatch):
    from friTap.protocols import registry
    monkeypatch.setattr(registry, "custom_cipher_handlers", lambda **_: [])
    with pytest.raises(SystemExit):
        _normalize(["custom"])


class _Cipher:
    def __init__(self, name, upcoming=False):
        self.name = name
        self.category = "custom_cipher"
        self.upcoming = upcoming


def test_custom_skips_upcoming_but_explicit_name_works(monkeypatch):
    from friTap.protocols import registry
    monkeypatch.setattr(
        registry, "custom_cipher_handlers",
        lambda **_: [_Cipher("aes", upcoming=True), _Cipher("rc4")],
    )
    names = ["tls", "ssh", "aes", "rc4"]
    parser = _parser()
    assert _normalize_protocol_selection(["tls,custom"], parser, names) == ["tls", "rc4"]
    # Explicitly named upcoming cipher is accepted and still a custom cipher
    # (ordered last, combinable with an exclusive protocol).
    assert _normalize_protocol_selection(["aes,ssh"], parser, names) == ["ssh", "aes"]


def test_custom_only_upcoming_ciphers_errors(monkeypatch):
    from friTap.protocols import registry
    monkeypatch.setattr(
        registry, "custom_cipher_handlers", lambda **_: [_Cipher("aes", upcoming=True)]
    )
    with pytest.raises(SystemExit):
        _normalize_protocol_selection(["custom"], _parser(), ["tls", "aes"])


# ---------------------------------------------------------------------------
# Config: canonical list + backward-compat primary
# ---------------------------------------------------------------------------

def test_config_default_exposes_both():
    from friTap.config import FriTapConfig
    cfg = FriTapConfig(target="app")
    assert cfg.protocols == ["tls"]
    assert cfg.protocol == "tls"  # primary


def test_config_multiselect_primary_is_first():
    from friTap.config import FriTapConfig
    companion = _combinable_companion()
    if companion is None:
        pytest.skip("build ships no combinable companion protocol")
    cfg = FriTapConfig(target="app", protocols=["tls", companion])
    assert cfg.protocols == ["tls", companion]
    assert cfg.protocol == "tls"  # primary == first selected


def test_config_legacy_single_protocol_threads_to_list():
    from friTap.config import FriTapConfig
    cfg = FriTapConfig.from_legacy_params(app="x", protocol="ssh")
    assert cfg.protocol == "ssh"
    assert cfg.protocols == ["ssh"]


def test_config_legacy_multiselect_threads_both():
    from friTap.config import FriTapConfig
    companion = _combinable_companion()
    if companion is None:
        pytest.skip("build ships no combinable companion protocol")
    cfg = FriTapConfig.from_legacy_params(app="x", protocols=["tls", companion])
    assert cfg.protocols == ["tls", companion]
    assert cfg.protocol == "tls"


# ---------------------------------------------------------------------------
# Output: keylog-formatter union across the selection
# ---------------------------------------------------------------------------

def test_formatter_union_includes_both_selected():
    from friTap.protocols.registry import create_default_registry
    from friTap.output.factory import _active_keylog_formatters
    companion = _combinable_companion()
    if companion is None:
        pytest.skip("build ships no combinable companion protocol")
    registry = create_default_registry(["tls", companion])
    protos = {f.protocol for f in _active_keylog_formatters(["tls", companion], registry)}
    # tls is always present; the companion contributes its own formatter (and any
    # TLS-wrapped companion also implies tls, which de-dups to a single tls file).
    assert "tls" in protos


def test_formatter_single_tls_path_unchanged():
    from friTap.protocols.registry import create_default_registry
    from friTap.output.factory import _active_keylog_formatters
    registry = create_default_registry(["tls"])
    # A plain string and a one-element list must both resolve to exactly the TLS
    # formatter — the single-protocol path is unchanged.
    assert [f.protocol for f in _active_keylog_formatters("tls", registry)] == ["tls"]
    assert [f.protocol for f in _active_keylog_formatters(["tls"], registry)] == ["tls"]
