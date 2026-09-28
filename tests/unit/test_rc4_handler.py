#!/usr/bin/env python3

"""Tests for the RC4 protocol handler and its registration.

RC4 is a first-class, INDEPENDENT protocol: selecting it must NOT pull in TLS
(no implication either direction), it leaves the agent path (legacy/--modern)
as the user chose it, and it is advertised in ``available_protocol_names()``.
"""

import argparse
import logging

import pytest

from friTap.protocols.registry import (
    available_protocol_names,
    create_default_registry,
    expand_protocols,
    implied_protocols,
)
from friTap.protocols.rc4_handler import RC4Handler, Rc4KeylogFormatter


def _parser():
    return argparse.ArgumentParser(prog="fritap")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_rc4_in_available_protocol_names():
    assert "rc4" in available_protocol_names()


def test_rc4_handler_registers_with_correct_identity():
    reg = create_default_registry(["rc4"])
    handler = reg.get("rc4")
    assert isinstance(handler, RC4Handler)
    assert handler.name == "rc4"
    assert handler.display_name == "RC4"


def test_rc4_keylog_formatter_targets_rc4():
    handler = RC4Handler()
    formatter = handler.keylog_formatter()
    assert isinstance(formatter, Rc4KeylogFormatter)
    assert formatter.protocol == "rc4"


# ---------------------------------------------------------------------------
# Independence from TLS — NO implication either direction
# ---------------------------------------------------------------------------

def test_rc4_does_not_imply_tls():
    assert implied_protocols("rc4") == []


def test_selecting_rc4_does_not_expand_to_tls():
    assert expand_protocols({"rc4"}) == {"rc4"}


def test_rc4_registry_has_no_tls_handler():
    # create_default_registry expands companion protocols; rc4 has none, so a
    # registry built for ["rc4"] must contain ONLY the rc4 handler.
    reg = create_default_registry(["rc4"])
    assert reg.get("rc4") is not None
    assert reg.get("tls") is None


def test_tls_and_rc4_both_present_when_both_selected():
    reg = create_default_registry(["tls", "rc4"])
    assert reg.get("tls") is not None
    assert reg.get("rc4") is not None


# ---------------------------------------------------------------------------
# CLI intent — keep the agent path as chosen; require a capture intent
# ---------------------------------------------------------------------------

def test_validate_cli_intent_keeps_legacy_agent_path():
    handler = RC4Handler()
    parsed = argparse.Namespace(
        use_modern=False, keylog=True, pcap=False, full_capture=False
    )
    handler.validate_cli_intent(parsed, _parser(), logging.getLogger("test"))
    assert parsed.use_modern is False


def test_validate_cli_intent_requires_capture_intent():
    handler = RC4Handler()
    parsed = argparse.Namespace(
        use_modern=False, keylog=False, pcap=False, full_capture=False
    )
    # argparse's .error() raises SystemExit.
    with pytest.raises(SystemExit):
        handler.validate_cli_intent(parsed, _parser(), logging.getLogger("test"))
