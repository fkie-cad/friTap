#!/usr/bin/env python3

"""The MessageRouter turns IPsec agent messages into structured KeylogEvents.

``ipsec_ike_keys`` and ``ipsec_esp_keys`` (the agent -> host contract) each
become ONE ``KeylogEvent(protocol="ipsec")`` carrying a structured payload the
:class:`~friTap.protocols.ipsec_handler.IPsecKeylogFormatter` turns into a
Wireshark UAT row. SPIs and keys are forwarded verbatim (lowercase hex, on-wire
byte order — no byte-swap). ``--protocol ipsec`` is also accepted by the CLI.
"""

from __future__ import annotations

import argparse

import pytest

from friTap.events import KeylogEvent
from friTap.friTap import _normalize_protocol_selection
from friTap.message_router import MessageRouter
from friTap.protocols.registry import available_protocol_names


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _route(payload: dict) -> KeylogEvent:
    bus = _Bus()
    MessageRouter(bus, active_protocol=["ipsec"]).route(payload, b"")
    assert len(bus.events) == 1
    event = bus.events[0]
    assert isinstance(event, KeylogEvent)
    assert event.protocol == "ipsec"
    return event


def test_ike_message_becomes_structured_event():
    event = _route({
        "contentType": "ipsec_ike_keys", "protocol": "ipsec", "ike_version": 2,
        "spi_i": "1111111111111111", "spi_r": "2222222222222222",
        "enc_alg": 12, "enc_key_len_bits": 256, "int_alg": 12,
        "keys": {
            "sk_ei": "aa" * 16, "sk_er": "bb" * 16,
            "sk_ai": "cc" * 16, "sk_ar": "dd" * 16,
            "sk_d": "ee" * 16,
        },
    })
    p = event.payload
    assert p["record"] == "ike"
    assert p["spi_i"] == "1111111111111111" and p["spi_r"] == "2222222222222222"
    assert p["enc_alg"] == 12 and p["enc_key_len_bits"] == 256 and p["int_alg"] == 12
    assert p["sk_ei"] == "aa" * 16 and p["sk_er"] == "bb" * 16
    assert p["sk_ai"] == "cc" * 16 and p["sk_ar"] == "dd" * 16
    assert p["sk_d"] == "ee" * 16


def test_esp_message_becomes_structured_event():
    event = _route({
        "contentType": "ipsec_esp_keys", "protocol": "ipsec",
        "spi": "0a0b0c0d", "src": "10.0.0.1", "dst": "10.0.0.2", "family": "IPv4",
        "enc_alg": 12, "int_alg": 12, "enc_key": "11" * 16, "int_key": "22" * 16,
    })
    p = event.payload
    assert p["record"] == "esp"
    assert p["spi"] == "0a0b0c0d"
    assert p["src"] == "10.0.0.1" and p["dst"] == "10.0.0.2" and p["family"] == "IPv4"
    assert p["enc_alg"] == 12 and p["int_alg"] == 12
    assert p["enc_key"] == "11" * 16 and p["int_key"] == "22" * 16


def test_esp_message_defaults_missing_endpoints_to_wildcard():
    event = _route({
        "contentType": "ipsec_esp_keys", "protocol": "ipsec",
        "spi": "deadbeef", "enc_alg": 20, "enc_key": "33" * 16,
    })
    p = event.payload
    assert p["src"] == "*" and p["dst"] == "*" and p["family"] == "IPv4"
    assert p["int_key"] == ""


def test_protocol_ipsec_is_accepted_by_cli():
    assert "ipsec" in available_protocol_names()
    parser = argparse.ArgumentParser(prog="fritap")
    assert _normalize_protocol_selection(["ipsec"], parser, available_protocol_names()) \
        == ["ipsec"]


def test_protocol_ipsec_is_exclusive():
    parser = argparse.ArgumentParser(prog="fritap")
    with pytest.raises(SystemExit):
        _normalize_protocol_selection(["ipsec,tls"], parser, available_protocol_names())
