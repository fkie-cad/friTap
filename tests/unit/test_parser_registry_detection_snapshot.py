"""Snapshot of default-registry parser selection per transport.

The expected table was generated against the registry BEFORE transport pins
and restrictions became declarative parser-class attributes; it guards that
refactor (same pin winners, restriction sets, priority order, fallback).
"""

import pytest

from friTap.parsers import registry as registry_mod

SAMPLES = {
    "http1_request": b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "h2_preface": b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    "websocket_frame": b"\x81\x05hello",
    "random_bytes": bytes(range(7, 71, 3)),
    "empty": b"",
}

_SNIFFED = {
    "http1_request": "Http1Parser",
    "h2_preface": "Http2Parser",
    "websocket_frame": "WebSocketParser",
    "random_bytes": "Http3Parser",
    "empty": "HexdumpParser",
}
_QUIC = {
    "http1_request": "HexdumpParser",
    "h2_preface": "HexdumpParser",
    "websocket_frame": "HexdumpParser",
    "random_bytes": "Http3Parser",
    "empty": "HexdumpParser",
}

EXPECTED = {
    None: _SNIFFED,
    "tls": _SNIFFED,
    "quic": _QUIC,
    "mtproto": dict.fromkeys(SAMPLES, "MtprotoParser"),
    "telegram_e2e": dict.fromkeys(SAMPLES, "TelegramE2EParser"),
    "signal": _SNIFFED,
    "rc4": _SNIFFED,
    "ssh": _SNIFFED,
}

EXPECTED_PRIORITIES = [
    (100, "Http1Parser"), (90, "Http2Parser"), (85, "WebSocketParser"),
    (80, "Http3Parser"), (0, "HexdumpParser"),
]

EXPECTED_RULES = {
    "telegram_e2e": ("TelegramE2EParser", None),
    "mtproto": ("MtprotoParser", None),
    "quic": (None, ["Http3Parser"]),
}


@pytest.fixture
def fresh_registry(monkeypatch):
    """A newly built default registry with ambient discovery disabled."""
    monkeypatch.setenv("FRITAP_DISABLE_PARSER_DISCOVERY", "1")
    monkeypatch.setattr(registry_mod, "_default_registry", None)
    return registry_mod.get_default_registry()


@pytest.mark.parametrize("transport", list(EXPECTED))
def test_detect_snapshot_per_transport(fresh_registry, transport):
    got = {
        name: type(fresh_registry.detect(data, transport=transport)).__name__
        for name, data in SAMPLES.items()
    }
    assert got == EXPECTED[transport]


def test_priority_order_snapshot(fresh_registry):
    got = [(prio, cls.__name__) for prio, cls in fresh_registry._parsers]
    assert got == EXPECTED_PRIORITIES


def test_transport_rules_snapshot(fresh_registry):
    for transport in EXPECTED:  # resolve lazy pins
        fresh_registry.pinned_parser_for(transport)
    got = {
        transport: (
            rule.pinned and rule.pinned.__name__,
            rule.allowed and sorted(cls.__name__ for cls in rule.allowed),
        )
        for transport, rule in fresh_registry._rules.items()
    }
    assert got == EXPECTED_RULES
