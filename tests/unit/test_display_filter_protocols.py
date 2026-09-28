"""Tests for the display-filter protocol vocabulary (friTap.filter.protocols)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from friTap.filter.protocols import (
    PROTOCOL_ALIASES,
    aliases_for,
    canonical_protocols,
    flow_has_ohttp,
    flow_has_protocol,
    known_protocol_names,
    normalize_labels,
    normalize_protocol,
    protocol_labels,
    protocol_members,
    protocol_prefix_matches,
    split_layered_label,
)
from friTap.flow import layer_registry
from friTap.flow.layers import (
    AppLayer,
    MtprotoLayer,
    ProtocolLayer,
    SignalLayer,
    TelegramE2ELayer,
)
from friTap.flow.models import Flow, FlowSummary
from friTap.parsers.base import ParseResult


# -- normalize_protocol -------------------------------------------------------

@pytest.mark.parametrize("label, expected", [
    ("HTTP/1.1", "http1"),
    ("HTTP/1.0", "http1"),
    ("HTTP/1.x", "http1"),
    ("http1.1", "http1"),
    ("HTTP/2", "http2"),
    ("HTTP/3", "http3"),
    ("WebSocket", "websocket"),
    ("Signal", "signal"),
    ("MTProto", "mtproto"),
    ("Telegram-E2E", "telegram_e2e"),
    ("telegram_e2e", "telegram_e2e"),
    ("telegram", "mtproto"),
    ("SSH", "ssh"),
    ("ipsec", "ipsec"),
    ("TLS", "tls"),
    ("quic", "quic"),
    ("quic_unprocessed", "quic"),
    ("RC4", "rc4"),
    ("bhttp", "bhttp"),
    ("ohttp", "ohttp"),
    ("  HTTP/2  ", "http2"),
    ("MyPluginProto", "mypluginproto"),
    ("", None),
    ("unknown", None),
    ("UNKNOWN", None),
    (None, None),
])
def test_normalize_protocol(label, expected):
    assert normalize_protocol(label) == expected


def test_normalize_protocol_covers_every_layer_display_name():
    from friTap.constants import LAYER_DISPLAY_NAMES

    for name, display in LAYER_DISPLAY_NAMES.items():
        assert normalize_protocol(display) == name
        assert normalize_protocol(name) == name


# -- split_layered_label ------------------------------------------------------

@pytest.mark.parametrize("label, expected", [
    ("HTTP/2[Signal]", ["HTTP/2", "Signal"]),
    ("MTProto[Telegram-E2E]", ["MTProto", "Telegram-E2E"]),
    ("WebSocket[Signal]", ["WebSocket", "Signal"]),
    ("HTTP/1.x", ["HTTP/1.x"]),
    ("", []),
    (None, []),
])
def test_split_layered_label(label, expected):
    assert split_layered_label(label) == expected


# -- canonical_protocols: real Flow / FlowSummary ------------------------------

def _telegram_secret_chat_flow() -> Flow:
    flow = Flow(flow_id="tg1", connection_id="c1", transport="tcp")
    flow.add_layer(MtprotoLayer(transport="intermediate", dc_id=2))
    flow.add_layer(TelegramE2ELayer())
    return flow


def _signal_over_http2_flow() -> Flow:
    flow = Flow(flow_id="sig1", connection_id="c2", ssl_session_id="abcd")
    flow.request = ParseResult(protocol="HTTP/2", method="PUT")
    http2 = AppLayer()
    http2._name = "http2"
    flow.add_layer(http2)
    flow.add_layer(SignalLayer())
    return flow


def test_canonical_protocols_telegram_flow():
    protos = canonical_protocols(_telegram_secret_chat_flow())
    assert {"mtproto", "telegram_e2e", "tcp"} <= protos
    assert "tls" not in protos


def test_canonical_protocols_telegram_summary_matches_flow():
    flow = _telegram_secret_chat_flow()
    summary = FlowSummary.from_flow(flow)
    assert summary.display_protocol_layered == "MTProto[Telegram-E2E]"
    assert {"mtproto", "telegram_e2e", "tcp"} <= canonical_protocols(summary)


def test_canonical_protocols_signal_flow_and_summary():
    flow = _signal_over_http2_flow()
    for obj in (flow, FlowSummary.from_flow(flow)):
        protos = canonical_protocols(obj)
        assert {"http2", "signal", "tls"} <= protos, type(obj).__name__


def test_canonical_protocols_does_not_grow_flow_layer_stack():
    flow = _telegram_secret_chat_flow()
    before = [layer.name for layer in flow.layers]
    canonical_protocols(flow)
    assert [layer.name for layer in flow.layers] == before


def test_canonical_protocols_replay_style_row():
    row = SimpleNamespace(
        outer_app_protocol="HTTP/2",
        inner_e2e_protocol="Signal",
        transport="quic",
    )
    assert canonical_protocols(row) == frozenset({"http2", "signal", "quic"})


def test_canonical_protocols_ohttp_and_bhttp():
    assert "ohttp" in canonical_protocols(SimpleNamespace(has_ohttp=True))
    flow = Flow()
    flow.ohttp_inner_request = ParseResult(protocol="bhttp")
    assert "ohttp" in canonical_protocols(flow)
    bhttp_only = SimpleNamespace(detected_protocol="bhttp")
    assert canonical_protocols(bhttp_only) == frozenset({"bhttp", "ohttp"})


def test_canonical_protocols_includes_precomputed_set():
    row = SimpleNamespace(protocols=frozenset({"myproto"}))
    assert canonical_protocols(row) == frozenset({"myproto"})


def test_canonical_protocols_never_raises():
    class Exploding:
        @property
        def transport(self):
            raise RuntimeError("boom")

    assert canonical_protocols(Exploding()) == frozenset()
    assert canonical_protocols(None) == frozenset()
    assert canonical_protocols(object()) == frozenset()


# -- aliases / membership ------------------------------------------------------

def test_protocol_aliases():
    assert PROTOCOL_ALIASES["telegram"] == {"mtproto", "telegram_e2e"}
    assert PROTOCOL_ALIASES["tg"] == {"mtproto", "telegram_e2e"}
    assert PROTOCOL_ALIASES["e2e"] == {"telegram_e2e"}
    assert PROTOCOL_ALIASES["secretchat"] == {"telegram_e2e"}
    assert PROTOCOL_ALIASES["ws"] == {"websocket"}
    assert PROTOCOL_ALIASES["http"] == {"http1", "http2", "http3"}


def test_protocol_members():
    assert protocol_members("TELEGRAM") == {"mtproto", "telegram_e2e"}
    assert protocol_members("signal") == {"signal"}
    assert protocol_members("HTTP/2") == {"http2"}
    assert protocol_members("ohttp") == {"ohttp"}
    assert protocol_members("nonsense") is None
    assert protocol_members("") is None
    assert protocol_members(None) is None


def test_flow_has_protocol():
    flow = _telegram_secret_chat_flow()
    assert flow_has_protocol(flow, "telegram")
    assert flow_has_protocol(flow, "E2E")
    assert flow_has_protocol(flow, "mtproto")
    assert not flow_has_protocol(flow, "signal")
    assert not flow_has_protocol(flow, "http")
    assert not flow_has_protocol(flow, "nonsense")
    assert flow_has_protocol(_signal_over_http2_flow(), "http")


# -- known names / prefix matches ---------------------------------------------

def test_known_protocol_names_include_registry_aliases_and_extras():
    names = known_protocol_names()
    assert names == sorted(names)
    assert set(layer_registry.get_registry().names()) <= set(names)
    assert set(PROTOCOL_ALIASES) <= set(names)
    assert {"ohttp", "bhttp", "tcp", "udp", "tls", "quic"} <= set(names)


def test_known_protocol_names_picks_up_late_registrations():
    class _PluginLayer(ProtocolLayer):
        NAME = "zzplugin"

    registry = layer_registry.get_registry()
    registry.register(layer_registry.ProtocolDescriptor("zzplugin", _PluginLayer))
    try:
        assert "zzplugin" in known_protocol_names()
        assert protocol_members("ZZPLUGIN") == {"zzplugin"}
    finally:
        registry._descriptors.pop("zzplugin", None)
    assert "zzplugin" not in known_protocol_names()


def test_protocol_prefix_matches():
    tele = protocol_prefix_matches("TELE")
    assert "telegram" in tele
    assert all(name.startswith("tele") for name in tele)
    assert protocol_prefix_matches("sig") == ["signal"]
    assert protocol_prefix_matches("signal") == []
    assert protocol_prefix_matches("") == []
    assert protocol_prefix_matches(None) == []


# -- public helpers used by the replay path ------------------------------------

def test_normalize_labels_splits_layered_and_drops_empty():
    assert normalize_labels(["HTTP/2[Signal]", "", "unknown", None, "telegram"]) == {
        "http2", "signal", "mtproto"}


def test_unknown_versioned_http_label_maps_via_parser_mapping():
    assert normalize_protocol("HTTP/1.1") == "http1"
    assert normalize_protocol("http/1.0") == "http1"
    assert normalize_protocol("Quic_Unprocessed") == "quic"
    assert normalize_protocol("myproto") == "myproto"


def test_flow_has_ohttp():
    assert flow_has_ohttp(SimpleNamespace(has_ohttp=True))
    assert flow_has_ohttp(SimpleNamespace(ohttp_inner_request=object()))
    assert not flow_has_ohttp(SimpleNamespace())


def test_aliases_for_is_sorted_and_shared_with_protocol_labels():
    assert aliases_for({"telegram_e2e"}) == ("e2e", "secretchat", "telegram", "tg")
    assert aliases_for({"http2", "websocket"}) == ("http", "ws")
    assert aliases_for(()) == ()
    assert protocol_labels("telegram_e2e")[1:] == aliases_for({"telegram_e2e"})
