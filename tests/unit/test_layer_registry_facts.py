"""Protocol facts derived from the layer registry equal their old literals."""

from __future__ import annotations

from friTap.flow import display, layer_pipeline, layer_registry
from friTap.flow.layer_registry import (
    ProtocolDescriptor,
    ProtocolRegistry,
    _register_builtins,
    carrier_for_inner,
    inner_e2e_layer_names,
    message_transport_names,
)
from friTap.flow.layers import ProtocolLayer

# The literals these constants held before they were derived.
OLD_MESSAGE_TRANSPORTS = frozenset({"mtproto", "telegram_e2e"})
OLD_INNER_E2E_LAYER_NAMES = ("signal", "mtproto", "telegram_e2e", "rc4")
OLD_CARRIER_FOR_INNER = {"telegram_e2e": "mtproto", "rc4": "tls"}
OLD_TELEGRAM_LAYER_NAMES = ("mtproto", "telegram_e2e")


class _PluginLayer(ProtocolLayer):
    NAME = "zzmsg"


def _builtin_registry() -> ProtocolRegistry:
    registry = ProtocolRegistry()
    _register_builtins(registry)
    return registry


def test_message_transports_equal_old_literal():
    assert type(layer_pipeline.MESSAGE_TRANSPORTS) is frozenset
    assert layer_pipeline.MESSAGE_TRANSPORTS == OLD_MESSAGE_TRANSPORTS
    assert layer_pipeline._NON_HTTP_E2E_TRANSPORTS is layer_pipeline.MESSAGE_TRANSPORTS


def test_inner_e2e_layer_names_keep_order_and_type():
    assert type(display.INNER_E2E_LAYER_NAMES) is tuple
    assert display.INNER_E2E_LAYER_NAMES == OLD_INNER_E2E_LAYER_NAMES


def test_carrier_for_inner_equals_old_literal():
    assert type(display._CARRIER_FOR_INNER) is dict
    assert list(display._CARRIER_FOR_INNER.items()) == list(OLD_CARRIER_FOR_INNER.items())


def test_telegram_layer_names_keep_order_and_type():
    assert type(display.TELEGRAM_LAYER_NAMES) is tuple
    assert display.TELEGRAM_LAYER_NAMES == OLD_TELEGRAM_LAYER_NAMES
    assert display._METHOD_LAYER_NAMES == OLD_TELEGRAM_LAYER_NAMES


def test_default_registry_derivations_match_builtins():
    assert message_transport_names() == OLD_TELEGRAM_LAYER_NAMES
    assert inner_e2e_layer_names() == OLD_INNER_E2E_LAYER_NAMES
    assert carrier_for_inner() == OLD_CARRIER_FOR_INNER


def test_third_party_message_transport_is_derived():
    registry = _builtin_registry()
    registry.register(ProtocolDescriptor(
        "zzmsg", _PluginLayer, data_source="chunks", is_message_transport=True,
        inner_e2e_rank=100, carrier="tls",
    ))
    assert message_transport_names(registry) == ("mtproto", "telegram_e2e", "zzmsg")
    assert inner_e2e_layer_names(registry)[-1] == "zzmsg"
    assert carrier_for_inner(registry)["zzmsg"] == "tls"
    # The process-global registry is untouched.
    assert layer_registry.get("zzmsg") is None


def test_inner_e2e_rank_ties_keep_registration_order():
    registry = ProtocolRegistry()
    for name in ("b", "a"):
        layer = type(f"_{name}", (ProtocolLayer,), {"NAME": name})
        registry.register(ProtocolDescriptor(name, layer, inner_e2e_rank=100))
    assert inner_e2e_layer_names(registry) == ("b", "a")


def test_descriptor_defaults_carry_no_facts():
    desc = ProtocolDescriptor("zzmsg", _PluginLayer)
    assert (desc.is_message_transport, desc.inner_e2e_rank, desc.carrier) == (
        False, None, None)
