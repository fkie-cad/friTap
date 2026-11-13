"""Pure transport-vs-originator attribution model (friTap/flow/attribution.py)."""

from __future__ import annotations

import itertools
from types import SimpleNamespace

from friTap.caller_stack_shapes import COMPACT_TEXT_LIMIT
from friTap.flow.attribution import (
    BUCKETS,
    CHROMIUM_FAMILY_KINDS,
    CONFIDENCE,
    KIND_PATTERN,
    KINDS,
    SOURCES,
    SYNCHRONOUS_KINDS,
    direct_attribution,
    flow_originator,
    flow_transport_kind,
    inherited_attribution,
    merge_attribution,
    module_basename,
    sanitize_attribution,
    transport_attribution,
)

SDK = {"sdk": "Facebook SDK", "vendor": "Meta", "category": "social"}
OTHER_SDK = {"sdk": "AppsFlyer", "vendor": "AppsFlyer", "category": "attribution"}
GMS_CRONET_PATH = ("/data/user_de/0/com.google.android.gms/app_chimera/m/0/"
                   "dynamite/libcronet.143.0.so")


# --- enums -------------------------------------------------------------------

def test_enums_match_the_model():
    assert CONFIDENCE == {"high", "medium", "low"}
    assert SOURCES == {"java-request", "native-stack", "connection-fallback", "context"}
    assert BUCKETS == {"chromium-internal", "cache"}
    assert CHROMIUM_FAMILY_KINDS == {
        "chrome", "webview", "cronet", "gms-cronet", "httpengine", "electron", "cef"}
    assert CHROMIUM_FAMILY_KINDS < KINDS
    assert {"flutter", "libsignal", "other"} <= KINDS
    assert all(KIND_PATTERN.fullmatch(kind) for kind in KINDS)


# --- transport_attribution ---------------------------------------------------

def test_transport_empty_module_is_none():
    assert transport_attribution("") is None


def test_transport_unknown_module_is_other_by_basename():
    assert transport_attribution("/system/lib64/libssl.so") == {
        "module": "libssl.so", "kind": "other"}


def test_transport_monochrome_splits_chrome_and_webview_by_target():
    chrome = transport_attribution("libmonochrome_64.so", "", "com.android.chrome",
                                   "com.android.chrome")
    webview = transport_attribution("libmonochrome_64.so", "", "com.fritap.attributionfixture",
                                    "com.fritap.attributionfixture")
    assert chrome == {"module": "libmonochrome_64.so", "kind": "chrome"}
    assert webview == {"module": "libmonochrome_64.so", "kind": "webview"}


def test_transport_returns_a_fresh_dict_per_call():
    first = transport_attribution("libcronet.143.0.so")
    first["kind"] = "mutated"
    assert transport_attribution("libcronet.143.0.so")["kind"] == "cronet"


def test_transport_gms_cronet_by_path():
    assert transport_attribution("libcronet.143.0.so", GMS_CRONET_PATH)["kind"] == "gms-cronet"
    assert transport_attribution("libcronet.143.0.so")["kind"] == "cronet"


def test_module_basename_handles_both_separators():
    assert module_basename("C:\\Windows\\chrome.dll") == "chrome.dll"
    assert module_basename("/a/b/libssl.so") == "libssl.so"
    assert module_basename("") == ""


# --- direct / inherited ------------------------------------------------------

def test_direct_is_high_only_on_synchronous_kinds():
    assert SYNCHRONOUS_KINDS == {"libsignal"}
    assert SYNCHRONOUS_KINDS <= KINDS
    assert not SYNCHRONOUS_KINDS & CHROMIUM_FAMILY_KINDS
    assert direct_attribution(SDK, "libsignal") == {
        "originator": SDK, "source": "native-stack", "confidence": "high"}
    assert direct_attribution(SDK, "webview")["confidence"] == "medium"


def test_direct_unknown_kinds_are_medium_not_high():
    for kind in ("", "other", "flutter", "good-kind", "my-overlay-kind", "LIBSIGNAL"):
        assert direct_attribution(SDK, kind)["confidence"] == "medium", kind


def test_direct_copies_the_sdk():
    claim = direct_attribution(SDK, "other")
    claim["originator"]["sdk"] = "changed"
    assert SDK["sdk"] == "Facebook SDK"


def test_inherited_is_low_connection_fallback():
    assert inherited_attribution(SDK) == {
        "originator": SDK, "source": "connection-fallback", "confidence": "low"}


def test_property_inherited_and_fallback_never_high():
    """Across every transport kind, direct/inherited path and merge order, an
    inherited claim -- and any connection-fallback claim -- is never high."""
    kinds = sorted(KINDS) + [""]
    for kind, direct_first in itertools.product(kinds, (True, False)):
        inherited = inherited_attribution(SDK)
        assert inherited["confidence"] != "high"
        direct = direct_attribution(SDK, kind)
        assert direct["source"] == "native-stack"
        assert direct["confidence"] == (
            "high" if kind in SYNCHRONOUS_KINDS else "medium")
        base = {"transport": {"module": "m", "kind": kind or "other"}}
        order = (direct, inherited) if direct_first else (inherited, direct)
        merged = merge_attribution(merge_attribution(base, order[0]), order[1])
        if merged["source"] == "connection-fallback":
            assert merged["confidence"] == "low"
    claims = [direct_attribution(SDK, kind) for kind in kinds]
    claims += [inherited_attribution(sdk) for sdk in (SDK, OTHER_SDK, {})]
    assert {claim["source"] for claim in claims} <= SOURCES
    for claim in claims:
        if claim["source"] == "connection-fallback":
            assert claim["confidence"] == "low"


# --- merge -------------------------------------------------------------------

def test_merge_keeps_existing_transport_and_originator():
    existing = {"transport": {"module": "a.so", "kind": "other"},
                **direct_attribution(SDK, "other")}
    update = {"transport": {"module": "b.so", "kind": "cronet"},
              **inherited_attribution(OTHER_SDK)}
    merged = merge_attribution(existing, update)
    assert merged == existing
    assert merged is not existing


def test_merge_fills_missing_fields_and_mixed_only_turns_on():
    merged = merge_attribution(None, {"transport": {"module": "a.so", "kind": "other"}})
    merged = merge_attribution(merged, inherited_attribution(SDK))
    assert merged["originator"] == SDK and merged["confidence"] == "low"
    merged = merge_attribution(merged, {"mixed": True})
    assert merge_attribution(merged, {"mixed": False})["mixed"] is True


# --- sanitize ----------------------------------------------------------------

def test_sanitize_round_trips_a_valid_value():
    value = {"transport": {"module": "libssl.so", "kind": "other"},
             **direct_attribution(SDK, "other"), "bucket": "cache", "mixed": True}
    assert sanitize_attribution(value) == value


def test_sanitize_rebounds_a_hostile_value():
    hostile = {
        "transport": {"module": "x" * 500, "kind": "Evil Kind!", "extra": 1},
        "originator": {"sdk": "y" * 500, "vendor": 7, "category": ["a"], "x": "z"},
        "confidence": "certain",
        "source": ["native-stack"],
        "bucket": "cache",
        "mixed": "true",
        "injected": {"a": 1},
    }
    assert sanitize_attribution(hostile) == {
        "transport": {"module": "x" * COMPACT_TEXT_LIMIT},
        "originator": {"sdk": "y" * COMPACT_TEXT_LIMIT},
        "bucket": "cache",
    }


def test_sanitize_returns_none_when_nothing_survives():
    assert sanitize_attribution(None) is None
    assert sanitize_attribution("text") is None
    assert sanitize_attribution({}) is None
    assert sanitize_attribution({"mixed": False, "confidence": "x",
                                 "transport": {"kind": "No Pe"}}) is None


def test_sanitize_drops_an_originator_without_an_sdk_name():
    for originator in ({"vendor": "Meta", "category": "social"},
                       {"sdk": "", "vendor": "Meta"}, {"sdk": "   "},
                       {"sdk": 7, "vendor": "Meta"}):
        clean = sanitize_attribution({"transport": {"module": "m.so", "kind": "other"},
                                      "originator": originator, "confidence": "high"})
        assert "originator" not in clean, originator
        assert clean["transport"] == {"module": "m.so", "kind": "other"}


def test_sanitize_escapes_ansi_in_module_and_sdk_fields():
    value = {"transport": {"module": "lib\x1b[31mevil.so", "kind": "other"},
             "originator": {"sdk": "\x1b]0;title\x07SDK", "vendor": "V\x9bX"}}
    clean = sanitize_attribution(value)
    assert clean["transport"]["module"] == "lib\\x1b[31mevil.so"
    assert clean["originator"]["sdk"] == "\\x1b]0;title\\x07SDK"
    assert clean["originator"]["vendor"] == "V\\x9bX"
    assert "\x1b" not in repr(clean).replace("\\x1b", "")
    assert sanitize_attribution(clean) == clean  # escaping is idempotent


def test_sanitize_keeps_overlay_slug_kinds_and_drops_non_slugs():
    def kind_of(kind):
        clean = sanitize_attribution({"transport": {"module": "m.so", "kind": kind}})
        return clean["transport"].get("kind")

    assert kind_of("foo-bar") == "foo-bar"
    assert kind_of("cronet") == "cronet"
    for bad in ("Bad Kind!", "-lead", "", "a" * 33, "foo\n", "UPPER", 7):
        assert kind_of(bad) is None, bad


# --- readers -----------------------------------------------------------------

def test_flow_originator_prefers_attribution_originator():
    flow = SimpleNamespace(attribution={"originator": SDK}, sdk=OTHER_SDK)
    assert flow_originator(flow) is SDK


def test_flow_originator_falls_back_to_flow_sdk():
    assert flow_originator(SimpleNamespace(attribution=None, sdk=OTHER_SDK)) is OTHER_SDK
    assert flow_originator(SimpleNamespace(attribution={"originator": "x"},
                                           sdk=OTHER_SDK)) is OTHER_SDK
    assert flow_originator(SimpleNamespace(attribution=["junk"], sdk=None)) is None
    assert flow_originator(SimpleNamespace()) is None


def test_flow_originator_ignores_a_nameless_originator():
    for originator in ({}, {"sdk": ""}, {"sdk": "  "}, {"sdk": None, "vendor": "V"},
                       {"sdk": 7}, {"vendor": "Meta", "category": "social"}):
        flow = SimpleNamespace(attribution={"originator": originator}, sdk=OTHER_SDK)
        assert flow_originator(flow) is OTHER_SDK, originator


def test_flow_transport_kind_reads_a_non_empty_string_only():
    def flow(attribution):
        return SimpleNamespace(attribution=attribution)

    assert flow_transport_kind(flow({"transport": {"kind": "cronet"}})) == "cronet"
    assert flow_transport_kind(flow({"transport": {"kind": ""}})) is None
    assert flow_transport_kind(flow({"transport": {"kind": 3}})) is None
    assert flow_transport_kind(flow({"transport": "cronet"})) is None
    assert flow_transport_kind(flow(None)) is None
    assert flow_transport_kind(SimpleNamespace()) is None


# --- claim precedence --------------------------------------------------------

def _java(sdk, confidence="high"):
    from friTap.flow.attribution import request_attribution
    return request_attribution(sdk, confidence, "java-request")


def test_claim_rank_is_confidence_first_then_source():
    from friTap.flow.attribution import claim_rank, request_attribution
    ordered = [
        inherited_attribution(SDK),                           # low / fallback
        direct_attribution(SDK, "cronet"),                    # medium / native-stack
        request_attribution(SDK, "medium", "context"),        # medium / context
        _java(SDK, "medium"),                                 # medium / java-request
        direct_attribution(SDK, "libsignal"),                 # high / native-stack
        _java(SDK, "high"),                                   # high / java-request
    ]
    ranks = [claim_rank(claim) for claim in ordered]
    assert ranks == sorted(ranks) and len(set(ranks)) == len(ranks)
    assert claim_rank(None) == claim_rank({}) == (0, 0)


def test_merge_stronger_java_request_replaces_native_stack_and_fallback():
    for weaker in (direct_attribution(OTHER_SDK, "cronet"), inherited_attribution(OTHER_SDK)):
        existing = {"transport": {"module": "libcronet.so", "kind": "cronet"}, **weaker}
        merged = merge_attribution(existing, _java(SDK))
        assert merged["originator"] == SDK
        assert (merged["source"], merged["confidence"]) == ("java-request", "high")
        assert merged["transport"] == existing["transport"]


def test_merge_equal_or_weaker_claim_never_replaces():
    existing = _java(SDK, "high")
    for update in (_java(OTHER_SDK, "high"), _java(OTHER_SDK, "medium"),
                   direct_attribution(OTHER_SDK, "libsignal"),
                   inherited_attribution(OTHER_SDK)):
        assert merge_attribution(existing, update) == existing


def test_request_attribution_validates_and_caps_context_at_medium():
    import pytest

    from friTap.flow.attribution import request_attribution
    assert request_attribution(SDK, "high", "context")["confidence"] == "medium"
    with pytest.raises(ValueError):
        request_attribution(SDK, "high", "native-stack")
    with pytest.raises(ValueError):
        request_attribution(SDK, "certain", "java-request")
    claim = request_attribution(SDK, "high", "java-request")
    assert claim["originator"] == SDK and claim["originator"] is not SDK
