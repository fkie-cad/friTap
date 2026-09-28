"""Regression tests for reviewed display-filter defects.

One section per defect: headless (DataCanonical) validation and protocol
normalization, the ``http`` predicate, protocol operand normalization, the
lexer, UTF-8 ``frame matches``, unknown-field suggestions, multi-valued
existence truthiness, ``method`` sources, leading-zero ints and the
``telegram.e2e`` / ``telegram.sender`` fields. Pure Python — no device/Frida.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from friTap.filter import FilterEngine, UnknownFieldError
from friTap.filter.layer_fields import extract_filter_attrs, lookup_attr
from friTap.filter.lexer import TokenType, tokenize
from friTap.filter.fields import CANONICAL_FIELDS
from friTap.filter.pipeline_filter import (
    FilteredSink,
    build_headless_filter,
    headless_filter_error,
)
from friTap.filter.protocols import protocol_equivalents, protocol_labels
from friTap.flow.layers import MtprotoLayer
from friTap.flow.models import Flow, FlowChunk
from friTap.flow.tap_format import FlowSummary as TapFlowSummary
from friTap.parsers.base import ParseResult
from tests.unit._display_filter_helpers import FakeCtx as _Ctx
from tests.unit._display_filter_helpers import data_event as _event
from tests.unit._display_filter_helpers import http_flow as _http_flow
from tests.unit._display_filter_helpers import match as _match
from tests.unit._display_filter_helpers import summary_row as _row


def _mtproto_flow_with_parse_results() -> Flow:
    """A Telegram flow that ALSO carries request/response parse results."""
    flow = Flow(flow_id="t1", connection_id="c2", transport="mtproto")
    flow.chunks.append(FlowChunk(data=b"x", direction="read", timestamp=1.0))
    flow.add_layer(MtprotoLayer(transport="intermediate", dc_id=2))
    flow.request = ParseResult(protocol="MTProto", method="", is_request=True)
    flow.response = ParseResult(protocol="MTProto", is_request=False)
    return flow


# ---------------------------------------------------------------------------
# 1. Headless validation + protocol normalization on data events
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("expr", [
    "telegram", "mtproto", 'frame contains "x"', "http.host == a",
    "mtproto.dc_id == 2", "ip.src == 1.2.3.4 and method contains get",
])
def test_headless_filter_error_rejects_flow_only_fields(expr):
    err = headless_filter_error(expr)
    assert err is not None and "not available in headless mode" in err
    for field in FilterEngine.non_canonical_fields(expr):
        assert field in err
    assert "protocol" in err and "ip.src" in err  # names the usable fields


@pytest.mark.parametrize("expr", [
    "ip.src == 10.0.0.1", "tcp.port == 443", "protocol == telegram",
    'frame.protocol == "tls"', "not protocol == ssh",
])
def test_headless_filter_error_accepts_canonical_fields(expr):
    assert headless_filter_error(expr) is None


def test_headless_filter_error_reports_syntax_errors():
    assert headless_filter_error("ip.src ==").startswith("Invalid filter expression")


def test_non_canonical_fields_lists_offenders_sorted():
    assert FilterEngine.non_canonical_fields("telegram and http.host == a") == [
        "http.host", "telegram"]
    assert FilterEngine.non_canonical_fields("ip.src == 1.2.3.4") == []
    assert FilterEngine.non_canonical_fields("bad ===") == []
    assert FilterEngine("ip.dst == 1.2.3.4").canonical_only
    assert not FilterEngine("telegram").canonical_only


@pytest.mark.parametrize("expr, protocol, expected", [
    ("protocol == telegram", "telegram", True),
    ("protocol == telegram", "telegram_e2e", True),
    ("protocol == mtproto", "telegram", True),
    ("frame.protocol == e2e", "telegram_e2e", True),
    ("protocol == telegram", "tls", False),
    ("protocol != telegram", "tls", True),
    ("protocol != telegram", "telegram", False),
    ('protocol == "TLS"', "tls", True),
])
def test_headless_protocol_is_normalized(expr, protocol, expected):
    assert FilterEngine(expr).matches_canonical(_event(protocol)) is expected


def test_headless_filtered_sink_keeps_telegram_events():
    received = []
    sink = FilteredSink(SimpleNamespace(on_data=received.append),
                        FilterEngine("protocol == telegram"))
    for proto in ("telegram", "tls", "telegram_e2e"):
        sink.on_data(_event(proto))
    assert [e.protocol for e in received] == ["telegram", "telegram_e2e"]


def test_protocol_labels_expand_raw_event_label():
    assert protocol_labels("telegram_e2e")[0] == "telegram_e2e"
    assert protocol_labels("HTTP/1.1")[:2] == ("HTTP/1.1", "http1")
    assert {"telegram", "tg", "e2e"} <= set(protocol_labels("telegram_e2e"))
    assert protocol_labels("") == () and protocol_labels(None) == ()


def test_build_headless_filter_parses_once_into_engine_or_error():
    assert isinstance(build_headless_filter("ip.src == 1.2.3.4"), FilterEngine)
    assert build_headless_filter("ip.src ==").startswith("Invalid filter expression")
    err = build_headless_filter("telegram")
    assert isinstance(err, str) and "not available in headless mode: telegram" in err


def test_headless_hint_lists_every_canonical_field():
    err = headless_filter_error("telegram")
    assert all(name in err for name in CANONICAL_FIELDS)


@pytest.mark.parametrize("expr, installed", [
    ("ip.src == 1.2.3.4", True),
    ("protocol == telegram", True),
    ("telegram", False),        # flow-only field: would drop every data event
    ("ip.src ==", False),       # syntax error
])
def test_ssl_logger_applies_headless_policy(expr, installed):
    """API users constructing SSL_Logger directly get the CLI's headless policy."""
    from friTap.config import FriTapConfig
    from friTap.ssl_logger import SSL_Logger

    config = FriTapConfig.from_legacy_params(app="test_app", filter_expression=expr)
    router = SSL_Logger(config=config)._message_router
    assert (router._data_filter is not None) is installed


# ---------------------------------------------------------------------------
# 2. ``http`` predicate and tap FlowSummary without ``request``
# ---------------------------------------------------------------------------

def test_http_does_not_match_telegram_flow_with_parse_results():
    tg = _mtproto_flow_with_parse_results()
    assert not _match("http", tg)
    assert _match("http", _http_flow())
    assert _match("http", _http_flow("HTTP/2"))


def test_tap_flow_summary_http_fields_do_not_crash():
    summary = TapFlowSummary(flow_id="s1", connection_id="c1",
                             has_request=True, has_response=False,
                             protocols=frozenset({"mtproto"}))
    assert not hasattr(summary, "request")
    assert _match("http.request", summary)
    assert _match("flow.has_request", summary)
    assert not _match("http.response", summary)
    assert not _match("http", summary)
    http_summary = TapFlowSummary(flow_id="s2", connection_id="c2",
                                  protocols=frozenset({"http1"}))
    assert _match("http", http_summary)


# ---------------------------------------------------------------------------
# 3. Protocol operand normalization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("expr", [
    'frame.protocol == "HTTP/1.x"', 'protocol == "HTTP/1.0"',
    'protocol == "http/1.1"', "protocol == http1", "protocol == http",
])
def test_protocol_equality_normalizes_operand(expr):
    assert _match(expr, _http_flow("HTTP/1.1"))


def test_protocol_equality_keeps_raw_and_negation_semantics():
    layered = _row(protocols={"http2", "signal"}, outer_app_protocol="HTTP/2",
                   inner_e2e_protocol="Signal")
    assert _match('protocol == "HTTP/2[Signal]"', layered)  # raw label
    assert _match('protocol == "http/2[signal]"', layered)  # case-insensitive
    assert not _match('protocol == "HTTP/1.0"', layered)
    assert _match('protocol != "HTTP/1.0"', layered)
    assert not _match('protocol != "HTTP/1.0"', _http_flow("HTTP/1.1"))
    # contains / matches stay on raw labels + canonical names.
    assert _match('protocol contains "1.1"', _http_flow("HTTP/1.1"))
    assert not _match('protocol contains "1.0"', _http_flow("HTTP/1.1"))
    assert _match('protocol matches "^http1$"', _http_flow("HTTP/1.1"))


def test_protocol_equivalents():
    assert protocol_equivalents("HTTP/1.0") == {"http/1.0", "http1"}
    assert protocol_equivalents("telegram") >= {"telegram", "mtproto", "telegram_e2e"}
    assert protocol_equivalents("") == frozenset()


# ---------------------------------------------------------------------------
# 4. Lexer: digit-led bare words and "/" in bare words
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("0a1b2c", [(TokenType.FIELD, "0a1b2c")]),
    ("0x1f", [(TokenType.FIELD, "0x1f")]),
    ("HTTP/2", [(TokenType.FIELD, "HTTP/2")]),
    ("HTTP/1.1", [(TokenType.FIELD, "HTTP/1.1")]),
    ("443", [(TokenType.NUMBER, "443")]),
    ("3.14", [(TokenType.NUMBER, "3.14")]),
    ("-5", [(TokenType.NUMBER, "-5")]),
    ("10.0.0.1", [(TokenType.FIELD, "10.0.0.1")]),
    ("10.0.", [(TokenType.FIELD, "10.0.")]),
])
def test_lexer_value_tokens(text, expected):
    tokens = [(t.type, t.value) for t in tokenize(text)[:-1]]
    assert tokens == expected


def test_hex_id_and_unquoted_slash_values_parse_and_match():
    row = _row(attrs={"mtproto.auth_key_id": ("0a1b2c",)})
    assert _match("mtproto.auth_key_id == 0a1b2c", row)
    assert _match("protocol == HTTP/2", _http_flow("HTTP/2"))
    assert _match("protocol == HTTP/1.1 and http", _http_flow())
    assert _match("mtproto.dc_id == 0x2", _row(attrs={"mtproto.dc_id": (2,)}))


# ---------------------------------------------------------------------------
# 5. frame matches over UTF-8 content
# ---------------------------------------------------------------------------

def test_frame_matches_utf8_text():
    ctx = _Ctx("grüße aus über".encode("utf-8"))
    flow = _row()
    assert _match('frame matches "über"', flow, ctx)
    assert _match('frame matches "gr.ße"', flow, ctx)
    assert _match('frame contains "über"', flow, ctx)
    assert not _match('frame matches "ueber"', flow, ctx)


def test_frame_matches_binary_content_never_raises():
    ctx = _Ctx(b"\xff\xfe\x00abc\xc3")
    assert _match('frame matches "abc"', _row(), ctx)


# ---------------------------------------------------------------------------
# 6. Unknown-field suggestions
# ---------------------------------------------------------------------------

def test_unknown_field_followed_by_operator_suggests_field_replacements():
    with pytest.raises(UnknownFieldError) as info:
        FilterEngine("htp.host == example.com")
    err = info.value
    assert "http.host" in err.did_you_mean
    assert err.suggestions == [f"{name} == example.com" for name in err.did_you_mean]
    for suggestion in err.suggestions:
        assert "contains" not in suggestion
        assert FilterEngine.validate(suggestion) is None


def test_unknown_field_foo_eq_3_has_no_invalid_suggestion():
    with pytest.raises(UnknownFieldError) as info:
        FilterEngine("foo == 3")
    for suggestion in info.value.suggestions:
        assert FilterEngine.validate(suggestion) is None, suggestion


def test_bare_unknown_word_keeps_generic_suggestions():
    with pytest.raises(UnknownFieldError) as info:
        FilterEngine("ip.src == 1.2.3.4 and foo")
    assert info.value.suggestions[0] == 'ip.src == 1.2.3.4 and protocol contains "foo"'


# ---------------------------------------------------------------------------
# 7. Multi-valued existence uses truthiness
# ---------------------------------------------------------------------------

def test_bool_layer_field_existence_requires_true():
    plain = {"name": "mtproto", "obfuscated": False, "transport": "abridged"}
    obf = {"name": "mtproto", "obfuscated": True, "transport": "abridged"}
    assert not _match("mtproto.obfuscated", _row(attrs=extract_filter_attrs([plain])))
    assert _match("mtproto.obfuscated", _row(attrs=extract_filter_attrs([obf])))
    assert _match("not mtproto.obfuscated", _row(attrs=extract_filter_attrs([plain])))


def test_int_multi_existence_ignores_zero():
    assert not _match("mtproto.seq_no", _row(attrs={"mtproto.seq_no": (0,)}))
    assert _match("mtproto.seq_no", _row(attrs={"mtproto.seq_no": (0, 3)}))


# ---------------------------------------------------------------------------
# 8. method sources, leading-zero ints, lenient typing
# ---------------------------------------------------------------------------

def test_method_excludes_inner_summary_display_text():
    row = _row(protocols={"telegram_e2e"}, inner_summary="1:1 · 3 msgs",
               flow_method="1:1 · 3 msgs",
               attrs={"telegram_e2e.method": ("decryptedMessage",)})
    assert _match('method == "decryptedMessage"', row)
    assert not _match('method contains "msgs"', row)


def test_method_includes_flow_method_and_http_methods():
    assert _match("method == sendMessage", _row(flow_method="sendMessage"))
    assert _match("method == get", _http_flow())
    tap = TapFlowSummary(flow_id="s", connection_id="c", method="POST")
    assert _match("method == post", tap)


def test_leading_zero_decimal_is_int():
    attrs = extract_filter_attrs([{"name": "mtproto", "dc_id": "010",
                                   "envelope": {"seq_no": "007"}}])
    assert attrs["mtproto.dc_id"] == (10,)
    assert attrs["mtproto.seq_no"] == (7,)


def test_try_create_lenient_still_treats_prefix_as_typing():
    assert FilterEngine.try_create_lenient("mtproto.dc") is None
    assert isinstance(FilterEngine.try_create_lenient("zzzz"), str)


# ---------------------------------------------------------------------------
# Plan fields: telegram.e2e, telegram.sender
# ---------------------------------------------------------------------------

def test_telegram_e2e_field():
    assert _match("telegram.e2e", _row(protocols={"telegram_e2e"}))
    assert not _match("telegram.e2e", _row(protocols={"mtproto"}))
    assert _match("TELEGRAM.E2E", _row(protocols={"telegram_e2e"}))


def test_telegram_sender_field():
    layers = [
        {"name": "mtproto", "messages": [{"method": "m", "sender_id": 42}]},
        {"name": "telegram_e2e", "messages": [{"method": "d", "sender_id": 7},
                                              {"method": "d", "sender_id": 0}]},
    ]
    attrs = extract_filter_attrs(layers)
    assert lookup_attr(attrs, "telegram.sender") == (42, 7)
    assert "telegram.sender" not in attrs      # union fields are not stored
    assert _match("telegram.sender == 7", _row(attrs=attrs))
    assert not _match("telegram.sender == 0", _row(attrs=attrs))


# ---------------------------------------------------------------------------
# Code review round: dual !=, dangling connectives, tap summary accessors,
# layer_signature coverage, findings-index race
# ---------------------------------------------------------------------------

def test_dual_field_not_equal_excludes_either_end():
    flow = Flow(flow_id="d1", connection_id="c", src_addr="10.0.0.1", src_port=5555,
                dst_addr="1.2.3.4", dst_port=443)
    assert not FilterEngine("ip.addr != 10.0.0.1").matches(flow)
    assert not FilterEngine("ip.addr != 1.2.3.4").matches(flow)
    assert FilterEngine("ip.addr != 9.9.9.9").matches(flow)
    assert not FilterEngine("tcp.port != 443").matches(flow)
    assert FilterEngine("tcp.port != 80").matches(flow)
    # == keeps the any-end rule
    assert FilterEngine("ip.addr == 1.2.3.4").matches(flow)
    assert FilterEngine("tcp.port == 5555").matches(flow)


@pytest.mark.parametrize("text", ["protocol == x and bogusmotor", "brand", "zzzznot"])
def test_word_ending_in_connective_letters_is_not_incomplete(text):
    err = FilterEngine.try_create_detailed(text)
    assert isinstance(err, UnknownFieldError)
    assert not FilterEngine.is_incomplete(text, err)


@pytest.mark.parametrize("text", ["http and", "http or", "http AND", "(http) and", "not"])
def test_dangling_connective_word_is_incomplete(text):
    err = FilterEngine.try_create_detailed(text)
    assert not isinstance(err, FilterEngine)
    assert FilterEngine.is_incomplete(text, err)


def test_tap_summary_flat_accessors_do_not_raise():
    summary = TapFlowSummary(flow_id="x", has_ohttp=True, total_size=10, state="complete")
    assert FilterEngine("ohttp.present").matches(summary)
    assert FilterEngine("flow.size > 5").matches(summary)
    assert FilterEngine("flow.state == complete").matches(summary)
    assert not FilterEngine("ohttp.present").matches(TapFlowSummary(flow_id="y"))


def test_layer_signature_sees_late_filterable_layer_metadata():
    pytest.importorskip("textual")
    from friTap.tui.widgets.flow_list import layer_signature

    flow = Flow(flow_id="s1", connection_id="c")
    mtproto, tls = flow.mtproto, flow.tls
    before = layer_signature(flow)
    mtproto.dc_id = 2
    assert layer_signature(flow) != before
    before = layer_signature(flow)
    tls.version = "TLSv1.3"
    assert layer_signature(flow) != before
    before = layer_signature(flow)
    flow.ssl_session_id = "abcd"
    assert layer_signature(flow) != before


def test_findings_lookup_survives_index_reset():
    from friTap.flow.tap_reader import TapReader

    reader = TapReader("unused.tap")
    reader._findings_index = {"f": ["x"]}
    index = reader._ensure_findings_index()
    reader._findings_index = None  # what a concurrent close() does
    assert index.get("f") == ["x"]
