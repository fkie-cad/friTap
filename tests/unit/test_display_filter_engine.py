"""Unit tests for the display filter engine (fields, parser, evaluator).

Covers case-insensitive and dynamic field resolution (protocol predicates,
per-layer attributes), multi-valued semantics, ``frame`` content search via an
evaluation context, cost reordering, ``UnknownFieldError`` hints, and that the
pre-existing expressions keep working. Pure Python — no device/Frida.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from friTap.filter import FilterEngine, FilterSyntaxError, UnknownFieldError
from friTap.filter.fields import (
    CANONICAL_FIELDS,
    all_field_names,
    get_field,
    is_canonical_only,
    is_field_prefix,
)
from friTap.filter.pipeline_filter import FilteredSink
from friTap.filter.protocols import PROTOCOL_ALIASES, known_protocol_names
from friTap.flow.layer_registry import get_registry
from friTap.flow.layers import MtprotoLayer, SignalLayer, TelegramE2ELayer, TlsLayer
from friTap.flow.models import Flow, FlowChunk, FlowSummary
from friTap.schemas.canonical import DataCanonical
from tests.unit._display_filter_helpers import FakeCtx as _FakeCtx
from tests.unit._display_filter_helpers import data_event
from tests.unit._display_filter_helpers import http_flow as _http_flow
from tests.unit._display_filter_helpers import match as _match
from tests.unit._display_filter_helpers import summary_row as _row
from tests.unit._display_filter_helpers import tg_message as _tg_message


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def _mtproto_flow() -> Flow:
    flow = Flow(flow_id="f1", connection_id="c1", transport="mtproto")
    flow.chunks.append(FlowChunk(data=b"x", direction="read", timestamp=1.0))
    layer = MtprotoLayer(transport="intermediate", dc_id=2,
                         auth_key_id="aabbccdd11223344", message_count=2)
    layer.messages = [_tg_message("upload.getFile", ""),
                      _tg_message("messages.sendMessage", "oh hi there")]
    flow.add_layer(layer)
    return flow


# ---------------------------------------------------------------------------
# Protocol predicates
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(get_registry().names()))
def test_every_registry_protocol_bare_explicit_and_uppercase(name):
    row = _row(protocols={name})
    other = _row(protocols={"__none__"})
    for expr in (name, f"protocol.{name}", name.upper(), f"PROTOCOL.{name.upper()}"):
        assert _match(expr, row), expr
        assert not _match(expr, other), expr
    assert _match(f'protocol == "{name}"', row)


@pytest.mark.parametrize("alias", ["telegram", "tg", "ws", "http", "TeLeGrAm"])
def test_aliases_match_any_member(alias):
    for member in PROTOCOL_ALIASES[alias.lower()]:
        assert _match(alias, _row(protocols={member}))
        assert _match(f"protocol == {alias}", _row(protocols={member}))
    assert not _match(alias, _row(protocols={"ssh"}))


def test_protocol_contains_and_display_labels():
    row = _row(protocols={"mtproto"}, inner_e2e_protocol="MTProto")
    assert _match('protocol contains "tele"', row)  # via the telegram alias
    assert _match('protocol == "mtproto"', row)
    assert _match('protocol == "MTProto"', row)
    assert not _match('protocol == "ssh"', row)


def test_protocol_equals_http2_display_label_and_layered_label():
    flow = _http_flow(protocol="HTTP/2")
    assert _match('protocol == "HTTP/2"', flow)
    assert _match("http2", flow)
    layered = _row(protocols={"http2", "signal"}, outer_app_protocol="HTTP/2",
                   inner_e2e_protocol="Signal")
    assert _match('protocol == "HTTP/2[Signal]"', layered)
    assert _match('frame.protocol == "signal"', layered)


def test_known_names_are_all_resolvable():
    for name in known_protocol_names():
        assert get_field(name) is not None, name
        assert get_field(f"protocol.{name}") is not None, name


# ---------------------------------------------------------------------------
# Method / layer fields (multi-valued)
# ---------------------------------------------------------------------------

_MT_ATTRS = {"mtproto.method": ("upload.getFile", "msgs_ack"),
             "mtproto.dc_id": (2,),
             "mtproto.msg": ("oh hi there",)}


def test_method_matches_any_tl_method_on_row():
    row = _row(protocols={"mtproto"}, attrs=_MT_ATTRS)
    assert _match('method == "upload.getFile"', row)
    assert _match("method contains msgs", row)
    assert _match('method == "UPLOAD.GETFILE"', row)
    assert not _match('method == "users.getUsers"', row)


def test_not_equal_is_none_match():
    row = _row(protocols={"mtproto"}, attrs=_MT_ATTRS)
    assert not _match('method != "msgs_ack"', row)
    assert _match('method != "users.getUsers"', row)
    # No values at all -> False (consistent with None -> False).
    assert not _match('method != "x"', _row())
    assert not _match("mtproto.dc_id != 3", _row())


def test_layer_fields_on_row():
    row = _row(protocols={"mtproto"}, attrs=_MT_ATTRS)
    assert _match("mtproto.dc_id == 2", row)
    assert _match("MTPROTO.DC_ID >= 2", row)
    assert not _match("mtproto.dc_id == 4", row)
    assert _match('telegram.msg contains "hi"', row)
    assert _match("mtproto.dc_id", row)
    assert not _match("mtproto.dc_id", _row())


def test_method_and_layer_fields_on_live_flow_and_summary():
    flow = _mtproto_flow()
    summary = FlowSummary.from_flow(flow)
    for obj in (flow, summary):
        assert _match('method == "upload.getFile"', obj)
        assert _match("mtproto.dc_id == 2", obj)
        assert _match('telegram.msg contains "hi"', obj)
        assert _match("telegram and mtproto", obj)
        assert not _match("signal", obj)
    # The filter must never materialize layers on a live flow.
    assert [ly.name for ly in flow.layers] == ["mtproto"]


def test_signal_and_tls_fields_on_live_flow():
    flow = Flow(flow_id="s1", connection_id="c3", transport="signal")
    signal = SignalLayer(chat_type="group", identifier="ab", message_count=1)
    signal.messages = [{"sender": "+49", "body": "signal hi", "kind": "text"}]
    flow.add_layer(TlsLayer(sni="chat.signal.org", alpn="h2"))
    flow.add_layer(signal)
    assert _match("signal", flow)
    assert _match('signal.msg contains "HI"', flow)
    assert _match('signal.chat_type == "group"', flow)
    assert _match('tls.sni == "chat.signal.org"', flow)
    assert _match("tls", flow)
    assert _match('tls.sni contains "signal"', _row(tls_sni="chat.signal.org"))


def test_e2e_flow_matches_telegram_and_e2e_aliases():
    flow = Flow(flow_id="e1", connection_id="c4", transport="mtproto")
    e2e = TelegramE2ELayer(chat_id=12345, message_count=1)
    e2e.messages = [_tg_message("decryptedMessage", "secret hi")]
    flow.add_layer(e2e)
    assert _match("telegram", flow)
    assert _match("e2e", flow)
    assert _match("protocol.telegram_e2e", flow)
    assert _match("telegram.chat_id == 12345", flow)


def test_scalar_generic_fields():
    row = _row(transport="quic", inner_summary="1:1 · 2 msgs",
               process_name="org.telegram.messenger")
    assert _match('transport == "quic"', row)
    assert _match('info contains "msgs"', row)
    assert _match('process contains "telegram"', row)


# ---------------------------------------------------------------------------
# frame content search
# ---------------------------------------------------------------------------

def test_frame_contains_is_case_insensitive_and_binary_safe():
    ctx = _FakeCtx(b"\x00\x01Hello World\xff\xfe")
    row = _row()
    assert _match('frame contains "hello"', row, ctx)
    assert _match('frame contains "WORLD"', row, ctx)
    assert not _match('frame contains "absent"', row, ctx)
    assert _match("frame", row, ctx)
    assert not _match('frame contains "hello"', row)          # no ctx
    assert not _match('frame contains "x"', row, _FakeCtx(None))


def test_frame_matches_regex_ignores_case():
    ctx = _FakeCtx(b"\x00token=ABC123\xff")
    assert _match('frame matches "TOKEN=[a-z]+[0-9]+"', _row(), ctx)
    assert not _match('frame matches "^token"', _row(), ctx)


def test_needs_context_flag():
    assert FilterEngine('frame contains "a"').needs_context
    assert FilterEngine('telegram and frame contains "a"').needs_context
    assert not FilterEngine("telegram").needs_context
    assert "frame" in FilterEngine('FRAME contains "a"').fields


def test_and_reordering_skips_context_when_cheap_side_false():
    ctx = _FakeCtx(b"hello")
    engine = FilterEngine('frame contains "hello" and telegram')
    assert not engine.matches(_row(protocols={"ssh"}), ctx)
    assert ctx.calls == 0
    assert engine.matches(_row(protocols={"mtproto"}), ctx)
    assert ctx.calls == 1


def test_or_reordering_skips_context_when_cheap_side_true():
    ctx = _FakeCtx(b"hello")
    engine = FilterEngine('(frame contains "zzz" or ssh) and not frame contains "q"')
    assert engine.matches(_row(protocols={"ssh"}), ctx)
    assert ctx.calls == 1  # only the "not frame" side needed the context


# ---------------------------------------------------------------------------
# Unknown fields and lenient typing
# ---------------------------------------------------------------------------

def test_unknown_field_tele_hints():
    with pytest.raises(UnknownFieldError) as info:
        FilterEngine("TELE")
    err = info.value
    assert isinstance(err, FilterSyntaxError)
    assert str(err) == "Unknown field 'TELE' (at position 0)"
    assert err.name == "TELE" and err.position == 0
    assert err.did_you_mean[0] == "telegram"
    assert len(err.did_you_mean) <= 3
    assert err.suggestions == [
        'protocol contains "TELE"',
        'method contains "TELE"',
        'frame contains "TELE"',
    ]
    for suggestion in err.suggestions:
        FilterEngine(suggestion)  # every suggestion parses


def test_unknown_field_getfile_suggestions():
    with pytest.raises(UnknownFieldError) as info:
        FilterEngine("getFile")
    assert info.value.suggestions[1] == 'method contains "getFile"'
    row = _row(attrs=_MT_ATTRS)
    assert FilterEngine(info.value.suggestions[1]).matches(row)


def test_unknown_field_inside_larger_expression_keeps_the_rest():
    with pytest.raises(UnknownFieldError) as info:
        FilterEngine("ip.src == 1.2.3.4 and foo")
    err = info.value
    assert err.position == 22
    assert err.suggestions[0] == 'ip.src == 1.2.3.4 and protocol contains "foo"'
    assert err.suggestions[2] == 'ip.src == 1.2.3.4 and frame contains "foo"'


def test_try_create_lenient_prefix_is_typing_state():
    assert FilterEngine.try_create_lenient("TELE") is None
    assert FilterEngine.try_create_lenient("http.resp") is None
    assert FilterEngine.try_create_lenient("mtproto.dc") is None
    assert isinstance(FilterEngine.try_create_lenient("zzzz"), str)
    assert isinstance(FilterEngine.try_create_lenient("TELEGRAM"), FilterEngine)


def test_field_name_helpers():
    assert get_field("IP.SRC") is get_field("ip.src")
    assert is_field_prefix("TELE")
    assert not is_field_prefix("telegram")
    names = all_field_names()
    assert "telegram" in names and "protocol.signal" in names
    assert "mtproto.dc_id" in names and "ip.src" in names


# ---------------------------------------------------------------------------
# Backwards compatibility
# ---------------------------------------------------------------------------

def test_old_expressions_unchanged():
    ok = _http_flow(status=404, host="api.example.com")
    assert _match("http.response.code >= 400", ok)
    assert not _match("http.response.code >= 400", _http_flow(status=200))
    assert _match("ip.addr == 1.2.3.4", ok)
    assert _match("ip.addr == 10.0.0.1", ok)
    assert _match("tcp.port == 443", ok)
    assert _match("http.host contains example", ok)
    assert _match("http", ok)
    assert _match('http.request.method == "get"', ok)
    ssh = _row(protocols={"ssh"}, detected_protocol="SSH")
    assert _match('frame.protocol == "ssh"', ssh)
    assert not _match('frame.protocol == "ssh"', ok)


def test_bool_predicates_work_on_replay_rows():
    assert _match("ssh", _row(protocols={"ssh"}))
    assert _match("ipsec", _row(protocols={"ipsec"}))
    assert _match("tls", _row(ssl_session_id="abcd"))
    assert _match("http", _row(protocols={"http2"}))
    assert not _match("http", _row(protocols={"ssh"}))


# ---------------------------------------------------------------------------
# Headless (DataCanonical)
# ---------------------------------------------------------------------------

def _event(protocol="ssh") -> DataCanonical:
    return data_event(protocol, dst_port=22)


def test_headless_canonical_fields_and_pipeline_filter():
    assert {"protocol", "frame.protocol", "ip.src"} <= CANONICAL_FIELDS
    assert is_canonical_only({"protocol", "ip.dst"})
    assert not is_canonical_only({"telegram"})
    assert FilterEngine.validate('protocol == "ssh"') is None
    assert not FilterEngine.requires_flow_collector('protocol == "ssh"')
    assert FilterEngine.requires_flow_collector("telegram")

    received = []
    inner = SimpleNamespace(on_data=received.append)
    for expr in ('frame.protocol == "ssh"', 'protocol == "ssh"'):
        received.clear()
        sink = FilteredSink(inner, FilterEngine(expr))
        sink.on_data(_event("ssh"))
        sink.on_data(_event("tls"))
        assert [e.protocol for e in received] == ["ssh"], expr


# -- FieldDef metadata / shared protocol predicate -----------------------------

def test_every_static_field_has_a_description():
    from friTap.filter.fields import FIELD_REGISTRY

    assert all(fdef.description for fdef in FIELD_REGISTRY.values())


def test_protocol_and_frame_protocol_share_one_definition():
    protocol, frame = get_field("protocol"), get_field("frame.protocol")
    assert protocol.accessor is frame.accessor
    assert protocol.operand_equivalents is frame.operand_equivalents
    assert protocol.multi and frame.multi


def test_tls_predicate_true_for_session_id_on_live_flow_and_summary():
    flow = Flow(ssl_session_id="abcd", transport="tcp")
    assert _match("tls", flow)
    assert _match("tls", FlowSummary.from_flow(flow))
    assert not _match("tls", Flow(transport="tcp"))
