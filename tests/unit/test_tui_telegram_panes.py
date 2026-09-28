#!/usr/bin/env python3

"""Tests for the forensic Telegram / MTProto panes (T6).

Covers the pure helpers of ``friTap.tui.widgets.telegram_panes`` (records,
``expect`` types, row references, envelope / refs / users / peer blocks, TL
trees) and their use in ``FlowDetailWidget``: the Request/Response TL message
pane (processing banner -> title -> Envelope -> Cross-references -> fields ->
Decoded TL -> body), the Detail-tab sections, and the flow-list row resolver.
Synthetic bytes only; widgets are built via ``__new__`` with fake logs.
"""

from __future__ import annotations

from types import SimpleNamespace

from friTap.flow.layers import MtprotoLayer, TelegramE2ELayer
from friTap.flow.models import Flow, FlowChunk
from friTap.parsers.base import ParseResult
from friTap.tui.modals.body_processing_modal import BodyProcessingResult
from friTap.tui.widgets import telegram_panes as tp
from tests.unit._render_helpers import RenderingFakeLog as _FakeLog
from tests.unit._tl_helpers import (
    VECTOR,
    gzip_packed,
    i32,
    msgs_ack,
    rpc_result,
    u32,
)
from tests.unit._tui_flow_helpers import make_flow_detail_widget
from tests.unit.test_tui_telegram_e2e_view import _HI_BLOB, _parse

PRIVACY_RULES = 0x50A04E45
_T = 1790358548.0
ACKED_ID = 0x6AB6B413EA17C001
REQ_ID = 0x6AB6B41851687400
ROWS = {"f-req": 47, "f-ack": 2, "f-carrier": 159}


def _privacy_rules() -> bytes:
    empty = u32(VECTOR) + i32(0)
    return u32(PRIVACY_RULES) + empty * 3


def _row_of(flow_id):
    return ROWS.get(flow_id)


def _envelope() -> dict:
    return {"msg_id": "0x6ab6b414049ba800", "msg_time": _T, "seq_no": 0,
            "auth_key_id": "09311c9766cbcf5f", "salt": "6995edaa5a330b96",
            "session_id": "b31afe7b70de4284", "msg_len": 28, "record_seq": 3}


def _ack_refs() -> dict:
    return {"acks": [{"msg_id": f"0x{ACKED_ID:016x}", "method": "new_session_created",
                      "flow_id": "f-ack"}], "acks_total": 1}


def _answer_refs() -> dict:
    return {"answers": [{"msg_id": f"0x{REQ_ID:016x}", "method": "account.getPrivacy",
                         "flow_id": "f-req"}],
            "request_method": "account.getPrivacy",
            "acked_by": [{"msg_id": "0x6ab6b41867efa000", "flow_id": "f-gone"}]}


def _mt_flow(data: bytes, direction: str, method: str, *, envelope=None, refs=None,
             users=None, with_layer=True, flow_id="m1") -> Flow:
    flow = Flow(flow_id=flow_id, transport="mtproto")
    flow.chunks.append(FlowChunk(data, direction, _T))
    parse = ParseResult(protocol="MTProto", method=method, body=data,
                        headers={"constructor": method, "messages": "0"})
    if direction == "write":
        flow.request = parse
    else:
        flow.response = parse
    if with_layer:
        flow.add_layer(MtprotoLayer(envelope=envelope or {}, refs=refs or {},
                                    users=list(users or [])))
    return flow


def _e2e_sent_flow() -> Flow:
    flow = Flow(flow_id="e2e-1", transport="telegram_e2e",
                ssl_session_id="telegram_e2e:71686e79a975226b")
    flow.chunks.append(FlowChunk(_HI_BLOB, "write", _T))
    flow.request = _parse(_HI_BLOB, "write")
    flow.add_layer(TelegramE2ELayer(
        chat_id=-1355992074, key_fingerprint="71686e79a975226b",
        envelope={"key_fingerprint": "71686e79a975226b", "msg_key": "0c81188a",
                  "chat_id": -1355992074, "carrier_msg_id": "0x6ab6b428b8937400"},
        refs={"carried_in": {"msg_id": "0x6ab6b428b8937400", "flow_id": "f-carrier"}},
        users=[_user()],
        peer={"user_id": 0, "label": "peer (unknown, chat_id -1355992074)",
              "chat_id": -1355992074}))
    return flow


def _user(**extra) -> dict:
    user = {"id": 42, "ctor": "user#b1b8cc83", "flags": ["self", "premium"],
            "access_hash": -32, "first_name": "Evil", "last_name": "kneebel",
            "username": "evil", "phone": "15550100", "lang_code": "en",
            "status": {"kind": "offline", "was_online": 1790355639}, "has_photo": False}
    user.update(extra)
    return user


def _widget(processing=None, resolver=_row_of):
    return make_flow_detail_widget(processing=processing, log_width=160,
                                   _current_flow=None, _row_resolver=resolver)


def _text(log) -> str:
    return "\n".join(log.lines)


def _pane(flow, direction="write", **kw) -> str:
    w = _widget(**kw)
    w._current_flow = flow
    log = _FakeLog(width=160)
    assert w._render_tl_message_pane(log, flow, direction) is True
    return _text(log)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_tl_records_for_returns_each_chunk_of_the_direction():
    flow = Flow(flow_id="g", transport="mtproto")
    flow.chunks += [FlowChunk(b"a", "write", 1), FlowChunk(b"b", "read", 2),
                    FlowChunk(b"c", "write", 3)]
    assert tp.tl_records_for(flow, "write") == [b"a", b"c"]
    assert tp.tl_records_for(flow, "read") == [b"b"]
    assert tp.tl_domain_for(flow) == "mtproto"
    assert tp.tl_domain_for(Flow(transport="telegram_e2e")) == "secret"


def test_result_type_for_uses_schema_function_result():
    assert tp.result_type_for("account.getPrivacy") == "account.PrivacyRules"
    assert tp.result_type_for("messages.receivedQueue") == "Vector<long>"
    assert tp.result_type_for("invokeWithLayer") is None  # generic X
    assert tp.result_type_for("no.suchMethod") is None
    assert tp.result_type_for(None) is None


def test_decode_record_types_the_rpc_result():
    node = tp.decode_record(rpc_result(REQ_ID, _privacy_rules()), "mtproto",
                            "account.getPrivacy")
    assert node.name == "rpc_result"
    assert node.value("result").name == "account.privacyRules"


def test_ref_label_maps_msg_ids_to_rows_and_falls_back_to_flow_id():
    refs = {"answers": [{"msg_id": "0x10", "method": "m.a", "flow_id": "f-req"}],
            "acked_by": [{"msg_id": "0x20", "flow_id": "net:1.2.3.4:5-6.7.8.9:10:99"}]}
    label = tp.make_ref_label(refs, _row_of)
    assert label(0x10) == "→ #47 m.a"
    assert label(0x20) == "→ flow …" + "net:1.2.3.4:5-6.7.8.9:10:99"[-18:]
    assert label(0x30) is None


def test_ref_label_skips_container_children():
    refs = {"container": [{"msg_id": "0x10", "method": "rpc_result"}]}
    assert tp.make_ref_label(refs, _row_of)(0x10) is None


def test_envelope_lines_render_fields_without_record_seq():
    text = "\n".join(tp.envelope_lines(MtprotoLayer(envelope=_envelope())))
    assert "0x6ab6b414049ba800" in text and "b31afe7b70de4284" in text
    assert "seq_no" in text and "(service)" in text
    assert "record_seq" not in text
    assert tp.envelope_lines(MtprotoLayer()) == []
    assert tp.envelope_lines(None) == []


def test_refs_lines_answers_acked_by_and_fallback():
    lines = tp.refs_lines(MtprotoLayer(refs=_answer_refs()), _row_of)
    text = _FakeLog(width=200)
    for line in lines:
        text.write(line)
    blob = _text(text)
    assert f"msg 0x{REQ_ID:016x} → #47 account.getPrivacy" in blob
    assert "request method" in blob
    assert "(flow f-gone)" in blob


def test_refs_lines_acks_total():
    refs = {"acks": [{"msg_id": "0x1", "flow_id": "f-ack"}], "acks_total": 5}
    blob = "\n".join(tp.refs_lines(MtprotoLayer(refs=refs), _row_of))
    assert "acks (1 of 5)" in blob and "→ #2" in blob


def test_users_lines_show_every_field_and_escape_markup():
    log = _FakeLog(width=200)
    for line in tp.users_lines([_user(first_name="[bold]Evil")]):
        log.write(line)
    blob = _text(log)
    assert "[bold]Evil kneebel" in blob and "(id 42)" in blob
    assert "[self, premium]" in blob
    for needle in ("@evil", "15550100", "offline, was_online 1790355639 (", "-32",
                   "lang_code", "en", "photo", "no", "user#b1b8cc83"):
        assert needle in blob


def test_peer_lines():
    blob = "\n".join(tp.peer_lines({"user_id": 7, "label": "Bob", "chat_id": -5}))
    assert "Bob" in blob and "7" in blob and "-5" in blob
    assert tp.peer_lines({}) == []


def test_decoded_tree_lines_numbers_multiple_records():
    lines = tp.decoded_tree_lines([msgs_ack(1), msgs_ack(2)], "mtproto")
    blob = "\n".join(lines)
    assert "Record 1/2" in blob and "Record 2/2" in blob
    assert "Record" not in "\n".join(tp.decoded_tree_lines([msgs_ack(1)], "mtproto"))


# ---------------------------------------------------------------------------
# TL message pane
# ---------------------------------------------------------------------------

def test_msgs_ack_pane_shows_decoded_ids_with_row_reference():
    flow = _mt_flow(msgs_ack(ACKED_ID), "write", "msgs_ack",
                    envelope=_envelope(), refs=_ack_refs())
    text = _pane(flow)
    tree = text.split("Decoded TL")[1]
    assert f"0x{ACKED_ID:016x}" in tree
    assert "→ #2 new_session_created" in tree
    assert "press h for the hexdump" in text
    assert "--- Message ---" not in text  # raw record hexdump stays behind h


def test_pane_section_order():
    flow = _mt_flow(msgs_ack(ACKED_ID), "write", "msgs_ack",
                    envelope=_envelope(), refs=_ack_refs())
    text = _pane(flow)
    order = [text.index(k) for k in ("SENT message", "Envelope", "Cross-references",
                                      "constructor:", "Decoded TL")]
    assert order == sorted(order)


def test_rpc_result_gzip_pane_shows_inflated_tree_and_answer_ref():
    data = rpc_result(REQ_ID, gzip_packed(_privacy_rules()))
    flow = _mt_flow(data, "read", "account.privacyRules", envelope=_envelope(),
                    refs=_answer_refs())
    text = _pane(flow, "read")
    tree = text.split("Decoded TL")[1]
    assert "gzip_packed" in tree and "inflated" in tree
    assert "account.privacyRules" in tree
    assert "→ #47 account.getPrivacy" in tree
    assert "answers" in text.split("Decoded TL")[0]


def test_old_tap_flow_without_layer_still_renders_tree():
    flow = _mt_flow(msgs_ack(ACKED_ID), "write", "msgs_ack", with_layer=False)
    text = _pane(flow, resolver=None)
    assert "Envelope" not in text and "Cross-references" not in text
    assert "msgs_ack#62d6b459" in text.split("Decoded TL")[1]


def test_flow_without_chunks_decodes_the_parse_body():
    flow = _mt_flow(msgs_ack(9), "write", "msgs_ack")
    flow.chunks.clear()
    assert "msg_ids" in _pane(flow).split("Decoded TL")[1]


def test_grouped_old_tap_renders_record_k_of_n():
    flow = _mt_flow(msgs_ack(1), "write", "msgs_ack", with_layer=False)
    flow.chunks.append(FlowChunk(msgs_ack(2), "write", _T + 1))
    text = _pane(flow)
    assert "Record 1/2" in text and "Record 2/2" in text


def test_processing_banner_stays_first():
    flow = _mt_flow(b"\x00" * 8, "write", "x", envelope=_envelope())
    text = _pane(flow, processing=BodyProcessingResult(decompression="gzip"))
    assert text.splitlines()[0].startswith("⚠ Processing failed")
    assert "--- Message ---" in text  # processed body section kept


def test_e2e_pane_shows_envelope_carrier_tree_and_text():
    text = _pane(_e2e_sent_flow())
    head, tree = text.split("Decoded TL")
    assert "71686e79a975226b" in head and "0c81188a" in head
    assert "carried in" in head and "→ #159" in head
    assert "decryptedMessageLayer" in tree
    assert "random_id" in head  # existing decoded TL fields kept
    assert "--- Message ---" in text and "Hi infected" in text.split("--- Message ---")[1]


# ---------------------------------------------------------------------------
# Detail tab
# ---------------------------------------------------------------------------

def test_detail_tab_telegram_packet_section():
    w = _widget()
    flow = _mt_flow(msgs_ack(ACKED_ID), "write", "msgs_ack", envelope=_envelope(),
                    refs=_ack_refs(), users=[_user()])
    w._update_detail(flow)
    text = _text(w._detail_log)
    assert "Telegram Packet (MTProto)" in text
    assert "b31afe7b70de4284" in text and "→ #2" in text
    assert "Users" in text and "Evil kneebel" in text and "15550100" in text


def test_detail_tab_secret_chat_section_has_peer_and_users():
    w = _widget()
    w._update_detail(_e2e_sent_flow())
    text = _text(w._detail_log)
    assert "Telegram Secret Chat" in text
    assert "peer (unknown, chat_id -1355992074)" in text
    assert "carried in" in text and "#159" in text
    assert "Evil kneebel" in text and "@evil" in text
    assert "Telegram Packet (MTProto)" not in text


# ---------------------------------------------------------------------------
# Row resolver
# ---------------------------------------------------------------------------

def test_flow_list_row_number_of():
    from friTap.tui.widgets.flow_list import FlowListWidget
    fl = FlowListWidget.__new__(FlowListWidget)
    fl._flow_row_keys = {"a": "key-a", "b": "key-b"}
    cells = {"key-a": ["12", "19:49:08"], "key-b": ["oops"]}
    fl.get_row = lambda key: cells[key]
    assert fl.row_number_of("a") == 12
    assert fl.row_number_of("b") is None
    assert fl.row_number_of("missing") is None


def test_widget_row_of_swallows_resolver_errors():
    def boom(_flow_id):
        raise RuntimeError("x")
    assert _widget(resolver=boom)._row_of("a") is None
    assert _widget(resolver=None)._row_of("a") is None
    w = _widget(resolver=None)
    w.set_row_resolver(_row_of)
    assert w._row_of("f-req") == 47


def test_main_screen_passes_flow_list_resolver():
    from friTap.tui.screens.main_screen import MainScreen
    screen = MainScreen.__new__(MainScreen)
    fl = SimpleNamespace(row_number_of=lambda fid: 3)
    screen.query_one = lambda *a, **k: fl
    assert screen._flow_row_resolver()("x") == 3
