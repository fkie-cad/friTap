#!/usr/bin/env python3

"""Unit tests for the TUI presentation of Telegram Secret Chat (E2E) flows.

Covers the detail header/Detail-tab protocol label, the message-transport
status strings (header + flow list), the clean Request/Response message panes,
the Detail-tab "Telegram Secret Chat" block, the Message tab's cross-flow
merge + identity dedupe, and MainScreen's Secret-Chat sibling selection.

Widgets are built via ``__new__`` with fake RichLogs (no Textual app), as in
tests/unit/test_mtproto_message_tab.py.
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from friTap.flow import display
from friTap.flow.layers import MtprotoLayer, TelegramE2ELayer
from friTap.flow.models import Flow, FlowChunk
from friTap.parsers.base import ParseResult
from friTap.parsers.telegram_tl import TelegramE2EParser
from tests.unit._tui_flow_helpers import FakeReplay as _FakeReplay
from tests.unit._tui_flow_helpers import make_flow_detail_widget as _widget

# Real decrypted decryptedMessageLayer carrying "Hi infected".
_HI_BLOB = bytes.fromhex(
    "8917e31b0fc1a2e4f91e39178d0905d8cb6391229700000014000000390000007446cc91"
    "0000000036f216008c205efc000000000b486920696e666563746564"
)
# Same packet shape, other random_id and text ("hello folks", same length).
_HELLO_BLOB = _HI_BLOB.replace(
    bytes.fromhex("36f216008c205efc"), bytes.fromhex("1122334455667788")
).replace(b"Hi infected", b"hello folks")

_T_SENT = 1790358703.257
_T_RECV = 1790358703.356
_FP = "71686e79a975226b"


def _parse(blob: bytes, direction: str) -> ParseResult:
    return TelegramE2EParser().feed(blob, direction)[0]


def _e2e_flow(flow_id="e1", messages=None, sent_ts=_T_SENT, recv_ts=_T_RECV,
              with_response=True, with_request=True) -> Flow:
    """Secret-Chat flow. Defaults model a legacy (round-1) paired tap; offline
    output since T1 is one packet per flow (see _sent_flow / _recv_flow)."""
    flow = Flow(flow_id=flow_id, transport="telegram_e2e",
                ssl_session_id=f"telegram_e2e:{_FP}")
    if with_request:
        flow.chunks.append(FlowChunk(_HI_BLOB, "write", sent_ts))
        flow.request = _parse(_HI_BLOB, "write")
    if with_response:
        flow.chunks.append(FlowChunk(_HELLO_BLOB, "read", recv_ts))
        flow.response = _parse(_HELLO_BLOB, "read")
    layer = TelegramE2ELayer()
    layer.messages = list(messages or [])
    flow.add_layer(layer)
    return flow


def _sent_flow(flow_id="s1", messages=None) -> Flow:
    """Per-packet (T1) sent Secret-Chat row, as offline conversion emits it."""
    return _e2e_flow(flow_id, messages, with_response=False)


def _recv_flow(flow_id="r1", messages=None) -> Flow:
    """Per-packet (T1) received Secret-Chat row, as offline conversion emits it."""
    return _e2e_flow(flow_id, messages, with_request=False)


def _http_flow() -> Flow:
    flow = Flow(flow_id="h1")
    flow.request = ParseResult(protocol="HTTP/1.1", method="GET", url="/", host="x")
    flow.response = ParseResult(protocol="HTTP/1.1", status_code=200,
                                status_text="OK", is_request=False)
    return flow


def _blob(log) -> str:
    return "\n".join(log.lines)


def _hms(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


# ---------------------------------------------------------------------------
# Protocol label / status
# ---------------------------------------------------------------------------

def test_detail_protocol_uses_layered_label_for_e2e_flow():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    flow = _e2e_flow()
    flow.request.protocol = "WebSocket"  # stale sniffed parse must not leak
    assert FlowDetailWidget._detail_protocol(flow) == "Telegram-E2E"


def test_detail_protocol_nests_e2e_inside_mtproto():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    flow = _e2e_flow()
    flow.add_layer(MtprotoLayer())
    assert FlowDetailWidget._detail_protocol(flow) == "MTProto[Telegram-E2E]"


def test_detail_protocol_unchanged_for_http_flow():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    flow = _http_flow()
    assert FlowDetailWidget._layered_detail_protocol(flow) == ""
    assert FlowDetailWidget._detail_protocol(flow) == flow.display_protocol


def test_display_status_for_message_transports_is_empty():
    assert display.display_status_for(_e2e_flow()) == ""
    assert display.display_status_for(Flow(transport="mtproto")) == ""
    assert display.display_status_for(_http_flow()) == "200 OK"


def test_header_status_part_omitted_for_message_transport():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    assert FlowDetailWidget._header_status_part(_e2e_flow()) == ""
    assert "pending" in FlowDetailWidget._header_status_part(Flow())
    assert "200 OK" in FlowDetailWidget._header_status_part(_http_flow())


def test_message_direction_status():
    assert display.message_direction_status(_e2e_flow()) == "sent+recv"
    assert display.message_direction_status(_e2e_flow(with_response=False)) == "sent"
    recv_only = _e2e_flow()
    recv_only.request = None
    assert display.message_direction_status(recv_only) == "recv"
    assert display.message_direction_status(Flow()) == ""


def test_list_status_strings():
    from friTap.tui.widgets.flow_list import FlowListWidget
    fmt = FlowListWidget.__new__(FlowListWidget)._format_status
    assert fmt(_e2e_flow()) == "sent+recv"
    assert fmt(_sent_flow()) == "sent"
    assert fmt(_recv_flow()) == "recv"
    empty_e2e = Flow(transport="telegram_e2e")
    assert fmt(empty_e2e) == "-"
    assert fmt(Flow(transport="mtproto")) == "-"
    assert "200 OK" in fmt(_http_flow())
    assert fmt(Flow()) == "..."


# ---------------------------------------------------------------------------
# Request / Response panes
# ---------------------------------------------------------------------------

def test_request_pane_shows_only_sent_message():
    w = _widget()
    flow = _sent_flow()
    w._update_request(flow)
    text = _blob(w._request_log)
    assert "SENT message" in text
    assert "Sent:" in text and _hms(_T_SENT) in text
    assert "Hi infected" in text
    assert "hello folks" not in text
    assert "random_id" in text and "in_seq_no" in text
    assert "content-type" not in text
    assert "SEGMENT" not in text


def test_response_pane_shows_only_received_message():
    w = _widget()
    flow = _recv_flow()
    flow.trailing_bytes = b"\x00\x01"  # must be ignored for message transports
    w._update_response(flow)
    text = _blob(w._response_log)
    assert "RECEIVED message" in text
    assert "Received:" in text and _hms(_T_RECV) in text
    assert "hello folks" in text
    assert "Hi infected" not in text


def test_pane_falls_back_to_transport_note_without_pinned_parse():
    w = _widget()
    flow = _e2e_flow(messages=[{"direction": "write", "kind": "text",
                                "body": "Hi infected", "timestamp": 1}])
    flow.request = ParseResult(protocol="WebSocket", method="PING")
    w._update_request(flow)
    text = _blob(w._request_log)
    assert "Message tab" in text
    assert "SENT message" not in text


# ---------------------------------------------------------------------------
# Detail tab
# ---------------------------------------------------------------------------

def test_detail_tab_secret_chat_section():
    w = _widget()
    w._update_detail(_e2e_flow())
    text = _blob(w._detail_log)
    assert "Protocol:" in text and "Telegram-E2E" in text
    assert "Telegram Secret Chat" in text
    assert _FP in text
    assert _hms(_T_SENT) in text and _hms(_T_RECV) in text
    assert "-261735942671896010" in text and "-8613303245920329199" in text
    assert "sent 20" in text and "sent 57" in text


# ---------------------------------------------------------------------------
# Message dedupe + Message tab
# ---------------------------------------------------------------------------

def _msg(direction, body, ts=0, random_id=None):
    return {"direction": direction, "kind": "text", "body": body,
            "timestamp": ts, "random_id": random_id, "method": "decryptedMessage"}


def test_dedupe_by_random_id():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    msgs = [_msg("write", "a", 1, 7), _msg("write", "a-edited", 2, 7),
            _msg("read", "b", 3, 8)]
    out = FlowDetailWidget._dedupe_by_message_identity(msgs)
    assert [m["body"] for m in out] == ["a", "b"]


def test_dedupe_fallback_direction_body_timestamp():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    msgs = [_msg("write", "x", 5), _msg("write", "x", 5), _msg("read", "x", 5),
            _msg("write", "x", 6), _msg("write", "y", 0, random_id=0)]
    out = FlowDetailWidget._dedupe_by_message_identity(msgs)
    assert len(out) == 4


def test_dedupe_legacy_four_plus_four_copies_to_two():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    per_flow = [_msg("write", "Hi infected"), _msg("read", "hello folks"),
                _msg("write", "Hi infected"), _msg("read", "hello folks")]
    out = FlowDetailWidget._dedupe_by_message_identity(per_flow + [dict(m) for m in per_flow])
    assert [(m["direction"], m["body"]) for m in out] == [
        ("write", "Hi infected"), ("read", "hello folks")]


def _legacy_pair():
    legacy = [_msg("write", "Hi infected"), _msg("read", "hello folks"),
              _msg("write", "Hi infected"), _msg("read", "hello folks")]
    a = _e2e_flow("a", messages=[dict(m) for m in legacy])
    b = _e2e_flow("b", messages=[dict(m) for m in legacy],
                  sent_ts=_T_SENT + 0.25, recv_ts=_T_RECV + 0.25)
    return a, b


def test_message_tab_merges_and_dedupes_secret_chat_with_times():
    a, b = _legacy_pair()
    w = _widget()
    w._conversation_siblings = [a, b]
    w._render_message_tab(a)
    text = _blob(w._message_log)
    assert "2 messages" in text
    assert text.count("Hi infected") == 1
    assert text.count("hello folks") == 1
    assert text.index("Hi infected") < text.index("hello folks")
    # Legacy messages lack timestamps: backfilled from the chunk pcap times.
    assert _hms(_T_SENT) in text


def test_message_tab_merges_per_packet_rows():
    sent = _sent_flow(messages=[_msg("write", "Hi infected", 100, 1)])
    recv = _recv_flow(messages=[_msg("read", "hello folks", 200, 2)])
    for flow in (sent, recv):
        w = _widget()
        w._conversation_siblings = [sent, recv]
        w._render_message_tab(flow)
        text = _blob(w._message_log)
        assert "2 messages" in text
        assert text.index("Hi infected") < text.index("hello folks")


def test_message_tab_orders_by_timestamp():
    msgs = [_msg("read", "later", 200, 2), _msg("write", "earlier", 100, 1)]
    w = _widget()
    w._render_message_tab(_e2e_flow(messages=msgs))
    text = _blob(w._message_log)
    assert "2 messages" in text
    assert text.index("earlier") < text.index("later")


def test_message_tab_without_merge_still_dedupes_single_flow():
    a, _ = _legacy_pair()
    w = _widget()
    w._render_message_tab(a)
    assert "2 messages" in _blob(w._message_log)


# ---------------------------------------------------------------------------
# MainScreen sibling selection
# ---------------------------------------------------------------------------

def _stub(flow_id, transport, sid):
    return SimpleNamespace(flow_id=flow_id, transport=transport, ssl_session_id=sid,
                           src_addr="", src_port=0, dst_addr="", dst_port=0)


def test_telegram_e2e_siblings_share_session_id():
    from friTap.tui.screens.main_screen import MainScreen
    sid = f"telegram_e2e:{_FP}"
    flows = [_stub("a", "telegram_e2e", sid), _stub("b", "telegram_e2e", sid),
             _stub("c", "telegram_e2e", "telegram_e2e:other"),
             _stub("d", "mtproto", sid)]
    screen = MainScreen.__new__(MainScreen)
    screen._replay_ctrl = _FakeReplay(flows)
    sibs = screen._conversation_siblings(flows[0])
    assert {f.flow_id for f in sibs} == {"a", "b"}
    assert set(screen._replay_ctrl.loaded_ids) == {"a", "b"}


def test_telegram_e2e_siblings_live_mode():
    from friTap.tui.screens.main_screen import MainScreen
    sid = f"telegram_e2e:{_FP}"
    flows = [_stub("a", "telegram_e2e", sid), _stub("b", "telegram_e2e", sid),
             _stub("c", "tls", sid)]
    screen = MainScreen.__new__(MainScreen)
    screen._replay_ctrl = None
    screen._capture = SimpleNamespace(
        flow_collector=SimpleNamespace(get_flows=lambda: flows))
    assert {f.flow_id for f in screen._telegram_e2e_conversation_siblings(flows[0])} == {"a", "b"}


def test_conversation_siblings_dispatch_non_e2e_empty():
    from friTap.tui.screens.main_screen import MainScreen
    screen = MainScreen.__new__(MainScreen)
    screen._replay_ctrl = _FakeReplay([])
    assert screen._conversation_siblings(_stub("x", "tls", "s")) == []
    assert screen._telegram_e2e_conversation_siblings(_stub("y", "telegram_e2e", "")) == []
