#!/usr/bin/env python3

"""Tests for the helpers shared between the Telegram TUI modules.

Covers the canonical time / msg_id / ref-target formatters of
``tl_tree_render`` (and the thin delegates in ``telegram_panes`` and
``FlowDetailWidget``), the Telegram-layer helpers of
``telegram_conversation``, the flow-detail chunk-time / unparsed-side helpers,
and the Body Processing modal's table-driven shortcut toggles.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from types import SimpleNamespace

from friTap.flow import telegram_conversation as tconv
from friTap.flow.display import TELEGRAM_LAYER_NAMES
from friTap.flow.layer_pipeline import MESSAGE_TRANSPORTS
from friTap.flow.layers import MtprotoLayer, TelegramE2ELayer
from friTap.flow.models import Flow, FlowChunk
from friTap.tui.widgets import telegram_panes as tp
from friTap.tui.widgets import tl_tree_render as tr
from tests.unit._render_helpers import RenderingFakeLog as _FakeLog

_T = 1790358548.25


def _expected_millis(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


# ---------------------------------------------------------------------------
# tl_tree_render: time and msg_id formatting
# ---------------------------------------------------------------------------

def test_local_time_matches_strftime_millis_and_keeps_private_alias():
    assert tr.local_time(_T, millis=True) == _expected_millis(_T)
    assert tr.local_time(_T) == _expected_millis(_T)[:-4]
    assert tr._local_time is tr.local_time


def test_local_time_and_datetime_reject_out_of_range():
    assert tr.local_datetime(1e20) is None
    assert tr.local_time(1e20) == ""
    assert tr.local_datetime(_T) == datetime.fromtimestamp(_T)


def test_format_msg_id_uses_hex_and_derived_time():
    msg_id = (int(_T) << 32) | (1 << 31)
    text = tr.format_msg_id(msg_id)
    assert text.startswith(f"0x{msg_id:016x} [dim](")
    assert _expected_millis(int(_T) + 0.5) in text


def test_u64_mask_is_shared():
    assert tp._U64 == tr.U64_MASK == tr._U64 == (1 << 64) - 1


# ---------------------------------------------------------------------------
# tl_tree_render: ref targets
# ---------------------------------------------------------------------------

def test_ref_items_single_list_and_other():
    item = {"msg_id": 1}
    assert tr.ref_items(item) == [item]
    assert tr.ref_items([item, "x", 3]) == [item]
    assert tr.ref_items("x") == []
    assert tr._as_items is tr.ref_items


def test_ref_target_text_row_method_and_fallback():
    item = {"flow_id": "f1", "method": "account.getPrivacy"}
    assert tr.ref_target_text(item, lambda f: 7) == "#7 account.getPrivacy"
    assert tr.ref_target_text(item, lambda f: None) == "account.getPrivacy"
    fallback = lambda it, method: f"{method} <{it['flow_id']}>"  # noqa: E731
    assert tr.ref_target_text(item, lambda f: None, fallback) == "account.getPrivacy <f1>"
    assert tr.ref_target_text({"method": "m"}, lambda f: None, fallback) == "m"


def test_format_ref_item_escapes_the_fallback_tail():
    item = {"msg_id": 5, "flow_id": "f[bold]", "method": "m"}
    text = tr.format_ref_item(item, lambda f: None, lambda it, m: f"{m} ({it['flow_id']})")
    assert text == "msg 0x0000000000000005 → m (f\\[bold])"


def test_panes_ref_target_label_prefixes_flow_and_refs_lines_suffixes_it():
    item = {"msg_id": "0x10", "flow_id": "gone-flow", "method": "ping"}
    assert tp.ref_target_label(item, lambda f: None) == "→ flow gone-flow ping"
    assert tp.ref_target_label(item, lambda f: 3) == "→ #3 ping"
    assert tp.ref_target_label({"method": ""}, None) is None
    lines = tp.refs_lines(SimpleNamespace(refs={"answers": [item]}), lambda f: None)
    assert "→ ping (flow gone-flow)" in "\n".join(lines)


def test_refs_lines_matches_legacy_fallback_copy():
    refs = {"answers": [{"msg_id": "0x10", "flow_id": "gone", "method": "ping"}],
            "acked_by": [{"msg_id": "0x11", "flow_id": "seen"}], "request_method": "x"}
    row_of = {"seen": 4}.get
    legacy = tr.render_refs(tp._with_fallback_targets(refs, row_of), row_of)
    assert tp.refs_lines(SimpleNamespace(refs=refs), row_of) == legacy


# ---------------------------------------------------------------------------
# telegram_conversation
# ---------------------------------------------------------------------------

def test_telegram_layer_names_match_message_transports():
    assert set(TELEGRAM_LAYER_NAMES) == set(MESSAGE_TRANSPORTS)
    assert tconv._CHAT_LAYER_NAMES == TELEGRAM_LAYER_NAMES
    assert tconv._OUTBOUND_DIRECTIONS is tconv.OUTBOUND_DIRECTIONS


def test_as_int_parses_or_returns_zero():
    assert tconv.as_int("12") == 12
    assert tconv.as_int(None) == 0
    assert tconv.as_int("x") == 0
    assert tconv._as_int is tconv.as_int


def test_telegram_layers_of_orders_cloud_then_e2e():
    flow = Flow(flow_id="f", transport="telegram_e2e")
    flow.add_layer(TelegramE2ELayer())
    flow.add_layer(MtprotoLayer())
    assert [lyr.name for lyr in tconv.telegram_layers_of(flow)] == ["mtproto", "telegram_e2e"]
    assert tconv.telegram_layers_of(SimpleNamespace()) == []


def test_conversation_keys_of_entries_ignores_non_chat_text():
    entries = [{"kind": "text", "body": "hi", "direction": "write", "peer_id": 9},
               {"kind": "user", "body": "u", "direction": "write", "peer_id": 8},
               {"kind": "text", "body": "", "direction": "write", "peer_id": 7}]
    assert tconv.conversation_keys_of_entries(entries) == {"9"}


# ---------------------------------------------------------------------------
# FlowDetailWidget helpers
# ---------------------------------------------------------------------------

def _widget():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    w = FlowDetailWidget.__new__(FlowDetailWidget)
    w._current_flow = None
    w._active_processing = None
    w._conversation_siblings = []
    w._row_resolver = None
    return w


def _chunked_flow() -> Flow:
    flow = Flow(flow_id="c", transport="mtproto")
    for data, direction, ts in ((b"a", "write", 0.0), (b"b", "write", 10.0),
                                (b"c", "read", 11.0), (b"d", "write", 12.0)):
        flow.chunks.append(FlowChunk(data, direction, ts))
    return flow


def test_chunk_times_first_and_nth_clamped():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget as W
    flow = _chunked_flow()
    assert W._chunk_times(flow, "write") == [10.0, 12.0]
    assert W._first_chunk_time(flow, "write") == 10.0
    assert W._nth_chunk_time(flow, "write", 5) == 12.0
    assert W._nth_chunk_time(flow, "nope", 0) == 0.0
    assert W._clamped_time([], 3) == 0.0


def test_backfill_uses_per_source_direction_chunk_times():
    w = _widget()
    flow = _chunked_flow()
    msgs = [{"direction": "write", "body": "1"}, {"direction": "write", "body": "2"},
            {"direction": "read", "body": "3"}, {"direction": "write", "timestamp": 99}]
    out = w._backfill_chunk_timestamps(msgs, {id(m): flow for m in msgs})
    assert [m["timestamp"] for m in out] == [10.0, 12.0, 11.0, 99]


def test_format_pane_time_delegates_to_local_time():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget as W
    assert W._format_pane_time(_T) == _expected_millis(_T)
    assert W._format_pane_time(0) == "" and W._format_pane_time(-1) == ""


def test_msg_datetime_seconds_and_millis():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget as W
    assert W._msg_datetime(int(_T), secs=True) == datetime.fromtimestamp(int(_T))
    assert W._msg_datetime(int(_T) * 1000) == datetime.fromtimestamp(int(_T))
    assert W._msg_datetime("x") is None and W._msg_datetime(0) is None


def test_render_unparsed_side_notes_and_empty_side():
    w = _widget()
    flow = Flow(flow_id="u", transport="")
    flow.chunks.append(FlowChunk(b"hello", "write", 1.0))
    log = _FakeLog(width=120)
    w._render_unparsed_side(log, flow, "write", "Request")
    assert "Request headers could not be parsed" in "\n".join(log.lines)
    empty = _FakeLog(width=120)
    w._render_unparsed_side(empty, flow, "read", "Response")
    assert empty.lines == ["No response data captured"]


def test_structured_self_id_uses_precomputed_users():
    w = _widget()
    users = [{"id": "77", "flags": ["self"]}]
    assert w._structured_self_id([], users) == 77
    assert w._structured_self_id([], []) == 0


# ---------------------------------------------------------------------------
# Body Processing modal shortcut table
# ---------------------------------------------------------------------------

def test_toggle_keys_hint_derived_from_option_tables():
    from friTap.tui.modals import body_processing_modal as bpm
    assert bpm._toggle_keys_hint() == "1-9/t"


def test_toggle_by_key_toggles_decompression_and_decoder():
    from friTap.tui.app import FriTapApp
    from friTap.tui.modals.body_processing_modal import BodyProcessingModal
    seen = {}

    async def _main() -> None:
        app = FriTapApp()
        async with app.run_test(size=(120, 40)) as pilot:
            modal = BodyProcessingModal()
            await app.push_screen(modal)
            await pilot.pause()
            modal.action_toggle_1()
            modal.action_toggle_tl()
            await pilot.pause()
            seen["on"] = (modal._decompression, modal._decoder, modal.focused.id)
            modal.action_toggle_1()
            seen["off"] = modal._decompression

    asyncio.run(_main())
    assert seen["on"] == ("gzip", "tl", "btn-apply")
    assert seen["off"] is None
