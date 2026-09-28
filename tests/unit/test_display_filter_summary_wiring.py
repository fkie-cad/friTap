"""Wiring of the precomputed display-filter inputs into both FlowSummary types.

``filter_attrs`` / ``protocols`` must come out the same for a live flow
(``models.FlowSummary.from_flow``), a decoded .tap row
(``tap_format.decode_flow_summary``) and the synthetic replay flow the TUI
rebuilds from that row (``models.FlowSummary.from_tap_summary``).
"""

from __future__ import annotations

import copy
import dataclasses
import pickle
from pathlib import Path

import pytest

from friTap.flow.layers import MtprotoLayer, TelegramE2ELayer
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.models import FlowSummary as LiveSummary
from friTap.flow.tap_format import FlowSummary as TapSummary
from friTap.flow.tap_format import decode_flow_summary, encode_flow
from tests.unit._display_filter_helpers import tg_message as _tg_message

REPO_ROOT = Path(__file__).resolve().parents[2]
E2E_TAP = REPO_ROOT / "e2e.tap"


def _telegram_flow() -> Flow:
    flow = Flow(flow_id="f1", connection_id="c1", transport="mtproto")
    flow.chunks.append(FlowChunk(data=b"x", direction="read", timestamp=1.0))
    flow._total_bytes = 1
    mtproto = MtprotoLayer(transport="intermediate", dc_id=2, message_count=1)
    mtproto.messages = [_tg_message("messages.sendMessage", "hello", peer_id=777)]
    e2e = TelegramE2ELayer(chat_id=12345, key_fingerprint="ff00", message_count=1)
    e2e.messages = [_tg_message("decryptedMessage", "secret hi")]
    flow.add_layer(mtproto)
    flow.add_layer(e2e)
    return flow


def test_live_summary_carries_filter_attrs_and_protocols():
    summary = LiveSummary.from_flow(_telegram_flow())

    assert isinstance(summary.filter_attrs, dict)
    assert summary.filter_attrs["mtproto.method"] == ("messages.sendMessage",)
    assert summary.filter_attrs["telegram_e2e.chat_id"] == (12345,)
    assert {"mtproto", "telegram_e2e"} <= summary.protocols


def test_live_summary_is_still_hashable_and_comparable():
    flow = _telegram_flow()
    first, second = LiveSummary.from_flow(flow), LiveSummary.from_flow(flow)

    hash(first)  # a dict is unhashable; the field is excluded from hash()
    assert hash(first) == hash(second)
    assert first.filter_attrs == second.filter_attrs


def _both_summaries():
    flow = _telegram_flow()
    tap = decode_flow_summary(encode_flow(flow))
    return [LiveSummary.from_flow(flow), tap, LiveSummary(), TapSummary()]


@pytest.mark.parametrize("index", range(4))
def test_summary_pickles(index):
    summary = _both_summaries()[index]

    restored = pickle.loads(pickle.dumps(summary))

    assert restored == summary
    assert dict(restored.filter_attrs) == dict(summary.filter_attrs)


@pytest.mark.parametrize("index", range(4))
def test_summary_deepcopies(index):
    summary = _both_summaries()[index]

    clone = copy.deepcopy(summary)

    assert clone == summary
    assert clone.filter_attrs is not summary.filter_attrs or not summary.filter_attrs


@pytest.mark.parametrize("index", range(4))
def test_summary_asdict(index):
    summary = _both_summaries()[index]

    as_dict = dataclasses.asdict(summary)

    assert as_dict["filter_attrs"] == dict(summary.filter_attrs)


def test_from_flow_copies_given_filter_attrs():
    tap_summary = decode_flow_summary(encode_flow(_telegram_flow()))
    flow = Flow(flow_id=tap_summary.flow_id)

    summary = LiveSummary.from_flow(flow, filter_attrs=tap_summary.filter_attrs)

    assert summary.filter_attrs == tap_summary.filter_attrs
    assert summary.filter_attrs is not tap_summary.filter_attrs


def test_from_flow_given_filter_attrs_skip_extraction_but_not_protocols():
    flow = _telegram_flow()

    summary = LiveSummary.from_flow(flow, filter_attrs={})

    assert dict(summary.filter_attrs) == {}
    assert {"mtproto", "telegram_e2e"} <= summary.protocols


def test_filter_attrs_key_tracks_scalar_and_message_changes():
    from friTap.filter.layer_fields import filter_attrs_key

    flow = _telegram_flow()
    key = filter_attrs_key(flow)
    assert filter_attrs_key(flow) == key

    flow.layer("mtproto").dc_id = 99
    changed = filter_attrs_key(flow)
    assert changed != key

    flow.layer("mtproto").messages.append(_tg_message("help.getConfig", "x"))
    assert filter_attrs_key(flow) != changed


def test_live_summary_defaults_are_empty():
    summary = LiveSummary()

    assert dict(summary.filter_attrs) == {}
    assert summary.protocols == frozenset()


def test_from_flow_does_not_grow_layer_stack():
    flow = _telegram_flow()
    before = [ly.name for ly in flow.layers]

    LiveSummary.from_flow(flow)

    assert [ly.name for ly in flow.layers] == before


def test_tap_round_trip_matches_live_summary():
    flow = _telegram_flow()
    live = LiveSummary.from_flow(flow)

    decoded = decode_flow_summary(encode_flow(flow))

    assert dict(decoded.filter_attrs) == dict(live.filter_attrs)
    assert decoded.protocols == live.protocols


def test_tap_from_flow_matches_live_summary():
    flow = _telegram_flow()

    tap = TapSummary.from_flow(flow)

    assert dict(tap.filter_attrs) == dict(LiveSummary.from_flow(flow).filter_attrs)
    assert {"mtproto", "telegram_e2e"} <= tap.protocols


def test_decode_without_layers_falls_back_to_protocol_labels():
    flow = Flow(flow_id="f2", transport="mtproto")
    flow.chunks.append(FlowChunk(data=b"x", direction="read", timestamp=1.0))

    decoded = decode_flow_summary(encode_flow(flow))

    assert dict(decoded.filter_attrs) == {}
    assert "mtproto" in decoded.protocols


def test_decode_derives_has_ohttp_from_meta():
    from friTap.parsers.base import ParseResult

    flow = Flow(flow_id="f3")
    flow.ohttp_inner_request = ParseResult(protocol="bhttp", is_request=True)

    decoded = decode_flow_summary(encode_flow(flow))

    assert decoded.has_ohttp is True
    assert "ohttp" in decoded.protocols


def _synthetic_replay_flow(tap_summary: TapSummary) -> Flow:
    """Mirror of the MainScreen replay population's layerless flow."""
    return Flow(flow_id=tap_summary.flow_id, state=FlowState.COMPLETE,
                transport=tap_summary.transport)


def test_from_tap_summary_uses_decoded_filter_inputs():
    tap_summary = decode_flow_summary(encode_flow(_telegram_flow()))

    summary = LiveSummary.from_tap_summary(
        tap_summary, _synthetic_replay_flow(tap_summary))

    assert summary.filter_attrs["mtproto.method"] == ("messages.sendMessage",)
    assert {"mtproto", "telegram_e2e"} <= summary.protocols


def test_from_tap_summary_carries_has_ohttp():
    tap_summary = TapSummary(flow_id="f4", has_ohttp=True)

    summary = LiveSummary.from_tap_summary(
        tap_summary, _synthetic_replay_flow(tap_summary))

    assert summary.has_ohttp is True
    assert summary.ohttp_inner_request is not None


def test_from_tap_summary_adds_reparsed_protocols():
    from friTap.parsers.base import ParseResult

    tap_summary = TapSummary(flow_id="f5", protocols=frozenset({"tls"}))
    flow = _synthetic_replay_flow(tap_summary)
    flow.request = ParseResult(protocol="HTTP/1.1", is_request=True)

    summary = LiveSummary.from_tap_summary(tap_summary, flow)

    assert {"tls", "http1"} <= summary.protocols


def test_tap_from_flow_derives_has_ohttp():
    from friTap.parsers.base import ParseResult

    flow = Flow(flow_id="f6")
    flow.ohttp_inner_response = ParseResult(protocol="bhttp")

    assert TapSummary.from_flow(flow).has_ohttp is True


@pytest.mark.skipif(not E2E_TAP.exists(), reason="e2e.tap not present in repo root")
def test_real_e2e_tap_summaries_are_filterable():
    from friTap.flow.tap_reader import TapReader

    with TapReader(str(E2E_TAP)) as reader:
        summaries = reader.read_flow_summaries()

    assert any(s.filter_attrs.get("mtproto.method") for s in summaries)
    assert any("mtproto" in s.protocols for s in summaries)
    assert any("telegram_e2e" in s.protocols for s in summaries)
