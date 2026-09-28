"""``frame`` content search: searchable-bytes builder, content index, flow list
wiring and TapReader thread-safety."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from friTap.filter.content_index import FlowContentIndex, build_searchable_bytes
from friTap.filter.evaluator import FilterEngine
from friTap.flow.layers import MtprotoLayer, SignalLayer, TelegramE2ELayer
from friTap.flow.models import Flow, FlowChunk, FlowSummary
from friTap.parsers.base import ParseResult

REPO_ROOT = Path(__file__).resolve().parents[2]
E2E_TAP = REPO_ROOT / "e2e.tap"


def _flow(flow_id: str = "f1", write: bytes = b"", read: bytes = b"") -> Flow:
    flow = Flow(flow_id=flow_id)
    if write:
        flow.chunks.append(FlowChunk(write, "write", 0.0))
    if read:
        flow.chunks.append(FlowChunk(read, "read", 0.0))
    flow._total_bytes = len(write) + len(read)
    return flow


class _CountingLookup:
    def __init__(self, flows):
        self.flows = {f.flow_id: f for f in flows}
        self.calls: list[str] = []

    def __call__(self, flow_id):
        self.calls.append(flow_id)
        return self.flows.get(flow_id)


# -- build_searchable_bytes ---------------------------------------------------

class TestBuildSearchableBytes:
    def test_both_directions_lowercased(self):
        text = build_searchable_bytes(_flow(write=b"GET /Hello", read=b"World OK"))
        assert b"get /hello" in text and b"world ok" in text

    def test_binary_chunks_survive(self):
        text = build_searchable_bytes(_flow(read=b"\x00\xffABC\x80"))
        assert b"\x00\xffabc\x80" in text

    def test_headers_and_present_bodies(self):
        flow = _flow()
        flow.request = ParseResult(protocol="http/1.1", headers={"X-Token": "SeCrEt"},
                                   body=b"Req-Body")
        flow.response = ParseResult(protocol="http/1.1", body=b"")
        text = build_searchable_bytes(flow)
        assert b"x-token: secret" in text and b"req-body" in text

    def test_ohttp_and_trailing_bytes(self):
        flow = _flow()
        flow.ohttp_inner_request = ParseResult(protocol="bhttp", body=b"InnerPayload")
        flow.trailing_bytes = b"TrailW"
        flow.response_trailing_bytes = b"TrailR"
        text = build_searchable_bytes(flow)
        for needle in (b"innerpayload", b"trailw", b"trailr"):
            assert needle in text

    def test_layer_message_bodies(self):
        flow = _flow(read=b"\x01\x02")
        mt = MtprotoLayer()
        mt.messages = [{"kind": "message", "body": "Hi From MTProto"}, {"kind": "x"}]
        sig = SignalLayer()
        sig.messages = [{"body": "Signal Über text"}]
        e2e = TelegramE2ELayer()
        e2e.messages = [{"body": None}, "not-a-dict"]
        flow.layers.extend([mt, sig, e2e])
        text = build_searchable_bytes(flow)
        assert b"hi from mtproto" in text
        # Non-ASCII letters are case-folded like the parser folds the needle.
        assert "signal über text".encode() in text

    def test_does_not_autocreate_layers(self):
        flow = _flow(write=b"abc")
        build_searchable_bytes(flow)
        assert flow.layers == []

    def test_owned_layer_bytes(self):
        flow = _flow()
        layer = SignalLayer()
        layer.data.set_owned(read=b"OwnedRead", write=b"OwnedWrite")
        flow.layers.append(layer)
        text = build_searchable_bytes(flow)
        assert b"ownedread" in text and b"ownedwrite" in text

    def test_utf8_chunk_folded_despite_binary_sibling_chunk(self):
        flow = _flow(read=b"\xff\xfe binary")
        flow.chunks.append(FlowChunk("Über alles".encode(), "read", 1.0))
        text = build_searchable_bytes(flow)
        assert "über alles".encode() in text
        assert b"\xff\xfe binary" in text

    def test_mixed_direction_matches_non_ascii_needle(self):
        flow = _flow("m", write=b"\x80\x81")
        flow.chunks.append(FlowChunk("Grüße ÜBER".encode(), "write", 1.0))
        index = FlowContentIndex()
        assert FilterEngine('frame contains "über"').matches(flow, ctx=index)

    def test_needle_spanning_chunk_boundary_matches(self):
        flow = _flow(write=b"HEL")
        flow.chunks.append(FlowChunk(b"LO", "write", 1.0))
        assert b"hello" in build_searchable_bytes(flow)

    def test_chunk_accumulation_stops_at_cap(self):
        class _Chunk:
            direction = "write"

            def __init__(self, data, touched):
                self._data, self._touched = data, touched

            @property
            def data(self):
                self._touched.append(1)
                return self._data

        touched: list = []
        flow = _flow()
        flow.chunks.extend(_Chunk(b"A" * 10, touched) for _ in range(1000))
        text = build_searchable_bytes(flow, cap=50)
        assert len(text) == 50
        assert len(touched) == 5  # stops reading once the cap is reached

    def test_cap_respects_direction(self):
        flow = _flow(write=b"W" * 30, read=b"R" * 30)
        flow.chunks.insert(0, FlowChunk(b"r" * 5, "read", 0.0))
        text = build_searchable_bytes(flow, cap=1000)
        assert text == b"w" * 30 + b"\n" + b"r" * 35

    def test_cap(self):
        text = build_searchable_bytes(_flow(write=b"A" * 1000), cap=100)
        assert len(text) == 100

    def test_never_raises(self):
        class Broken:
            @property
            def chunks(self):
                raise RuntimeError("boom")
        assert build_searchable_bytes(Broken()) == b""
        assert build_searchable_bytes(None) == b""


# -- FlowContentIndex ---------------------------------------------------------

class TestFlowContentIndex:
    def test_caches_per_size(self):
        flow = _flow("a", write=b"Hello")
        lookup = _CountingLookup([flow])
        index = FlowContentIndex(lookup)
        summary = FlowSummary.from_flow(flow)
        assert index.text_for(summary) == b"hello"
        assert index.text_for(summary) == b"hello"
        assert lookup.calls == ["a"]

        flow.chunks.append(FlowChunk(b" More", "write", 1.0))
        flow._total_bytes += 5
        grown = FlowSummary.from_flow(flow)
        assert index.text_for(grown) == b"hello more"
        assert lookup.calls == ["a", "a"]
        assert len(index) == 1  # stale size entry replaced

    def test_lookup_none(self):
        index = FlowContentIndex(lambda _id: None)
        assert index.text_for(FlowSummary(flow_id="x", total_bytes=3)) is None
        assert FlowContentIndex().text_for(FlowSummary(flow_id="x")) is None

    def test_full_flow_needs_no_lookup(self):
        assert FlowContentIndex().text_for(_flow("a", write=b"XY")) == b"xy"

    def test_lru_eviction_by_budget(self):
        flows = [_flow(str(i), write=bytes([65 + i]) * 40) for i in range(3)]
        lookup = _CountingLookup(flows)
        index = FlowContentIndex(lookup, max_bytes=100)
        s0, s1, s2 = (FlowSummary.from_flow(f) for f in flows)
        index.text_for(s0)
        index.text_for(s1)
        index.text_for(s0)          # s0 becomes most recently used
        index.text_for(s2)          # evicts s1 (LRU)
        assert index.used_bytes <= 100
        lookup.calls.clear()
        index.text_for(s0)
        assert lookup.calls == []
        index.text_for(s1)
        assert lookup.calls == ["1"]

    def test_invalidate_and_clear(self):
        flow = _flow("a", write=b"x")
        lookup = _CountingLookup([flow])
        index = FlowContentIndex(lookup)
        summary = FlowSummary.from_flow(flow)
        index.text_for(summary)
        index.invalidate("a")
        index.text_for(summary)
        index.clear()
        assert index.used_bytes == 0
        index.text_for(summary)
        assert lookup.calls == ["a", "a", "a"]

    def test_filter_engine_end_to_end(self):
        flow = _flow("a", write=b"say Hello there", read=b"\x00\x01")
        index = FlowContentIndex(_CountingLookup([flow]))
        summary = FlowSummary.from_flow(flow)
        assert FilterEngine('frame contains "Hello"').matches(summary, ctx=index)
        assert not FilterEngine('frame contains "Goodbye"').matches(summary, ctx=index)
        assert FilterEngine('frame matches "hel+o"').matches(summary, ctx=index)
        # Without a context the frame field has no value.
        assert not FilterEngine('frame contains "Hello"').matches(summary)


# -- FlowListWidget wiring ----------------------------------------------------

def _make_flow_list():
    """A FlowListWidget whose DataTable I/O is stubbed (no running app)."""
    from friTap.tui.widgets.flow_list import FlowListWidget

    class _StubFlowList(FlowListWidget):
        def add_row(self, *values, key=None):
            self.rows_added.append(key)
            return key

        def clear(self, columns: bool = False):
            self.rows_added = []
            return self

        def remove_row(self, row_key):
            self.rows_added.remove(row_key)

        def update_cell(self, *args, **kwargs):
            pass

    widget = _StubFlowList()
    widget.rows_added = []
    widget._auto_scroll = False
    return widget


class _SpyEngine:
    """Wraps a FilterEngine, counting evaluations per flow id."""

    def __init__(self, expression: str):
        self._engine = FilterEngine(expression)
        self.calls: dict[str, int] = {}
        self.ctx_seen: list = []

    @property
    def needs_context(self):
        return self._engine.needs_context

    def matches(self, flow, ctx=None):
        self.calls[flow.flow_id] = self.calls.get(flow.flow_id, 0) + 1
        self.ctx_seen.append(ctx)
        return self._engine.matches(flow, ctx)


class TestFlowListFrameFilter:
    def _populated(self):
        flows = [_flow("a", write=b"Hello world"), _flow("b", write=b"nothing here"),
                 _flow("c", read=b"HELLO again")]
        widget = _make_flow_list()
        lookup = _CountingLookup(flows)
        widget.set_flow_lookup(lookup)
        for flow in flows:
            widget.add_or_update_flow(flow)
        return widget, flows, lookup

    def test_frame_filter_rows_and_single_evaluation(self):
        widget, _flows, _lookup = self._populated()
        spy = _SpyEngine('frame contains "hello"')
        widget.set_filter(spy)
        assert widget.rows_added == ["a", "c"]
        assert widget.visible_count == 2
        assert spy.calls == {"a": 1, "b": 1, "c": 1}
        assert all(ctx is widget.content_index for ctx in spy.ctx_seen)

    def test_cheap_filter_loads_no_content(self):
        widget, _flows, lookup = self._populated()
        spy = _SpyEngine('protocol == "unknown"')
        widget.set_filter(spy)
        assert lookup.calls == []
        assert len(widget.content_index) == 0

    def test_count_matches_ignores_active_filter(self):
        widget, _flows, _lookup = self._populated()
        widget.set_filter(FilterEngine('frame contains "nothing"'))
        assert widget.visible_count == 1
        assert widget.count_matches(FilterEngine('frame contains "hello"')) == 2
        assert widget.count_matches(FilterEngine('frame contains "zzz"')) == 0

    def test_live_update_invalidates_content(self):
        widget, flows, lookup = self._populated()
        widget.set_filter(FilterEngine('frame contains "late word"'))
        assert widget.visible_count == 0
        flow_b = flows[1]
        flow_b.chunks.append(FlowChunk(b" LATE WORD", "read", 1.0))
        flow_b._total_bytes += 10
        widget.add_or_update_flow(flow_b)
        assert widget.visible_count == 1
        assert widget.content_index.text_for(FlowSummary.from_flow(flow_b)).endswith(b"late word")

    def test_same_size_layer_change_rebuilds_summary_and_content(self):
        widget, flows, _lookup = self._populated()
        flow_b = flows[1]
        widget.set_filter(FilterEngine('frame contains "decoded later"'))
        assert widget.visible_count == 0
        stale = widget._all_flow_data["b"]
        # MTProto message decoded after the fact: no byte change.
        layer = MtprotoLayer()
        layer.messages = [{"kind": "text", "body": "Decoded Later",
                           "method": "messages.sendMessage"}]
        flow_b.layers.append(layer)
        widget.add_or_update_flow(flow_b)
        fresh = widget._all_flow_data["b"]
        assert fresh is not stale
        assert "mtproto" in fresh.protocols
        assert fresh.filter_attrs.get("mtproto.method") == ("messages.sendMessage",)
        assert widget.visible_count == 1

    def test_new_message_on_existing_layer_rebuilds(self):
        widget, flows, _lookup = self._populated()
        flow_b = flows[1]
        layer = MtprotoLayer()
        layer.messages = [{"kind": "text", "body": "one", "method": "a.first"}]
        flow_b.layers.append(layer)
        widget.add_or_update_flow(flow_b)
        widget.set_filter(FilterEngine('frame contains "two"'))
        assert widget.visible_count == 0
        layer.messages.append({"kind": "text", "body": "two", "method": "a.second"})
        widget.add_or_update_flow(flow_b)
        assert widget.visible_count == 1

    def test_unchanged_flow_reuses_summary(self):
        widget, flows, lookup = self._populated()
        before = widget._all_flow_data["a"]
        widget.add_or_update_flow(flows[0])
        assert widget._all_flow_data["a"] is before

    def test_layer_signature_does_not_autocreate_layers(self):
        from friTap.tui.widgets.flow_list import layer_signature

        flow = _flow(write=b"x")
        layer_signature(flow)
        assert flow.layers == []

    def test_clear_flows_clears_index(self):
        widget, _flows, _lookup = self._populated()
        widget.count_matches(FilterEngine('frame contains "x"'))
        assert len(widget.content_index) == 3
        widget.clear_flows()
        assert len(widget.content_index) == 0


# -- Real data: e2e.tap -------------------------------------------------------

@pytest.mark.skipif(not E2E_TAP.exists(), reason="repo-root e2e.tap not present")
class TestE2ETapContentSearch:
    def test_frame_contains_decoded_message_word(self):
        from friTap.flow.replay import ReplayController

        ctrl = ReplayController(str(E2E_TAP))
        ctrl.load()
        summaries = ctrl.get_summaries()
        index = FlowContentIndex(ctrl.get_flow)
        # "together" appears in a decrypted Telegram E2E message body
        # ("hi together"); "Forscher" in an MTProto contact line.
        for word in ("together", "Forscher"):
            engine = FilterEngine(f'frame contains "{word}"')
            started = time.perf_counter()
            cold = sum(engine.matches(s, ctx=index) for s in summaries)
            cold_ms = (time.perf_counter() - started) * 1000
            started = time.perf_counter()
            warm = sum(engine.matches(s, ctx=index) for s in summaries)
            warm_ms = (time.perf_counter() - started) * 1000
            print(f"\ne2e.tap frame contains {word!r}: {cold} matches / "
                  f"{len(summaries)} flows, cold {cold_ms:.1f} ms, warm {warm_ms:.1f} ms, "
                  f"index {index.used_bytes} bytes")
            assert cold > 0
            assert warm == cold
        assert FilterEngine('frame contains "zq-no-such-word-zq"').matches(
            summaries[0], ctx=index) is False

    def test_tap_reader_concurrent_get_flow(self):
        from friTap.flow.tap_reader import TapReader

        reader = TapReader(str(E2E_TAP))
        reader.open()
        try:
            flow_ids = list(reader._flow_offsets)
            expected = {fid: reader.read_flow(fid).flow_id for fid in flow_ids[:40]}
            errors: list[BaseException] = []
            mismatches: list[str] = []

            def worker(ids):
                try:
                    for _ in range(5):
                        for fid in ids:
                            flow = reader.read_flow(fid)
                            if flow is None or flow.flow_id != expected[fid]:
                                mismatches.append(fid)
                except BaseException as exc:  # pragma: no cover - failure path
                    errors.append(exc)

            ids = list(expected)
            threads = [threading.Thread(target=worker, args=(ids,)),
                       threading.Thread(target=worker, args=(ids[::-1],))]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)
            assert not errors
            assert not mismatches
        finally:
            reader.close()
