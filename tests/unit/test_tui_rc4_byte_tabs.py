#!/usr/bin/env python3

"""RC4-in-TLS flow detail: Wireshark-style per-layer byte tabs and the
layered protocol tree in the Layers tab."""

import asyncio

import pytest

pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.widgets import RichLog  # noqa: E402

from friTap.flow.models import Flow, FlowChunk, FlowState, TlsMetadata  # noqa: E402
from friTap.tui.widgets.flow_detail import FlowDetailWidget  # noqa: E402

RC4_WRITE = b"\x00\x01\x02\x03" + b"\xfe" * 22
RC4_READ = b"\x40\x41\x42\x43" + b"\xff" * 60
TLS_WRITE = b"\x00\x00\x00\x1a" + b"\xaa" * 26
TLS_READ = b"\x00\x00\x00\x40" + b"\xbb" * 64
BYTE_TAB_IDS = [f"tab-bytes-{i}" for i in range(4)]


def _rc4_in_tls_flow() -> Flow:
    flow = Flow(flow_id="rc4tls", state=FlowState.COMPLETE, transport="rc4")
    flow.chunks.append(FlowChunk(data=RC4_WRITE, direction="write", timestamp=1.0, function="rc4"))
    flow.chunks.append(FlowChunk(data=RC4_READ, direction="read", timestamp=2.0, function="rc4"))
    flow.set_layer(TlsMetadata(library="SChannel", version="TLS 1.2"))
    flow.tls.data.set_owned(read=TLS_READ, write=TLS_WRITE)
    rc4 = flow.rc4  # registry-created: chunk-backed data
    rc4.source, rc4.key_len, rc4.framing = "RC4_set_key", 16, "u32be-length"
    rc4.records = [
        {"direction": "write", "length": 26, "tls_frames": [22, 26],
         "timestamp": 1.0, "cipher_offset": 4, "frame_header_len": 4},
        {"direction": "read", "length": 64, "tls_frames": [28],
         "timestamp": 2.0, "cipher_offset": 34, "frame_header_len": 4},
    ]
    return flow


def _plain_tls_flow() -> Flow:
    flow = Flow(flow_id="plain", state=FlowState.COMPLETE)
    flow.chunks.append(FlowChunk(data=b"GET / HTTP/1.1\r\n\r\n", direction="write", timestamp=1.0))
    flow.tls.version = "TLS 1.3"
    return flow


class _DetailApp(App):
    def compose(self):
        yield FlowDetailWidget(id="detail")


def _richlog_text(log: RichLog) -> str:
    deferred = getattr(log, "_deferred_renders", None)
    if deferred:
        return "\n".join(str(getattr(d, "content", d)) for d in deferred)
    return "".join(
        "".join(seg.text for seg in line._segments) + "\n" for line in log.lines
    )


def _visible_byte_tabs(widget: FlowDetailWidget) -> dict:
    tabs = {}
    for pane_id in BYTE_TAB_IDS:
        tab = widget._tabs.get_tab(pane_id)
        if not tab.has_class("-hidden"):
            tabs[pane_id] = str(tab.label)
    return tabs


def _run_with_widget(body) -> None:
    async def _run() -> None:
        app = _DetailApp()
        async with app.run_test() as pilot:
            widget = app.query_one("#detail", FlowDetailWidget)
            await pilot.pause()
            await body(widget, pilot)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_byte_sources_orders_outer_to_inner_with_labels():
    widget = FlowDetailWidget()
    labels = [label for _, label in widget._byte_sources(_rc4_in_tls_flow())]
    assert labels == ["Decrypted TLS (98 bytes)", "Decrypted RC4 (90 bytes)"]


def test_byte_sources_single_layer_for_plain_flow():
    widget = FlowDetailWidget()
    assert len(widget._byte_sources(_plain_tls_flow())) <= 1


def test_tree_prefix_indents_by_depth():
    assert FlowDetailWidget._tree_prefix(0) == ""
    assert FlowDetailWidget._tree_prefix(1) == "└─ "
    assert FlowDetailWidget._tree_prefix(2) == "  └─ "


def test_record_frames_text_singular_and_plural():
    assert FlowDetailWidget._record_frames_text([28]) == "from TLS frame #28"
    assert FlowDetailWidget._record_frames_text([22, 26]) == "reassembled from TLS frames #22, #26"
    assert FlowDetailWidget._record_frames_text([]) == ""


def test_record_framing_text_uses_frame_header_offset():
    record = {"cipher_offset": 34, "frame_header_len": 4}
    assert FlowDetailWidget._record_framing_text(record, "u32be-length") == \
        "u32be-length framed @offset 30"
    assert FlowDetailWidget._record_framing_text(record, "") == ""


# ---------------------------------------------------------------------------
# Textual pilot
# ---------------------------------------------------------------------------

def test_rc4_flow_shows_two_labelled_byte_tabs():
    async def body(widget, pilot):
        widget.show_flow(_rc4_in_tls_flow())
        await pilot.pause()
        assert _visible_byte_tabs(widget) == {
            "tab-bytes-0": "Decrypted TLS (98 bytes)",
            "tab-bytes-1": "Decrypted RC4 (90 bytes)",
        }

    _run_with_widget(body)


def test_byte_tab_content_has_per_direction_hexdump():
    async def body(widget, pilot):
        widget.show_flow(_rc4_in_tls_flow())
        widget._tabs.active = "tab-bytes-0"
        await pilot.pause()
        text = _richlog_text(widget._byte_logs["tab-bytes-0"])
        assert "00 00 00 1a" in text
        assert "→ client→server (30 bytes)" in text
        assert "← server→client (68 bytes)" in text

        widget._tabs.active = "tab-bytes-1"
        await pilot.pause()
        rc4_text = _richlog_text(widget._byte_logs["tab-bytes-1"])
        assert "00 01 02 03" in rc4_text
        assert "→ client→server (26 bytes)" in rc4_text

    _run_with_widget(body)


def test_layers_tab_renders_tree_and_records():
    async def body(widget, pilot):
        flow = _rc4_in_tls_flow()
        widget.show_flow(flow)
        widget._render_layers_tab(flow)
        await pilot.pause()
        text = _richlog_text(widget._layers_log)
        assert "[0] tls" in text
        assert "└─ [1] rc4" in text
        assert "reassembled from TLS frames #22, #26" in text
        assert "from TLS frame #28" in text
        assert "u32be-length framed @offset 0" in text
        assert "records:" in text and "'tls_frames'" not in text

    _run_with_widget(body)


def test_plain_flow_shows_no_byte_tabs():
    async def body(widget, pilot):
        widget.show_flow(_plain_tls_flow())
        await pilot.pause()
        assert _visible_byte_tabs(widget) == {}

    _run_with_widget(body)


def test_switching_to_plain_flow_hides_stale_byte_tabs():
    async def body(widget, pilot):
        widget.show_flow(_rc4_in_tls_flow())
        widget._tabs.active = "tab-bytes-1"
        await pilot.pause()
        widget.show_flow(_plain_tls_flow())
        await pilot.pause()
        assert _visible_byte_tabs(widget) == {}
        assert not widget._tabs.active.startswith("tab-bytes-")

    _run_with_widget(body)


def test_request_and_response_tabs_show_rc4_plaintext():
    async def body(widget, pilot):
        flow = _rc4_in_tls_flow()
        widget.show_flow(flow)
        widget._update_request(flow)
        widget._update_response(flow)
        await pilot.pause()
        assert "00 01 02 03" in _richlog_text(widget._request_log)
        assert "40 41 42 43" in _richlog_text(widget._response_log)

    _run_with_widget(body)


# ---------------------------------------------------------------------------
# Regressions found on real captures
# ---------------------------------------------------------------------------

def _plain_http_over_tls_flow() -> Flow:
    """TLS + HTTP/1.x layers both view the same chunks (dump_premaster case)."""
    from friTap.flow.layers import AppLayer, LayerData

    flow = _plain_tls_flow()
    http = AppLayer(data=LayerData(data_source="chunks"))
    http._name = "http1"
    flow.add_layer(http)
    return flow


def test_chunk_backed_layers_share_one_byte_source():
    widget = FlowDetailWidget()
    sources = widget._byte_sources(_plain_http_over_tls_flow())
    assert len(sources) == 1
    assert sources[0][0].name == "http1"


def test_plain_http_over_tls_flow_shows_no_byte_tabs():
    async def body(widget, pilot):
        widget.show_flow(_plain_http_over_tls_flow())
        await pilot.pause()
        assert _visible_byte_tabs(widget) == {}

    _run_with_widget(body)


def test_header_keeps_layered_label_and_omits_pending_status():
    async def body(widget, pilot):
        widget.show_flow(_rc4_in_tls_flow())
        await pilot.pause()
        header = widget.query_one("#flow-detail-header")
        text = str(header.render())
        assert "TLS[RC4]" in text
        assert "pending" not in text

    _run_with_widget(body)
