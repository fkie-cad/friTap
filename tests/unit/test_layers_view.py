"""Tests for the two Phase 4 layer-stack *views* that surface a flow's protocol
stack to the user:

* CLI ``--show-layers`` printer — ``friTap.offline.cli._print_layer_stacks`` and
  its ``_layer_metadata_hint`` helper, which read a produced .tap and print each
  multi-layer flow's ``src:port -> dst:port  tls > http2 > websocket > signal``
  line plus per-layer metadata/byte hints.
* TUI Layers tab — ``FlowDetailWidget._render_layers_tab`` which renders
  ``flow.layers`` into the ``#layers-log`` RichLog (per-layer header, typed
  metadata, byte summaries; "No layer stack" when empty).

Both views are exercised against a layered Signal flow built with the same
``_attach_transport_metadata_layers`` correlation helper used in
``tests/unit/test_signal_metadata_layers.py`` (TLS -> HTTP/2 -> WebSocket ->
Signal). The tshark-free tests hand-build that stack and never touch a pcap; one
optional CLI test additionally converts the committed HTTP/2 Signal fixture and
skips cleanly when tshark or the fixtures are unavailable.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os

import pytest

_SIGNAL_AVAILABLE = importlib.util.find_spec("friTap.offline.signal") is not None

from friTap.flow.models import Flow, FlowChunk
from friTap.offline.pcap_to_tap import _attach_transport_metadata_layers


# ---------------------------------------------------------------------------
# Shared helpers — build a layered Signal flow + write it to a .tap
# ---------------------------------------------------------------------------

def _make_tls_flow(src, sport, dst, dport, *, alpn="h2"):
    """A correlatable TLS flow carrying the SNI/ALPN copied onto the marker."""
    flow = Flow(flow_id="t", connection_id="ct",
                src_addr=src, src_port=sport, dst_addr=dst, dst_port=dport)
    flow.transport = "tls"
    tls = flow.tls
    tls.sni = "grpc.chat.signal.org"
    tls.version = "TLS 1.3"
    tls.alpn = alpn
    tls.cipher = "TLS_AES_128_GCM_SHA256"
    return flow


def _make_signal_flow(src, sport, dst, dport):
    """A Signal flow with one decrypted Content chunk (non-empty signal layer)."""
    flow = Flow(flow_id="s", connection_id="cs",
                src_addr=src, src_port=sport, dst_addr=dst, dst_port=dport)
    flow.transport = "signal"
    flow.chunks.append(FlowChunk(data=b"\x0a\x03abc", direction="write", timestamp=0.0))
    return flow


def _layered_signal_flow() -> Flow:
    """Return a Signal flow whose stack is tls > http2 > websocket > signal."""
    tls = _make_tls_flow("1.1.1.1", 5, "2.2.2.2", 443, alpn="h2")
    sig = _make_signal_flow("2.2.2.2", 443, "1.1.1.1", 5)
    _attach_transport_metadata_layers([tls, sig])
    return sig


def _write_tap_with_flow(flow: Flow, tap_path: str) -> None:
    """Write a single flow to *tap_path* via the public TapWriter API."""
    from friTap.flow.tap_writer import TapWriter

    writer = TapWriter()
    writer.open(tap_path, target="test")
    try:
        writer.write_flow(flow)
    finally:
        writer.close()


# ===========================================================================
# CLI: _layer_metadata_hint
# ===========================================================================

@pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
def test_layer_metadata_hint_tls_returns_sni():
    from friTap.offline.cli import _layer_metadata_hint

    sig = _layered_signal_flow()
    assert _layer_metadata_hint(sig.layer("tls")) == "sni=grpc.chat.signal.org"


def test_layer_metadata_hint_empty_for_plain_layer():
    from friTap.offline.cli import _layer_metadata_hint

    sig = _layered_signal_flow()
    # The websocket marker carries no sni/chat_type, so no hint.
    assert _layer_metadata_hint(sig.layer("websocket")) == ""


# ===========================================================================
# CLI: _print_layer_stacks (tshark-free, hand-built .tap)
# ===========================================================================

@pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
def test_print_layer_stacks_prints_full_stack(tmp_path, capsys):
    """A layered Signal flow prints its endpoints + tls > http2 > websocket >
    signal stack, with the TLS SNI hint — no tshark/pcap required."""
    from friTap.offline.cli import _print_layer_stacks

    tap_path = str(tmp_path / "layered.tap")
    _write_tap_with_flow(_layered_signal_flow(), tap_path)

    _print_layer_stacks(tap_path)
    out = capsys.readouterr().out

    assert "Layer stacks:" in out
    assert "tls > http2 > websocket > signal" in out
    # Endpoints line (server -> client direction of the Signal flow).
    assert "2.2.2.2:443 -> 1.1.1.1:5" in out
    # TLS metadata hint surfaced through _layer_metadata_hint.
    assert "sni=grpc.chat.signal.org" in out


def test_print_layer_stacks_skips_single_layer_flow(tmp_path, capsys):
    """A flow with <= 1 layer is not printed (header never appears)."""
    from friTap.offline.cli import _print_layer_stacks

    # Plain Signal flow with no correlated TLS flow -> payload-only (1 layer).
    sig = _make_signal_flow("2.2.2.2", 443, "1.1.1.1", 5)
    _attach_transport_metadata_layers([sig])

    tap_path = str(tmp_path / "single.tap")
    _write_tap_with_flow(sig, tap_path)

    _print_layer_stacks(tap_path)
    out = capsys.readouterr().out

    assert "Layer stacks:" not in out
    assert ">" not in out


# ===========================================================================
# CLI: _print_layer_stacks (optional end-to-end via committed HTTP/2 fixture)
# ===========================================================================

_FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")
_H2_PCAP = os.path.join(_FIXTURES, "signal_h2_ws_modern.pcapng")
_H2_TLS_KEYS = os.path.join(_FIXTURES, "signal_h2_ws_modern.tls.log")
_H2_SIGNAL_KEYS = os.path.join(_FIXTURES, "signal_h2_ws_modern.signal.log")
_h2_fixture_present = all(
    os.path.isfile(p) for p in (_H2_PCAP, _H2_TLS_KEYS, _H2_SIGNAL_KEYS)
)


def _tshark_or_skip() -> str:
    from friTap.offline.tshark import find_tshark

    try:
        return find_tshark(None)
    except RuntimeError:
        pytest.skip("tshark not available")


@pytest.mark.skipif(
    not _h2_fixture_present, reason="committed HTTP/2 Signal fixture missing"
)
def test_print_layer_stacks_on_converted_fixture(tmp_path, capsys):
    """End-to-end: convert the committed Signal HTTP/2 capture and print its
    real layer stacks. Locks the SNI (grpc.chat.signal.org) + full stack line."""
    pytest.importorskip("cryptography")
    tshark_bin = _tshark_or_skip()

    import friTap.offline.pcap_to_tap as p2t
    from friTap.offline.cli import _print_layer_stacks

    tap_path = str(tmp_path / "fixture.tap")
    p2t.convert_pcap_to_tap(
        _H2_PCAP,
        keylog_path=_H2_TLS_KEYS,
        signal_keylog=_H2_SIGNAL_KEYS,
        tap_path=tap_path,
        tshark_path=tshark_bin,
    )

    _print_layer_stacks(tap_path)
    out = capsys.readouterr().out

    assert "tls > http2 > websocket > signal" in out
    assert "grpc.chat.signal.org" in out


# ===========================================================================
# TUI: FlowDetailWidget._render_layers_tab
# ===========================================================================

pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.widgets import RichLog  # noqa: E402

from friTap.tui.widgets.flow_detail import FlowDetailWidget  # noqa: E402


class _DetailApp(App):
    """Minimal host app so FlowDetailWidget can compose its RichLogs."""

    def compose(self):
        yield FlowDetailWidget(id="detail")


def _richlog_text(log: RichLog) -> str:
    """Flatten a RichLog's content into a single plain-text string.

    An *inactive* TabPane has no size, so RichLog buffers everything written to
    it in ``_deferred_renders`` (raw markup strings/renderables) rather than
    rendering segments. We read those when present; otherwise we flatten the
    rendered segments. Either path yields the text ``_render_layers_tab`` wrote.
    """
    deferred = getattr(log, "_deferred_renders", None)
    if deferred:
        return "\n".join(str(getattr(d, "content", d)) for d in deferred)

    parts: list[str] = []
    for line in log.lines:
        for segment in line._segments:
            parts.append(segment.text)
        parts.append("\n")
    return "".join(parts)


@pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
def test_render_layers_tab_lists_all_layer_names():
    flow = _layered_signal_flow()

    async def _run() -> None:
        app = _DetailApp()
        async with app.run_test() as pilot:
            widget = app.query_one("#detail", FlowDetailWidget)
            widget._render_layers_tab(flow)
            await pilot.pause()

            text = _richlog_text(widget._layers_log)
            assert "Protocol Layer Stack" in text
            for name in ("tls", "http2", "websocket", "signal"):
                assert name in text, f"layer {name!r} not rendered: {text!r}"
            # Typed TLS metadata surfaces (sni from the correlated marker).
            assert "grpc.chat.signal.org" in text

    asyncio.run(_run())


def test_render_layers_tab_empty_shows_placeholder():
    """A flow with no layer stack renders the 'No layer stack' placeholder."""
    flow = Flow(flow_id="empty", connection_id="ce",
                src_addr="1.1.1.1", src_port=1, dst_addr="2.2.2.2", dst_port=2)

    async def _run() -> None:
        app = _DetailApp()
        async with app.run_test() as pilot:
            widget = app.query_one("#detail", FlowDetailWidget)
            widget._render_layers_tab(flow)
            await pilot.pause()

            text = _richlog_text(widget._layers_log)
            assert "No layer stack" in text
            assert "Protocol Layer Stack" not in text

    asyncio.run(_run())
