#!/usr/bin/env python3

"""Code-review fixes R1: Textual-markup escaping of file names, error texts and
the pipeline label; offline-decryptor discovery off the UI thread; a tolerant
extension change key.

``a[/]b.tap`` is a real path (directory ``a[`` + file ``]b.tap``): unescaped in
Textual markup its ``[/]`` raises ``MarkupError``; ``[RC4]`` is silently eaten.
"""

from __future__ import annotations

import asyncio
import os
import threading
from unittest.mock import MagicMock

import pytest

pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.widgets import Static  # noqa: E402

from friTap.extensions import (  # noqa: E402
    BodyDecoderSpec,
    DetailTabSpec,
    register_body_decoder,
    register_detail_tab,
)
from friTap.tui.app import FriTapApp  # noqa: E402
from friTap.tui.modals.body_processing_modal import BodyProcessingResult  # noqa: E402
from friTap.tui.screens.tap_viewer import TapViewerScreen  # noqa: E402
from friTap.tui.widgets import flow_detail as fd  # noqa: E402
from tests.unit._tui_flow_helpers import make_flow, write_tap  # noqa: E402
from tests.unit.test_flow_detail_optional_tabs import (  # noqa: E402
    _log_text,
    _plain_flow,
    _run_with_widget,
    _show,
)


def _slash_bracket_path(tmp_path, content: bytes | None = b"not a tap file") -> str:
    """``<tmp>/a[/]b.tap``: a markup-breaking path (``[/]`` spans the separator)."""
    folder = tmp_path / "a["
    folder.mkdir()
    path = folder / "]b.tap"
    if content is not None:
        path.write_bytes(content)
    return str(path)


def _rendered(screen, selector: str) -> str:
    return str(screen.query_one(selector, Static).render())


class _BareHost(App):
    pass


def _open_viewer(tap_path: str, body) -> None:
    async def _go() -> None:
        app = _BareHost()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(TapViewerScreen(tap_path))
            await pilot.pause()
            await pilot.pause()
            await body(app, pilot)

    asyncio.run(_go())


# ------------------------------------------------- 1. viewer: corrupt a[/]b.tap


def test_viewer_corrupt_bracket_path_shows_replay_error(tmp_path):
    tap_path = _slash_bracket_path(tmp_path)

    async def body(app, pilot):
        assert type(app.screen).__name__ == "AlertModal"
        assert "]b.tap" in _rendered(app.screen, "#alert-message")
        assert app.is_running

    _open_viewer(tap_path, body)


def test_viewer_reload_replay_alert_keeps_bracketed_name_literal(tmp_path):
    bad = tmp_path / "x[RC4]y.tap"
    bad.write_bytes(b"garbage")

    async def body(app, pilot):
        assert "Failed to open x[RC4]y.tap" in _rendered(app.screen, "#alert-message")

    _open_viewer(str(bad), body)


# ---------------------------------------- 3. fritap -r: unreadable a[/]b.tap


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root can read a mode-000 file")
def test_main_screen_unreadable_bracket_path_alerts_without_crash(tmp_path):
    tap_path = _slash_bracket_path(tmp_path)
    write_tap(tap_path, [make_flow("f1", 443)])
    os.chmod(tap_path, 0)
    seen: dict = {}

    async def _go() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.pause()
            seen["screen"] = type(app.screen).__name__
            seen["message"] = _rendered(app.screen, "#alert-message")
            seen["running"] = app.is_running

    try:
        asyncio.run(_go())
    finally:
        os.chmod(tap_path, 0o600)
    assert seen["screen"] == "AlertModal"
    assert "a[/]b.tap" in seen["message"]
    assert seen["running"]


def test_open_failure_escapes_exception_text():
    host = MagicMock()
    host._open_controller.side_effect = OSError("Permission denied: 'a[/]b.tap'")
    from friTap.tui.screens.viewer_mixins.navigation import FlowNavigationMixin

    assert FlowNavigationMixin._open_source_or_alert(host, "p", "b.tap") is None
    message = host._alert.call_args[0][0]
    assert message.endswith("Permission denied: 'a\\[/]b.tap'")


def test_decrypt_alerts_escape_pcap_and_message(tmp_path):
    from friTap.tui.screens.viewer_mixins.decrypt import DecryptMixin

    host = MagicMock()
    missing = str(tmp_path / "x[/]y.pcap")
    assert DecryptMixin._build_convert_args(
        host, pcap=missing, keylog="", proto_keylog="", protocol="tls", tap="") is None
    assert host._alert.call_args[0][0].endswith("x\\[/]y.pcap")
    assert DecryptMixin._build_convert_args_multi(
        host, pcap=missing, tls_keylog="", protocol_keylogs={}, tap="") is None
    assert host._alert.call_args[0][0].endswith("x\\[/]y.pcap")
    host._is_live_screen.return_value = True
    DecryptMixin._on_decrypt_error(host, "bad [/] record")
    assert host._alert.call_args[0][0] == "Decrypt failed: bad \\[/] record"


# ------------------------------------------- 4. capture[RC4].tap stays literal


def test_viewer_banner_and_indicator_show_bracketed_name(tmp_path):
    tap_path = str(tmp_path / "capture[RC4].tap")
    write_tap(tap_path, [make_flow("f1", 443)])

    async def body(app, pilot):
        viewer = app.screen
        assert isinstance(viewer, TapViewerScreen)
        for selector in ("#activity-title", "#capture-indicator"):
            assert "capture[RC4].tap" in _rendered(viewer, selector), selector

    _open_viewer(tap_path, body)


def test_main_screen_banner_and_indicator_show_bracketed_name(tmp_path):
    tap_path = str(tmp_path / "capture[RC4].tap")
    write_tap(tap_path, [make_flow("f1", 443)])
    seen: dict = {}

    async def _go() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            for selector in ("#activity-title", "#capture-indicator"):
                seen[selector] = _rendered(app.screen, selector)

    asyncio.run(_go())
    for selector, text in seen.items():
        assert "capture[RC4].tap" in text, (selector, text)


def test_export_alert_escapes_upper_case_tag(tmp_path):
    from types import SimpleNamespace

    from friTap.tui.screens.viewer_mixins import ExportMixin

    host = SimpleNamespace(_replay_file=str(tmp_path / "src.tap"),
                           _replay_ctrl=MagicMock(), app=MagicMock(), _alert=MagicMock())
    host._replay_ctrl.header = None
    host._replay_ctrl.get_flows.return_value = []
    host._replay_ctrl.read_request_contexts.return_value = []
    host._collect_export_findings = lambda: {}
    ExportMixin._export_replay_to_tap(host, str(tmp_path / "out[RC4].tap"))
    message = host.app.push_screen.call_args[0][0]._message
    assert message.endswith("out\\[RC4].tap[/]")


# ---------------------------------------- 2. extension decoder name in header


def test_header_shows_extension_decoder_name_literally():
    register_body_decoder(BodyDecoderSpec(
        name="x[/]y", label="X", decode=lambda body, headers: ["decoded"]))

    async def body(widget, pilot):
        flow = _plain_flow()
        _show(widget, flow)
        await pilot.pause()
        widget._on_body_processing_result(BodyProcessingResult(decoder="x[/]y"))
        await pilot.pause()
        header = str(widget._header_widget.render())
        assert "x[/]y" in header
        assert widget._describe_pipeline() == "x[/]y"  # raw value unchanged

    _run_with_widget(body)


# --------------------------------------- 5. discovery off the UI thread


def _wait_for_workers(app, pilot):
    async def _wait() -> None:
        await app.workers.wait_for_complete()
        await pilot.pause()
        await pilot.pause()
    return _wait()


def test_start_decrypt_discovers_off_the_ui_thread(tmp_path, monkeypatch):
    import friTap.offline.discovery as disc

    pcap = tmp_path / "c.pcap"
    pcap.write_bytes(b"\x00")
    tap_path = str(tmp_path / "r.tap")
    write_tap(tap_path, [make_flow("f1", 443)])
    threads: list = []
    monkeypatch.setattr(disc, "discover_external_offline_decryptors",
                        lambda *a, **k: threads.append(threading.current_thread()) or {})
    seen: dict = {}

    async def _go() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            screen._launch_decrypt_worker = MagicMock()
            seen["ui"] = threading.current_thread()
            screen.start_decrypt_to_flow(str(pcap), "")
            await _wait_for_workers(app, pilot)
            seen["launch"] = screen._launch_decrypt_worker

    asyncio.run(_go())
    assert threads and all(t is not seen["ui"] for t in threads)
    seen["launch"].assert_called_once()
    assert seen["launch"].call_args[0][0]["pcap_path"] == str(pcap)


# ------------------------------------------- 6. tolerant extension change key


class _FlowLike:
    """Delegates to a real Flow but hides its private ``_total_bytes``."""

    def __init__(self, flow):
        object.__setattr__(self, "_flow", flow)

    def __getattr__(self, name):
        if name == "_total_bytes":
            raise AttributeError(name)
        return getattr(self._flow, name)


def test_change_key_tolerates_missing_flow_internals():
    key = fd._extension_change_key(object())
    assert key[2] == 0 and key[3] is None and key[4] is None


def test_raising_fingerprint_means_always_rerender():
    def boom(flow):
        raise RuntimeError("bad flow")

    assert fd._fingerprint_or_unique(boom, None) != fd._fingerprint_or_unique(boom, None)


def test_flow_like_without_total_bytes_renders_extension_tab():
    register_detail_tab(DetailTabSpec(
        id="demo.tab", label="Demo", render=lambda flow: f"ext {flow.flow_id}"))
    pane_id = "tab-ext-demo_tab"

    async def body(widget, pilot):
        flow = _FlowLike(_plain_flow())
        _show(widget, flow, pane_id)
        await pilot.pause()
        assert "ext plain" in _log_text(widget._ext_logs[pane_id])
        assert "p:parse" in str(widget._header_widget.render())  # header not blank

    _run_with_widget(body)
