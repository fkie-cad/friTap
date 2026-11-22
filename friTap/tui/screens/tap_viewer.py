#!/usr/bin/env python3

"""
Replay-only ``.tap`` viewer screen, embeddable in a host Textual app.

``TapViewerScreen`` uses the same widget IDs and viewer mixins as the replay
path of :class:`~friTap.tui.screens.main_screen.MainScreen`, without the
wizard, capture controller, ``AppState``, console log or left menu. A host pushes it::

    app.push_screen(TapViewerScreen("capture.tap"))

Embedding rules:

* Close, never quit: ``q`` (and ``escape``/``backspace`` at the top level)
  dismiss it, never ``app.exit()``. :class:`TapViewerScreen.Closed` is posted on close.
* A host binding ``escape`` with ``priority=True`` calls :meth:`go_back` and
  closes the viewer itself when it returns ``False``.
* ``compose`` installs the ``$fritap-*`` variables into the host app
  (idempotent); layout CSS is scoped on :class:`~friTap.tui.screens.viewer_css.ViewerBody`.
* Importing this module loads no frida, capture controller, wizard or ``main_screen``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.message import Message
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from friTap.extensions import load_extensions
from friTap.flow.replay_rows import iter_replay_rows

from ..theme_install import install_theme
from ..themes import c
from ..widgets.analyzer_finding_detail import AnalyzerFindingDetailWidget
from ..widgets.analyzer_panel import AnalyzerPanel
from ..widgets.filter_bar import FilterBar
from ..widgets.findings_filter_bar import FindingsFilterBar
from ..widgets.findings_list import FindingsListWidget
from ..widgets.flow_detail import FlowDetailWidget
from ..widgets.flow_list import FlowListWidget
from ..widgets.wire_text import safe_static_text
from .viewer_css import ViewerBody
from .viewer_mixins import (
    AnalyzerMixin,
    ConversationSiblingsMixin,
    DecryptMixin,
    ExportMixin,
    FilterMixin,
    FindingsMixin,
    FlowNavigationMixin,
    ViewerHostDefaults,
)

if TYPE_CHECKING:
    from friTap.flow.replay import TapSource

logger = logging.getLogger(__name__)

# Widgets hidden until the .tap is loaded (MainScreen.on_mount does the same).
_INITIALLY_HIDDEN = (
    "#filter-bar", "#flow-list", "#flow-detail", "#findings-filter-bar",
    "#findings-list", "#finding-detail", "#analyzer-panel",
)

# Worker groups the viewer mixins start (AnalyzerMixin, DecryptMixin).
_WORKER_GROUPS = ("analyzer", "decrypt")

# Key hints closing the initial replay banner (inside its ``[dim]``).
_BANNER_HINTS = (" | Enter: details | /: filter | a: analyzers | w: export"
                 " | q: close")


def _discard(*args, **kwargs) -> None:
    return None


class NullActivityLog:
    """Stand-in for the console ``ActivityLog``: every ``log_*``/``show_*`` method and ``clear`` is a silent no-op."""

    def __getattr__(self, name: str):
        if name == "clear" or name.startswith(("log_", "show_")):
            return _discard
        raise AttributeError(name)

    def get_plain_text(self) -> str:
        return ""

    def get_line_count(self) -> int:
        return 0


class TapViewerScreen(
    DecryptMixin, FindingsMixin, AnalyzerMixin, FilterMixin, FlowNavigationMixin,
    ExportMixin, ConversationSiblingsMixin, ViewerHostDefaults, Screen
):
    """Replay-only viewer of one ``.tap`` file, pushable into any Textual app."""

    # Action names mirror MainScreen / FriTapApp; no "r" (restart wizard) or "t" (theme) here.
    BINDINGS = [
        Binding("escape", "escape_action", "Back", show=False),
        Binding("backspace", "escape_action", "Back", show=False),
        Binding("q", "close_viewer", "Close", show=True),
        Binding("slash", "focus_filter", "Filter", show=False),
        Binding("shift+escape", "clear_filter", "Clear Filter", show=False),
        Binding("ctrl+l", "clear_filter", "Clear Filter", show=False),
        Binding("shift+f", "toggle_findings_view", "Findings", show=False),
        Binding("a", "analyzer_panel", "Analyzers", show=False),
        Binding("c", "findings_quick_creds", "Creds", show=False),
        Binding("p", "findings_quick_pii", "PII", show=False),
        Binding("1", "findings_quick_critical", "Critical", show=False),
        Binding("w", "save_tap", "Save .tap", show=False),
        Binding("o", "open_pcap", "Open PCAP", show=False),
        Binding("R", "report_digest", "Report", show=False),
    ]

    class Closed(Message):
        """Posted to the app once when the viewer closes (dismissed or removed)."""

        def __init__(self, viewer: "TapViewerScreen", tap_path: Optional[str]) -> None:
            super().__init__()
            self.viewer = viewer
            self.tap_path = tap_path

    def __init__(
        self,
        tap_path: str,
        *,
        title: Optional[str] = None,
        sub_title: Optional[str] = None,
        output_dir: Optional[str] = None,
        source: Optional["TapSource"] = None,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ) -> None:
        """Create a viewer of *tap_path*.

        *source* is an optional, already loaded :class:`TapSource` (*tap_path* then
        only names it in the banner). The host keeps ownership: the viewer never
        closes it (not on unmount, not when a decrypt swaps in a new ``.tap``).
        Without *source* the viewer opens and closes *tap_path* itself.
        """
        # Extension filter fields / layers must be registered before any .tap is read.
        load_extensions(offline_decryptors=False)
        super().__init__(name=name, id=id, classes=classes)
        # Host-contract state (tests/unit/test_viewer_host_contract.py).
        self._replay_file: Optional[str] = tap_path
        self._replay_ctrl = None
        # True only for a controller the viewer opened itself.
        self._owns_ctrl = False
        self._findings_cache: list | None = None
        self._analyzer_run_id = 0
        self._detail_origin = "flow"
        self._output_dir = output_dir
        self._initial_source = source
        self._closed_posted = False
        self._activity_log = NullActivityLog()
        if title is not None:
            self.title = title
        if sub_title is not None:
            self.sub_title = sub_title

    def compose(self) -> ComposeResult:
        # Safety net: friTap modals/widgets need $fritap-* in a foreign host.
        install_theme(self.app)
        yield Header()
        with ViewerBody(id="tap-viewer-body"):
            with Horizontal(id="activity-title-row"):
                yield Static("", id="capture-indicator")
                yield Static(f"[bold {c('primary')}]friTap Replay[/]", id="activity-title")
                yield Static("", id="title-spacer")
            yield FilterBar(id="filter-bar")
            yield AnalyzerPanel(id="analyzer-panel")
            yield FlowListWidget(id="flow-list")
            yield FlowDetailWidget(id="flow-detail")
            yield FindingsFilterBar(id="findings-filter-bar")
            yield FindingsListWidget(id="findings-list")
            yield AnalyzerFindingDetailWidget(id="finding-detail")
        yield Footer()

    def on_mount(self) -> None:
        for selector in _INITIALLY_HIDDEN:
            self.query_one(selector).display = False
        self.query_one("#flow-list", FlowListWidget).set_flow_lookup(self._lookup_flow)
        source, self._initial_source = self._initial_source, None
        if source is not None:
            self._show_replay(self._replay_file, source, owned=False)
        elif self._replay_file:
            self.reload_replay(self._replay_file)

    def on_unmount(self) -> None:
        """Stop background work and release the .tap; safe mid-analyzer-run."""
        # A late analyzer completion compares run ids and is dropped.
        self._analyzer_run_id += 1
        self._cancel_worker_groups()
        self._close_controller()
        self._post_closed()

    def _cancel_worker_groups(self) -> None:
        for group in _WORKER_GROUPS:
            try:
                self.workers.cancel_group(self, group)
            except Exception:
                logger.debug("cancelling worker group %s failed", group, exc_info=True)

    def _close_controller(self) -> None:
        """Drop the current source; close it only if the viewer opened it."""
        ctrl, self._replay_ctrl = self._replay_ctrl, None
        owned, self._owns_ctrl = self._owns_ctrl, False
        if owned:
            self._close_source(ctrl)  # FlowNavigationMixin; tolerates no close()

    def go_back(self) -> bool:
        """One back step; ``False`` at the top level (the caller decides whether to close).

        Order: nested view (finding detail, flow detail, findings list), then the
        analyzer panel, then an active flow-list filter.
        """
        if self._escape_step():  # FlowNavigationMixin's Esc hierarchy
            return True
        if self._close_open_analyzer_panel():
            return True
        return self._clear_active_flow_filter()

    def action_escape_action(self) -> None:
        """Esc / Backspace: one back step, or close the viewer at the top level."""
        if not self.go_back():
            self._request_close()

    def action_close_viewer(self) -> None:
        """``q``: close the viewer (never quits the host app)."""
        self._request_close()

    def _close_open_analyzer_panel(self) -> bool:
        if not self._analyzer_panel().display:
            return False
        self.on_analyzer_panel_close_requested(None)
        return True

    def _clear_active_flow_filter(self) -> bool:
        filter_bar = self.query_one("#filter-bar", FilterBar)
        if not (filter_bar.display and filter_bar.has_active_filter):
            return False
        self.action_clear_filter()
        return True

    def _post_closed(self) -> None:
        """Post :class:`Closed` to the app exactly once."""
        if self._closed_posted:
            return
        self._closed_posted = True
        try:
            self.app.post_message(self.Closed(self, self._replay_file))
        except Exception:
            logger.debug("posting TapViewerScreen.Closed failed", exc_info=True)

    def reload_replay(self, path: str) -> None:
        """Load *path* (.tap) into this viewer (initial load, and after a pcap->tap decrypt).

        The new file is opened first; on failure only an alert is shown and the view is untouched.
        """
        ctrl = self._open_source_or_alert(path, safe_static_text(Path(path).name))
        if ctrl is None:
            return
        self._show_replay(path, ctrl, owned=True)

    def _show_replay(self, path: Optional[str], ctrl, *, owned: bool) -> None:
        """Swap in *ctrl* (a loaded TapSource) and repopulate the flow view.

        *owned* marks a controller the viewer opened (closed on replace/unmount);
        a host source is never closed. ``_swap_in_source`` also resets findings and rows.
        """
        previous_owned = self._owns_ctrl
        self._swap_in_source(ctrl, close_previous=previous_owned)
        self._owns_ctrl = owned
        self._replay_file = path
        self._activate_flow_view()
        self._update_replay_banner()
        self._update_capture_indicator()
        flow_list = self.query_one("#flow-list", FlowListWidget)
        for flow, row in iter_replay_rows(ctrl):
            flow_list.add_or_update_flow(flow, summary=row)

    @property
    def _replay_filename(self) -> str:
        """Textual-markup-safe name of the loaded .tap ("tap" for a pathless source)."""
        return safe_static_text(Path(self._replay_file).name) if self._replay_file else "tap"

    def _update_replay_banner(self) -> None:
        self.query_one("#activity-title", Static).update(
            self._replay_banner_markup(
                self._replay_filename, self._replay_ctrl.flow_count, _BANNER_HINTS,
            )
        )

    # Replay-only host hooks (tests/unit/test_viewer_host_contract.py); the rest keep ViewerHostDefaults.

    def _request_close(self) -> None:
        """Post :class:`Closed` and dismiss; never quits the app.

        Ignored unless active (``dismiss()`` pops the TOP screen). When the viewer
        is the only screen of its stack ``dismiss()`` would raise
        ``ScreenStackError``, so only :class:`Closed` is posted.
        """
        if not self.is_active:
            logger.debug("TapViewerScreen close requested while not the active screen")
            return
        self._post_closed()
        if len(self.app.screen_stack) > 1:
            self.dismiss()

    def _flow_title_hints(self) -> list:
        return ["[dim]q: close[/]"]

    def _update_capture_indicator(self) -> None:
        try:
            indicator = self.query_one("#capture-indicator", Static)
        except Exception:
            return
        if self._replay_ctrl is None:
            indicator.update("")
            return
        indicator.update(self._tap_indicator_markup(self._replay_filename))

    def _get_activity_log(self) -> NullActivityLog:
        return self._activity_log
