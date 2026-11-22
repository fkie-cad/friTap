"""Optional flow-detail panes: per-layer byte tabs, OHTTP inner, extension tabs.

Extension ``render()`` is third-party code, so live refreshes are throttled;
the throttle clock and interval are read through the package so tests can patch them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text
from textual.widgets import RichLog

from friTap.tui.themes import c
from friTap.tui.widgets import flow_detail as _fd

from .helpers import (
    _BYTE_TAB_IDS,
    _TAB_EXT_PREFIX,
    _TAB_OHTTP,
    _extension_change_key,
    _fingerprint_or_unique,
    _flow_has_ohttp,
    _GuardedRenderable,
    _log,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow


class OptionalTabsMixin:
    """Per-layer byte tabs, the OHTTP pane and extension tabs (shown per flow)."""

    @staticmethod
    def _layer_bytes_total(layer) -> int:
        """Total decrypted bytes (write + read) a layer carries, 0 if none."""
        data = getattr(layer, "data", None)
        if data is None:
            return 0
        try:
            return len(data.write) + len(data.read)
        except Exception:
            return 0

    @staticmethod
    def _byte_tab_label(layer, total: int) -> str:
        """Tab label like ``Decrypted TLS (98 bytes)``."""
        from friTap.flow.display import layer_display_name

        name = getattr(layer, "name", "") or "?"
        display = layer_display_name(name) or name.upper()
        return f"Decrypted {display} ({total:,} bytes)"

    @staticmethod
    def _is_chunk_backed(layer) -> bool:
        """True when *layer* views the flow's chunks rather than owning bytes."""
        data = getattr(layer, "data", None)
        return getattr(data, "data_source", "") == "chunks"

    def _byte_sources(self, flow: "Flow") -> list:
        """``(layer, label)`` per distinct byte buffer, outer -> inner.

        Chunk-backed layers all view the same flow chunks (e.g. TLS and
        HTTP/1.x on a plain HTTPS flow), so only the innermost of them is a
        distinct buffer; layers with owned bytes (an RC4-in-TLS carrier)
        are each their own buffer.
        """
        sources = []
        for layer in getattr(flow, "layers", None) or []:
            if getattr(layer, "metadata_only", False):
                continue
            total = self._layer_bytes_total(layer)
            if not total:
                continue
            if self._is_chunk_backed(layer):
                sources = [s for s in sources
                           if not self._is_chunk_backed(s[0])]
            sources.append((layer, self._byte_tab_label(layer, total)))
        return sources

    def _set_byte_tab_visible(self, pane_id: str, visible: bool) -> None:
        """Show or hide one byte-tab pane (no-op before compose)."""
        if self._tabs is None:
            return
        try:
            if visible:
                self._tabs.show_tab(pane_id)
            else:
                self._tabs.hide_tab(pane_id)
        except Exception:
            pass

    def _update_byte_tabs(self, flow: "Flow") -> None:
        """Bind the byte-tab pool to *flow*'s layers; hide unused panes.

        Tabs appear only for a flow with >= 2 byte-carrying layers, so a
        plain single-layer flow keeps the ordinary tab set.
        """
        sources = self._byte_sources(flow)
        if len(sources) < 2:
            sources = []
        self._byte_tab_layers = {}
        for i, pane_id in enumerate(_BYTE_TAB_IDS):
            if i < len(sources):
                layer, label = sources[i]
                self._byte_tab_layers[pane_id] = layer
                self._set_byte_tab_label(pane_id, label)
            self._set_byte_tab_visible(pane_id, i < len(sources))

    def _set_byte_tab_label(self, pane_id: str, label: str) -> None:
        try:
            self._tabs.get_tab(pane_id).label = label
        except Exception:
            pass

    def _render_byte_tab_by_id(self, pane_id: str) -> None:
        """Render the byte pane *pane_id* for the layer currently bound to it."""
        log = self._byte_logs.get(pane_id)
        layer = self._byte_tab_layers.get(pane_id)
        if log is None:
            return
        if layer is None:
            log.clear()
            log.write("[dim]No decrypted bytes[/]")
            return
        self._render_byte_tab(log, layer)

    _BYTE_TAB_DIRECTIONS = (
        ("write", "→", "client→server"),
        ("read", "←", "server→client"),
    )

    def _render_byte_tab(self, log: RichLog, layer) -> None:
        """Write a layer's decrypted bytes as per-direction hexdump sections."""
        log.clear()
        total = self._layer_bytes_total(layer)
        log.write(f"[bold {c('primary')}]{self._byte_tab_label(layer, total)}[/]")
        log.write("")
        for direction, arrow, label in self._BYTE_TAB_DIRECTIONS:
            try:
                raw = layer.data.direction(direction)
            except Exception:
                raw = b""
            if not raw:
                continue
            log.write(f"[bold {c('success')}]{arrow} {label} ({len(raw):,} bytes)[/]")
            self._write_hexdump(log, raw)
            log.write("")
        log.scroll_home(animate=False)

    # Optional panes (OHTTP inner, extension tabs) are composed up front and
    # shown/hidden per flow: add_pane is async and races.

    def _update_optional_tabs(self, flow: "Flow") -> None:
        """Show the OHTTP / extension panes that have content for *flow*."""
        self._set_optional_tab_visible(_TAB_OHTTP, _flow_has_ohttp(flow), flow)
        self._refresh_extension_tabs(flow)

    def _refresh_extension_tabs(self, flow: "Flow") -> bool:
        """Re-run extension renders if *flow* changed, throttled; True if they ran.

        The first render after a selection is immediate; later ones run at
        most once per ``_EXT_RERENDER_INTERVAL``, a throttled change being
        picked up by one deferred re-check.
        """
        if not self._ext_tabs:
            return False
        key = _fingerprint_or_unique(_extension_change_key, flow)
        # The layer walk runs only when the cheap key shows no change.
        if (key == self._ext_render_key
                and _fingerprint_or_unique(_fd._extension_layer_signature, flow)
                == self._ext_layer_sig):
            return False
        now = _fd.time.monotonic()
        since_last = now - self._ext_rendered_at
        if self._ext_rendered_at and since_last < _fd._EXT_RERENDER_INTERVAL:
            self._schedule_extension_recheck(_fd._EXT_RERENDER_INTERVAL - since_last)
            return False
        first_render = self._ext_render_key is None
        self._ext_render_key = key
        self._ext_layer_sig = _fingerprint_or_unique(_fd._extension_layer_signature, flow)
        self._ext_rendered_at = 0.0 if first_render else now
        self._render_extension_contents(flow)
        return True

    def _render_extension_contents(self, flow: "Flow") -> None:
        """Run every extension render for *flow* and show/hide its pane."""
        self._ext_content = {}
        for pane_id, spec in self._ext_tabs:
            content = self._extension_content(spec, flow)
            if content is not None:
                self._ext_content[pane_id] = content
            self._set_optional_tab_visible(pane_id, content is not None, flow)

    def _reset_extension_render_state(self) -> None:
        """Forget the last extension render: the next one runs immediately.

        Also drops the rendered content, which may pin a large flow.
        """
        self._cancel_extension_recheck()
        self._ext_render_key = None
        self._ext_layer_sig = None
        self._ext_rendered_at = 0.0
        self._ext_content = {}

    def _schedule_extension_recheck(self, delay: float) -> None:
        """Arm the single deferred extension re-check (no-op if already armed)."""
        if self._ext_recheck_timer is None:
            self._ext_recheck_timer = self.set_timer(
                max(delay, 0.01), self._run_extension_recheck)

    def _cancel_extension_recheck(self) -> None:
        timer, self._ext_recheck_timer = self._ext_recheck_timer, None
        if timer is not None:
            timer.stop()

    def _run_extension_recheck(self) -> None:
        """Deferred re-check: bring the extension panes up to date with the current flow."""
        self._ext_recheck_timer = None
        flow = self._current_flow
        if flow is None or not self.is_mounted:
            return
        if self._refresh_extension_tabs(flow) and self._tabs is not None:
            active = self._tabs.active
            if active.startswith(_TAB_EXT_PREFIX):
                self._render_tab_safely(flow, active)

    def on_unmount(self) -> None:
        self._cancel_extension_recheck()

    def _set_optional_tab_visible(self, pane_id: str, visible: bool, flow: "Flow") -> None:
        """Toggle *pane_id*; hiding the active pane falls back to the default tab.

        A no-op when *pane_id* already has that visibility (live refreshes
        call this for every optional pane on each update).
        """
        tabs = self._tabs
        if tabs is None or self._optional_tab_visible.get(pane_id) == visible:
            return
        if not visible and tabs.active == pane_id:
            # Re-select first: Tabs.hide() on the active tab would otherwise
            # jump to its neighbour (asynchronously overriding our choice).
            self._auto_select_tab(tabs, flow)
        self._set_byte_tab_visible(pane_id, visible)
        self._optional_tab_visible[pane_id] = visible

    @staticmethod
    def _extension_content(spec, flow: "Flow"):
        """``spec.render(flow)``; a raising (third-party) render hides the tab."""
        try:
            return spec.render(flow)
        except Exception:
            _log.exception("flow detail: extension tab %r render failed", spec.id)
            return None

    def _render_extension_tab(self, pane_id: str) -> None:
        """Write the content last rendered for extension pane *pane_id*."""
        log = self._ext_logs.get(pane_id)
        if log is None:
            return
        log.clear()
        content = self._ext_content.get(pane_id)
        if content is not None:
            # A plain str is third-party text: render literally, not as markup.
            log.write(Text(content) if isinstance(content, str)
                      else _GuardedRenderable(content, pane_id))
        log.scroll_home(animate=False)

    def _render_ohttp_tab(self, flow: "Flow") -> None:
        """Render the decrypted OHTTP inner request/response pane."""
        from friTap.tui.widgets.ohttp_tab import OhttpTabProvider

        log = self._ohttp_log
        if log is None:
            return
        log.clear()
        markup = OhttpTabProvider().render(flow) or "[dim]No OHTTP data[/]"
        # Parse now (inside _render_tab_safely): a deferred RichLog write
        # would hit a markup error later, outside any try.
        log.write(log.highlighter(Text.from_markup(markup)))
        log.scroll_home(animate=False)
