#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Explorer mode modal for friTap TUI.

Full-screen overlay showing raw body content (hex or text) with
cursor navigation and byte-range selection.  Users select a region
and press ``p`` to parse only the selected bytes.

The viewer uses a custom ``HexViewerWidget`` subclass of ``ScrollView``
instead of ``TextArea`` — TextArea's internal cursor/selection/blink
machinery causes the cursor to jump back to its initial position, so
we replace it with a simple byte-offset based cursor we fully own.
"""

from __future__ import annotations

import bisect
import json
from dataclasses import dataclass
from typing import Literal

from rich.segment import Segment
from rich.style import Style

# Display modes
MODE_HEX = "hex"
MODE_TEXT = "text"
DisplayMode = Literal["hex", "text"]

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.containers import Vertical
    from textual.geometry import Region, Size
    from textual.message import Message
    from textual.reactive import reactive
    from textual.screen import ModalScreen
    from textual.scroll_view import ScrollView
    from textual.strip import Strip
    from textual.widgets import RichLog, Static

    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


# ── Data classes (always available) ─────────────────────────────


@dataclass
class ExplorerSelection:
    """A selected byte range within a body."""

    start: int  # byte offset (inclusive)
    end: int  # byte offset (exclusive)
    data: bytes  # the selected bytes


@dataclass
class ExplorerResult:
    """Result returned when Explorer Mode is dismissed after parsing.

    Contains the byte-range selection and the processing that was applied.
    Callers can use this to, e.g., annotate the flow detail view or
    persist the parsed sub-region.
    """

    selection: ExplorerSelection
    processing: "BodyProcessingResult | None"


# Render limits (same as FlowDetailWidget)
_HEXDUMP_RENDER_LIMIT = 64 * 1024
_TEXT_RENDER_LIMIT = 256 * 1024


if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c
    from friTap.tui.widgets.flow_detail import format_hexdump_lines, _is_text

    class HexViewerWidget(ScrollView, can_focus=True):
        """Custom hex/text viewer with byte-range selection.

        Replaces ``TextArea`` for complete cursor control — cursor is a
        simple reactive byte offset with ``repaint=False``, so no
        Textual internals (selection reactive, blink timer, scroll
        cascade, ``text_selection_started_signal``, wrapped-document
        validation, etc.) can interfere.

        The widget handles its own rendering via ``render_line`` and its
        own key/click events.  It posts ``CursorChanged`` messages when
        the cursor or selection anchor changes.
        """

        DEFAULT_CSS = """
        HexViewerWidget {
            background: $surface;
        }
        HexViewerWidget:focus {
            background: $surface;
        }
        """

        BYTES_PER_LINE = 16
        HEX_REGION_START = 10  # after 8-char offset + 2 spaces

        cursor_byte: reactive[int] = reactive(0, repaint=False)
        anchor_byte: reactive[int | None] = reactive(None, repaint=False)

        class CursorChanged(Message):
            """Posted when cursor or selection anchor changes."""

            def __init__(self, cursor: int, anchor: int | None) -> None:
                super().__init__()
                self.cursor = cursor
                self.anchor = anchor

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self._data: bytes = b""
            self._mode: DisplayMode = MODE_HEX
            self._text_lines: list[str] = []
            self._text_line_byte_starts: list[int] = [0]
            self._styles: dict[str, Style] | None = None

        # ── Data loading ───────────────────────────────────────

        def set_data(self, data: bytes, mode: DisplayMode = MODE_HEX) -> None:
            """Load data and reset cursor."""
            self._data = data
            self._mode = mode
            self._styles = None
            self._configure_for_mode()
            self.anchor_byte = None
            self.cursor_byte = 0
            if self.is_mounted:
                self.scroll_home(animate=False)
            self.refresh()

        def set_mode(self, mode: DisplayMode) -> None:
            """Change display mode, keeping the same data."""
            if mode == self._mode:
                return
            self.set_data(self._data, mode)

        @property
        def mode(self) -> DisplayMode:
            return self._mode

        @property
        def is_truncated(self) -> bool:
            limit = _HEXDUMP_RENDER_LIMIT if self._mode == MODE_HEX else _TEXT_RENDER_LIMIT
            return len(self._data) > limit

        def _configure_for_mode(self) -> None:
            """Update ``virtual_size`` and per-mode state for current data."""
            if self._mode == MODE_HEX:
                limited = min(len(self._data), _HEXDUMP_RENDER_LIMIT)
                num_data_lines = (limited + self.BYTES_PER_LINE - 1) // self.BYTES_PER_LINE
                total_lines = num_data_lines + (1 if self.is_truncated else 0)
                line_width = (
                    8 + 2 + self.BYTES_PER_LINE * 3 - 1 + 2 + self.BYTES_PER_LINE
                )
                self.virtual_size = Size(line_width, max(1, total_lines))
                return

            limited = min(len(self._data), _TEXT_RENDER_LIMIT)
            text = self._data[:limited].decode("utf-8", errors="replace")
            self._text_lines = text.split("\n")
            if self.is_truncated:
                remaining = len(self._data) - _TEXT_RENDER_LIMIT
                self._text_lines.append(
                    f"... {remaining:,} more bytes ({len(self._data):,} total)"
                )
            # Single pass: build byte-start index and track max display width
            self._text_line_byte_starts = [0]
            pos = 0
            max_width = 1
            for line in self._text_lines:
                w = len(line)
                if w > max_width:
                    max_width = w
                pos += len(line.encode("utf-8", errors="replace")) + 1
                self._text_line_byte_starts.append(pos)
            self.virtual_size = Size(max_width, max(1, len(self._text_lines)))

        # ── Style cache ────────────────────────────────────────

        def _get_styles(self) -> dict[str, Style]:
            """Return cached per-render styles, rebuilding on theme change."""
            if self._styles is None:
                self._styles = {
                    "offset": Style(color=c("hex-offset")),
                    "hex": Style(color=c("hex-data")),
                    "ascii": Style(color=c("hex-ascii")),
                    "sel_offset": Style(
                        color=c("hex-offset"), bgcolor=c("hex-sel-offset")
                    ),
                    "sel_hex": Style(
                        color=c("hex-data"), bgcolor=c("hex-sel-data")
                    ),
                    "sel_ascii": Style(
                        color=c("hex-ascii"), bgcolor=c("hex-sel-ascii")
                    ),
                    "cursor": Style(color=c("background"), bgcolor=c("accent"), bold=True),
                    "text": Style(color=c("hex-data")),
                    "text_cursor": Style(
                        color=c("hex-data"), bgcolor=c("hex-sel-offset")
                    ),
                    "text_sel": Style(
                        color=c("hex-data"), bgcolor=c("hex-sel-data")
                    ),
                }
            return self._styles

        def on_mount(self) -> None:
            # Rebuild style cache whenever the app theme changes so the
            # cached foreground / selection colors stay in sync with c().
            self.watch(self.app, "theme", self._on_theme_change)

        def _on_theme_change(self, _old: str, _new: str) -> None:
            self._styles = None
            self.refresh()

        # ── Rendering ──────────────────────────────────────────

        def render_line(self, y: int) -> Strip:
            scroll_x, scroll_y = self.scroll_offset
            line_idx = y + scroll_y
            width = self.size.width

            if self._mode == MODE_HEX:
                strip = self._build_hex_line(line_idx)
            else:
                strip = self._build_text_line(line_idx)

            return strip.crop(scroll_x, scroll_x + width).apply_style(self.rich_style)

        def _build_hex_line(self, line_idx: int) -> Strip:
            limited = min(len(self._data), _HEXDUMP_RENDER_LIMIT)
            num_data_lines = (limited + self.BYTES_PER_LINE - 1) // self.BYTES_PER_LINE
            truncated = self.is_truncated

            if line_idx < 0 or line_idx >= num_data_lines + (1 if truncated else 0):
                return Strip.blank(self.virtual_size.width, self.rich_style)

            if line_idx == num_data_lines and truncated:
                remaining = len(self._data) - _HEXDUMP_RENDER_LIMIT
                marker = f"... {remaining:,} more bytes ({len(self._data):,} total)"
                return Strip([Segment(marker, self._get_styles()["offset"])])

            byte_start = line_idx * self.BYTES_PER_LINE
            byte_end = min(byte_start + self.BYTES_PER_LINE, limited)
            line_bytes = self._data[byte_start:byte_end]
            cursor = self.cursor_byte

            sel_range = self._selection_range_exclusive()
            sel_lo, sel_hi = sel_range if sel_range else (-1, -1)
            s = self._get_styles()

            segments: list[Segment] = []

            line_has_sel = sel_lo < byte_end and sel_hi > byte_start
            segments.append(
                Segment(
                    f"{byte_start:08x}",
                    s["sel_offset"] if line_has_sel else s["offset"],
                )
            )
            segments.append(Segment("  "))

            # Hex bytes
            for i in range(self.BYTES_PER_LINE):
                byte_idx = byte_start + i
                if i < len(line_bytes):
                    b = line_bytes[i]
                    is_cursor = byte_idx == cursor
                    is_selected = sel_lo <= byte_idx < sel_hi
                    style = (
                        s["cursor"] if is_cursor
                        else s["sel_hex"] if is_selected
                        else s["hex"]
                    )
                    segments.append(Segment(f"{b:02x}", style))
                    if i < self.BYTES_PER_LINE - 1:
                        next_in_sel = is_selected and (byte_idx + 1) < sel_hi
                        segments.append(
                            Segment(" ", s["sel_hex"] if next_in_sel else s["hex"])
                        )
                else:
                    segments.append(Segment("  ", s["hex"]))
                    if i < self.BYTES_PER_LINE - 1:
                        segments.append(Segment(" ", s["hex"]))

            segments.append(Segment("  "))

            # ASCII bytes
            for i in range(self.BYTES_PER_LINE):
                byte_idx = byte_start + i
                if i < len(line_bytes):
                    b = line_bytes[i]
                    ch = chr(b) if 32 <= b < 127 else "."
                    is_cursor = byte_idx == cursor
                    is_selected = sel_lo <= byte_idx < sel_hi
                    style = (
                        s["cursor"] if is_cursor
                        else s["sel_ascii"] if is_selected
                        else s["ascii"]
                    )
                    segments.append(Segment(ch, style))
                else:
                    segments.append(Segment(" ", s["ascii"]))

            return Strip(segments)

        def _build_text_line(self, line_idx: int) -> Strip:
            if line_idx < 0 or line_idx >= len(self._text_lines):
                return Strip.blank(self.virtual_size.width, self.rich_style)

            line_text = self._text_lines[line_idx]
            s = self._get_styles()
            sel_lines = self._text_selection_line_range()

            if sel_lines is not None and sel_lines[0] <= line_idx <= sel_lines[1]:
                style = s["text_sel"]
            elif line_idx == self._text_line_of_byte(self.cursor_byte):
                style = s["text_cursor"]
            else:
                style = s["text"]

            return Strip([Segment(line_text, style)])

        # ── Selection helpers ──────────────────────────────────

        def _selection_range_exclusive(self) -> tuple[int, int] | None:
            """Return (start, end) with exclusive end, or None if no mark."""
            if self.anchor_byte is None:
                return None
            lo = min(self.anchor_byte, self.cursor_byte)
            hi = max(self.anchor_byte, self.cursor_byte) + 1
            return (lo, hi)

        def _text_line_of_byte(self, byte_offset: int) -> int:
            """Find which text line contains the given byte offset."""
            starts = self._text_line_byte_starts
            if len(starts) < 2:
                return 0
            idx = bisect.bisect_right(starts, byte_offset) - 1
            return max(0, min(idx, len(self._text_lines) - 1))

        def _text_selection_line_range(self) -> tuple[int, int] | None:
            if self.anchor_byte is None:
                return None
            a = self._text_line_of_byte(self.anchor_byte)
            c_ = self._text_line_of_byte(self.cursor_byte)
            return (min(a, c_), max(a, c_))

        def _line_of_byte(self, byte_offset: int) -> int:
            if self._mode == MODE_HEX:
                return byte_offset // self.BYTES_PER_LINE
            return self._text_line_of_byte(byte_offset)

        # ── Watchers ───────────────────────────────────────────

        def watch_cursor_byte(self, old: int, new: int) -> None:
            if not self._data or old == new:
                return

            old_line = self._line_of_byte(old)
            new_line = self._line_of_byte(new)

            if self.anchor_byte is not None:
                lo, hi = (old_line, new_line) if old_line <= new_line else (new_line, old_line)
                for ln in range(lo, hi + 1):
                    self.refresh_line(ln)
            else:
                self.refresh_line(old_line)
                if new_line != old_line:
                    self.refresh_line(new_line)

            if self.is_mounted:
                self.scroll_to_region(
                    Region(0, new_line, 1, 1), animate=False, force=True,
                )

            self.post_message(self.CursorChanged(new, self.anchor_byte))

        def watch_anchor_byte(self, old, new) -> None:
            self.refresh()
            self.post_message(self.CursorChanged(self.cursor_byte, new))

        # ── Input handling ─────────────────────────────────────

        def _max_byte(self) -> int:
            limit = _HEXDUMP_RENDER_LIMIT if self._mode == MODE_HEX else _TEXT_RENDER_LIMIT
            return min(len(self._data), limit) - 1

        def _line_start(self, line: int, max_byte: int) -> int:
            """Return the first byte offset of ``line`` in the current mode."""
            if self._mode == MODE_HEX:
                return min(max(0, line) * self.BYTES_PER_LINE, max_byte)
            n_lines = len(self._text_lines)
            line = max(0, min(line, n_lines - 1))
            return min(self._text_line_byte_starts[line], max_byte)

        def _move_line(self, cur: int, delta: int, max_byte: int) -> int:
            """Move the cursor by ``delta`` lines.

            In hex mode this preserves the column (``cur ± delta*BPL``);
            in text mode it jumps to the start of the target line.
            """
            if self._mode == MODE_HEX:
                return max(0, min(cur + delta * self.BYTES_PER_LINE, max_byte))
            return self._line_start(self._line_of_byte(cur) + delta, max_byte)

        def on_key(self, event) -> None:
            if not self._data:
                return
            max_byte = self._max_byte()
            if max_byte < 0:
                return

            key = event.key
            cur = self.cursor_byte
            page = max(1, self.size.height - 1)

            if key == "right":
                new = min(cur + 1, max_byte)
            elif key == "left":
                new = max(cur - 1, 0)
            elif key == "up":
                new = self._move_line(cur, -1, max_byte)
            elif key == "down":
                new = self._move_line(cur, 1, max_byte)
            elif key == "pageup":
                new = self._move_line(cur, -page, max_byte)
            elif key == "pagedown":
                new = self._move_line(cur, page, max_byte)
            elif key == "home":
                new = self._line_start(self._line_of_byte(cur), max_byte)
            elif key == "end":
                if self._mode == MODE_HEX:
                    line = self._line_of_byte(cur)
                    new = min((line + 1) * self.BYTES_PER_LINE - 1, max_byte)
                else:
                    new = max_byte
            elif key == "ctrl+home":
                new = 0
            elif key == "ctrl+end":
                new = max_byte
            else:
                return

            self.cursor_byte = new
            event.stop()
            event.prevent_default()

        def on_click(self, event) -> None:
            if not self._data:
                return
            max_byte = self._max_byte()
            if max_byte < 0:
                return

            scroll_x, scroll_y = self.scroll_offset
            line_idx = event.y + scroll_y
            col = event.x + scroll_x

            if self._mode == MODE_HEX:
                limited = min(len(self._data), _HEXDUMP_RENDER_LIMIT)
                num_lines = (limited + self.BYTES_PER_LINE - 1) // self.BYTES_PER_LINE
                if line_idx < 0 or line_idx >= num_lines:
                    return

                hex_end = self.HEX_REGION_START + self.BYTES_PER_LINE * 3 - 1
                ascii_start = hex_end + 2

                if col < self.HEX_REGION_START:
                    byte_in_line = 0
                elif col < hex_end:
                    byte_in_line = (col - self.HEX_REGION_START) // 3
                elif col >= ascii_start:
                    byte_in_line = col - ascii_start
                else:
                    byte_in_line = 0

                byte_in_line = max(0, min(byte_in_line, self.BYTES_PER_LINE - 1))
                new_cursor = line_idx * self.BYTES_PER_LINE + byte_in_line
                self.cursor_byte = min(new_cursor, max_byte)
            elif 0 <= line_idx < len(self._text_lines):
                self.cursor_byte = self._line_start(line_idx, max_byte)

            event.stop()

        # ── Public API (mark mode control) ─────────────────────

        def toggle_mark(self) -> None:
            """Toggle mark mode at current cursor position."""
            self.anchor_byte = None if self.anchor_byte is not None else self.cursor_byte

        def clear_mark(self) -> None:
            self.anchor_byte = None

        @property
        def is_marking(self) -> bool:
            return self.anchor_byte is not None

        def get_selection(self) -> tuple[int, int] | None:
            """Return ``(start, end)`` byte range with exclusive end, or None."""
            return self._selection_range_exclusive()

    class ExplorerModal(ModalScreen[ExplorerResult | None]):
        """Full-screen explorer for raw body content with byte-range selection."""

        DEFAULT_CSS = """
        ExplorerModal {
            background: $surface;
        }
        ExplorerModal > #explorer-container {
            width: 100%;
            height: 100%;
            background: $surface;
        }
        ExplorerModal #explorer-title {
            height: 1;
            background: $primary-background;
            color: $text;
            padding: 0 1;
            text-style: bold;
        }
        ExplorerModal #explorer-status {
            height: 1;
            background: $surface;
            color: $accent;
            padding: 0 1;
        }
        ExplorerModal #explorer-content {
            height: 1fr;
        }
        ExplorerModal #explorer-preview {
            height: auto;
            max-height: 40%;
            display: none;
        }
        ExplorerModal #explorer-preview.visible {
            display: block;
        }
        ExplorerModal #preview-title {
            height: 1;
            background: $primary-background;
            padding: 0 1;
            text-style: bold;
        }
        ExplorerModal #preview-log {
            height: auto;
            max-height: 15;
            background: $surface;
            border: solid $panel;
        }
        ExplorerModal #explorer-hints {
            height: 1;
            dock: bottom;
            background: $primary-background;
            color: $text-muted;
            padding: 0 1;
        }
        """

        BINDINGS = [
            Binding("escape", "close_explorer", "Close", show=False),
            Binding("v", "toggle_mark", "Mark", show=False),
            Binding("p", "parse_selection", "Parse", show=False),
            Binding("t", "toggle_display", "Toggle Hex/Text", show=False),
            Binding("tab", "focus_viewer", show=False),
            Binding("shift+tab", "focus_viewer", show=False),
        ]

        def __init__(
            self,
            body: bytes,
            direction: str,
            headers: dict | None = None,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._body = body
            self._direction = direction
            self._headers = headers or {}
            self._last_result: ExplorerResult | None = None
            self._pending_selection: ExplorerSelection | None = None
            self._viewer: HexViewerWidget | None = None
            self._status: Static | None = None

        def compose(self) -> ComposeResult:
            size_str = f"{len(self._body):,}"
            label = self._direction.capitalize()
            with Vertical(id="explorer-container"):
                yield Static(
                    f"Explorer \u2014 {label} Body ({size_str} bytes) [HEX]",
                    id="explorer-title",
                )
                yield Static(
                    "Cursor at 0x0000 \u2014 press v to mark, then arrows to select",
                    id="explorer-status",
                )
                yield HexViewerWidget(id="explorer-content")
                with Vertical(id="explorer-preview"):
                    yield Static("", id="preview-title")
                    preview_log = RichLog(
                        id="preview-log",
                        wrap=True,
                        highlight=True,
                        markup=True,
                        auto_scroll=False,
                    )
                    preview_log.can_focus = False
                    yield preview_log
                yield Static(
                    "arrows: navigate | v: mark | p: parse | t: hex/text | Esc: cancel/close",
                    id="explorer-hints",
                )

        def on_mount(self) -> None:
            self._viewer = self.query_one("#explorer-content", HexViewerWidget)
            self._status = self.query_one("#explorer-status", Static)
            self._viewer.set_data(self._body, MODE_HEX)
            self._update_title()
            self._viewer.focus()
            self._update_selection_status()

        def on_screen_resume(self) -> None:
            """Restore focus to the viewer after a child modal dismisses."""
            if self._viewer is not None:
                self._viewer.focus()

        def action_focus_viewer(self) -> None:
            """Keep focus on the viewer — prevent tab-cycling."""
            if self._viewer is not None:
                self._viewer.focus()

        # ── Title / status ─────────────────────────────────────

        def _update_title(self) -> None:
            viewer = self._viewer
            mode_label = "HEX" if viewer is None or viewer.mode == MODE_HEX else "TEXT"
            label = self._direction.capitalize()
            size_str = f"{len(self._body):,}"
            title = self.query_one("#explorer-title", Static)
            trunc_note = " (truncated)" if (viewer and viewer.is_truncated) else ""
            title.update(
                f"Explorer \u2014 {label} Body ({size_str} bytes) "
                f"[{mode_label}]{trunc_note}"
            )

        def on_hex_viewer_widget_cursor_changed(
            self, event: "HexViewerWidget.CursorChanged"
        ) -> None:
            """Update status bar whenever cursor/anchor changes."""
            self._update_selection_status()

        def _update_selection_status(self) -> None:
            """Refresh the status bar with the current selection or cursor."""
            status = self._status
            viewer = self._viewer
            if status is None or viewer is None:
                return

            if viewer.is_marking:
                sel = viewer.get_selection()
                if sel is None or sel[1] <= sel[0]:
                    status.update(
                        "[MARK] Move arrows to select bytes", layout=False
                    )
                    return
                start, end = sel
                count = end - start
                status.update(
                    f"[MARK] Selection: 0x{start:04x}\u20130x{end:04x} "
                    f"({count:,} bytes)",
                    layout=False,
                )
            else:
                cursor = viewer.cursor_byte
                status.update(
                    f"Cursor at 0x{cursor:04x} \u2014 press v to mark, "
                    f"then arrows to select",
                    layout=False,
                )

        # ── Selection helpers ──────────────────────────────────

        def _get_current_selection(self) -> ExplorerSelection | None:
            """Build an ExplorerSelection from the viewer's current state."""
            if self._viewer is None:
                return None
            rng = self._viewer.get_selection()
            if rng is None:
                return None
            start, end = rng
            if end <= start:
                return None
            return ExplorerSelection(
                start=start,
                end=end,
                data=self._body[start:end],
            )

        def _get_selected_bytes(self) -> bytes | None:
            sel = self._get_current_selection()
            return sel.data if sel is not None else None

        # ── Actions ────────────────────────────────────────────

        def action_close_explorer(self) -> None:
            if self._viewer is not None and self._viewer.is_marking:
                self._viewer.clear_mark()
                self._update_selection_status()
            else:
                self.dismiss(self._last_result)

        def action_toggle_mark(self) -> None:
            """Toggle mark mode for byte-range selection."""
            if self._viewer is not None:
                self._viewer.toggle_mark()
                self._update_selection_status()

        def action_toggle_display(self) -> None:
            """Switch between hex and text display modes."""
            viewer = self._viewer
            if viewer is None:
                return
            viewer.set_mode(MODE_TEXT if viewer.mode == MODE_HEX else MODE_HEX)
            viewer.focus()
            self._update_title()
            self._update_selection_status()

        def action_parse_selection(self) -> None:
            """Parse selected bytes or full body using the body processing modal."""
            selection = self._get_current_selection()
            if selection is None:
                selection = ExplorerSelection(
                    start=0,
                    end=len(self._body),
                    data=self._body,
                )

            # Stash selection so the callback uses the same bytes
            # even if the cursor moves while the modal is open.
            self._pending_selection = selection

            from friTap.tui.modals.body_processing_modal import (
                BodyProcessingModal,
            )

            self.app.push_screen(
                BodyProcessingModal(
                    body_preview=selection.data,
                    segment_count=1,
                ),
                callback=self._on_parse_result,
            )

        def _on_parse_result(self, result) -> None:
            """Handle the body processing modal result."""
            selection = self._pending_selection
            self._pending_selection = None
            if result is None or selection is None:
                return

            processed = selection.data
            preview_parts = []

            if result.decompression:
                try:
                    from friTap.parsers.decompress import decompress_body

                    processed, err = decompress_body(
                        processed, result.decompression
                    )
                    preview_parts.append(result.decompression)
                    if err:
                        self._show_preview(
                            f"Decompression error: {err}",
                            " \u2192 ".join(preview_parts),
                            len(selection.data),
                            is_error=True,
                        )
                        return
                except ImportError:
                    self._show_preview(
                        "Decompression module not available",
                        result.decompression,
                        len(selection.data),
                        is_error=True,
                    )
                    return

            decoder = result.decoder or ""
            if decoder:
                preview_parts.append(decoder)

            label = " \u2192 ".join(preview_parts) if preview_parts else "raw"
            output = self._apply_decoder(processed, decoder, result)
            self._show_preview(output, label, len(selection.data))

            self._last_result = ExplorerResult(
                selection=selection, processing=result
            )

            if self._viewer is not None:
                self._viewer.focus()

        def _apply_decoder(
            self, data: bytes, decoder: str, result
        ) -> str:
            """Decode bytes using the selected decoder, return display string."""
            if decoder == "json":
                try:
                    parsed = json.loads(data)
                    return json.dumps(parsed, indent=2)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return f"JSON decode failed \u2014 showing raw:\n{data!r}"

            if decoder == "hex":
                return "\n".join(format_hexdump_lines(data, markup=True))

            if decoder == "base64":
                import base64

                try:
                    decoded = base64.b64decode(data)
                    try:
                        return decoded.decode("utf-8")
                    except UnicodeDecodeError:
                        return repr(decoded)
                except Exception as exc:
                    return f"Base64 decode failed: {exc}"

            if decoder == "raw_utf8":
                return data.decode("utf-8", errors="replace")

            if decoder == "protobuf":
                return self._decode_protobuf(data, result)

            if _is_text(data):
                return data.decode("utf-8", errors="replace")
            return repr(data)

        def _decode_protobuf(self, data: bytes, result) -> str:
            """Attempt protobuf decode of selected data."""
            cfg = result.protobuf_config
            if cfg and cfg.grpc_mode and len(data) >= 5:
                data = data[5:]

            try:
                import blackboxprotobuf  # type: ignore

                message, typedef = blackboxprotobuf.decode_message(data)
                return json.dumps(message, indent=2, default=str)
            except Exception:
                pass

            # Use the project's own protobuf wire decoder
            try:
                from friTap.parsers.protobuf.wire import (
                    decode_raw,
                    format_message,
                )

                msg = decode_raw(data)
                if msg.fields:
                    return format_message(msg)
            except (ValueError, ImportError):
                pass

            return f"Could not decode protobuf ({len(data)} bytes)"

        def _show_preview(
            self, content: str, label: str, size: int = 0,
            is_error: bool = False,
        ) -> None:
            """Display parse results in the preview pane."""
            preview = self.query_one("#explorer-preview", Vertical)
            title = self.query_one("#preview-title", Static)
            log = self.query_one("#preview-log", RichLog)

            if is_error:
                title.update(
                    f"[bold {c('error')}]Parse Error ({label})[/]"
                )
            else:
                title.update(
                    f"[bold {c('accent')}]Parse Result "
                    f"({size:,} bytes, {label})[/]"
                )

            log.clear()
            log.write(content)

            preview.add_class("visible")
