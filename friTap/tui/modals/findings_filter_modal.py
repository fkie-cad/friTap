#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Findings filter modal for friTap TUI.

Provides a dialog to build a :class:`~friTap.analysis.filtering.FindingFilter`
from severity / category chips, a free-text search, and a min-confidence input.
Mirrors :class:`~friTap.tui.modals.filter_modal.FilterModal`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Button, Input, Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


@dataclass
class FindingFilterResult:
    """Result returned when the findings filter modal is dismissed with Apply."""

    flt: Any  # FindingFilter
    label: str = ""


if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c
    from .base import FriTapModal

    class FindingsFilterModal(FriTapModal[Optional[FindingFilterResult]]):
        """Modal dialog for configuring the findings display filter."""

        # Severity chips: (button_id, label, severity_value)
        SEVERITY_CHIPS: list[tuple[str, str, str]] = [
            ("sev-critical", "CRITICAL", "critical"),
            ("sev-high", "HIGH", "high"),
            ("sev-medium", "MEDIUM", "medium"),
            ("sev-low", "LOW", "low"),
            ("sev-info", "INFO", "info"),
        ]

        # Category chips: (button_id, label, category_value)
        CATEGORY_CHIPS: list[tuple[str, str, str]] = [
            ("cat-secret", "secret", "secret"),
            ("cat-pii", "pii", "pii"),
            ("cat-network", "network", "network"),
            ("cat-protocol", "protocol", "protocol"),
        ]

        DEFAULT_CSS = """
        FindingsFilterModal > #modal-container {
            width: 80;
            height: auto;
            max-height: 85%;
        }
        FindingsFilterModal .chip-row {
            height: 1;
            margin: 0 0 1 0;
        }
        FindingsFilterModal .findings-chip {
            min-width: 8;
            height: 1;
            margin: 0 1 0 0;
        }
        FindingsFilterModal .findings-chip.active {
            background: $accent;
            text-style: bold;
        }
        FindingsFilterModal .field-label {
            height: 1;
            color: $fritap-text-muted;
        }
        FindingsFilterModal Input {
            margin: 0 0 1 0;
        }
        """

        BINDINGS = [
            Binding("escape", "cancel", "Cancel", show=True),
        ]

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self._active_severity: str | None = None  # single floor
            self._active_categories: set[str] = set()

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Findings Filter[/]",
                    classes="modal-title",
                )
                yield Static("[dim]Min severity (floor):[/]", classes="field-label")
                with Horizontal(classes="chip-row"):
                    for btn_id, label, _ in self.SEVERITY_CHIPS:
                        yield Button(label, id=btn_id, classes="findings-chip")
                yield Static("[dim]Category:[/]", classes="field-label")
                with Horizontal(classes="chip-row"):
                    for btn_id, label, _ in self.CATEGORY_CHIPS:
                        yield Button(label, id=btn_id, classes="findings-chip")
                yield Static("[dim]Text search:[/]", classes="field-label")
                yield Input(placeholder="substring in title/description/evidence", id="findings-text")
                yield Static("[dim]Min confidence (0.0 - 1.0):[/]", classes="field-label")
                yield Input(placeholder="e.g. 0.5", id="findings-conf")
                yield Static(
                    f"[{c('text-muted')}]Enter: Apply  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Apply", id="btn-apply", variant="primary")
                    yield Button("Clear", id="btn-clear", variant="default")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def on_mount(self) -> None:
            try:
                self.query_one("#findings-text", Input).focus()
            except Exception:
                pass

        # -- Chip handling ----------------------------------------------------

        def on_button_pressed(self, event: Button.Pressed) -> None:
            btn_id = event.button.id

            if btn_id == "btn-apply":
                self._apply()
                return
            if btn_id == "btn-clear":
                self._clear_all()
                return
            if btn_id == "btn-cancel":
                self.dismiss(None)
                return

            # Severity chips are mutually exclusive (a single floor).
            sev_match = next((s for bid, _, s in self.SEVERITY_CHIPS if bid == btn_id), None)
            if sev_match is not None:
                if self._active_severity == sev_match:
                    self._active_severity = None
                    event.button.remove_class("active")
                else:
                    self._active_severity = sev_match
                    for bid, _, _ in self.SEVERITY_CHIPS:
                        try:
                            self.query_one(f"#{bid}", Button).remove_class("active")
                        except Exception:
                            pass
                    event.button.add_class("active")
                return

            # Category chips are multi-select.
            cat_match = next((cv for bid, _, cv in self.CATEGORY_CHIPS if bid == btn_id), None)
            if cat_match is not None:
                if cat_match in self._active_categories:
                    self._active_categories.discard(cat_match)
                    event.button.remove_class("active")
                else:
                    self._active_categories.add(cat_match)
                    event.button.add_class("active")

        # -- Apply / Clear ----------------------------------------------------

        def _apply(self) -> None:
            from friTap.analysis.filtering import FindingFilter

            text_val = self.query_one("#findings-text", Input).value.strip()
            conf_raw = self.query_one("#findings-conf", Input).value.strip()
            min_conf: float | None = None
            if conf_raw:
                try:
                    min_conf = float(conf_raw)
                except ValueError:
                    min_conf = None

            categories = frozenset(self._active_categories) if self._active_categories else None

            flt = FindingFilter(
                min_severity=self._active_severity,
                categories=categories,
                min_confidence=min_conf,
                text=text_val or None,
            )

            # Build a short human-readable label.
            parts: list[str] = []
            if self._active_severity:
                parts.append(f">={self._active_severity}")
            if categories:
                parts.append("/".join(sorted(categories)))
            if text_val:
                parts.append(f'"{text_val}"')
            if min_conf is not None:
                parts.append(f"conf>={min_conf:g}")
            label = " ".join(parts)

            self.dismiss(FindingFilterResult(flt=flt, label=label))

        def _clear_all(self) -> None:
            self._active_severity = None
            self._active_categories.clear()
            for bid, _, _ in self.SEVERITY_CHIPS + self.CATEGORY_CHIPS:
                try:
                    self.query_one(f"#{bid}", Button).remove_class("active")
                except Exception:
                    pass
            try:
                self.query_one("#findings-text", Input).value = ""
                self.query_one("#findings-conf", Input).value = ""
            except Exception:
                pass
            # Apply an empty (match-all) filter.
            from friTap.analysis.filtering import FindingFilter
            self.dismiss(FindingFilterResult(flt=FindingFilter(), label=""))

        def on_input_submitted(self, event: Input.Submitted) -> None:
            """Enter in any input applies the filter."""
            event.prevent_default()
            event.stop()
            self._apply()
