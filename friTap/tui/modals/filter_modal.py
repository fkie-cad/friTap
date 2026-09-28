#!/usr/bin/env python3

"""
Display filter modal for friTap TUI.

Provides a Wireshark-style display filter dialog with a text input field,
toggle buttons for common filters, and real-time validation feedback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional

from friTap.filter.errors import FIELD_REPLACEMENT
from friTap.filter.presets import FILTER_PRESETS, combined_preset_expression

if TYPE_CHECKING:
    from friTap.filter import FilterEngine
    from friTap.filter.errors import UnknownFieldError

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.timer import Timer
    from textual.widgets import Button, Input, Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


@dataclass
class FilterResult:
    """Result returned when the filter modal is dismissed with Apply or Clear."""

    text: str
    text_engine: Any  # FilterEngine | None
    toggle_engine: Any  # FilterEngine | None
    active_toggles: set[str] = field(default_factory=set)


# -- Unknown-field hints (pure, Textual-free) ---------------------------------

# Counts the flow-list rows a filter engine matches (None: cannot count).
MatchCounter = Callable[["FilterEngine"], Optional[int]]
# Current number of flow-list rows (keys the match-count cache).
RowCounter = Callable[[], int]

# Keys that apply the n-th fix of an ``UnknownFieldError`` (``err.actions``):
# for a bare unknown word F2-F4 are the generic searches (protocol / method /
# frame) and F5 the first did-you-mean name; for a word followed by an
# operator F2-F4 are the did-you-mean field replacements.
HINT_KEYS: tuple[str, ...] = ("f2", "f3", "f4", "f5")

CONTENT_SEARCH_NOTE = "(content search)"


@dataclass(frozen=True)
class HintAction:
    """One actionable hint line: press *key* to replace the input."""

    key: str
    expression: str
    note: str = ""

    def body(self, width: int) -> str:
        """The expression padded to *width*, followed by the note."""
        return f"{self.expression:<{width}}  {self.note}".rstrip()


@dataclass(frozen=True)
class UnknownFieldHint:
    """Structured hint block for an ``UnknownFieldError``."""

    message: str
    actions: list[HintAction]

    @property
    def expression_width(self) -> int:
        """Width of the longest action expression (aligns the notes)."""
        return max((len(a.expression) for a in self.actions), default=0)


def _unknown_field_message(err: "UnknownFieldError") -> str:
    message = f"Unknown field {err.name!r}."
    if not err.did_you_mean:
        return message
    if all(a.kind == FIELD_REPLACEMENT for a in err.actions):
        return f"{message} Did you mean:"  # the names are the actions below
    return f"{message} Did you mean: {', '.join(err.did_you_mean)}?"


def suggestion_note(expression: str, counter: MatchCounter | None) -> str:
    """Return ``(N rows)``, ``(content search)`` or ``""`` for *expression*.

    Content (``frame``) searches are never counted: they are expensive.
    Any failure while building the engine or counting yields ``""``.
    """
    from friTap.filter import FilterEngine

    engine = FilterEngine.try_create(expression)
    if isinstance(engine, str):
        return ""
    if engine.needs_context:
        return CONTENT_SEARCH_NOTE
    if counter is None:
        return ""
    try:
        count = counter(engine)
    except Exception:  # noqa: BLE001 — a hint must never break the modal
        return ""
    return f"({count} rows)" if isinstance(count, int) else ""


def build_unknown_field_hint(
    err: "UnknownFieldError", counter: MatchCounter | None = None,
) -> UnknownFieldHint:
    """Build the hint block for *err*: its actions on F2, F3, ... in order."""
    actions = [
        HintAction(key, action.expression, suggestion_note(action.expression, counter))
        for key, action in zip(HINT_KEYS, err.actions)
    ]
    return UnknownFieldHint(_unknown_field_message(err), actions)


if TEXTUAL_AVAILABLE:
    from rich.markup import escape

    from friTap.filter.errors import FilterSyntaxError, UnknownFieldError
    from friTap.tui.themes import c

    from .base import FriTapModal

    class FilterModal(FriTapModal[Optional[FilterResult]]):
        """Modal dialog for configuring display filters and toggle buttons."""

        # Toggle definitions: (button_id, label, filter_expression). Kept for
        # compatibility; the modal itself iterates friTap.filter.presets.
        TOGGLES: list[tuple[str, str, str]] = [
            (p.toggle_id, p.label, p.expression) for p in FILTER_PRESETS
        ]

        DEFAULT_CSS = """
        FilterModal > #modal-container {
            width: 80;
            height: auto;
            max-height: 85%;
            overflow-y: auto;
        }
        FilterModal #filter-input {
            margin: 1 0;
        }
        FilterModal #filter-input.valid {
            border: tall $success;
        }
        FilterModal #filter-input.invalid {
            border: tall $error;
        }
        FilterModal #filter-status {
            height: 1;
            margin: 0 0 1 0;
        }
        FilterModal #toggle-row {
            height: 1;
            margin: 0 0 1 0;
        }
        FilterModal .filter-toggle {
            min-width: 8;
            height: 1;
            margin: 0 1 0 0;
        }
        FilterModal .filter-toggle.active {
            background: $accent;
            text-style: bold;
        }
        FilterModal #filter-hints {
            height: auto;
            margin: 0 0 1 0;
        }
        FilterModal .filter-hint {
            height: auto;
        }
        FilterModal .filter-hint-action:hover {
            background: $boost;
        }
        """

        # Buttons on which Enter keeps its native meaning (press the button).
        # Everywhere else -- input, toggle buttons -- Enter applies the filter.
        ENTER_PRESSES_BUTTON: frozenset[str] = frozenset(
            {"btn-apply", "btn-clear", "btn-help", "btn-cancel"}
        )

        BINDINGS = [
            Binding("escape", "cancel", "Cancel", show=True),
            Binding("enter", "submit", "Apply", show=False, priority=True),
            Binding("space", "toggle_focused", "Toggle", show=False),
            Binding("f1", "show_help", "Help", show=False),
            *(
                Binding(key, f"apply_hint('{key}')", "Use hint", show=False)
                for key in HINT_KEYS
            ),
        ]

        def __init__(
            self,
            current_text: str = "",
            active_toggles: set[str] | None = None,
            match_counter: MatchCounter | None = None,
            row_count: RowCounter | None = None,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._match_counter = match_counter
            self._row_count = row_count
            # (expression, row count) -> match count: new rows invalidate.
            self._count_cache: dict[tuple[str, int], Optional[int]] = {}
            self._hint_expressions: dict[str, str] = {}
            self._current_text = current_text
            self._active_toggles: set[str] = set(active_toggles) if active_toggles else set()
            self._text_engine: Any = None  # FilterEngine | None
            self._toggle_engine: Any = None  # FilterEngine | None
            self._debounce_timer: Timer | None = None

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Display Filter[/]",
                    classes="modal-title",
                )
                yield Input(
                    placeholder='e.g., http.response.code >= 400',
                    id="filter-input",
                )
                yield Static("", id="filter-status")
                with Vertical(id="filter-hints"):
                    yield Static("", id="filter-hint-message", classes="filter-hint")
                    for key in HINT_KEYS:
                        yield Static(
                            "", id=f"filter-hint-{key}",
                            classes="filter-hint filter-hint-action",
                        )
                with Horizontal(id="toggle-row"):
                    for preset in FILTER_PRESETS:
                        yield Button(preset.label, id=preset.toggle_id, classes="filter-toggle")
                yield Static(
                    f"[{c('text-muted')}]Enter: Apply  |  Space: Toggle  |  F1: Help  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Apply", id="btn-apply", variant="primary")
                    yield Button("Clear", id="btn-clear", variant="default")
                    yield Button("?", id="btn-help", variant="default")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def on_mount(self) -> None:
            """Restore previous filter state on mount."""
            inp = self.query_one("#filter-input", Input)
            if self._current_text:
                inp.value = self._current_text
            # Activate previously active toggle buttons
            for tid in self._active_toggles:
                try:
                    btn = self.query_one(f"#{tid}", Button)
                    btn.add_class("active")
                except Exception:
                    pass
            # Rebuild the toggle engine from restored state
            if self._active_toggles:
                self._rebuild_toggle_engine()
            self._show_hint(None)
            inp.focus()

        # -- Input handling ---------------------------------------------------

        def on_input_changed(self, event: Input.Changed) -> None:
            """Debounce filter input -- lenient validation after 250ms."""
            if event.input.id != "filter-input":
                return
            self._cancel_debounce()
            self._debounce_timer = self.set_timer(0.25, self._validate_lenient)

        def on_input_submitted(self, event: Input.Submitted) -> None:
            """Strict validation and apply on Enter."""
            if event.input.id != "filter-input":
                return
            # Prevent the base class from pressing the primary button --
            # we handle Enter ourselves with strict validation.
            event.prevent_default()
            event.stop()
            self._cancel_debounce()
            self._apply_strict()

        def _cancel_debounce(self) -> None:
            """Stop a pending lenient validation."""
            if self._debounce_timer is not None:
                self._debounce_timer.stop()
                self._debounce_timer = None

        def _validate_lenient(self) -> None:
            """Run lenient validation on the current input text."""
            from friTap.filter import FilterEngine

            self._debounce_timer = None
            inp = self.query_one("#filter-input", Input)
            status = self.query_one("#filter-status", Static)
            text = inp.value.strip()

            if not text:
                self._text_engine = None
                inp.remove_class("valid", "invalid")
                status.update("")
                self._show_hint(None)
                return

            result = FilterEngine.try_create_detailed(text)
            self._show_hint(result)
            if isinstance(result, FilterSyntaxError):
                if FilterEngine.is_incomplete(text, result):
                    # Incomplete but plausible input
                    self._text_engine = None
                    inp.remove_class("valid", "invalid")
                    status.update("[dim]typing...[/]")
                else:
                    self._show_invalid(result)
            else:
                # Valid engine
                self._text_engine = result
                inp.remove_class("invalid")
                inp.add_class("valid")
                status.update(f"[{c('success')}]valid[/]")

        def _apply_strict(self) -> None:
            """Strict validation and dismiss with result on success."""
            from friTap.filter import FilterEngine

            inp = self.query_one("#filter-input", Input)
            status = self.query_one("#filter-status", Static)
            text = inp.value.strip()

            if not text:
                # Empty text filter is valid -- dismiss with current toggles
                self._text_engine = None
                status.update("[dim]Applying...[/]")
                self._dismiss_with_result()
                return

            result = FilterEngine.try_create_detailed(text)
            self._show_hint(result)
            if isinstance(result, FilterSyntaxError):
                self._show_invalid(result)
                return

            # Valid engine
            self._text_engine = result
            inp.remove_class("invalid")
            inp.add_class("valid")
            status.update("[dim]Applying...[/]")
            self._dismiss_with_result()

        def _show_invalid(self, error: FilterSyntaxError) -> None:
            """Mark the input invalid and show *error* in the status line.

            An unknown field is already explained by the hint block (with
            "did you mean" names), so the status line stays empty then.
            """
            self._text_engine = None
            inp = self.query_one("#filter-input", Input)
            inp.remove_class("valid")
            inp.add_class("invalid")
            message = "" if isinstance(error, UnknownFieldError) else str(error)
            if len(message) > 60:
                message = message[:57] + "..."
            self.query_one("#filter-status", Static).update(
                f"[red]{escape(message)}[/]" if message else ""
            )

        # -- Keyboard: Enter applies, Space toggles ---------------------------

        def action_submit(self) -> None:
            """Enter: apply the filter, unless an action button has focus."""
            focused = self.focused
            if isinstance(focused, Button) and focused.id in self.ENTER_PRESSES_BUTTON:
                focused.press()
                return
            self._cancel_debounce()
            self._apply_strict()

        def action_toggle_focused(self) -> None:
            """Space on a focused toggle button flips it (Enter applies)."""
            focused = self.focused
            if isinstance(focused, Button) and focused.has_class("filter-toggle"):
                focused.press()

        # -- Unknown-field hints ----------------------------------------------

        def _count_matches(self, engine: "FilterEngine") -> Optional[int]:
            """Cached call of the injected match counter.

            Keyed on (expression, row count), so rows that arrived since the
            last count refresh it. Errors propagate to ``suggestion_note``.
            """
            if self._match_counter is None:
                return None
            rows = self._row_count() if self._row_count else 0
            key = (engine.expression, rows)
            if key not in self._count_cache:
                self._count_cache[key] = self._match_counter(engine)
            return self._count_cache[key]

        def _show_hint(self, result: Any) -> None:
            """Render the hint block if *result* is an UnknownFieldError, else hide it."""
            err = result if isinstance(result, UnknownFieldError) else None
            hint = build_unknown_field_hint(err, self._count_matches) if err else None
            self._hint_expressions = {a.key: a.expression for a in hint.actions} if hint else {}
            self.query_one("#filter-hints").display = hint is not None
            if hint is None:
                return
            self.query_one("#filter-hint-message", Static).update(f"[red]{escape(hint.message)}[/]")
            actions = {a.key: a for a in hint.actions}
            width = hint.expression_width
            for key in HINT_KEYS:
                widget = self.query_one(f"#filter-hint-{key}", Static)
                action = actions.get(key)
                widget.display = action is not None
                widget.update(self._hint_markup(action, width) if action else "")

        @staticmethod
        def _hint_markup(action: HintAction, width: int) -> str:
            key = f"[bold {c('accent')}]{escape(action.key.upper())}[/]"
            return f"{key}  {escape(action.body(width))}"

        def action_apply_hint(self, key: str) -> None:
            """Replace the input with the hint bound to *key* and revalidate."""
            expression = self._hint_expressions.get(key)
            if not expression:
                return
            inp = self.query_one("#filter-input", Input)
            inp.value = expression
            inp.cursor_position = len(expression)
            self._cancel_debounce()
            self._validate_lenient()

        def on_click(self, event: Any) -> None:
            """Clicking a hint line applies it like its function key."""
            widget_id = getattr(getattr(event, "widget", None), "id", None) or ""
            if widget_id.startswith("filter-hint-f"):
                self.action_apply_hint(widget_id.removeprefix("filter-hint-"))

        # -- Toggle handling --------------------------------------------------

        def on_button_pressed(self, event: Button.Pressed) -> None:
            btn_id = event.button.id

            if btn_id == "btn-apply":
                self._apply_strict()
                return

            if btn_id == "btn-clear":
                self._clear_all()
                return

            if btn_id == "btn-help":
                self._push_help()
                return

            if btn_id == "btn-cancel":
                self.dismiss(None)
                return

            # Check if it's a toggle button
            is_toggle = any(p.toggle_id == btn_id for p in FILTER_PRESETS)
            if not is_toggle:
                return

            # Toggle the button state
            if btn_id in self._active_toggles:
                self._active_toggles.discard(btn_id)
                event.button.remove_class("active")
            else:
                self._active_toggles.add(btn_id)
                event.button.add_class("active")

            self._rebuild_toggle_engine()

        def _rebuild_toggle_engine(self) -> None:
            """Build a combined FilterEngine from all active toggles."""
            from friTap.filter import FilterEngine

            if not self._active_toggles:
                self._toggle_engine = None
                return

            combined = combined_preset_expression(self._active_toggles)
            if not combined:
                self._toggle_engine = None
                return

            try:
                self._toggle_engine = FilterEngine(combined)
            except Exception:
                self._toggle_engine = None

        # -- Clear / Help / Dismiss -------------------------------------------

        def _clear_all(self) -> None:
            """Clear input and all toggles, then dismiss with empty result."""
            inp = self.query_one("#filter-input", Input)
            inp.value = ""
            inp.remove_class("valid", "invalid")

            for preset in FILTER_PRESETS:
                try:
                    btn = self.query_one(f"#{preset.toggle_id}", Button)
                    btn.remove_class("active")
                except Exception:
                    pass

            self._active_toggles.clear()
            self._text_engine = None
            self._toggle_engine = None

            self.dismiss(FilterResult(
                text="",
                text_engine=None,
                toggle_engine=None,
                active_toggles=set(),
            ))

        def action_show_help(self) -> None:
            """Show the filter help modal (F1 binding)."""
            self._push_help()

        def _push_help(self) -> None:
            """Push the filter help modal screen."""
            from .filter_help_modal import FilterHelpScreen
            self.app.push_screen(FilterHelpScreen())

        def _dismiss_with_result(self) -> None:
            """Dismiss the modal with the current filter state."""
            inp = self.query_one("#filter-input", Input)
            self.dismiss(FilterResult(
                text=inp.value.strip(),
                text_engine=self._text_engine,
                toggle_engine=self._toggle_engine,
                active_toggles=set(self._active_toggles),
            ))
