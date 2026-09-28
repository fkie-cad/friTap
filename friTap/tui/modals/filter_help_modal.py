#!/usr/bin/env python3

"""
Filter help screen overlay for friTap TUI.

Full-screen overlay showing available filter fields, operators,
boolean logic, quick toggles, and example expressions.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Callable, Union

from rich.console import Console, Group, RenderableType
from rich.markup import escape
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.containers import VerticalScroll
    from textual.screen import Screen
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from friTap.filter.fields import FIELD_REGISTRY, FieldDef
from friTap.filter.layer_fields import LAYER_FIELD_SPECS
from friTap.filter.presets import FILTER_PRESETS
from friTap.filter.protocols import PROTOCOL_ALIASES, known_protocol_names
from friTap.tui.themes import c

# -- Help content model --------------------------------------------------------
#
# The help is a list of blocks, each rendered as a Rich renderable. Grid cells
# wrap inside their own column, so continuation lines stay aligned at any width.


@dataclass(frozen=True)
class _Para:
    """A paragraph of Rich markup, indented by *indent* columns on every line."""

    markup: str
    indent: int = 2

    def renderable(self) -> RenderableType:
        return Padding(Text.from_markup(self.markup), (0, 0, 0, self.indent))


@dataclass(frozen=True)
class _Grid:
    """Aligned columns: fixed-width styled columns, the last one wraps."""

    rows: tuple[tuple[str, ...], ...]
    styles: tuple[str, ...]
    widths: tuple[int, ...]  # min widths of all but the last column
    indent: int = 2

    def renderable(self) -> RenderableType:
        grid = Table.grid(padding=(0, 1))
        for i, style in enumerate(self.styles):
            fixed = i < len(self.widths)
            grid.add_column(
                style=style or None,
                min_width=self.widths[i] if fixed else None,
                no_wrap=fixed,
                ratio=None if fixed else 1,
            )
        for row in self.rows:
            grid.add_row(*(Text(cell) for cell in row))  # cells are plain text
        return Padding(grid, (0, 0, 0, self.indent))


_Block = Union[_Para, _Grid]


def _field_grid(rows: tuple[tuple[str, str, str], ...]) -> _Grid:
    """Name / type / description table in the standard field layout."""
    return _Grid(rows, (c('accent'), c('text-dim'), ""), (24, 8))


def _protocols_blocks(accent: str, dim: str) -> list[_Block]:
    """Generated list of protocol names and alias -> members."""
    names = [n for n in known_protocol_names() if n not in PROTOCOL_ALIASES]
    aliases = tuple(
        (alias, "-> " + ", ".join(sorted(PROTOCOL_ALIASES[alias])))
        for alias in sorted(PROTOCOL_ALIASES)
    )
    return [
        _Para(f"Use a name as a bare word ([{dim}]telegram[/]) or as "
              f"[{dim}]protocol.<name>[/]; matching is case-insensitive."),
        _Para(f"[{accent}]{', '.join(names)}[/]"),
        _Para("Aliases (match any member):"),
        _Grid(aliases, (accent, ""), (12,)),
    ]


def _layer_field_groups() -> dict[str, list]:
    """LAYER_FIELD_SPECS grouped by protocol prefix, in table order."""
    groups: dict[str, list] = {}
    for spec in LAYER_FIELD_SPECS:
        groups.setdefault(spec.field.split(".", 1)[0], []).append(spec)
    return groups


def _protocol_field_blocks() -> list[_Block]:
    blocks: list[_Block] = []
    for proto, specs in _layer_field_groups().items():
        blocks.append(_Para(f"[bold]{proto}[/]"))
        blocks.append(_field_grid(tuple((s.field, s.value_type, s.description) for s in specs)))
    return blocks


# Static fields (FIELD_REGISTRY) grouped for the help. Generic fields come in
# this fixed order; the other groups match by name, in registry order. Fields
# matching no group land in "Other", so a new field can never go missing.
_GENERIC_FIELD_ORDER = ("protocol", "frame.protocol", "method", "transport",
                        "frame", "info", "process")

_FIELD_GROUPS: tuple[tuple[str, Callable[[str], bool]], ...] = (
    ("Network", lambda name: name.startswith(("ip.", "tcp."))),
    ("HTTP", lambda name: name.startswith("http")),
    ("Flow", lambda name: name.startswith("flow.")),
    ("TLS", lambda name: name == "tls" or name.startswith("tls.")),
)


def _field_row(fdef: FieldDef) -> tuple[str, str, str]:
    """Name / type (``*`` = multi-valued) / description of one static field."""
    return fdef.name, fdef.value_type + ("*" if fdef.multi else ""), fdef.description


def _static_field_groups() -> list[tuple[str, tuple[tuple[str, str, str], ...]]]:
    """FIELD_REGISTRY as (group title, rows); layer fields are listed separately."""
    layer_fields = {spec.field for spec in LAYER_FIELD_SPECS}
    remaining = [name for name in FIELD_REGISTRY
                 if name not in layer_fields and name not in _GENERIC_FIELD_ORDER]
    groups = [("Generic", [n for n in _GENERIC_FIELD_ORDER if n in FIELD_REGISTRY])]
    for title, belongs in _FIELD_GROUPS:
        groups.append((title, [n for n in remaining if belongs(n)]))
        remaining = [n for n in remaining if not belongs(n)]
    groups.append(("Other", remaining))
    return [(title, tuple(_field_row(FIELD_REGISTRY[n]) for n in names))
            for title, names in groups if names]


_OPERATORS = (
    ("==", "Equal to", 'http.host == "example.com"'),
    ("!=", "Not equal to", 'http.request.method != "GET"'),
    (">", "Greater than", "http.response.code > 400"),
    (">=", "Greater or equal", "flow.size >= 1024"),
    ("<", "Less than", "tcp.dstport < 1024"),
    ("<=", "Less or equal", "flow.duration <= 5.0"),
    ("contains", "Substring match", 'http.host contains "api"'),
    ("matches", "Regex match", 'http.request.uri matches "/v[0-9]+"'),
)

_BOOLEAN_LOGIC = (
    ("and", "Both conditions must be true"),
    ("or", "Either condition must be true"),
    ("not / !", "Negate a condition"),
    ("( )", "Group expressions to control precedence"),
)

# (expression, explanation) pairs for the Examples section.
_EXAMPLES: tuple[tuple[str, str], ...] = (
    ('ip.addr == "10.0.0.1"', "All flows involving 10.0.0.1"),
    ('tcp.port == 443 and http.host contains "google"', "HTTPS flows to Google hosts"),
    ("http.response.code >= 400", "All error responses"),
    ('http.request.method == "POST" and http.host != "localhost"',
     "POST requests to remote hosts"),
    ('not ohttp.present and frame.protocol == "HTTP/2"', "HTTP/2 flows without OHTTP"),
    ("http1", "HTTP/1.x flows (same as protocol == http1)"),
    ('frame.protocol == "HTTP/1.x"', "HTTP/1.x flows, by display label "
                                     "(or frame.protocol == http1)"),
    ('(ip.src == "192.168.1.1" or ip.dst == "192.168.1.1") and tcp.port == 80',
     "HTTP traffic to or from a specific host"),
    ("flow.size > 10000 and flow.has_response", "Large flows that have a response"),
    ('http.request.uri matches "/api/v[0-9]+/users"', "API user endpoint requests"),
    ("http", "HTTP flows only (HTTP/1.x, HTTP/2, HTTP/3)"),
    ("http2", "HTTP/2 flows only"),
    ("http and http.response.code >= 400", "HTTP errors across all versions"),
    ("telegram", "All Telegram flows (MTProto cloud + Secret Chats)"),
    ('protocol contains "tele"', 'Any flow whose protocol name contains "tele"'),
    ('method == "upload.getFile"', "Flows carrying a given TL method"),
    ("mtproto.dc_id == 2", "MTProto flows to data center 2"),
    ('signal.msg contains "hi"', 'Signal flows with a message containing "hi"'),
    ('frame contains "password"', "Decrypted content search (case-insensitive)"),
    ("telegram and not method contains msgs_ack", "Telegram flows without msgs_ack messages"),
)


def _example_blocks(dim: str) -> list[_Block]:
    blocks: list[_Block] = []
    for expression, explanation in _EXAMPLES:
        blocks += [_Para(f"[{dim}]{escape(expression)}[/]"), _Para(explanation, indent=6),
                   _Para("", indent=0)]
    return blocks


def _static_field_blocks(section: Callable[..., list[_Block]], dim: str) -> list[_Block]:
    """One "Fields: <group>" section per static field group; str* is footnoted once."""
    blocks: list[_Block] = []
    for title, rows in _static_field_groups():
        body: list[_Block] = [_field_grid(rows)]
        if title == "Generic":
            body.append(_Para(f'[{dim}]str* = multi-valued (see "Multi-valued fields" below)[/]'))
        blocks += section(f"Fields: {title}", *body)
    return blocks


def _build_filter_help_blocks() -> list[_Block]:
    """The whole filter reference as blocks, using current theme colors."""
    primary, accent = c('primary'), c('accent')
    muted, dim = c('text-muted'), c('text-dim')
    blank = _Para("", indent=0)

    def section(title: str, *body: _Block) -> list[_Block]:
        return [_Para(f"[bold {muted}]=== {title} ===[/]", indent=0), *body, blank]

    presets = tuple((p.label, p.description, p.expression) for p in FILTER_PRESETS)
    return [
        _Para(f"[bold {primary}]Display Filter Reference[/]", indent=0),
        blank,
        *section("Protocols", *_protocols_blocks(accent, dim)),
        *_static_field_blocks(section, dim),
        *section("Protocol Fields",
                 _Para("Fields parsed from the decoded protocol layers, grouped by protocol:"),
                 *_protocol_field_blocks()),
        *section("Multi-valued fields", _Para(
            f"[{accent}]protocol[/], [{accent}]method[/] and most protocol fields can hold "
            "several values per flow (e.g. all TL methods of a Telegram flow). A comparison "
            f"matches if [bold]any[/] value matches; [{accent}]!=[/] matches only if "
            "[bold]no[/] value is equal.")),
        *section("Content search", _Para(
            f'[{accent}]frame contains "text"[/] searches the decrypted flow content, '
            "case-insensitively. It can be slower on large captures; the engine evaluates "
            f"cheaper terms of an [{accent}]and[/] first automatically.")),
        *section("Values", _Para(
            'Quote strings with spaces or special characters ("HTTP/1.x"). Plain words, '
            f"numbers and hex ids work unquoted ([{dim}]protocol == http1[/], "
            f"[{dim}]mtproto.session_id == 0a1b2c[/]). Inside quotes \\\" \\' \\n \\r "
            "\\t and \\\\ (a literal backslash) are escapes; any other backslash is kept, so "
            f"regex escapes work directly ([{dim}]frame matches \"id=\\d+\\s\"[/]) and "
            f"match a literal backslash in [{accent}]contains[/]/[{accent}]==[/]. Raw strings "
            f"[{dim}]r\"...\"[/] keep every backslash.")),
        *section("Operators", _Grid(_OPERATORS, (accent, "", dim), (11, 18))),
        *section("Boolean Logic", _Grid(_BOOLEAN_LOGIC, (accent, ""), (11,)), blank,
                 _Para(f"Precedence (high to low): [{accent}]not[/] > [{accent}]and[/] > "
                       f"[{accent}]or[/]"),
                 _Para(f"Use parentheses to override: [{dim}](A or B) and C[/]")),
        *section("Quick Toggles",
                 _Para("Toggle buttons in the filter dialog provide one-click filtering "
                       "(click or Space toggles, Enter applies):"),
                 _Grid(presets, (accent, "", dim), (11, 20)), blank,
                 _Para(f"Toggles combine with the text filter using [{accent}]and[/] logic.")),
        *section("Examples", *_example_blocks(dim), _Para(
            "Unknown field? The filter dialog suggests fixes: F2/F3/F4 apply the "
            'protocol / method / frame search, F5 the "did you mean" name. For an '
            'unknown field before an operator (mtprot.dc_id == 2), F2/F3/F4 apply '
            'the "did you mean" corrections instead.')),
        _Para(f"[dim {dim}]Press Esc to close.  Shift+Esc clears the active filter.[/]",
              indent=0),
    ]


def _build_filter_help_text(width: int = 100) -> str:
    """The filter reference as plain text, rendered at *width* columns."""
    console = Console(record=True, width=width, file=io.StringIO())
    console.print(build_filter_help_renderable())
    return console.export_text()


def build_filter_help_renderable() -> RenderableType:
    """The filter reference as an aligned Rich renderable for the help screen."""
    return Group(*(block.renderable() for block in _build_filter_help_blocks()))


if TEXTUAL_AVAILABLE:

    class FilterHelpScreen(Screen):
        """Full-screen overlay with display filter reference."""

        DEFAULT_CSS = """
        FilterHelpScreen {
            align: center middle;
            background: $fritap-modal-overlay;
        }
        FilterHelpScreen > #filter-help-container {
            width: 90;
            max-width: 95%;
            max-height: 85%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 2 3;
        }
        """

        BINDINGS = [
            Binding("escape", "dismiss_filter_help", "Close", show=True),
            Binding("q", "dismiss_filter_help", "Close", show=False),
        ]

        def compose(self) -> ComposeResult:
            with VerticalScroll(id="filter-help-container"):
                yield Static(build_filter_help_renderable(), id="filter-help-text")

        def action_dismiss_filter_help(self) -> None:
            """Close the filter help screen."""
            self.app.pop_screen()
