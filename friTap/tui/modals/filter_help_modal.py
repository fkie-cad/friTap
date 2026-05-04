#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Filter help screen overlay for friTap TUI.

Full-screen overlay showing available filter fields, operators,
boolean logic, quick toggles, and example expressions.
"""

from __future__ import annotations

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.screen import Screen
    from textual.widgets import Static
    from textual.containers import VerticalScroll
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from friTap.tui.themes import c


def _build_filter_help_text() -> str:
    """Build filter reference text with current theme colors."""

    primary = c('primary')
    accent = c('accent')
    muted = c('text-muted')
    dim = c('text-dim')
    # Use a slightly different accent for field types
    type_color = c('text-dim')

    def _field_line(name: str, ftype: str, desc: str) -> str:
        return f"  [{accent}]{name:<24}[/] [{type_color}]{ftype:<8}[/] {desc}"

    def _section(title: str) -> str:
        return f"[bold {muted}]=== {title} ===[/]"

    fields_network = "\n".join([
        _field_line("ip.src", "str", "Source IP address"),
        _field_line("ip.dst", "str", "Destination IP address"),
        _field_line("ip.addr", "str", "Source or destination IP (dual)"),
        _field_line("tcp.srcport", "int", "Source port"),
        _field_line("tcp.dstport", "int", "Destination port"),
        _field_line("tcp.port", "int", "Source or destination port (dual)"),
    ])

    fields_http = "\n".join([
        _field_line("http", "bool", "Any HTTP traffic (request or response)"),
        _field_line("http.request", "bool", "Request exists"),
        _field_line("http.request.method", "str", "HTTP method (GET, POST, ...)"),
        _field_line("http.request.uri", "str", "Request path and query"),
        _field_line("http.host", "str", "Host header"),
        _field_line("http.response", "bool", "Response exists"),
        _field_line("http.response.code", "int", "HTTP status code"),
        _field_line("http.content_type", "str", "Content-Type header"),
        _field_line("http.content_length", "int", "Response body size"),
    ])

    fields_protocol = "\n".join([
        _field_line("http2", "bool", "HTTP/2 traffic"),
        _field_line("http3", "bool", "HTTP/3 traffic"),
        _field_line("frame.protocol", "str", "Detected protocol (HTTP/1.1, HTTP/2, ...)"),
    ])

    fields_flow = "\n".join([
        _field_line("flow.state", "str", "Flow state (active, complete)"),
        _field_line("flow.duration", "float", "Duration in seconds"),
        _field_line("flow.size", "int", "Total bytes transferred"),
        _field_line("flow.has_request", "bool", "Has request data"),
        _field_line("flow.has_response", "bool", "Has response data"),
    ])

    fields_tls = "\n".join([
        _field_line("tls", "bool", "TLS traffic (session ID present)"),
        _field_line("tls.session_id", "str", "TLS session identifier"),
    ])

    fields_ohttp = "\n".join([
        _field_line("ohttp.present", "bool", "OHTTP inner request/response present"),
    ])

    fields_other = "\n".join([
        _field_line("ssh", "bool", "SSH traffic"),
        _field_line("ipsec", "bool", "IPSec traffic"),
    ])

    return f"""\
[bold {primary}]Display Filter Reference[/]

{_section("Fields: Network")}
{fields_network}

{_section("Fields: HTTP")}
{fields_http}

{_section("Fields: Protocol")}
{fields_protocol}

{_section("Fields: Flow")}
{fields_flow}

{_section("Fields: TLS")}
{fields_tls}

{_section("Fields: OHTTP")}
{fields_ohttp}

{_section("Fields: Other Protocols")}
{fields_other}

{_section("Operators")}
  [{accent}]==[/]          Equal to                [{dim}]http.host == "example.com"[/]
  [{accent}]!=[/]          Not equal to            [{dim}]http.request.method != "GET"[/]
  [{accent}]>[/]           Greater than            [{dim}]http.response.code > 400[/]
  [{accent}]>=[/]          Greater than or equal   [{dim}]flow.size >= 1024[/]
  [{accent}]<[/]           Less than               [{dim}]tcp.dstport < 1024[/]
  [{accent}]<=[/]          Less than or equal      [{dim}]flow.duration <= 5.0[/]
  [{accent}]contains[/]    Substring match         [{dim}]http.host contains "api"[/]
  [{accent}]matches[/]     Regex match             [{dim}]http.request.uri matches "/v[0-9]+"[/]

{_section("Boolean Logic")}
  [{accent}]and[/]         Both conditions must be true
  [{accent}]or[/]          Either condition must be true
  [{accent}]not[/] / [{accent}]![/]    Negate a condition
  [{accent}]( )[/]         Group expressions to control precedence

  Precedence (high to low): [{accent}]not[/] > [{accent}]and[/] > [{accent}]or[/]
  Use parentheses to override: [{dim}](A or B) and C[/]

{_section("Quick Toggles")}
  Toggle buttons in the filter modal provide one-click filtering:
  [{accent}]HTTP[/]        Show flows with detected protocol (not "unknown")
  [{accent}]Errors[/]      Show HTTP error responses (4xx/5xx)
  [{accent}]OHTTP[/]       Show flows with OHTTP encapsulation
  [{accent}]IPSec[/]       Show IPSec flows
  [{accent}]SSH[/]         Show SSH flows

  Toggles combine with the text filter using [{accent}]and[/] logic.

{_section("Examples")}
  [{dim}]ip.addr == "10.0.0.1"[/]
      All flows involving 10.0.0.1

  [{dim}]tcp.port == 443 and http.host contains "google"[/]
      HTTPS flows to Google hosts

  [{dim}]http.response.code >= 400[/]
      All error responses

  [{dim}]http.request.method == "POST" and http.host != "localhost"[/]
      POST requests to remote hosts

  [{dim}]not ohttp.present and frame.protocol == "HTTP/2"[/]
      HTTP/2 flows without OHTTP

  [{dim}](ip.src == "192.168.1.1" or ip.dst == "192.168.1.1") and tcp.port == 80[/]
      HTTP traffic to or from a specific host

  [{dim}]flow.size > 10000 and flow.has_response[/]
      Large flows that have a response

  [{dim}]http.request.uri matches "/api/v[0-9]+/users"[/]
      API user endpoint requests

  [{dim}]http[/]
      All HTTP traffic (any version)

  [{dim}]http2[/]
      HTTP/2 flows only

  [{dim}]http and http.response.code >= 400[/]
      HTTP errors across all versions

[dim {dim}]Press Esc to close.  Shift+Esc clears the active filter.[/]
"""


if TEXTUAL_AVAILABLE:

    class FilterHelpScreen(Screen):
        """Full-screen overlay with display filter reference."""

        DEFAULT_CSS = """
        FilterHelpScreen {
            align: center middle;
            background: $fritap-modal-overlay;
        }
        FilterHelpScreen > #filter-help-container {
            width: 75;
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
                yield Static(_build_filter_help_text(), id="filter-help-text")

        def action_dismiss_filter_help(self) -> None:
            """Close the filter help screen."""
            self.app.pop_screen()
