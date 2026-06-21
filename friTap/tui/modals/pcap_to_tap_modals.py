#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modals for the guided pcap-to-tap conversion wizard.

These power :class:`friTap.tui.wizard.PcapToTapWizard`, the flow launched when
the user runs ``fritap -r <file>.pcap`` / ``fritap <file>.pcapng``. The wizard
converts an existing capture into a ``.tap`` (decrypting with an optional TLS
keylog and one or more per-protocol/layered keylogs) and then opens the result
in the replay view.

Three modals, mirroring the shape of the live-capture wizard modals:

* :class:`PcapPathsModal`  — confirm the pcap input and choose the output
  ``.tap`` path (both path inputs).
* :class:`ProtocolKeylogModal` — add ONE per-protocol keylog: pick the protocol
  (``tls`` plus every offline-decryptor, e.g. Signal / Telegram) and give its
  keylog path. Returns a dict the wizard loops on so several keylogs can be
  collected. TLS is offered here like any other protocol — its keylog strips
  TLS so protocols that ride inside it (Signal) can be decrypted.
* :class:`PcapToTapConfirmModal` — summarize the collected answers and confirm.

Each modal returns ``None`` when the user backs out (Esc / Cancel), mirroring
the established wizard back-navigation convention.
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.widgets import Button, Input, OptionList, Static
    from textual.widgets.option_list import Option
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c
    from .base import FriTapModal

    class PcapPathsModal(FriTapModal[Optional[dict]]):
        """Step 1: confirm pcap input and output .tap path.

        TLS and per-protocol keylogs are collected in step 2
        (:class:`ProtocolKeylogModal`), where TLS is offered like any other
        protocol — so this screen only deals with the two file paths.
        """

        DEFAULT_CSS = """
        PcapPathsModal > #modal-container {
            width: 70;
            height: auto;
            max-height: 80%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        PcapPathsModal .path-label {
            margin-top: 1;
            color: $fritap-text-secondary;
        }
        PcapPathsModal .modal-description {
            margin: 1 0;
            color: $fritap-text-dim;
            text-align: center;
        }
        PcapPathsModal Input {
            margin-bottom: 1;
        }
        """

        def __init__(
            self,
            default_pcap: str = "",
            default_tap: str = "",
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._default_pcap = default_pcap
            self._default_tap = default_tap

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Convert PCAP to .tap[/]",
                    classes="modal-title",
                )
                yield Static(
                    "Confirm the capture to convert and the output file. "
                    "Keylogs (TLS, Signal, ...) are added on the next screen.",
                    classes="modal-description",
                )

                yield Static(f"[{c('text-secondary')}]PCAP file:[/]", classes="path-label")
                yield Input(
                    value=self._default_pcap,
                    placeholder="Path to .pcap or .pcapng...",
                    id="pcap-input",
                )

                yield Static(
                    f"[{c('text-secondary')}]Output .tap file:[/]",
                    classes="path-label",
                )
                yield Input(
                    value=self._default_tap,
                    placeholder="Defaults to <pcap stem>.tap...",
                    id="tap-input",
                )

                yield Static(
                    f"[{c('text-muted')}]Enter: Next  |  Tab: Edit fields  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Next", id="btn-next", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def _auto_focus(self) -> None:
            try:
                self.query_one("#pcap-input", Input).focus()
            except Exception:
                pass

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-next":
                self._submit()
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

        def _value(self, widget_id: str) -> str:
            try:
                return self.query_one(widget_id, Input).value.strip()
            except Exception:
                return ""

        def _submit(self) -> None:
            """Collect input values and dismiss with a result dict."""
            pcap = self._value("#pcap-input")
            if not pcap:
                # Nothing to convert without a pcap — keep the modal open.
                try:
                    self.query_one("#pcap-input", Input).focus()
                except Exception:
                    pass
                return
            self.dismiss({
                "pcap": pcap,
                "tap": self._value("#tap-input"),
            })

    class ProtocolKeylogModal(FriTapModal[Optional[dict]]):
        """Step 2: add ONE per-protocol (layered) keylog.

        Pick the protocol from the offline-decryptor registry and supply its
        keylog path. The wizard re-shows this modal so several keylogs can be
        added (e.g. a Signal keylog AND a Telegram keylog). When no protocol
        decryptors are registered the protocol list is empty and the user can
        only finish.

        Result dict keys:
            * ``action`` — ``"add"`` (add this protocol+keylog and ask again) or
              ``"done"`` (finished adding; proceed to confirm).
            * ``protocol`` / ``keylog`` — present when ``action == "add"``.
        """

        DEFAULT_CSS = """
        ProtocolKeylogModal > #modal-container {
            width: 70;
            height: auto;
            max-height: 80%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        ProtocolKeylogModal .path-label {
            margin-top: 1;
            color: $fritap-text-secondary;
        }
        ProtocolKeylogModal .modal-description {
            margin: 1 0;
            color: $fritap-text-dim;
            text-align: center;
        }
        ProtocolKeylogModal #proto-list {
            height: auto;
            max-height: 10;
            margin: 1 0;
            background: $surface;
        }
        ProtocolKeylogModal Input {
            margin-bottom: 1;
        }
        """

        def __init__(
            self,
            protocol_names: Optional[list[str]] = None,
            added: Optional[dict[str, str]] = None,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._protocol_names = list(
                protocol_names if protocol_names is not None
                else self._discover_protocol_names()
            )
            self._added = dict(added or {})

        def _discover_protocol_names(self) -> list[str]:
            """Names of friTap-owned offline decryptors (signal, mtproto, ...)."""
            try:
                from friTap.offline.registry import get_offline_decryptor_registry
                return get_offline_decryptor_registry().names()
            except Exception:
                return []

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Add Protocol Key Log[/]",
                    classes="modal-title",
                )
                if self._added:
                    summary = ", ".join(
                        f"{name}" for name in self._added.keys()
                    )
                    yield Static(
                        f"[{c('success')}]Added so far: {summary}[/]",
                        classes="modal-description",
                    )
                yield Static(
                    "Add a key log — TLS, Signal, Telegram, or a plugin. You "
                    "can add more than one. (TLS strips the transport so "
                    "TLS-wrapped protocols like Signal can be decrypted.)",
                    classes="modal-description",
                )

                if self._protocol_names:
                    options = [
                        Option(f"[{idx + 1}] {name}")
                        for idx, name in enumerate(self._protocol_names)
                    ]
                    yield Static(
                        f"[{c('text-secondary')}]Protocol:[/]",
                        classes="path-label",
                    )
                    yield OptionList(*options, id="proto-list")

                    yield Static(
                        f"[{c('text-secondary')}]Key log file:[/]",
                        classes="path-label",
                    )
                    yield Input(
                        value="",
                        placeholder="Path to the protocol keylog...",
                        id="proto-keylog-input",
                    )
                else:
                    yield Static(
                        f"[{c('warning-amber')}]No protocol decryptors registered.[/]",
                        classes="modal-description",
                    )

                yield Static(
                    f"[{c('text-muted')}]Enter: Add  |  Tab: Edit  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    if self._protocol_names:
                        yield Button("Add", id="btn-add", variant="primary")
                    yield Button("Done", id="btn-done", variant="success")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def _auto_focus(self) -> None:
            try:
                self.query_one("#proto-list", OptionList).focus()
            except Exception:
                pass

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-add":
                self._add()
            elif event.button.id == "btn-done":
                self.dismiss({"action": "done"})
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

        def _selected_protocol(self) -> Optional[str]:
            try:
                option_list = self.query_one("#proto-list", OptionList)
                idx = option_list.highlighted
                if idx is not None and 0 <= idx < len(self._protocol_names):
                    return self._protocol_names[idx]
            except Exception:
                pass
            return None

        def _add(self) -> None:
            """Collect the chosen protocol + keylog and dismiss to add it."""
            protocol = self._selected_protocol()
            if not protocol:
                self._auto_focus()
                return
            try:
                keylog = self.query_one("#proto-keylog-input", Input).value.strip()
            except Exception:
                keylog = ""
            if not keylog:
                # A protocol keylog is required to add an entry — keep open.
                try:
                    self.query_one("#proto-keylog-input", Input).focus()
                except Exception:
                    pass
                return
            self.dismiss({
                "action": "add",
                "protocol": protocol,
                "keylog": keylog,
            })

    class PcapToTapConfirmModal(FriTapModal[Optional[bool]]):
        """Step 3: summarize the collected conversion settings and confirm."""

        DEFAULT_CSS = """
        PcapToTapConfirmModal > #modal-container {
            width: 70;
            height: auto;
            max-height: 80%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        PcapToTapConfirmModal #summary-block {
            margin: 1 2;
            color: $fritap-text-secondary;
        }
        """

        def __init__(self, summary: dict, **kwargs) -> None:
            super().__init__(**kwargs)
            self._summary = summary

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('success')}]Ready to Convert[/]",
                    classes="modal-title",
                )
                yield Static(self._build_summary_text(), id="summary-block")
                yield Static(
                    f"[{c('text-muted')}]Enter: Convert  |  Esc: Back[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Convert", id="btn-convert", variant="primary")
                    yield Button("Back", id="btn-back", variant="default")

        def _build_summary_text(self) -> str:
            """Build the formatted summary block from the summary dict.

            TLS is just another entry in ``protocol_keylogs`` now, so there is no
            dedicated "TLS keylog:" line — keylogs are only listed when actually
            provided. ``tls_note`` (e.g. embedded-DSB info) and ``warning`` (e.g.
            Signal missing its TLS keys) are rendered when present.
            """
            dash = "—"
            pcap = self._summary.get("pcap", "") or dash
            tap = self._summary.get("tap", "") or dash
            protocol_keylogs = self._summary.get("protocol_keylogs", {}) or {}

            lines = [
                f"  PCAP:          {pcap}",
                f"  Output .tap:   {tap}",
            ]
            if protocol_keylogs:
                lines.append("  Keylogs:")
                for name, path in protocol_keylogs.items():
                    lines.append(f"    - {name}: {path}")
            else:
                lines.append(f"  Keylogs:       {dash}")

            tls_note = self._summary.get("tls_note", "")
            if tls_note:
                lines.append(f"  [{c('info')}]{tls_note}[/]")

            warning = self._summary.get("warning", "")
            if warning:
                lines.append("")
                lines.append(f"  [{c('warning-amber')}]⚠ {warning}[/]")
            return "\n".join(lines)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-convert":
                self.dismiss(True)
            elif event.button.id == "btn-back":
                self.dismiss(None)
