#!/usr/bin/env python3

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

from typing import Callable, Optional

try:
    from textual import events
    from textual.app import ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.message import Message
    from textual.widgets import Button, Input, OptionList, SelectionList, Static
    from textual.widgets.option_list import Option
    from textual.widgets.selection_list import Selection
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from friTap.offline.mtproto.transport import DEFAULT_OBF_MAX_BLOCKS
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

    class SuggestedPathInput(Input):
        """Path input pre-filled with a suggestion that one click clears.

        While the value is still the untouched suggestion, the first mouse
        click empties the field so the user can type another path. Keyboard
        users are covered by ``select_on_focus``: typing after Tab-focus
        replaces the (fully selected) suggestion. Clearing posts
        :class:`SuggestionCleared` so the owning modal can drop its hint.
        """

        class SuggestionCleared(Message):
            """The untouched suggestion was cleared by a click."""

        def __init__(self, suggested: str = "", **kwargs) -> None:
            super().__init__(**kwargs)
            self._suggested = suggested

        def on_click(self, event: events.Click) -> None:
            if self._suggested and self.value == self._suggested:
                self.value = ""
                self.post_message(self.SuggestionCleared())
            self._suggested = ""

    class ProtocolKeylogModal(FriTapModal[Optional[dict]]):
        """Step 2: add ONE per-protocol (layered) keylog.

        Pick the protocol (``tls``, the standalone offline decryptors and one
        grouped ``custom`` entry) and supply its keylog path. The wizard
        re-shows this modal so several keylogs can be added (e.g. a Signal
        keylog AND a Telegram keylog). When no protocol decryptors are
        registered the protocol list is empty and the user can only finish.

        ``suggested_keylog`` pre-fills the path input with a keylog found next
        to the pcap; ``initial_protocol`` / ``initial_keylog`` restore the
        picker state when the wizard re-shows the modal (e.g. after backing
        out of the custom-cipher selection).

        Result dict keys:
            * ``action`` — ``"add"`` (add this protocol+keylog and ask again) or
              ``"done"`` (finished adding; proceed to confirm).
            * ``protocol`` / ``keylog`` — present when ``action == "add"``;
              ``protocol`` is the picker name (``tls``, ``custom``, ...).
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
        ProtocolKeylogModal #keylog-suggestion-hint {
            color: $fritap-text-dim;
        }
        ProtocolKeylogModal Input {
            margin-bottom: 1;
        }
        """

        HINTS_DEFAULT = "Enter: Add  |  Tab: Edit  |  Esc: Cancel"
        HINTS_AFTER_ADD = "Enter: Done  |  Shift+Tab: add another  |  Esc: Back"

        def __init__(
            self,
            protocol_names: Optional[list[str]] = None,
            added: Optional[dict[str, str]] = None,
            suggested_keylog: Optional[str] = None,
            initial_protocol: Optional[str] = None,
            initial_keylog: Optional[str] = None,
            suggestion_evidence: Optional[tuple[int, int]] = None,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            # ``(covered, total)`` capture TLS sessions the suggestion matches;
            # ``None`` when only the timestamp rules picked it.
            self._suggestion_evidence = suggestion_evidence
            self._protocol_names = list(
                protocol_names if protocol_names is not None
                else self._discover_protocol_names()
            )
            self._added = dict(added or {})
            self._initial_protocol = initial_protocol
            self._initial_keylog = initial_keylog or ""
            self._input_value = self._initial_keylog or suggested_keylog or ""
            # The suggestion only counts (hint + click-to-clear) while it is
            # what the input shows; a restored ``initial_keylog`` wins.
            self._suggested_keylog = (
                suggested_keylog
                if suggested_keylog and self._input_value == suggested_keylog
                else ""
            )

        def _discover_protocol_names(self) -> list[str]:
            """Picker entries: ``tls``, standalone decryptors, ``custom``."""
            from friTap.offline.keylog_picker import picker_protocol_names
            return picker_protocol_names()

        # -- compose ------------------------------------------------------

        def _added_summary(self) -> str:
            """``"tls: keys.log, custom encryption (rc4): x.log"``."""
            import os

            from friTap.offline.keylog_picker import (
                keylog_protocol_label,
                offline_custom_ciphers,
            )
            custom_ciphers = offline_custom_ciphers()
            return ", ".join(
                f"{keylog_protocol_label(name, custom_ciphers=custom_ciphers)}: "
                f"{os.path.basename(path)}"
                for name, path in self._added.items()
            )

        def _suggestion_hint(self) -> str:
            import os
            name = os.path.basename(self._suggested_keylog)
            if self._suggestion_evidence is None:
                return (
                    f"Suggested (matches pcap timestamp): {name} — "
                    "Enter to use, click to type another"
                )
            return (
                f"Suggested: {name} — {self._evidence_text()} — "
                "Enter to use, click to type another"
            )

        def _evidence_text(self) -> str:
            """``"matches 2/2 TLS sessions"``; amber when it matches none."""
            covered, total = self._suggestion_evidence
            noun = "session" if total == 1 else "sessions"
            text = f"matches {covered}/{total} TLS {noun}"
            if covered == 0:
                return f"[{c('warning-amber')}]{text}[/]"
            return text

        def _key_hints(self) -> str:
            return self.HINTS_AFTER_ADD if self._added else self.HINTS_DEFAULT

        def _compose_protocol_picker(self) -> ComposeResult:
            from friTap.offline.keylog_picker import picker_display_name
            options = [
                Option(f"[{idx + 1}] {picker_display_name(name)}")
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
            if self._suggested_keylog:
                yield Static(self._suggestion_hint(), id="keylog-suggestion-hint")
            yield SuggestedPathInput(
                suggested=self._suggested_keylog,
                value=self._input_value,
                placeholder="Path to the protocol keylog...",
                id="proto-keylog-input",
            )

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Add Protocol Key Log[/]",
                    classes="modal-title",
                )
                if self._added:
                    yield Static(
                        f"[{c('success')}]Added so far: {self._added_summary()}[/]",
                        classes="modal-description",
                    )
                yield Static(
                    "Add a key log — TLS, Signal, Telegram, custom encryption "
                    "or a plugin. You can add more than one. (TLS strips the "
                    "transport so TLS-wrapped protocols like Signal can be "
                    "decrypted.)",
                    classes="modal-description",
                )

                if self._protocol_names:
                    yield from self._compose_protocol_picker()
                else:
                    yield Static(
                        f"[{c('warning-amber')}]No protocol decryptors registered.[/]",
                        classes="modal-description",
                    )

                yield Static(
                    f"[{c('text-muted')}]{self._key_hints()}[/]",
                    classes="key-hints",
                    id="proto-key-hints",
                )
                with Horizontal(classes="button-row"):
                    if self._protocol_names:
                        yield Button("Add", id="btn-add", variant="primary")
                    yield Button("Done", id="btn-done", variant="success")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        # -- focus --------------------------------------------------------

        def _apply_initial_highlight(self) -> None:
            """Highlight ``initial_protocol`` in the list when it is offered."""
            if self._initial_protocol not in self._protocol_names:
                return
            try:
                self.query_one("#proto-list", OptionList).highlighted = (
                    self._protocol_names.index(self._initial_protocol)
                )
            except Exception:
                pass

        def _focus_target(self) -> str:
            """Selector to focus: Add with a prefilled path, else Done after an add.

            A prefilled path (suggestion or restored ``initial_keylog``) wins
            so e.g. backing out of the custom-cipher selection focuses Add
            even when other keylogs were already added.
            """
            if self._input_value and self._protocol_names:
                return "#btn-add"
            if self._added:
                return "#btn-done"
            return "#proto-list"

        def _auto_focus(self) -> None:
            self._apply_initial_highlight()
            try:
                self.query_one(self._focus_target()).focus()
            except Exception:
                pass

        def _focus_protocol_list(self) -> None:
            try:
                self.query_one("#proto-list", OptionList).focus()
            except Exception:
                pass

        # -- actions ------------------------------------------------------

        def on_suggested_path_input_suggestion_cleared(
            self, event: "SuggestedPathInput.SuggestionCleared"
        ) -> None:
            """Hide the suggestion hint once the user cleared the suggestion."""
            for hint in self.query("#keylog-suggestion-hint"):
                hint.display = False

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
                self._focus_protocol_list()
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

    class PcapToTapConfirmModal(FriTapModal[Optional[dict]]):
        """Step 3: summarize the collected conversion settings and confirm.

        The keylogs are rendered as a :class:`SelectionList` (all checked by
        default) so the user can uncheck any before converting. ``Convert``
        dismisses with ``{"enabled_keylogs": [<protocol>, ...]}`` (the still-
        checked protocols); ``Back`` / ``Re-pair`` are unchanged (``None`` /
        the re-pair callback).
        """

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
        PcapToTapConfirmModal #keylog-select-label {
            margin: 1 2 0 2;
            color: $fritap-text-secondary;
        }
        PcapToTapConfirmModal #keylog-select {
            height: auto;
            max-height: 8;
            margin: 0 2 1 2;
            background: $surface;
        }
        PcapToTapConfirmModal #resync-depth-label {
            margin: 1 2 0 2;
            color: $fritap-text-muted;
        }
        PcapToTapConfirmModal #resync-depth-input {
            margin: 0 2 1 2;
        }
        PcapToTapConfirmModal #resync-depth-error {
            margin: 0 2 1 2;
            color: $error;
            display: none;
        }
        PcapToTapConfirmModal #resync-depth-error.visible {
            display: block;
        }
        """

        # severity -> (theme color, first-line prefix) for coverage/re-pair lines
        _SEVERITY_STYLES = {
            "ok": ("success", "✓ "),
            "info": ("info", ""),
            "warning": ("warning-amber", "⚠ "),
            "busy": ("text-muted", ""),
        }

        def __init__(
            self,
            summary: dict,
            on_repair: Optional[Callable[[], None]] = None,
            resync_search_depth: int = DEFAULT_OBF_MAX_BLOCKS,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._summary = summary
            # Called when "Re-pair keys" is pressed; the wizard runs the worker.
            self._on_repair = on_repair
            self._repair_attempted = False
            # Advanced override for the mid-stream resync search depth.
            self._resync_search_depth = resync_search_depth

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('success')}]Ready to Convert[/]",
                    classes="modal-title",
                )
                yield Static(self._build_summary_text(), id="summary-block")
                yield from self._compose_keylog_selection()
                yield Static(
                    f"[{c('text-muted')}]Mid-stream resync search depth "
                    f"(advanced)[/]",
                    id="resync-depth-label",
                )
                yield Input(
                    value=str(self._resync_search_depth),
                    placeholder=str(DEFAULT_OBF_MAX_BLOCKS),
                    id="resync-depth-input",
                )
                yield Static("", id="resync-depth-error")
                yield Static(
                    f"[{c('text-muted')}]Enter: Convert  |  Esc: Back[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Convert", id="btn-convert", variant="primary")
                    yield self._repair_button()
                    yield Button("Back", id="btn-back", variant="default")

        def _compose_keylog_selection(self) -> ComposeResult:
            """The keylogs as a checkable list (all checked by default).

            Nothing is yielded when there are no keylogs — the summary already
            shows the ``Keylogs: —`` line in that case and there is nothing to
            deselect.
            """
            protocol_keylogs = self._summary.get("protocol_keylogs", {}) or {}
            if not protocol_keylogs:
                return
            yield Static(
                f"[{c('text-secondary')}]Keylogs (uncheck to skip):[/]",
                id="keylog-select-label",
            )
            yield SelectionList(
                *self._keylog_selections(protocol_keylogs),
                id="keylog-select",
            )

        def _keylog_selections(self, protocol_keylogs: dict) -> list:
            """``Selection`` per keylog, keyed by protocol, checked by default.

            A protocol already checked in a mounted list stays checked across a
            rebuild (e.g. after a TLS re-pair); on the first build every keylog
            is checked.
            """
            enabled = self._current_selection()
            selections = []
            for name, path in protocol_keylogs.items():
                label = self._keylog_label(name)
                initial = name in enabled if enabled is not None else True
                selections.append(Selection(f"{label}: {path}", name, initial))
            return selections

        def _repair_button(self) -> "Button":
            """The "Re-pair keys" button, shown only when re-pairing can help."""
            button = Button("Re-pair keys", id="btn-repair", variant="warning")
            button.display = self._repair_visible()
            return button

        def _repair_visible(self) -> bool:
            return bool(self._summary.get("can_repair")) and self._on_repair is not None

        def _build_summary_text(self) -> str:
            """Build the formatted summary block from the summary dict.

            The keylogs themselves are rendered below the summary as a checkable
            :class:`SelectionList` (:meth:`_compose_keylog_selection`), so this
            block only carries a ``Keylogs: —`` line when none were provided.
            ``tls_note`` (e.g. embedded-DSB info) and ``warning`` (e.g. Signal
            missing its TLS keys) are rendered when present, followed by the TLS
            keylog coverage (``coverage_*``) and any re-pair message.
            """
            dash = "—"
            pcap = self._summary.get("pcap", "") or dash
            tap = self._summary.get("tap", "") or dash
            protocol_keylogs = self._summary.get("protocol_keylogs", {}) or {}

            lines = [
                f"  PCAP:          {pcap}",
                f"  Output .tap:   {tap}",
            ]
            # The keylogs themselves are rendered below as a checkable
            # SelectionList (see ``_compose_keylog_selection``); only the
            # "none" case needs a line here.
            if not protocol_keylogs:
                lines.append(f"  Keylogs:       {dash}")

            tls_note = self._summary.get("tls_note", "")
            if tls_note:
                lines.append(f"  [{c('info')}]{tls_note}[/]")

            warning = self._summary.get("warning", "")
            if warning:
                lines.append("")
                lines.append(f"  [{c('warning-amber')}]⚠ {warning}[/]")

            lines.extend(self._coverage_text_lines())
            lines.extend(self._repair_text_lines())
            return "\n".join(lines)

        def _styled_lines(self, severity: str, texts: list) -> list:
            """Indent *texts* in *severity*'s color, the first line prefixed."""
            color, prefix = self._SEVERITY_STYLES.get(severity, ("info", ""))
            return [
                f"  [{c(color)}]{prefix if idx == 0 else ''}{text}[/]"
                for idx, text in enumerate(texts)
            ]

        def _coverage_text_lines(self) -> list:
            """Keylog-coverage lines (or the pending note), blank-line separated."""
            if self._summary.get("coverage_pending"):
                return ["", f"  [{c('text-muted')}]Checking keylog coverage…[/]"]
            texts = self._summary.get("coverage_lines") or []
            if not texts:
                return []
            severity = self._summary.get("coverage_severity", "info")
            return [""] + self._styled_lines(severity, list(texts))

        def _repair_text_lines(self) -> list:
            """The re-pair progress/result message, when there is one."""
            message = self._summary.get("repair_message", "")
            if not message:
                return []
            severity = self._summary.get("repair_severity", "info")
            return [""] + self._styled_lines(severity, [message])

        # -- async updates (called by the wizard on the UI thread) ---------

        def set_coverage(self, severity: str, lines: list, can_repair: bool) -> None:
            """Replace the coverage lines (e.g. once the capture read finishes)."""
            self._summary.pop("coverage_pending", None)
            self._summary.update({
                "coverage_severity": severity,
                "coverage_lines": list(lines),
                "can_repair": can_repair,
            })
            self._refresh()

        def set_repair_status(
            self, message: str, severity: str = "info", busy: bool = False,
        ) -> None:
            """Show re-pair progress (*busy*) or its result below the coverage."""
            self._summary["repair_message"] = message
            self._summary["repair_severity"] = "busy" if busy else severity
            self._repair_attempted = True
            self._refresh()

        def set_protocol_keylogs(self, protocol_keylogs: dict) -> None:
            """Show the current keylogs (e.g. the repaired TLS keylog)."""
            self._summary["protocol_keylogs"] = dict(protocol_keylogs)
            self._refresh()

        def _refresh(self) -> None:
            """Re-render the summary and the re-pair button (no-op before mount)."""
            self._rebuild_keylog_selection()
            try:
                self.query_one("#summary-block", Static).update(self._build_summary_text())
                button = self.query_one("#btn-repair", Button)
            except Exception:
                return
            button.display = self._repair_visible()
            # One attempt per modal: the same secrets would not match again.
            button.disabled = self._repair_attempted

        @staticmethod
        def _keylog_rows(protocol_keylogs: dict) -> list:
            """``(label, path)`` rows labelled like step 2 (``tls (schannel)``)."""
            from friTap.offline.keylog_picker import (
                keylog_protocol_label,
                offline_custom_ciphers,
            )
            custom_ciphers = offline_custom_ciphers()
            return [
                (keylog_protocol_label(name, custom_ciphers=custom_ciphers), path)
                for name, path in protocol_keylogs.items()
            ]

        @staticmethod
        def _keylog_label(protocol: str) -> str:
            """Step-2 style label for a single stored *protocol* name."""
            from friTap.offline.keylog_picker import keylog_protocol_label
            return keylog_protocol_label(protocol)

        # -- keylog selection ---------------------------------------------

        def _current_selection(self) -> Optional[set]:
            """Protocols currently checked in the mounted list, else ``None``.

            ``None`` means "not mounted yet" so a first build checks everything;
            a mounted (possibly empty) list returns the live checked set.
            """
            try:
                return set(self.query_one("#keylog-select", SelectionList).selected)
            except Exception:
                return None

        def _selected_protocols(self) -> list:
            """The protocols still checked (all keylogs when there is no list)."""
            protocol_keylogs = self._summary.get("protocol_keylogs", {}) or {}
            selection = self._current_selection()
            if selection is None:
                return list(protocol_keylogs.keys())
            return [name for name in protocol_keylogs if name in selection]

        def _rebuild_keylog_selection(self) -> None:
            """Re-populate the keylog list in place (e.g. after a TLS re-pair)."""
            try:
                sel = self.query_one("#keylog-select", SelectionList)
            except Exception:
                return
            protocol_keylogs = self._summary.get("protocol_keylogs", {}) or {}
            selections = self._keylog_selections(protocol_keylogs)
            sel.clear_options()
            for selection in selections:
                sel.add_option(selection)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-convert":
                depth, error = self._parse_resync_depth()
                self._show_resync_depth_error(error)
                if error is not None:
                    return  # refuse Convert until the depth is valid
                self.dismiss({
                    "enabled_keylogs": self._selected_protocols(),
                    "resync_search_depth": depth,
                })
            elif event.button.id == "btn-back":
                self.dismiss(None)
            elif event.button.id == "btn-repair" and self._on_repair is not None:
                self._on_repair()

        def _resync_depth_value(self) -> int:
            """The advanced resync-depth input as a valid int.

            Falls back to :data:`DEFAULT_OBF_MAX_BLOCKS` when the field is
            empty or invalid (Convert itself refuses invalid input).
            """
            depth, error = self._parse_resync_depth()
            return DEFAULT_OBF_MAX_BLOCKS if error is not None else depth

        def _parse_resync_depth(self) -> tuple:
            """``(depth, error)``: the field validated with the CLI's bounds.

            An empty field means the default; a non-integer or out-of-range
            value (negative disables recovery, huge allocates GBs) yields an
            error message and ``depth`` is ``None``.
            """
            from friTap.offline.cli import parse_resync_search_depth
            try:
                raw = self.query_one("#resync-depth-input", Input).value.strip()
            except Exception:
                return DEFAULT_OBF_MAX_BLOCKS, None
            if not raw:
                return DEFAULT_OBF_MAX_BLOCKS, None
            try:
                return parse_resync_search_depth(raw), None
            except Exception as exc:  # argparse.ArgumentTypeError
                return None, str(exc)

        def _show_resync_depth_error(self, error: Optional[str]) -> None:
            """Show (or clear) the inline error under the depth field."""
            try:
                label = self.query_one("#resync-depth-error", Static)
            except Exception:
                return
            label.update(error or "")
            label.set_class(error is not None, "visible")

        def on_input_changed(self, event: Input.Changed) -> None:
            """Live-validate the depth field so the error clears as it's fixed."""
            if event.input.id == "resync-depth-input":
                self._show_resync_depth_error(self._parse_resync_depth()[1])
