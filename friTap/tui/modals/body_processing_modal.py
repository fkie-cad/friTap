#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Body processing modal for friTap TUI.

Provides a pipeline-style body processing dialog where users can select
decompression and decode/format steps to apply to captured body data.
Pressing [6] opens a nested ProtobufModal for protobuf configuration.

Returns a BodyProcessingResult on Apply, or None on Cancel/ESC.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import (
        Button,
        Input,
        RadioButton,
        RadioSet,
        RichLog,
        Static,
        Switch,
    )

    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


# ── Data classes (always available) ──────────────────────────────


@dataclass
class ProtobufConfig:
    """Configuration for protobuf decoding."""

    schema_less: bool = True
    schema_path: str = ""
    message_type: str = ""
    grpc_mode: bool = False


@dataclass
class BodyProcessingResult:
    """Result returned when the body processing modal is dismissed with Apply."""

    decompression: str | None = None  # "gzip", "deflate", "brotli", "zstd"
    decoder: str | None = None  # "json", "protobuf", "base64", "hex", "raw_utf8"
    protobuf_config: ProtobufConfig | None = None
    segment_index: int = 0  # 0=primary, 1=trailing segment


# ── Modals (only when Textual is available) ──────────────────────

if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c
    from .base import FriTapModal

    # -- Protobuf sub-modal -----------------------------------------------

    class ProtobufModal(FriTapModal[Optional[ProtobufConfig]]):
        """Sub-modal for configuring protobuf decode settings."""

        DEFAULT_CSS = """
        ProtobufModal > #modal-container {
            width: 68;
            height: auto;
            max-height: 85%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        ProtobufModal #proto-schema-input,
        ProtobufModal #proto-message-input {
            margin: 0 0 1 0;
        }
        ProtobufModal #proto-schema-input.dimmed,
        ProtobufModal #proto-message-input.dimmed {
            opacity: 0.35;
        }
        ProtobufModal #proto-grpc-row {
            height: 3;
            align: left middle;
            margin: 0 0 1 0;
        }
        ProtobufModal #proto-grpc-label {
            width: 1fr;
        }
        ProtobufModal #proto-preview-label {
            margin-top: 1;
        }
        ProtobufModal #proto-preview {
            height: 10;
            max-height: 14;
            margin: 0 0 1 0;
            background: $surface;
            border: solid $fritap-border-panel;
        }
        ProtobufModal RadioSet {
            margin: 0 0 1 0;
            height: auto;
        }
        """

        BINDINGS = [
            Binding("escape", "cancel", "Cancel", show=True),
        ]

        def __init__(
            self,
            current: ProtobufConfig | None = None,
            body_preview: bytes = b"",
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._config = current or ProtobufConfig()
            self._body_preview = body_preview

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Protobuf Decoder[/]",
                    classes="modal-title",
                )
                with RadioSet(id="proto-mode-radio"):
                    yield RadioButton(
                        "Schema-less decode",
                        value=self._config.schema_less,
                        id="radio-schemaless",
                    )
                    yield RadioButton(
                        "Load .proto schema",
                        value=not self._config.schema_less,
                        id="radio-schema",
                    )
                yield Static(
                    f"[{c('text-muted')}]Schema:[/]",
                    id="proto-schema-label",
                )
                yield Input(
                    placeholder="/path/to/file.proto",
                    value=self._config.schema_path,
                    id="proto-schema-input",
                )
                yield Static(
                    f"[{c('text-muted')}]Message:[/]",
                    id="proto-message-label",
                )
                yield Input(
                    placeholder="package.MessageType",
                    value=self._config.message_type,
                    id="proto-message-input",
                )
                with Horizontal(id="proto-grpc-row"):
                    yield Static(
                        f"[{c('text-secondary')}]gRPC mode (strip 5-byte framing)[/]",
                        id="proto-grpc-label",
                    )
                    yield Switch(value=self._config.grpc_mode, id="proto-grpc-switch")
                yield Static(
                    f"[bold {c('text-muted')}]--- Preview ---[/]",
                    id="proto-preview-label",
                )
                yield RichLog(id="proto-preview", wrap=True, markup=True)
                yield Static(
                    f"[{c('text-muted')}]Esc: Cancel  |  Enter: Apply[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Apply", id="btn-apply", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def on_mount(self) -> None:
            """Set initial input dimming state and render preview."""
            self._update_input_state()
            self._render_preview()
            # Focus the radio set
            try:
                self.query_one("#proto-mode-radio", RadioSet).focus()
            except Exception:
                pass

        def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
            """Toggle between schema-less and schema mode."""
            self._config.schema_less = event.index == 0
            self._update_input_state()
            self._render_preview()

        def on_input_changed(self, event: Input.Changed) -> None:
            """Update config when schema path or message type changes."""
            if event.input.id == "proto-schema-input":
                self._config.schema_path = event.value.strip()
            elif event.input.id == "proto-message-input":
                self._config.message_type = event.value.strip()
            self._render_preview()

        def on_switch_changed(self, event: Switch.Changed) -> None:
            """Toggle gRPC mode."""
            if event.switch.id == "proto-grpc-switch":
                self._config.grpc_mode = event.value
                self._render_preview()

        def _update_input_state(self) -> None:
            """Dim/enable schema inputs based on schema-less toggle."""
            schema_input = self.query_one("#proto-schema-input", Input)
            message_input = self.query_one("#proto-message-input", Input)
            if self._config.schema_less:
                schema_input.add_class("dimmed")
                message_input.add_class("dimmed")
                schema_input.disabled = True
                message_input.disabled = True
            else:
                schema_input.remove_class("dimmed")
                message_input.remove_class("dimmed")
                schema_input.disabled = False
                message_input.disabled = False

        def _render_preview(self) -> None:
            """Attempt to decode body_preview and display in the RichLog."""
            preview = self.query_one("#proto-preview", RichLog)
            preview.clear()

            if not self._body_preview:
                preview.write(f"[{c('text-muted')}](no body data to preview)[/]")
                return

            data = self._body_preview
            # Strip gRPC 5-byte framing if enabled
            if self._config.grpc_mode and len(data) > 5:
                data = data[5:]

            if self._config.schema_less:
                self._preview_schema_less(preview, data)
            else:
                self._preview_with_schema(preview, data)

        def _preview_schema_less(self, preview: RichLog, data: bytes) -> None:
            """Schema-less protobuf decode using blackboxprotobuf or manual parse."""
            try:
                import blackboxprotobuf

                message, _ = blackboxprotobuf.decode_message(data)
                for field_num, value in message.items():
                    preview.write(f"field {field_num}: {value!r}")
            except ImportError:
                # Fallback: basic varint field display
                self._preview_raw_fields(preview, data)
            except Exception as exc:
                preview.write(
                    f"[{c('error')}]Decode error: {exc}[/]"
                )

        def _preview_raw_fields(self, preview: RichLog, data: bytes) -> None:
            """Minimal protobuf field parser for preview when no library is available."""
            try:
                offset = 0
                field_count = 0
                while offset < len(data) and field_count < 20:
                    if offset >= len(data):
                        break
                    # Read varint (tag)
                    tag, offset = self._read_varint(data, offset)
                    if tag is None:
                        break
                    field_number = tag >> 3
                    wire_type = tag & 0x07

                    if wire_type == 0:  # Varint
                        value, offset = self._read_varint(data, offset)
                        if value is None:
                            break
                        preview.write(f"field {field_number}: {value}")
                    elif wire_type == 1:  # 64-bit
                        if offset + 8 > len(data):
                            break
                        preview.write(
                            f"field {field_number}: (64-bit) 0x{data[offset:offset+8].hex()}"
                        )
                        offset += 8
                    elif wire_type == 2:  # Length-delimited
                        length, offset = self._read_varint(data, offset)
                        if length is None or offset + length > len(data):
                            break
                        chunk = data[offset : offset + length]
                        offset += length
                        # Try as UTF-8 string first
                        try:
                            text = chunk.decode("utf-8")
                            if text.isprintable():
                                preview.write(f'field {field_number}: "{text}"')
                            else:
                                preview.write(
                                    f"field {field_number}: ({length} bytes) {chunk[:32].hex()}..."
                                )
                        except UnicodeDecodeError:
                            preview.write(
                                f"field {field_number}: ({length} bytes) {chunk[:32].hex()}..."
                            )
                    elif wire_type == 5:  # 32-bit
                        if offset + 4 > len(data):
                            break
                        preview.write(
                            f"field {field_number}: (32-bit) 0x{data[offset:offset+4].hex()}"
                        )
                        offset += 4
                    else:
                        preview.write(
                            f"[{c('text-muted')}]field {field_number}: (wire type {wire_type}, skipped)[/]"
                        )
                        break
                    field_count += 1

                if field_count == 0:
                    preview.write(
                        f"[{c('text-muted')}](no protobuf fields detected)[/]"
                    )
            except Exception as exc:
                preview.write(f"[{c('error')}]Parse error: {exc}[/]")

        @staticmethod
        def _read_varint(data: bytes, offset: int) -> tuple[int | None, int]:
            """Read a protobuf varint from data at offset."""
            result = 0
            shift = 0
            while offset < len(data):
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if (byte & 0x80) == 0:
                    return result, offset
                shift += 7
                if shift > 63:
                    return None, offset
            return None, offset

        def _preview_with_schema(self, preview: RichLog, data: bytes) -> None:
            """Decode protobuf using a .proto schema file."""
            if not self._config.schema_path:
                preview.write(
                    f"[{c('text-muted')}](enter a .proto schema path above)[/]"
                )
                return
            if not self._config.message_type:
                preview.write(
                    f"[{c('text-muted')}](enter a message type above)[/]"
                )
                return

            try:
                from google.protobuf import descriptor_pool, descriptor_pb2  # noqa: F401
                from google.protobuf.compiler import plugin_pb2  # noqa: F401
                from google.protobuf import text_format
                import subprocess
                import tempfile
                import os

                # Use protoc to compile .proto to descriptor set
                schema_path = self._config.schema_path
                if not os.path.isfile(schema_path):
                    preview.write(
                        f"[{c('error')}]Schema file not found: {schema_path}[/]"
                    )
                    return

                with tempfile.NamedTemporaryFile(suffix=".desc", delete=False) as tmp:
                    tmp_path = tmp.name

                try:
                    proto_dir = os.path.dirname(schema_path) or "."
                    result = subprocess.run(
                        [
                            "protoc",
                            f"--proto_path={proto_dir}",
                            f"--descriptor_set_out={tmp_path}",
                            schema_path,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode != 0:
                        preview.write(
                            f"[{c('error')}]protoc error: {result.stderr.strip()}[/]"
                        )
                        return

                    from google.protobuf import descriptor_pb2 as dp2
                    from google.protobuf import descriptor_pool as pool_mod
                    from google.protobuf import message_factory
                    from google.protobuf import symbol_database  # noqa: F401

                    with open(tmp_path, "rb") as f:
                        fds = dp2.FileDescriptorSet.FromString(f.read())

                    p = pool_mod.DescriptorPool()
                    for fd_proto in fds.file:
                        p.Add(fd_proto)

                    msg_desc = p.FindMessageTypeByName(self._config.message_type)
                    factory = message_factory.MessageFactory(pool=p)
                    msg_class = factory.GetPrototype(msg_desc)
                    msg = msg_class()
                    msg.ParseFromString(data)
                    formatted = text_format.MessageToString(msg, indent=2)
                    for line in formatted.splitlines()[:20]:
                        preview.write(line)
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

            except ImportError:
                preview.write(
                    f"[{c('error')}]protobuf library not installed "
                    f"(pip install protobuf)[/]"
                )
            except Exception as exc:
                preview.write(f"[{c('error')}]Schema decode error: {exc}[/]")

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-apply":
                self.dismiss(ProtobufConfig(
                    schema_less=self._config.schema_less,
                    schema_path=self._config.schema_path,
                    message_type=self._config.message_type,
                    grpc_mode=self._config.grpc_mode,
                ))
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

    # -- Body Processing modal --------------------------------------------

    # Decompression options: (key, id, label)
    _DECOMPRESS_OPTIONS: list[tuple[str, str, str]] = [
        ("1", "gzip", "Gzip"),
        ("2", "deflate", "Deflate"),
        ("3", "brotli", "Brotli"),
        ("4", "zstd", "Zstd"),
    ]

    # Decoder options: (key, id, label, opens_sub_modal)
    _DECODER_OPTIONS: list[tuple[str, str, str, bool]] = [
        ("5", "json", "JSON pretty-print", False),
        ("6", "protobuf", "Protobuf decode...", True),
        ("7", "base64", "Base64 decode", False),
        ("8", "hex", "Hex view", False),
        ("9", "raw_utf8", "Raw text (force UTF-8)", False),
    ]

    class BodyProcessingModal(FriTapModal[Optional[BodyProcessingResult]]):
        """Modal for configuring body processing pipeline (decompression + decode)."""

        DEFAULT_CSS = """
        BodyProcessingModal > #modal-container {
            width: 70;
            height: auto;
            max-height: 85%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        BodyProcessingModal #active-line {
            text-align: center;
            margin-bottom: 1;
        }
        BodyProcessingModal .section-header {
            margin-top: 1;
            margin-bottom: 0;
        }
        BodyProcessingModal .option-row {
            height: 1;
            margin: 0 0 0 2;
        }
        BodyProcessingModal .option-btn {
            min-width: 12;
            height: 1;
            margin: 0 1 0 0;
        }
        BodyProcessingModal .option-btn.active {
            background: $accent;
            text-style: bold;
        }
        BodyProcessingModal .option-btn:focus {
            text-style: underline;
        }
        BodyProcessingModal #decompress-row {
            height: 1;
            margin: 0 0 1 2;
        }
        BodyProcessingModal #reset-row {
            margin-top: 1;
            height: 1;
            margin-left: 2;
        }
        """

        BINDINGS = [
            Binding("escape", "cancel", "Cancel", show=True),
            Binding("left", "focus_left", show=False, priority=True),
            Binding("right", "focus_right", show=False, priority=True),
            Binding("up", "focus_up", show=False, priority=True),
            Binding("down", "focus_down", show=False, priority=True),
            Binding("enter", "do_apply", "Apply", show=False, priority=True),
            Binding("1", "toggle_1", "Gzip", show=False, priority=True),
            Binding("2", "toggle_2", "Deflate", show=False, priority=True),
            Binding("3", "toggle_3", "Brotli", show=False, priority=True),
            Binding("4", "toggle_4", "Zstd", show=False, priority=True),
            Binding("5", "toggle_5", "JSON", show=False, priority=True),
            Binding("6", "toggle_6", "Protobuf", show=False, priority=True),
            Binding("7", "toggle_7", "Base64", show=False, priority=True),
            Binding("8", "toggle_8", "Hex", show=False, priority=True),
            Binding("9", "toggle_9", "Raw UTF-8", show=False, priority=True),
            Binding("0", "reset", "Reset", show=False, priority=True),
            Binding("bracketright", "next_segment", "Next Segment", show=False, priority=True),
            Binding("bracketleft", "prev_segment", "Prev Segment", show=False, priority=True),
        ]

        def __init__(
            self,
            current: BodyProcessingResult | None = None,
            body_preview: bytes = b"",
            on_change: Callable[[BodyProcessingResult], None] | None = None,
            segment_count: int = 1,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._body_preview = body_preview
            self._on_change = on_change
            self._segment_count = segment_count
            # Restore state from previous result
            if current is not None:
                self._decompression: str | None = current.decompression
                self._decoder: str | None = current.decoder
                self._protobuf_config: ProtobufConfig | None = current.protobuf_config
                self._segment_index: int = current.segment_index
            else:
                self._decompression = None
                self._decoder = None
                self._protobuf_config = None
                self._segment_index = 0

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Body Processing[/]",
                    classes="modal-title",
                )

                # Segment selector (only shown for multi-segment flows)
                if self._segment_count > 1:
                    yield Static("", id="segment-line")

                yield Static("", id="active-line")

                # Decompression section
                yield Static(
                    f"[bold {c('text-secondary')}]--- Decompression ---[/]",
                    classes="section-header",
                )
                with Horizontal(id="decompress-row"):
                    for key, opt_id, label in _DECOMPRESS_OPTIONS:
                        yield Button(
                            f"[{key}] {label}",
                            id=f"opt-{opt_id}",
                            classes="option-btn",
                        )

                # Decode / Format section
                yield Static(
                    f"[bold {c('text-secondary')}]--- Decode / Format ---[/]",
                    classes="section-header",
                )
                for key, opt_id, label, opens_sub in _DECODER_OPTIONS:
                    arrow = "  ->" if opens_sub else ""
                    with Horizontal(classes="option-row"):
                        yield Button(
                            f"[{key}] {label}{arrow}",
                            id=f"opt-{opt_id}",
                            classes="option-btn",
                        )

                # Reset
                with Horizontal(id="reset-row"):
                    yield Button(
                        "[0] Reset to original",
                        id="opt-reset",
                        classes="option-btn",
                    )

                seg_hint = "  |  [/]: Segment" if self._segment_count > 1 else ""
                yield Static(
                    f"[{c('text-muted')}]1-9: Toggle  |  0: Reset  |  Arrows/Tab: Navigate{seg_hint}  |  Enter: Select/Apply  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Apply", id="btn-apply", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        _PRIORITY_KEYS = frozenset(
            b.key for b in BINDINGS if getattr(b, "priority", False)
        )

        @property
        def _option_buttons(self) -> list[Button]:
            """All option buttons in DOM order."""
            return list(self.query(".option-btn"))

        def _navigate_option_focus(self, direction: str) -> None:
            """Move focus among option buttons."""
            buttons = self._option_buttons
            if not buttons:
                return
            focused = self.focused
            if focused not in buttons:
                buttons[0].focus()
                return
            idx = buttons.index(focused)
            if direction in ("left", "up"):
                new_idx = (idx - 1) % len(buttons)
            else:
                new_idx = (idx + 1) % len(buttons)
            buttons[new_idx].focus()

        def action_focus_left(self) -> None:
            self._navigate_option_focus("left")

        def action_focus_right(self) -> None:
            self._navigate_option_focus("right")

        def action_focus_up(self) -> None:
            self._navigate_option_focus("up")

        def action_focus_down(self) -> None:
            self._navigate_option_focus("down")

        def on_key(self, event) -> None:
            """Handle Tab cycling and prevent priority keys from bubbling."""
            if event.key == "tab":
                self._navigate_option_focus("right")
                event.stop()
                event.prevent_default()
            elif event.key == "shift+tab":
                self._navigate_option_focus("left")
                event.stop()
                event.prevent_default()
            elif event.key in self._PRIORITY_KEYS:
                event.stop()

        def on_mount(self) -> None:
            """Restore previous selection state and update active line."""
            # Mark decompression button as active
            if self._decompression:
                try:
                    btn = self.query_one(f"#opt-{self._decompression}", Button)
                    btn.add_class("active")
                except Exception:
                    pass
            # Mark decoder button as active
            if self._decoder:
                try:
                    btn = self.query_one(f"#opt-{self._decoder}", Button)
                    btn.add_class("active")
                except Exception:
                    pass
            self._update_active_line()
            self._update_segment_line()
            # Focus the first option button for keyboard navigation
            buttons = self._option_buttons
            if buttons:
                buttons[0].focus()

        # -- Active pipeline display ------------------------------------------

        def _update_active_line(self) -> None:
            """Update the 'Active: ...' status line."""
            parts: list[str] = []
            if self._decompression:
                parts.append(self._decompression)
            if self._decoder:
                label = self._decoder
                if self._decoder == "protobuf" and self._protobuf_config:
                    mode = "schema-less" if self._protobuf_config.schema_less else "schema"
                    label = f"protobuf ({mode})"
                elif self._decoder == "raw_utf8":
                    label = "raw text (UTF-8)"
                parts.append(label)

            try:
                active_static = self.query_one("#active-line", Static)
                if parts:
                    chain = " -> ".join(parts)
                    active_static.update(
                        f"[{c('text-secondary')}]Active: {chain}[/]"
                    )
                else:
                    active_static.update(
                        f"[{c('text-muted')}]Active: (none)[/]"
                    )
            except Exception:
                pass

        def _notify_change(self) -> None:
            """Notify the caller of the current processing state for live preview."""
            if self._on_change is not None:
                self._on_change(BodyProcessingResult(
                    decompression=self._decompression,
                    decoder=self._decoder,
                    protobuf_config=self._protobuf_config,
                    segment_index=self._segment_index,
                ))

        def _update_segment_line(self) -> None:
            """Update the segment selector display."""
            if self._segment_count <= 1:
                return
            try:
                seg = self.query_one("#segment-line", Static)
                labels = []
                for i in range(self._segment_count):
                    marker = f"[bold {c('accent')}]" if i == self._segment_index else f"[{c('text-muted')}]"
                    labels.append(f"{marker}Segment {i + 1}[/]")
                seg.update(f"  {'  |  '.join(labels)}    [dim](\\[/])[/]")
            except Exception:
                pass

        def action_next_segment(self) -> None:
            if self._segment_count <= 1:
                return
            self._segment_index = (self._segment_index + 1) % self._segment_count
            self._update_segment_line()
            self._notify_change()

        def action_prev_segment(self) -> None:
            if self._segment_count <= 1:
                return
            self._segment_index = (self._segment_index - 1) % self._segment_count
            self._update_segment_line()
            self._notify_change()

        # -- Decompression toggles --------------------------------------------

        def _toggle_decompression(self, opt_id: str) -> None:
            """Toggle a decompression option (only one at a time)."""
            if self._decompression == opt_id:
                # Deselect
                self._decompression = None
                try:
                    self.query_one(f"#opt-{opt_id}", Button).remove_class("active")
                except Exception:
                    pass
            else:
                # Deselect previous
                if self._decompression:
                    try:
                        self.query_one(
                            f"#opt-{self._decompression}", Button
                        ).remove_class("active")
                    except Exception:
                        pass
                # Select new
                self._decompression = opt_id
                try:
                    self.query_one(f"#opt-{opt_id}", Button).add_class("active")
                except Exception:
                    pass
            self._update_active_line()
            self._notify_change()

        # -- Decoder toggles --------------------------------------------------

        def _toggle_decoder(self, opt_id: str) -> None:
            """Toggle a decoder option (only one at a time)."""
            if self._decoder == opt_id:
                # Deselect
                self._decoder = None
                if opt_id == "protobuf":
                    self._protobuf_config = None
                try:
                    self.query_one(f"#opt-{opt_id}", Button).remove_class("active")
                except Exception:
                    pass
                self._update_active_line()
                self._notify_change()
            else:
                # Deselect previous decoder
                if self._decoder:
                    try:
                        self.query_one(
                            f"#opt-{self._decoder}", Button
                        ).remove_class("active")
                    except Exception:
                        pass

                if opt_id == "protobuf":
                    # Open sub-modal for protobuf configuration
                    self._open_protobuf_modal()
                else:
                    self._decoder = opt_id
                    self._protobuf_config = None
                    try:
                        self.query_one(f"#opt-{opt_id}", Button).add_class("active")
                    except Exception:
                        pass
                    self._update_active_line()
                    self._notify_change()

        def _open_protobuf_modal(self) -> None:
            """Push the ProtobufModal as a sub-modal."""
            self.app.push_screen(
                ProtobufModal(
                    current=self._protobuf_config,
                    body_preview=self._body_preview,
                ),
                callback=self._on_protobuf_result,
            )

        def _on_protobuf_result(self, result: ProtobufConfig | None) -> None:
            """Handle the result from the ProtobufModal."""
            if result is not None:
                self._decoder = "protobuf"
                self._protobuf_config = result
                try:
                    self.query_one("#opt-protobuf", Button).add_class("active")
                except Exception:
                    pass
            # If result is None (cancelled), keep previous state
            self._update_active_line()
            self._notify_change()
            # Focus Apply so user can quickly confirm after protobuf config
            try:
                self.query_one("#btn-apply", Button).focus()
            except Exception:
                pass

        # -- Reset ------------------------------------------------------------

        def _reset_all(self) -> None:
            """Reset all selections to original."""
            # Clear decompression
            if self._decompression:
                try:
                    self.query_one(
                        f"#opt-{self._decompression}", Button
                    ).remove_class("active")
                except Exception:
                    pass
            self._decompression = None

            # Clear decoder
            if self._decoder:
                try:
                    self.query_one(
                        f"#opt-{self._decoder}", Button
                    ).remove_class("active")
                except Exception:
                    pass
            self._decoder = None
            self._protobuf_config = None

            self._update_active_line()
            self._notify_change()

        # -- Key bindings → actions -------------------------------------------

        def action_toggle_1(self) -> None:
            self._toggle_decompression("gzip")

        def action_toggle_2(self) -> None:
            self._toggle_decompression("deflate")

        def action_toggle_3(self) -> None:
            self._toggle_decompression("brotli")

        def action_toggle_4(self) -> None:
            self._toggle_decompression("zstd")

        def action_toggle_5(self) -> None:
            self._toggle_decoder("json")

        def action_toggle_6(self) -> None:
            self._toggle_decoder("protobuf")

        def action_toggle_7(self) -> None:
            self._toggle_decoder("base64")

        def action_toggle_8(self) -> None:
            self._toggle_decoder("hex")

        def action_toggle_9(self) -> None:
            self._toggle_decoder("raw_utf8")

        def action_reset(self) -> None:
            self._reset_all()

        # -- Button handling --------------------------------------------------

        def on_button_pressed(self, event: Button.Pressed) -> None:
            btn_id = event.button.id

            if btn_id == "btn-apply":
                self._apply()
                return

            if btn_id == "btn-cancel":
                self.dismiss(None)
                return

            if btn_id == "opt-reset":
                self._reset_all()
                return

            # Check decompression buttons
            for key, opt_id, _ in _DECOMPRESS_OPTIONS:
                if btn_id == f"opt-{opt_id}":
                    self._toggle_decompression(opt_id)
                    return

            # Check decoder buttons
            for key, opt_id, _, _ in _DECODER_OPTIONS:
                if btn_id == f"opt-{opt_id}":
                    self._toggle_decoder(opt_id)
                    return

        def action_do_apply(self) -> None:
            """Enter key: toggle focused option, or apply if on Apply/Cancel."""
            focused = self.focused
            if focused is not None and focused.has_class("option-btn"):
                focused.press()
                return
            self._apply()

        def _apply(self) -> None:
            """Dismiss with the current processing result."""
            self.dismiss(BodyProcessingResult(
                decompression=self._decompression,
                decoder=self._decoder,
                protobuf_config=self._protobuf_config,
                segment_index=self._segment_index,
            ))
