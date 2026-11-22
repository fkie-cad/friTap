"""Flow-detail Layers tab: the protocol layer stack, parsed or as hex."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.widgets import RichLog

from friTap.flow import telegram_conversation as _tconv
from friTap.tui.themes import c
from friTap.tui.widgets.tl_tree_render import local_time

from .helpers import _safe_wire_text

if TYPE_CHECKING:
    from friTap.flow.models import Flow


class LayersMixin:
    """Layers tab: the protocol layer stack, parsed or as hex."""

    # Per-layer typed metadata fields rendered (in order) above the generic
    # to_dict() fallback. Keeps the most useful fields prominent.
    _LAYER_PRIMARY_FIELDS = {
        "tls": ("sni", "version", "alpn", "cipher", "library"),
        "quic": ("sni", "version", "alpn", "cipher", "library"),
        "signal": ("chat_type", "identifier", "message_count"),
        "mtproto": ("transport", "dc_id", "auth_key_id", "message_count"),
        "rc4": ("source", "key_len", "framing", "direction", "message_count"),
    }

    _LAYER_BYTES_PREVIEW = 256

    def _render_layers_tab(self, flow: "Flow") -> None:
        """Render the flow's protocol layer stack as a drillable view."""
        log = self._layers_log
        log.clear()

        layers = getattr(flow, "layers", None) or []
        if not layers:
            log.write("[dim]No layer stack[/]")
            log.scroll_home(animate=False)
            return

        log.write(f"[bold {c('primary')}]Protocol Layer Stack[/]  [dim]({len(layers)} layers)[/]")
        log.write("")

        # Clamp the focused-layer index to the current layer set.
        if self._current_layer_idx >= len(layers):
            self._current_layer_idx = max(0, len(layers) - 1)

        for idx, layer in enumerate(layers):
            self._render_one_layer(log, layer, idx)
            log.write("")

        log.scroll_home(animate=False)

    @staticmethod
    def _layer_has_messages(layer) -> bool:
        """True if a layer carries parsed message entries (rendered as a transcript)."""
        return bool(getattr(layer, "messages", None))

    def _default_layer_view(self, layer) -> str:
        """Default view for a layer: parsed for layers with messages, else hex."""
        return "parsed" if self._layer_has_messages(layer) else "hex"

    def _render_one_layer(self, log: RichLog, layer, idx: int = 0) -> None:
        """Render a single protocol layer: header, metadata, then parsed/hex body."""
        name = getattr(layer, "name", "?")
        depth = getattr(layer, "depth", 0)
        data = getattr(layer, "data", None)
        source = getattr(data, "data_source", "none") if data is not None else "none"
        metadata_only = getattr(layer, "metadata_only", False)

        tags = [source]
        if metadata_only:
            tags.append("metadata-only")
        marker = "▸ " if idx == self._current_layer_idx else "  "
        log.write(
            f"[bold {c('accent')}]{marker}{self._tree_prefix(depth)}[{depth}] {self._esc(name)}[/] "
            f"[dim]({', '.join(tags)})[/]"
        )

        self._render_layer_metadata(log, layer, name)
        self._render_layer_records(log, layer)

        view = self._layer_view.get(idx, self._default_layer_view(layer))
        if view == "parsed":
            self._render_layer_parsed(log, layer, idx)
        elif source != "none" and data is not None:
            self._render_layer_bytes(log, data)

    def _render_layer_parsed(self, log: RichLog, layer, idx: int) -> None:
        """Render the parsed view of a layer; layers without messages get a
        hint to switch to hex."""
        is_signal = getattr(layer, "name", "") == "signal" or self._layer_has_messages(layer)
        if not is_signal:
            log.write("    [dim]no parsed view — press l for hex[/]")
            return

        messages = getattr(layer, "messages", None) or []
        if not messages:
            log.write("    [dim]no parsed messages[/]")
            return

        # Legend for the MTProto transport categories, shown once when any
        # are present so "ack"/"rpc"/"service" rows below are self-explaining.
        if {(m.get("kind") or "") for m in messages} & {"ack", "rpc", "service"}:
            log.write("    [dim]ack = msgs_ack · rpc = rpc_result · "
                      "service = pong/salt/session/error[/]")

        for entry in messages:
            try:
                direction = entry.get("direction", "") or ""
                sender = entry.get("sender", "") or ""
                timestamp = entry.get("timestamp", "") or ""
                kind = entry.get("kind", "") or ""
                body = entry.get("body", "") or ""
                method = entry.get("method", "") or ""
            except AttributeError:
                continue

            # "write" (or a synonym) = sent by this device.
            arrow = "→" if direction in _tconv.OUTBOUND_DIRECTIONS else "←"
            head_bits = [b for b in (arrow, sender, kind) if b]
            # Escape wire-derived fields: a literal "[" would be parsed as
            # Rich markup and can raise MarkupError.
            head = "  ".join(self._esc(b) for b in head_bits)
            # TL type name (e.g. "rpc  users"), unless it repeats the kind.
            method_suffix = (f"  [dim]{self._esc(method)}[/]"
                             if method and method.lower() != kind.lower()
                             else "")
            ts_suffix = f"  [dim]@{self._esc(timestamp)}[/]" if timestamp else ""
            log.write(f"    [bold {c('accent')}]{head}[/]{method_suffix}{ts_suffix}")

            # Plaintext metadata records have no chat body: show verb/path/
            # status and the parsed JSON dict.
            rest_line = self._rest_label(entry)
            if rest_line:
                log.write(f"      [dim]{self._esc(rest_line)}[/]")
            entry_meta = entry.get("meta")
            if isinstance(entry_meta, dict) and entry_meta:
                for k, v in entry_meta.items():
                    if k == "type":
                        continue
                    log.write(f"      [dim]{self._esc(k)}: {self._esc(v)}[/]")
            self._write_message_note(log, entry)

            if body:
                self._write_text_body(
                    log, body.encode("utf-8", "replace"), errors="replace"
                )

            flag_bits = []
            if entry.get("attachments"):
                flag_bits.append("attachments")
            if entry.get("quote"):
                flag_bits.append("quote")
            if entry.get("reaction"):
                flag_bits.append("reaction")
            if flag_bits:
                log.write(f"    [dim]• {', '.join(flag_bits)}[/]")

    @staticmethod
    def _write_message_note(log: RichLog, entry) -> None:
        """Show a per-message parser ``note`` (e.g. a truncated gzip_packed body).

        Offline MTProto message dicts carry ``note`` only when set; it is
        wire-adjacent text, so it goes through :func:`safe_wire_text`.
        """
        note = entry.get("note") or ""
        if note:
            log.write(f"      [{c('warning')}]note: {_safe_wire_text(note)}[/]")

    def _render_layer_metadata(self, log: RichLog, layer, name: str) -> None:
        """Render typed metadata fields for a layer (indented)."""
        try:
            meta = layer.to_dict()
        except Exception:
            meta = {}
        # Drop identity fields already shown in the header, and the parsed
        # message list (rendered separately by _render_layer_parsed, not as a
        # raw repr in the metadata block).
        meta = {k: v for k, v in meta.items()
                if k not in ("name", "depth", "messages")}

        primary = self._LAYER_PRIMARY_FIELDS.get(name, ())
        ordered_keys = [k for k in primary if k in meta]
        ordered_keys += [k for k in meta if k not in ordered_keys]

        wrote_any = False
        for key in ordered_keys:
            value = meta.get(key)
            if value in (None, "", 0, False):
                continue
            # rc4 ``records`` get their own renderer (_render_layer_records).
            if key == "records" and isinstance(value, list):
                continue
            log.write(f"    [bold]{self._esc(key)}:[/] {self._esc(value)}")
            wrote_any = True
        if not wrote_any:
            log.write("    [dim]no metadata[/]")

    @staticmethod
    def _tree_prefix(depth: int) -> str:
        """Tree connector for a layer header: "" at depth 0, else indented "└─ "."""
        if depth <= 0:
            return ""
        return "  " * (depth - 1) + "└─ "

    @staticmethod
    def _record_frames_text(frames) -> str:
        """``from TLS frame #28`` / ``reassembled from TLS frames #22, #26``."""
        frames = [f for f in (frames or []) if isinstance(f, int)]
        if not frames:
            return ""
        refs = ", ".join(f"#{f}" for f in frames)
        if len(frames) == 1:
            return f"from TLS frame {refs}"
        return f"reassembled from TLS frames {refs}"

    @staticmethod
    def _record_framing_text(record: dict, framing: str) -> str:
        """``u32be-length framed @offset 0`` (offset = start of the frame header)."""
        if not framing:
            return ""
        offset = int(record.get("cipher_offset", 0) or 0) - int(record.get("frame_header_len", 0) or 0)
        return f"{framing} framed @offset {max(offset, 0)}"

    def _format_layer_record(self, record: dict, framing: str) -> str:
        """One-line summary of a per-message layer record (rc4 ``records``)."""
        direction = record.get("direction", "") or ""
        arrow = "→" if direction == "write" else "←"
        ts = record.get("timestamp")
        parts = [
            f"{arrow} {direction} {int(record.get('length', 0) or 0):,} B",
            self._record_framing_text(record, framing),
            self._record_frames_text(record.get("tls_frames")),
            local_time(ts, millis=True) if ts else "",
        ]
        return "  ".join(self._esc(p) for p in parts if p)

    def _render_layer_records(self, log: RichLog, layer) -> None:
        """Render a layer's per-message ``records`` list (e.g. RC4-in-TLS)."""
        records = getattr(layer, "records", None)
        if not isinstance(records, list) or not records:
            return
        framing = getattr(layer, "framing", "") or ""
        log.write(f"    [bold]records:[/] {len(records)}")
        for record in records:
            if isinstance(record, dict):
                log.write(f"      {self._format_layer_record(record, framing)}")

    def _render_layer_bytes(self, log: RichLog, data) -> None:
        """Render a short read/write byte summary for a layer with data."""
        limit = self._LAYER_BYTES_PREVIEW
        for label, direction in (("write (c2s)", "write"), ("read (s2c)", "read")):
            try:
                raw = data.direction(direction)
            except Exception:
                raw = b""
            if not raw:
                continue
            log.write(f"    [bold {c('success')}]{label}:[/] {len(raw):,} bytes")
            self._write_hexdump(log, raw[:limit])
            if len(raw) > limit:
                log.write(f"    [dim]... {len(raw) - limit:,} more bytes[/]")
