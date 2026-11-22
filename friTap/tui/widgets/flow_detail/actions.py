"""Flow-detail key-binding actions and the body-processing / save helpers they use."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from friTap.flow.models import format_byte_size
from friTap.tui.modals.alert_modal import AlertModal
from friTap.tui.modals.body_processing_modal import BodyProcessingModal, ProtobufConfig

from .helpers import (
    _TAB_LAYERS,
    _TAB_REQUEST,
    _TAB_RESPONSE,
    _get_header,
    _log,
    save_without_overwrite,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow


class ActionsMixin:
    """Key-binding actions: body processing, raw hex, layer/segment navigation, explorer, save."""

    def action_back(self) -> None:
        """Go back to the flow list."""
        self.post_message(self.BackRequested())

    def action_open_body_processing(self) -> None:
        if not self._current_flow:
            return
        body = self._get_active_body_preview()
        self._pre_modal_processing = self._active_processing
        seg_count = len(self._current_flow.pane_segments(self._active_pane()))
        self.app.push_screen(
            BodyProcessingModal(
                current=self._active_processing,
                body_preview=body,
                on_change=self._on_body_processing_change,
                segment_count=max(seg_count, 1),
                content_type=self._active_pane_content_type(),
            ),
            callback=self._on_body_processing_result,
        )

    def _on_body_processing_change(self, result) -> None:
        """Live-update the flow detail while the body processing modal is open."""
        self._active_processing = result
        self._rerender_active_tab()

    def _on_body_processing_result(self, result) -> None:
        if result is None:
            # Cancelled: revert to the pre-modal state.

            self._active_processing = self._pre_modal_processing
            self._rerender_active_tab()
            return
        self._active_processing = result
        self._rerender_active_tab()

    def _rerender_active_tab(self) -> None:
        """Re-render the tab the user is on, keeping it selected.

        ``show_flow`` would auto-select a tab (e.g. jump from Response to
        Message) and so hide the pane the processing was applied to.
        """
        flow = self._current_flow
        if not flow:
            return
        self._last_protobuf_mode = None
        try:
            self._render_tab(flow, self._tabs.active)
        except Exception:
            self.show_flow(flow)
            return
        self._update_header(flow)

    def action_processing_reset(self) -> None:
        self._reset_view_state()
        if self._current_flow:
            self.show_flow(self._current_flow)

    def action_toggle_raw_hex(self) -> None:
        """Toggle raw hexdump mode for the current tab (request or response)."""
        if not self._current_flow:
            return
        try:
            active = self._tabs.active
        except Exception:
            return
        if active == _TAB_REQUEST:
            self._raw_request = not self._raw_request
        elif active == _TAB_RESPONSE:
            self._raw_response = not self._raw_response
        else:
            return
        try:
            self._update_header(self._current_flow)
            self._update_tab_labels(self._tabs, self._current_flow)
        except Exception:
            _log.exception("flow detail: header update failed")
        self._render_tab_safely(self._current_flow, active)

    def _on_layers_tab(self) -> bool:
        """True when a flow is loaded and the active tab is the Layers tab."""
        if not self._current_flow:
            return False
        try:
            return self._tabs.active == _TAB_LAYERS
        except Exception:
            return False

    def _rerender_layers(self) -> None:
        """Re-render the Layers tab and refresh the header hint."""
        self._update_header(self._current_flow)
        self._render_tab(self._current_flow, _TAB_LAYERS)

    def action_prev_layer(self) -> None:
        """Move the layer focus marker up one layer (clamped)."""
        if not self._on_layers_tab():
            return
        self._current_layer_idx = max(0, self._current_layer_idx - 1)
        self._rerender_layers()

    def action_next_layer(self) -> None:
        """Move the layer focus marker down one layer (clamped)."""
        if not self._on_layers_tab():
            return
        layers = getattr(self._current_flow, "layers", None) or []
        self._current_layer_idx = min(max(0, len(layers) - 1), self._current_layer_idx + 1)
        self._rerender_layers()

    def action_toggle_layer_view(self) -> None:
        """``l``: open the raw layer view, or flip parsed/hex when on it.

        From any non-Layers tab (e.g. the Message tab, which advertises
        "press l for the raw layer view"), this switches to the Layers tab
        and lands on the message-bearing layer. Once on the Layers tab it
        flips the focused layer between its parsed and hex views.
        """
        if not self._current_flow:
            return
        if not self._on_layers_tab():
            try:
                self._tabs.active = _TAB_LAYERS
            except Exception:
                return
            self._focus_message_layer()
            self._rerender_layers()
            return
        layers = getattr(self._current_flow, "layers", None) or []
        idx = self._current_layer_idx
        if idx >= len(layers):
            return
        current = self._layer_view.get(idx, self._default_layer_view(layers[idx]))
        self._layer_view[idx] = "hex" if current == "parsed" else "parsed"
        self._rerender_layers()

    def _focus_message_layer(self) -> None:
        """Point ``_current_layer_idx`` at the message-bearing layer, if any.

        So jumping to the raw layer view lands on the layer whose transport
        records the user came to inspect, rather than the outermost layer.
        """
        layers = getattr(self._current_flow, "layers", None) or []
        for idx, layer in enumerate(layers):
            if self._layer_has_messages(layer):
                self._current_layer_idx = idx
                return

    def action_next_segment(self) -> None:
        """Scroll to next segment boundary in the request tab."""
        self._scroll_to_segment(1)

    def action_prev_segment(self) -> None:
        """Scroll to previous segment boundary in the request tab."""
        self._scroll_to_segment(-1)

    def _scroll_to_segment(self, direction: int) -> None:
        """Scroll the request log to the next/previous segment boundary."""
        if not self._segment_offsets or not self._current_flow:
            return
        try:
            log = self._request_log
            current_y = log.scroll_y
            if direction > 0:
                # Next offset after the current scroll position.
                for offset in self._segment_offsets:
                    if offset > current_y + 2:
                        log.scroll_to(y=offset, animate=True)
                        return
            else:
                # Previous offset before the current scroll position.
                for offset in reversed(self._segment_offsets):
                    if offset < current_y - 2:
                        log.scroll_to(y=offset, animate=True)
                        return
        except Exception:
            pass

    @staticmethod
    def _explorer_body(flow: "Flow", direction: str) -> tuple[bytes, dict]:
        """Return (body, headers) for the explorer, preferring raw pre-decompression bytes."""
        is_request = direction == "request"
        msg = flow.request if is_request else flow.response
        dir_key = "write" if is_request else "read"
        body = getattr(msg, "raw", b"") or (
            flow.request_body if is_request else flow.response_body
        )
        if not body:
            body = flow.get_direction_bytes(dir_key)
        headers = msg.headers if msg else {}
        return body, headers

    def action_open_explorer(self) -> None:
        """Open Explorer Mode for the active tab's body."""
        flow = self._current_flow
        if not flow:
            return
        try:
            active = self._tabs.active
        except Exception:
            return
        if active == _TAB_REQUEST:
            body, headers = self._explorer_body(flow, "request")
            direction = "request"
        elif active == _TAB_RESPONSE:
            body, headers = self._explorer_body(flow, "response")
            direction = "response"
        else:
            return  # no explorer on Detail tab
        if not body:
            return
        from friTap.tui.modals.explorer_modal import ExplorerModal
        self.app.push_screen(
            ExplorerModal(body=body, direction=direction, headers=headers),
            callback=self._on_explorer_result,
        )

    def _on_explorer_result(self, result) -> None:
        """Keep the ExplorerResult returned from Explorer Mode."""
        if result is None:
            return
        self._last_explorer_result = result

    def _get_active_body_preview(self) -> bytes:
        """Get first 4096 bytes of the currently displayed body for preview.

        Previews the trailing segment when the active processing targets it.
        """
        flow = self._current_flow
        if not flow:
            return b""
        pane = self._active_pane()
        if self._processing_applies_to(1) and self._trailing_slot(flow, pane)[0] is not None:
            body = self._trailing_segment_body(flow, pane)
        else:
            body = self._active_pane_body(flow, pane)
        return body[:4096] if body else b""

    @classmethod
    def _active_pane_body(cls, flow: "Flow", pane: str) -> bytes:
        """Primary body shown in *pane* (``"request"`` / ``"response"``).

        For MTProto / Secret-Chat flows this is the pane's parsed TL body
        (write direction on the request pane, read on the response pane);
        otherwise the request / response body.
        """
        direction = "read" if pane == "response" else "write"
        if cls._is_message_transport_flow(flow):
            msg = cls._parsed_tl_message(flow, direction)
            if msg is not None:
                return msg.body or b""
        return flow.response_body if pane == "response" else flow.request_body

    def _active_pane_content_type(self) -> str:
        """Content-Type of the active pane's message (``""`` when unknown)."""
        flow = self._current_flow
        msg = getattr(flow, "response" if self._active_pane() == "response" else "request", None)
        return _get_header(getattr(msg, "headers", None) or {}, "content-type")

    def _active_pane(self) -> str:
        """``"response"`` when the Response tab is active, else ``"request"``.

        Segment indices are per pane: segment 1 is the active pane's own
        trailing data (request tab -> write-direction trailing, response
        tab -> read-direction trailing).
        """
        try:
            return "response" if self._tabs.active == _TAB_RESPONSE else "request"
        except Exception:
            return "request"

    @staticmethod
    def _trailing_slot(flow: "Flow", which: str = "request"):
        """``(bytes, protocol, parse)`` of the request or response trailing slot."""
        if which == "response":
            return (getattr(flow, "response_trailing_bytes", None),
                    getattr(flow, "response_trailing_protocol", ""),
                    getattr(flow, "response_trailing_parse", None))
        return flow.trailing_bytes, flow.trailing_protocol, flow.trailing_parse

    def _processing_applies_to(self, segment: int) -> bool:
        """True when user-selected body processing targets *segment*.

        Segment 0 is the primary message, segment 1 the trailing data.
        """
        processing = self._active_processing
        if not processing:
            return False
        return getattr(processing, "segment_index", 0) == segment

    @staticmethod
    def _trailing_segment_body(flow: "Flow", which: str = "request") -> bytes:
        """Body bytes of the trailing segment: sub-parsed body, else raw bytes."""
        tb, _proto, sp = ActionsMixin._trailing_slot(flow, which)
        if sp is not None and sp.body:
            return sp.body
        return tb or b""

    def _describe_pipeline(self) -> str:
        """Human-readable description of the active processing chain."""
        if not self._active_processing:
            return ""
        parts = []
        if self._active_processing.decompression:
            parts.append(self._active_processing.decompression)
        if self._active_processing.decoder:
            label = self._active_processing.decoder
            if label == "protobuf" and self._active_processing.protobuf_config:
                label = self._protobuf_pipeline_label(self._active_processing.protobuf_config)
            parts.append(label)
        return " -> ".join(parts)

    _PROTOBUF_MODE_LABELS = {"schema": "schema", "blackbox": "blackbox", "wire": "raw"}

    def _protobuf_pipeline_label(self, pc: ProtobufConfig) -> str:
        """``protobuf (<mode>)`` from the decoder the last decode actually used.

        A schema that failed to load falls back to the wire decoder, so the
        configured mode alone would mislabel it; before the first decode the
        label is derived from the configuration.
        """
        mode = getattr(self, "_last_protobuf_mode", None)
        if mode is None:
            mode = "schema" if not pc.schema_less and pc.schema_path else "wire"
        return f"protobuf ({self._PROTOBUF_MODE_LABELS.get(mode, mode)})"

    def _save_directory(self) -> str:
        """Directory for saved bodies: the screen's optional ``_output_dir``, else the cwd."""
        try:
            directory = getattr(self.screen, "_output_dir", None)
        except Exception:
            directory = None
        return str(directory) if directory else os.getcwd()

    def action_save_body(self) -> None:
        """Save the active tab's body (request or response) to a file."""
        from friTap.flow.http_utils import (
            filename_from_url,
            parse_content_disposition_filename,
            sanitize_filename,
        )

        flow = self._current_flow
        if flow is None:
            return

        active = self._tabs.active
        if active == _TAB_REQUEST:
            msg = flow.request
            direction = "request"
        else:
            msg = flow.response
            direction = "response"

        if msg is None:
            self.app.push_screen(
                AlertModal(
                    message=f"No {direction} data to save.",
                    title="Nothing to Save",
                    severity="warning",
                )
            )
            return

        dir_key = "write" if direction == "request" else "read"
        raw_body = msg.body if msg.body else flow.reconstruct_body(dir_key)
        if not raw_body:
            self.app.push_screen(
                AlertModal(
                    message=f"Empty {direction} body.",
                    title="Empty Body",
                    severity="warning",
                )
            )
            return

        # The active processing's decompression overrides the detected encoding.
        encoding_override = self._active_processing.decompression if self._active_processing else ""
        body = flow._get_decompressed_body(msg, dir_key, encoding_override=encoding_override)

        filename = None
        if direction == "response":
            cd = flow.get_response_header("content-disposition")
            if cd:
                filename = parse_content_disposition_filename(cd)
        if not filename and flow.request and flow.request.url:
            filename = filename_from_url(flow.request.url)
        if not filename:
            filename = f"body_{direction}.bin"
        filename = sanitize_filename(filename)

        try:
            save_path = save_without_overwrite(self._save_directory(), filename, body)
            size_str = format_byte_size(len(body))
            self.app.notify(f"Saved {size_str} to {save_path}")
        except OSError as e:
            self.app.push_screen(
                AlertModal(
                    message=f"Save failed: {e}",
                    title="Save Failed",
                    severity="error",
                )
            )
