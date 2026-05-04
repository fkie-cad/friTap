#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example protobuf plugin — auto-decode protobuf/gRPC payloads in flow detail.

To use: copy this file to your platform's plugin directory and run friTap.
Find the path with: python -c "from friTap.plugins.loader import PLUGIN_DIR; print(PLUGIN_DIR)"

Provides a "Protobuf" tab in the flow detail view that shows decoded
protobuf structures for both request and response bodies.
"""

import logging
from typing import TYPE_CHECKING

from friTap.plugins.base import FriTapPlugin
from friTap.events import FlowEvent, EventBus
from friTap.parsers.protobuf import (
    decode_raw,
    format_message,
    extract_grpc_messages,
    is_grpc_content_type,
    is_likely_protobuf,
    is_protobuf_content_type,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow
    from friTap.session import Session

logger = logging.getLogger("friTap.plugins.protobuf")


def _decode_body(body: bytes, content_type: str) -> str | None:
    """Attempt to decode a body as protobuf, returning formatted text or None."""
    if not body:
        return None

    is_grpc = is_grpc_content_type(content_type)

    if is_grpc:
        try:
            messages = extract_grpc_messages(body, content_type)
        except Exception:
            messages = []
        if not messages:
            return None
        parts: list[str] = []
        for i, msg_bytes in enumerate(messages):
            try:
                msg = decode_raw(msg_bytes)
                if msg.fields:
                    header = f"--- gRPC message {i + 1} ({len(msg_bytes)} bytes) ---"
                    parts.append(f"{header}\n{format_message(msg)}")
            except (ValueError, IndexError):
                parts.append(f"--- gRPC message {i + 1}: decode failed ({len(msg_bytes)} bytes) ---")
        return "\n\n".join(parts) if parts else None

    # Non-gRPC: check heuristic or content-type
    if not is_protobuf_content_type(content_type) and not is_likely_protobuf(body):
        return None

    try:
        msg = decode_raw(body)
        if msg.fields:
            return format_message(msg)
    except (ValueError, IndexError):
        return f"[decode failed: {len(body)} bytes]"

    return None


class Plugin(FriTapPlugin):
    """Auto-decode protobuf/gRPC payloads and provide a detail tab."""

    # --- TabProvider protocol ---
    title = "Protobuf"
    tab_id = "protobuf"

    @property
    def name(self) -> str:
        return "protobuf"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Auto-decode protobuf/gRPC payloads"

    def on_load(self, session: "Session") -> None:
        self._session = session
        session.lifecycle_bus.subscribe(
            FlowEvent,
            self._on_flow,
            priority=EventBus.PLUGIN_PRIORITY,
        )
        logger.debug("Protobuf plugin loaded")

    def _on_flow(self, event: FlowEvent) -> None:
        """Log protobuf detections for completed flows."""
        if event.flow_event_type != "completed" or event.flow is None:
            return
        flow = event.flow
        # Check if there is any protobuf content
        for direction in ("request", "response"):
            ct = (
                flow.request_content_type if direction == "request"
                else flow.response_content_type
            )
            if is_grpc_content_type(ct) or is_protobuf_content_type(ct):
                logger.debug(
                    "Protobuf %s detected in flow %s (%s)",
                    direction,
                    flow.flow_id,
                    ct,
                )

    def render(self, flow: "Flow") -> str | None:
        """Render decoded protobuf content for the flow detail tab.

        Returns formatted text showing decoded protobuf structures for
        both request and response, or None if no protobuf content is found.
        """
        sections: list[str] = []

        # Request
        try:
            req_body = flow.get_decompressed_request_body() if flow.request else b""
        except Exception:
            req_body = b""
        req_ct = flow.request_content_type
        req_decoded = _decode_body(req_body, req_ct)
        if req_decoded:
            sections.append(f"=== Request ({len(req_body)} bytes) ===\n{req_decoded}")

        # Response
        try:
            resp_body = flow.get_decompressed_response_body() if flow.response else b""
        except Exception:
            resp_body = b""
        resp_ct = flow.response_content_type
        resp_decoded = _decode_body(resp_body, resp_ct)
        if resp_decoded:
            sections.append(f"=== Response ({len(resp_body)} bytes) ===\n{resp_decoded}")

        if not sections:
            return None

        return "\n\n".join(sections)

    def on_unload(self, session: "Session") -> None:
        logger.debug("Protobuf plugin unloaded")
