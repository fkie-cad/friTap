"""BodyProcessor integration for protobuf decoding.

Implements the :class:`~friTap.parsers.body_processors.BodyProcessor` protocol
so protobuf decoding can be chained in a :class:`~friTap.parsers.body_processors.BodyPipeline`.

Usage::

    from friTap.parsers.body_processors import BodyPipeline, DecompressProcessor
    from friTap.parsers.protobuf.processor import ProtobufProcessor

    pipeline = BodyPipeline()
    pipeline.add(DecompressProcessor())
    pipeline.add(ProtobufProcessor(force=True))

    body, ct, err = pipeline.process(raw_body, "application/grpc", "gzip")
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from .grpc import extract_grpc_messages, is_grpc_content_type, is_protobuf_content_type
from .wire import decode_raw, format_message

_log = logging.getLogger(__name__)


class ProtobufProcessor:
    """BodyProcessor that decodes protobuf/gRPC bodies.

    Activates for protobuf-related content types. When ``force=True``,
    also attempts decoding for ``application/octet-stream`` and other
    binary types.

    Args:
        schema_path: Optional path to a compiled ``.desc`` file for
            schema-based decoding.
        message_type: Protobuf message type name (required if schema_path is set).
        force: If ``True``, attempt decoding regardless of content type.
    """

    def __init__(
        self,
        schema_path: Optional[str] = None,
        message_type: Optional[str] = None,
        force: bool = False,
    ) -> None:
        self._schema_path = schema_path
        self._message_type = message_type
        self._force = force
        self._schema_decoder = None

        if schema_path and message_type:
            try:
                from .schema import SchemaDecoder
                self._schema_decoder = SchemaDecoder()
                self._schema_decoder.load_descriptor(schema_path, message_type)
            except (ImportError, Exception) as exc:
                _log.warning("Failed to load protobuf schema: %s", exc)

    def _should_activate(self, content_type: str) -> bool:
        """Check if this processor should activate for the given content type."""
        if self._force:
            return True
        if not content_type:
            return False
        return is_protobuf_content_type(content_type) or is_grpc_content_type(content_type)

    def process(
        self, body: bytes, content_type: str, encoding: str
    ) -> tuple[bytes, str, str]:
        """Decode protobuf body if content type matches.

        Returns:
            Tuple of (decoded_body_as_text_bytes, updated_content_type, error).
        """
        if not body or not self._should_activate(content_type):
            return body, content_type, ""

        try:
            payloads = extract_grpc_messages(body, content_type)

            if self._schema_decoder is not None:
                return self._decode_with_schema(payloads, content_type)

            parts: list[str] = []
            is_grpc = is_grpc_content_type(content_type)

            for i, payload in enumerate(payloads):
                if not payload:
                    continue
                msg = decode_raw(payload)
                formatted = format_message(msg)
                if is_grpc and len(payloads) > 1:
                    parts.append(f"--- gRPC message {i + 1} ---")
                parts.append(formatted)

            if not parts:
                return body, content_type, "no protobuf fields decoded"

            decoded_text = "\n".join(parts)
            return (
                decoded_text.encode("utf-8"),
                "text/x-protobuf-decoded",
                "",
            )

        except ValueError as exc:
            return body, content_type, f"protobuf decode failed: {exc}"
        except Exception as exc:
            _log.debug("Unexpected protobuf decode error: %s", exc, exc_info=True)
            return body, content_type, f"protobuf decode error: {exc}"

    def _decode_with_schema(
        self, payloads: list[bytes], content_type: str
    ) -> tuple[bytes, str, str]:
        """Decode payloads using the loaded schema."""

        parts: list[str] = []
        for i, payload in enumerate(payloads):
            if not payload:
                continue
            result = self._schema_decoder.decode(payload)
            formatted = json.dumps(result, indent=2, ensure_ascii=False)
            if len(payloads) > 1:
                parts.append(f"--- message {i + 1} ---")
            parts.append(formatted)

        if not parts:
            return b"", content_type, "no protobuf messages decoded"

        decoded_text = "\n".join(parts)
        return (
            decoded_text.encode("utf-8"),
            "text/x-protobuf-decoded",
            "",
        )
