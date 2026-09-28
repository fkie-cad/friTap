"""Transport-pinned parsers for decrypted Telegram TL payloads.

Decrypted MTProto (cloud) and Secret-Chat (E2E) plaintexts are TL-serialized
binary objects, not a byte-sniffable wire protocol: blind detection mislabels
them (a ``decryptedMessageLayer`` starts ``89 17`` = WebSocket FIN|PING). These
parsers therefore never claim data via :meth:`can_parse`; the registry selects
them only by the flow's transport (see ``ParserRegistry.pin_transport``).

Each ``feed`` call is exactly one decrypted packet: no buffering, no trailing
data. Decoding is delegated to the tolerant helpers in
:mod:`friTap.offline.mtproto.content`, so a malformed payload yields an error
result instead of raising.
"""

from __future__ import annotations

import struct
from functools import lru_cache

from friTap.constants import PROTOCOL_MTPROTO, PROTOCOL_TELEGRAM_E2E

from .base import BaseParser, ParseResult

_TEXT_CONTENT_TYPE = "text/plain; charset=utf-8"


def _leading_ctor_label(data: bytes) -> str:
    """Hex label of the first little-endian uint32, or ``"unknown"`` if too short."""
    if len(data) < 4:
        return "unknown"
    return f"0x{struct.unpack_from('<I', data)[0]:08x}"


def _raw_result(protocol: str, data: bytes, direction: str, **kwargs) -> ParseResult:
    """A complete ParseResult carrying *data* as both body and raw bytes."""
    return ParseResult(
        protocol=protocol, raw=data, body=kwargs.pop("body", data),
        is_complete=True, is_request=(direction == "write"), **kwargs,
    )


def _secret_chat_headers(fields) -> dict:
    """String-valued display headers for decoded Secret-Chat *fields*."""
    headers = {"constructor": f"{fields.ctor_name} (0x{fields.ctor:08x})"}
    if fields.has_layer_envelope:
        headers.update({
            "layer": str(fields.layer),
            "in_seq_no": str(fields.in_seq_no),
            "out_seq_no": str(fields.out_seq_no),
            "random_bytes_len": str(fields.random_bytes_len),
        })
    headers["random_id"] = str(fields.random_id)
    if fields.ctor_name == "decryptedMessage":
        headers["ttl"] = str(fields.ttl)
    if fields.has_media:
        headers["media"] = fields.media_ctor or "present"
    if fields.action:
        headers["action"] = fields.action
    headers["content-type"] = _TEXT_CONTENT_TYPE
    return headers


class TelegramE2EParser(BaseParser):
    """One decrypted Secret-Chat plaintext (``decryptedMessageLayer``) per feed."""

    PROTOCOL = PROTOCOL_TELEGRAM_E2E

    def can_parse(self, data: bytes) -> bool:
        """Never blind-detected: selected only via the ``telegram_e2e`` transport pin."""
        return False

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        from friTap.offline.mtproto.content import decode_secret_chat_fields

        fields = decode_secret_chat_fields(data)
        if fields is None:
            return [self._error_result(data, direction)]
        body = (fields.message or fields.action).encode("utf-8")
        return [_raw_result(
            self.PROTOCOL, data, direction, body=body, body_size=len(body),
            method=fields.ctor_name, headers=_secret_chat_headers(fields),
            content_type=_TEXT_CONTENT_TYPE,
        )]

    def _error_result(self, data: bytes, direction: str) -> ParseResult:
        method = _leading_ctor_label(data)
        return _raw_result(
            self.PROTOCOL, data, direction, body_size=len(data), method=method,
            error=f"undecodable Telegram secret-chat TL payload (constructor {method})",
        )

    def flush(self) -> list[ParseResult]:
        return []


def _best_ranked_method(parsed) -> str:
    """Highest-priority TL method among *parsed* items (chat > RPC > updates > service)."""
    from friTap.flow.display import _classify_method

    best_method, best_rank = "", 0
    for item in parsed:
        method = _schema_method_name(item.method)
        rank = _classify_method(method)
        if rank > best_rank:
            best_method, best_rank = method, rank
    return best_method


def _rpc_result_name(data: bytes) -> str | None:
    """Schema name of a top-level ``rpc_result``'s result object (through gzip), if known."""
    return _rpc_result_name_cached(bytes(data))


@lru_cache(maxsize=1024)
def _rpc_result_name_cached(data: bytes) -> str | None:
    """Name-only lookup: peek the result constructor id, then ask the schema.

    Vector and nested-gzip results are never named objects in the full decode,
    so they stay unnamed here too. ``None`` also when *data* is no ``rpc_result``.
    """
    from friTap.offline.mtproto.tl.decoder import (
        GZIP_PACKED_ID,
        VECTOR_ID,
        rpc_result_ctor_id,
    )

    ctor = rpc_result_ctor_id(data)
    if ctor is None or ctor in (VECTOR_ID, GZIP_PACKED_ID):
        return None
    return _schema_name(ctor)


def _refine_rpc_method(method: str, data: bytes) -> str:
    """Name a generic ``rpc_result`` method by its schema-decoded result object."""
    if method != "rpc_result":
        return method  # (a non-rpc_result payload is rejected by the name lookup)
    return _rpc_result_name(data) or method


def _schema_name(ctor: int) -> str | None:
    """Vendored-schema name of *ctor* (cloud domain), or ``None`` when unknown."""
    from friTap.offline.mtproto.tl import name_for_id

    try:
        return name_for_id(ctor, "mtproto")
    except Exception:  # noqa: BLE001 - a missing/broken schema must not break parsing
        return None


def _schema_method_name(method: str) -> str:
    """Replace a hex fallback label (``0x1234abcd``) by its schema name when known."""
    if not (method.startswith("0x") and len(method) == 10):
        return method
    try:
        ctor = int(method, 16)
    except ValueError:
        return method
    return _schema_name(ctor) or method


def _mtproto_constructor(data: bytes, legacy_name) -> tuple[str, str]:
    """``(label, name)`` of the leading constructor: ``("pong#347773c5", "pong")``.

    The name comes from the vendored schema, then the legacy content table; an
    id neither knows keeps the hex label (``0x12345678``) for both.
    """
    if len(data) < 4:
        return "unknown", "unknown"
    ctor = struct.unpack_from("<I", data)[0]
    name = _schema_name(ctor) or legacy_name(ctor)
    if name.startswith("0x"):
        return name, name
    return f"{name}#{ctor:08x}", name


class MtprotoParser(BaseParser):
    """One decrypted cloud MTProto TL payload per feed."""

    PROTOCOL = PROTOCOL_MTPROTO

    def can_parse(self, data: bytes) -> bool:
        """Never blind-detected: selected only via the ``mtproto`` transport pin."""
        return False

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        from friTap.offline.mtproto.content import ctor_name, parse_mtproto_message

        constructor, ctor_label_name = _mtproto_constructor(data, ctor_name)
        parsed = parse_mtproto_message(data)
        method = _refine_rpc_method(_best_ranked_method(parsed) or ctor_label_name, data)
        return [_raw_result(
            self.PROTOCOL, data, direction, body_size=len(data), method=method,
            headers={"constructor": constructor, "messages": str(len(parsed))},
        )]

    def flush(self) -> list[ParseResult]:
        return []
