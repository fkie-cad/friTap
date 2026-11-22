#!/usr/bin/env python3

"""Telegram MTProto protocol handler.

The keylog carries Telegram auth keys (and PFS temp keys used on the wire) so
the offline decryptor can match a record's ``auth_key_id`` to its ``auth_key``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from ..backends.base import BackendName
from ..output.keylog_format import KeylogFormatter
from . import mtproto_keylog_spec as spec
from .base import BackendSupport, ProtocolHandler
from .mtproto_hints import attach_mode_hint

if TYPE_CHECKING:
    from ..events import KeylogEvent

# Native Telegram networking library (tgnet) and adjacent name fragments.
MTPROTO_LIBRARY_PATTERNS = ["libtmessages", "tmessages", "tgnet"]


class MtprotoKeylogFormatter(KeylogFormatter):
    """Formats Telegram auth keys into the canonical friTap MTProto keylog.

    Renders the :class:`KeylogEvent` payload (``auth_key_id``, ``auth_key``,
    ``dc_id``, ``key_type``) per :mod:`friTap.protocols.mtproto_keylog_spec`.
    Only friTap's offline decryptor (``--mtproto-keylog``) reads it.
    """

    @property
    def protocol(self) -> str:
        return "mtproto"

    def header_comment(self) -> Optional[str]:
        return spec.HEADER_COMMENT

    def format(self, event: "KeylogEvent") -> List[str]:
        payload = event.payload or {}
        line = spec.format_line(
            dc_id=payload.get("dc_id", 0),
            auth_key_id=str(payload.get("auth_key_id", "")),
            auth_key=str(payload.get("auth_key", "")),
            key_type=str(payload.get("key_type", spec.KEY_TYPE_PERM)),
        )
        return [line] if line else []

    def dedup_key(self, event: "KeylogEvent") -> str:
        payload = event.payload or {}
        return f"{payload.get('auth_key_id', '')}|{payload.get('key_type', spec.KEY_TYPE_PERM)}"


class MTProtoHandler(ProtocolHandler):
    """Handler for Telegram MTProto key material."""

    library_patterns = MTPROTO_LIBRARY_PATTERNS

    @property
    def name(self) -> str:
        return "mtproto"

    @property
    def display_name(self) -> str:
        return "Telegram MTProto"

    def get_keylog_format(self) -> str:
        return f"friTap MTProto Key Log Format v{spec.VERSION}"

    def get_wireshark_protocol_preference(self) -> str:
        # No Wireshark-native MTProto keylog preference exists.
        return ""

    def get_display_filter_template(self) -> str:
        # Wireshark has no built-in MTProto dissector; filter by endpoints only.
        return "ip.addr == {src} && ip.addr == {dst} && tcp.port == {port}"

    def keylog_formatter(self) -> Optional[KeylogFormatter]:
        return MtprotoKeylogFormatter()

    @property
    def supported_backends(self) -> dict[str, str]:
        return {BackendName.FRIDA: BackendSupport.FULL}

    def validate_cli_intent(self, parsed, parser, logger) -> None:
        """Log hints (never change flags): prefer spawn, and warn if the offline backend is missing."""
        # Offline decryption needs each TCP stream from its first 64 bytes;
        # attaching misses that init block on already-open connections.
        if not getattr(parsed, "spawn", False):
            memory_scan = bool(getattr(parsed, "memory_scan", False))
            logger.info(f"[mtproto] {attach_mode_hint(memory_scan)}")
        # Without a transport auth key an E2E key alone decrypts nothing.
        logger.info(
            "[mtproto] transport auth keys are captured by the spawn getAuthKey hook "
            "(-k) or -ms memory scan; without a transport auth key the obfuscated "
            "envelope can't be decrypted (an E2E-only keylog yields 0 flows)."
        )
        # Live capture needs no Python-side crypto; offline decryption does.
        from .mtproto_backend import MTPROTO_DEPENDENCY_HINT, mtproto_backend_available
        if not mtproto_backend_available():
            logger.warning(
                "[mtproto] %s  (live key capture works without it; that backend is "
                "needed to decrypt the captured pcap offline.)",
                MTPROTO_DEPENDENCY_HINT,
            )
