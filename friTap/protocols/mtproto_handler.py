#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Telegram MTProto protocol handler.

Mirrors the SSH handler. The keylog carries Telegram auth keys (and, for PFS,
the ephemeral temp keys actually used on the wire) so the offline MTProto
decryptor can match a captured record's ``auth_key_id`` to its ``auth_key``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from .base import BackendSupport, ProtocolHandler
from . import mtproto_keylog_spec as spec
from ..backends.base import BackendName
from ..output.keylog_format import KeylogFormatter

if TYPE_CHECKING:
    from ..events import KeylogEvent

# Native Telegram networking library (tgnet) and adjacent name fragments.
MTPROTO_LIBRARY_PATTERNS = ["libtmessages", "tmessages", "tgnet"]


class MtprotoKeylogFormatter(KeylogFormatter):
    """Formats Telegram auth keys into the canonical friTap MTProto keylog.

    Consumes a structured :class:`KeylogEvent` payload
    (``auth_key_id``, ``auth_key``, ``dc_id``, ``key_type``) and renders the
    line defined in :mod:`friTap.protocols.mtproto_keylog_spec`. There is no
    Wireshark-native MTProto dissector, so this file is consumed by friTap's
    own offline decryptor (``--mtproto-keylog``).
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
