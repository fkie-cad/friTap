#!/usr/bin/env python3

"""Telegram MTProto protocol handler.

Mirrors the SSH handler. The keylog carries Telegram auth keys (and, for PFS,
the ephemeral temp keys actually used on the wire) so the offline MTProto
decryptor can match a captured record's ``auth_key_id`` to its ``auth_key``.
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

    def validate_cli_intent(self, parsed, parser, logger) -> None:
        """Nudge MTProto captures toward spawn and warn on a missing backend.

        Attach mode misses the obfuscated-transport init bytes
        so we nudge toward spawn; and we warn early if the offline-decrypt
        backend is missing.
        """
        # MTProto's obfuscated transport can only be decrypted offline when each
        # TCP stream is captured from its first 64 bytes. Attaching to an already
        # running Telegram misses that init block on connections opened earlier
        # (they come back "degraded" and decrypt to nothing), so nudge toward spawn.
        if not getattr(parsed, "spawn", False):
            memory_scan = bool(getattr(parsed, "memory_scan", False))
            logger.info(f"[mtproto] {attach_mode_hint(memory_scan)}")
        # Offline decryption needs the transport auth key for every stream: friTap
        # captures it via the spawn getAuthKey hook (-k) or an -ms memory scan.
        # Without it the transport envelope can't be opened, so a secret-chat (E2E)
        # key alone decrypts nothing. Emit only — never touch the user's flags.
        logger.info(
            "[mtproto] transport auth keys are captured by the spawn getAuthKey hook "
            "(-k) or -ms memory scan; without a transport auth key the obfuscated "
            "envelope can't be decrypted (an E2E-only keylog yields 0 flows)."
        )
        # Live capture only needs to extract keys/plaintext (no Python-side crypto),
        # but offline decryption of the resulting pcap does. Nudge the user early so
        # a later `--mtproto-keylog` run does not surprise them.
        from ..offline.mtproto import MTPROTO_DEPENDENCY_HINT, mtproto_backend_available
        if not mtproto_backend_available():
            logger.warning(
                "[mtproto] %s  (live key capture works without it; that backend is "
                "needed to decrypt the captured pcap offline.)",
                MTPROTO_DEPENDENCY_HINT,
            )
