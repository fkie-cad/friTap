#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Telegram protocol handler (combined MTProto cloud + Secret-Chat E2E).

Unlike the bare :class:`~friTap.protocols.mtproto_handler.MTProtoHandler` (which
emits only cloud-chat ``MTPROTO_AUTH_KEY`` lines), the ``telegram`` protocol
writes BOTH key kinds into ONE combined keylog file:

  * ``MTPROTO_AUTH_KEY`` — cloud-chat transport auth keys (the offline MTProto
    decryptor matches a record's ``auth_key_id`` to its ``auth_key``).
  * ``MTPROTO_E2E_KEY``  — Secret-Chat (end-to-end) per-chat shared keys (the
    offline secret-chat decryptor matches a blob's ``key_fingerprint`` to its
    ``shared_key``).

Both labels coexist in the same file because the offline readers each ignore the
other's lines (``load_mtproto_keylog`` reads only auth-key lines,
``load_secret_chat_keylog`` reads only E2E lines). The line layouts are the
single source of truth in :mod:`friTap.protocols.mtproto_keylog_spec`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from .base import BackendSupport, ProtocolHandler
from . import mtproto_keylog_spec as spec
from .mtproto_handler import MTPROTO_LIBRARY_PATTERNS
from ..backends.base import BackendName
from ..output.keylog_format import KeylogFormatter

if TYPE_CHECKING:
    from ..events import KeylogEvent

# The MTProto networking-library hints plus the Telegram application package /
# native-library name fragments, so library auto-detection matches Telegram.
TELEGRAM_LIBRARY_PATTERNS = MTPROTO_LIBRARY_PATTERNS + [
    "libtmessages",
    "tmessages",
    "tgnet",
    "org.telegram",
]

HEADER_COMMENT = (
    f"# friTap Telegram keylog v{spec.VERSION} — combined MTProto cloud + "
    f"Secret-Chat E2E keys. Formats: "
    f"{spec.LABEL} <dc_id> <auth_key_id_hex16> <auth_key_hex512> <key_type> | "
    f"{spec.E2E_LABEL} <key_fingerprint_hex16> <shared_key_hex512> <chat_id>"
)


class TelegramKeylogFormatter(KeylogFormatter):
    """Formats Telegram key material into the combined MTProto/E2E keylog.

    Inspects each :class:`KeylogEvent` payload shape: a non-empty
    ``shared_key``/``key_fingerprint`` renders a Secret-Chat ``MTPROTO_E2E_KEY``
    line; otherwise the cloud-chat ``MTPROTO_AUTH_KEY`` line is rendered. Both
    line kinds are defined in :mod:`friTap.protocols.mtproto_keylog_spec`.
    """

    @property
    def protocol(self) -> str:
        return "telegram"

    def header_comment(self) -> Optional[str]:
        return HEADER_COMMENT

    def format(self, event: "KeylogEvent") -> List[str]:
        payload = event.payload or {}
        if payload.get("shared_key") or payload.get("key_fingerprint"):
            line = spec.format_e2e_line(
                key_fingerprint=str(payload.get("key_fingerprint", "")),
                shared_key=str(payload.get("shared_key", "")),
                chat_id=int(payload.get("chat_id", 0) or 0),
            )
        else:
            line = spec.format_line(
                dc_id=payload.get("dc_id", 0),
                auth_key_id=str(payload.get("auth_key_id", "")),
                auth_key=str(payload.get("auth_key", "")),
                key_type=str(payload.get("key_type", spec.KEY_TYPE_PERM)),
            )
        return [line] if line else []

    def dedup_key(self, event: "KeylogEvent") -> str:
        payload = event.payload or {}
        if payload.get("shared_key") or payload.get("key_fingerprint"):
            return f"e2e|{payload.get('key_fingerprint', '')}"
        return (
            f"cloud|{payload.get('auth_key_id', '')}|"
            f"{payload.get('key_type', spec.KEY_TYPE_PERM)}"
        )


class TelegramHandler(ProtocolHandler):
    """Handler for combined Telegram cloud + Secret-Chat key material."""

    library_patterns = TELEGRAM_LIBRARY_PATTERNS

    @property
    def name(self) -> str:
        return "telegram"

    @property
    def display_name(self) -> str:
        return "Telegram"

    def get_keylog_format(self) -> str:
        return f"friTap Telegram Key Log Format v{spec.VERSION}"

    def get_wireshark_protocol_preference(self) -> str:
        # No Wireshark-native MTProto/Telegram keylog preference exists; the
        # combined keylog is consumed by friTap's own offline decryptors.
        return ""

    def get_display_filter_template(self) -> str:
        # Wireshark has no built-in MTProto dissector; filter by endpoints only.
        return "ip.addr == {src} && ip.addr == {dst} && tcp.port == {port}"

    def keylog_formatter(self) -> Optional[KeylogFormatter]:
        return TelegramKeylogFormatter()

    @property
    def supported_backends(self) -> dict[str, str]:
        return {BackendName.FRIDA: BackendSupport.FULL}

    def validate_cli_intent(self, parsed, parser, logger) -> None:
        """Telegram needs the modern agent and an explicit capture intent.

        Moved here from the generic CLI parser so the public core stays
        protocol-agnostic. ``--protocol telegram`` auto-enables the modern path
        (legacy has no Telegram support); attach mode misses the obfuscated-
        transport init bytes so we nudge toward spawn; a bare invocation that
        would produce no output is rejected; and we warn early if the
        offline-decrypt backend is missing.
        """
        if not getattr(parsed, "use_modern", False):
            logger.info("[telegram] --protocol telegram auto-enables use_modern=true (legacy path has no Telegram support)")
            parsed.use_modern = True
        # Same byte-0 caveat as mtproto (cloud transport is the obfuscated MTProto):
        # attaching to a running Telegram misses the init block on already-open
        # connections, so those streams can't be decrypted offline. Nudge to spawn.
        if not getattr(parsed, "spawn", False):
            logger.info(
                "[telegram] attach mode: connections opened before capture can't be "
                "decrypted (obfuscated-transport init bytes are missed). Use -s (spawn) "
                "so every connection is captured from the start, or force-stop + relaunch "
                "the app before attaching."
            )
        # Require an explicit capture intent: -k extracts the combined Telegram
        # keys for offline decrypt, -p captures live plaintext, -f captures a raw
        # pcap for offline decrypt. Bare `--protocol telegram` would install hooks
        # that produce no output, so reject it with an actionable message.
        if not (parsed.keylog or parsed.pcap or parsed.full_capture):
            parser.error(
                "--protocol telegram requires a capture intent: -k (extract the "
                "combined MTProto cloud + Secret-Chat E2E keys for offline "
                "decryption) and/or -p (capture live plaintext); -f -p -k captures "
                "a raw pcap plus keys for offline decryption."
            )
        # Live capture only extracts keys/plaintext (no Python-side crypto), but
        # offline decryption of the resulting pcap does. Nudge the user early so
        # a later `--telegram-keylog` run does not surprise them.
        from ..offline.mtproto import MTPROTO_DEPENDENCY_HINT, mtproto_backend_available
        if not mtproto_backend_available():
            logger.warning(
                "[telegram] %s  (live key capture works without it; the extra is "
                "needed to decrypt the captured pcap offline.)",
                MTPROTO_DEPENDENCY_HINT,
            )
