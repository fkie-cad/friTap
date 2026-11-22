#!/usr/bin/env python3

"""Telegram protocol handler (combined MTProto cloud + Secret-Chat E2E).

Unlike :class:`~friTap.protocols.mtproto_handler.MTProtoHandler` (cloud-chat
``MTPROTO_AUTH_KEY`` only), this writes both kinds into one keylog:

  * ``MTPROTO_AUTH_KEY``: cloud-chat transport auth keys.
  * ``MTPROTO_E2E_KEY``: Secret-Chat per-chat shared keys.

The offline readers (``load_mtproto_keylog``, ``load_secret_chat_keylog``) each
ignore the other label. Line layouts: :mod:`friTap.protocols.mtproto_keylog_spec`.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, List, Optional

from .._warn_once import warn_once
from ..backends.base import BackendName
from ..output.keylog_format import KeylogFormatter
from . import mtproto_keylog_spec as spec
from .base import BackendSupport, ProtocolHandler
from .mtproto_handler import MTPROTO_LIBRARY_PATTERNS
from .mtproto_hints import attach_mode_hint

if TYPE_CHECKING:
    from ..events import KeylogEvent

logger = logging.getLogger(__name__)

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

# Secret-Chat ids are signed 64-bit; the agent is untrusted, so chat_id is validated.
_INT64_MIN = -(2 ** 63)
_INT64_MAX = 2 ** 63 - 1
# Optional ``-`` plus at most 19 digits (int64 max); the cap keeps int() away from huge strings.
_DECIMAL_CHAT_ID_RE = re.compile(r"-?[0-9]{1,19}")
_UNKNOWN_CHAT_ID = 0

def _parse_chat_id(value) -> Optional[int]:
    """*value* (``int`` or decimal ``str``) as an int64 chat id, else ``None``. Never raises."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        if not _DECIMAL_CHAT_ID_RE.fullmatch(value):
            return None
        value = int(value)
    if not isinstance(value, int):
        return None
    return value if _INT64_MIN <= value <= _INT64_MAX else None


def _warn_invalid_chat_id_once(value) -> None:
    """Log the first invalid agent ``chat_id``; later ones are not logged."""
    warn_once(
        logger, "telegram:invalid_chat_id",
        "Ignoring invalid Secret-Chat chat_id from the agent (%s); the key is "
        "recorded with chat_id %d. Further invalid chat_ids are not logged",
        type(value).__name__, _UNKNOWN_CHAT_ID)


def _chat_id_from(payload: dict) -> int:
    """The validated ``chat_id`` of an E2E *payload*; unknown/invalid -> 0."""
    raw = payload.get("chat_id", _UNKNOWN_CHAT_ID)
    if not raw:
        return _UNKNOWN_CHAT_ID
    chat_id = _parse_chat_id(raw)
    if chat_id is None:
        _warn_invalid_chat_id_once(raw)
        return _UNKNOWN_CHAT_ID
    return chat_id


class TelegramKeylogFormatter(KeylogFormatter):
    """Formats Telegram keys into the combined MTProto/E2E keylog.

    A payload with ``shared_key``/``key_fingerprint`` renders ``MTPROTO_E2E_KEY``;
    otherwise ``MTPROTO_AUTH_KEY`` (see :mod:`friTap.protocols.mtproto_keylog_spec`).
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
                chat_id=_chat_id_from(payload),
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
        # No Wireshark preference; friTap's offline decryptors read the keylog.
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
        """Hint toward spawn, require -k/-p/-f, and warn if the offline backend is missing."""
        # Same byte-0 caveat as mtproto: attach misses the init block of open connections.
        if not getattr(parsed, "spawn", False):
            memory_scan = bool(getattr(parsed, "memory_scan", False))
            logger.info(f"[telegram] {attach_mode_hint(memory_scan)}")
        # Without a transport auth key an E2E key alone decrypts nothing.
        logger.info(
            "[telegram] transport auth keys are captured by the spawn getAuthKey hook "
            "(-k) or -ms memory scan; without a transport auth key the obfuscated "
            "envelope can't be decrypted (an E2E-only keylog yields 0 flows)."
        )
        # Bare `--protocol telegram` would install hooks that produce no output.
        if not (parsed.keylog or parsed.pcap or parsed.full_capture):
            parser.error(
                "--protocol telegram requires a capture intent: -k (extract the "
                "combined MTProto cloud + Secret-Chat E2E keys for offline "
                "decryption) and/or -p (capture live plaintext); -f -p -k captures "
                "a raw pcap plus keys for offline decryption."
            )
        # Live capture needs no Python-side crypto; offline decryption does.
        from .mtproto_backend import MTPROTO_DEPENDENCY_HINT, mtproto_backend_available
        if not mtproto_backend_available():
            logger.warning(
                "[telegram] %s  (live key capture works without it; the extra is "
                "needed to decrypt the captured pcap offline.)",
                MTPROTO_DEPENDENCY_HINT,
            )
