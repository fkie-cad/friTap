#!/usr/bin/env python3

"""RC4 protocol handler.

RC4 is independent of TLS (``_ext/rc4.py`` passes no ``implies=``);
``--protocol tls,rc4`` runs both hook sets for nested plaintext->RC4->TLS.

The agent (agent/rc4/) emits each key on the private-key-material channel
(``classifier="rc4"``); the router forwards the fields to
:class:`Rc4KeylogFormatter`, which renders the ``RC4_KEY`` line from
:mod:`friTap.protocols.rc4_keylog_spec`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from ..backends.base import BackendName
from ..output.keylog_format import KeylogFormatter
from . import rc4_keylog_spec as spec
from .base import BackendSupport, ProtocolHandler

if TYPE_CHECKING:
    from ..events import KeylogEvent

# Libraries that carry an RC4 key-setup function friTap hooks (OpenSSL family,
# Nettle/GnuTLS, mbedTLS) plus the Windows crypto providers (CNG, legacy CAPI).
RC4_LIBRARY_PATTERNS = [
    "libcrypto", "libssl", "boringssl",
    "libnettle", "nettle",
    "libmbedcrypto", "mbedcrypto", "mbedtls",
    "bcrypt", "advapi32",
]


class Rc4KeylogFormatter(KeylogFormatter):
    """Formats recovered RC4 key material into the ``RC4_KEY`` keylog layout.

    Reads the payload fields ``key``, ``key_len``, ``source``, ``direction``,
    ``assoc`` and renders the line from :mod:`friTap.protocols.rc4_keylog_spec`.
    """

    @property
    def protocol(self) -> str:
        return "rc4"

    def header_comment(self) -> Optional[str]:
        return spec.HEADER_COMMENT

    def format(self, event: "KeylogEvent") -> List[str]:
        payload = event.payload or {}
        line = spec.format_line(
            key=str(payload.get("key", "")),
            key_len=payload.get("key_len"),
            source=str(payload.get("source", "")),
            direction=str(payload.get("direction", spec.DIR_UNKNOWN)),
            assoc=str(payload.get("assoc", "-")),
        )
        return [line] if line else []

    def dedup_key(self, event: "KeylogEvent") -> str:
        payload = event.payload or {}
        # The same key bytes may recur on distinct directions/threads.
        return (
            f"{str(payload.get('key', '')).lower()}"
            f"|{payload.get('direction', '')}"
            f"|{payload.get('assoc', '')}"
        )


class RC4Handler(ProtocolHandler):
    """Handler for RC4 protocol key material."""

    library_patterns = RC4_LIBRARY_PATTERNS

    @property
    def name(self) -> str:
        return "rc4"

    @property
    def display_name(self) -> str:
        return "RC4"

    @property
    def category(self) -> str:
        # Custom encryption routine: grouped under `--protocol custom`.
        return "custom_cipher"

    @property
    def description(self) -> str:
        return "RC4 stream cipher key extraction"

    def get_keylog_format(self) -> str:
        return f"friTap RC4 Key Log Format v{spec.VERSION}"

    def get_wireshark_protocol_preference(self) -> str:
        # No Wireshark preference; friTap's own offline decrypt reads RC4 keys.
        return ""

    def get_display_filter_template(self) -> str:
        return "ip.addr == {src} && ip.addr == {dst} && tcp.port == {port}"

    def keylog_formatter(self) -> Optional[KeylogFormatter]:
        return Rc4KeylogFormatter()

    @property
    def supported_backends(self) -> dict[str, str]:
        return {BackendName.FRIDA: BackendSupport.FULL}

    def validate_cli_intent(self, parsed, parser, logger) -> None:
        """Require ``-k``, ``-p`` or ``-f``; bare ``--protocol rc4`` produces no output."""
        if not (
            getattr(parsed, "keylog", False)
            or getattr(parsed, "pcap", False)
            or getattr(parsed, "full_capture", False)
        ):
            parser.error(
                "--protocol rc4 requires a capture intent: -k (extract RC4 keys "
                "for offline decryption) and/or -p (capture live plaintext); "
                "-f -p -k captures a raw pcap plus keys for offline decryption."
            )
