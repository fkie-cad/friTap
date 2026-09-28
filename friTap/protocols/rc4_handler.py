#!/usr/bin/env python3

"""RC4 protocol handler.

RC4 is a FIRST-CLASS, INDEPENDENT friTap protocol: ``--protocol rc4`` captures
RC4 keys with no TLS hooks, and ``--protocol tls,rc4`` runs BOTH the TLS and the
RC4 hooks (the nested plaintext→RC4→TLS case). RC4 does NOT imply TLS and TLS
does not imply RC4 — the ``_ext/rc4.py`` registration passes no ``implies=``.

The agent (agent/rc4/) hooks the RC4 key-setup functions across platforms and
emits each recovered key on the generic private-key-material channel
(``classifier="rc4"``); the router forwards those fields verbatim to
:class:`Rc4KeylogFormatter`, which renders the ``RC4_KEY`` keylog line defined in
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

    Consumes the structured :class:`KeylogEvent` payload emitted by the agent
    (``key`` hex plus ``key_len``/``source``/``direction``/``assoc``) and renders
    the line defined in :mod:`friTap.protocols.rc4_keylog_spec`.
    """

    @property
    def protocol(self) -> str:
        return "rc4"

    def header_comment(self) -> Optional[str]:
        # friTap-owned format; the file is consumed by friTap's own offline RC4
        # decrypt (a later workstream), whose parser skips ``#`` lines.
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
        # A key is uniquely identified for dedup by its bytes plus the direction
        # and association hint (the same key may legitimately recur on distinct
        # threads / directions).
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
        # No Wireshark preference path; RC4 keys drive friTap's own offline decrypt.
        return ""

    def get_display_filter_template(self) -> str:
        return "ip.addr == {src} && ip.addr == {dst} && tcp.port == {port}"

    def keylog_formatter(self) -> Optional[KeylogFormatter]:
        return Rc4KeylogFormatter()

    @property
    def supported_backends(self) -> dict[str, str]:
        return {BackendName.FRIDA: BackendSupport.FULL}

    def validate_cli_intent(self, parsed, parser, logger) -> None:
        """RC4 needs an explicit capture intent.

        ``--protocol rc4`` requires a capture intent (``-k`` to extract RC4
        keys for offline decryption, ``-p`` live plaintext, or ``-f`` full
        capture), since bare ``--protocol rc4`` would install hooks that
        produce no output.
        """
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
