"""AppLovin MAX ``/1.0/mediate`` decoder for the app-cipher registry.

Matches ``*.applovin.com/1.0/mediate...`` requests by host/path only, then
extracts the envelope (``p=`` query/form value or raw base64 body) and
decrypts it with an :class:`AppLovinKeyring`. The keyring is built lazily on
the first matching request (``FRITAP_APPLOVIN_*`` environment variables) and
reused afterwards, so bundle mining happens at most once per session.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable

from friTap.parsers.app_ciphers.applovin_keyring import (
    ENV_BUNDLE,
    ENV_SALT,
    ENV_SDK_KEY,
    AppLovinKeyring,
)
from friTap.parsers.app_ciphers.applovin_mediate import (
    MEDIATE_HOST_SUFFIX,
    MEDIATE_PATH_PREFIX,
    extract_envelope_payload,
    is_mediate_request,
    parse_envelope,
)
from friTap.parsers.app_ciphers.registry import DecodedView

if TYPE_CHECKING:
    from friTap.parsers.app_ciphers.applovin_mediate import DecryptResult, MediateEnvelope

TITLE = "AppLovin (decrypted)"
REASON_NO_ENVELOPE = "no AppLovin mediate envelope found in the request"
KEY_MATERIAL_HINT = f"set {ENV_SDK_KEY} + {ENV_SALT}, or {ENV_BUNDLE}"


# Backward-compatible alias; the predicate lives in applovin_mediate.
is_mediate_target = is_mediate_request


def _utc_iso(timestamp_ms: int) -> str:
    try:
        return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return str(timestamp_ms)


def _plaintext_text(result: "DecryptResult") -> str:
    """Pretty JSON when the plaintext parsed as JSON, else the text itself."""
    if result.json is not None:
        return json.dumps(result.json, indent=2, ensure_ascii=False, default=str)
    return result.plaintext.decode("utf-8", "replace")


class AppLovinMediateDecoder:
    """Decrypts AppLovin MAX mediate request envelopes for display."""

    title = TITLE

    def __init__(self, keyring_factory: Callable[[], AppLovinKeyring] = AppLovinKeyring.from_sources):
        self._keyring_factory = keyring_factory
        self._keyring: AppLovinKeyring | None = None

    @property
    def keyring(self) -> AppLovinKeyring:
        """The keyring, built on first use and cached."""
        if self._keyring is None:
            self._keyring = self._keyring_factory()
        return self._keyring

    def matches(self, host: str, path: str, query: str, body: bytes) -> bool:
        return is_mediate_request(host, path)

    def decode(self, host: str, path: str, query: str, body: bytes) -> DecodedView | None:
        envelope = self._envelope(body, query)
        if envelope is None:
            return DecodedView(title=TITLE, reason=REASON_NO_ENVELOPE)
        result, reason = self.keyring.try_decrypt(envelope)
        if result is None:
            return self._failure_view(envelope, reason)
        return self._success_view(envelope, result)

    @staticmethod
    def _envelope(body: bytes, query: str) -> "MediateEnvelope | None":
        raw = extract_envelope_payload(body, query)
        if raw is None:
            return None
        try:
            return parse_envelope(raw)
        except ValueError:
            return None

    def _failure_view(self, envelope: "MediateEnvelope", reason: str) -> DecodedView:
        notes = [f"protocol_id: {envelope.protocol_id}",
                 f"sdk_key suffix: {envelope.sdk_key_suffix}"]
        # The failure reason already names the CLI flags and env vars, so no
        # separate KEY_MATERIAL_HINT note is added here.
        return DecodedView(title=TITLE, reason=reason, notes=tuple(notes))

    @staticmethod
    def _success_view(envelope: "MediateEnvelope", result: "DecryptResult") -> DecodedView:
        notes = (
            f"timestamp: {_utc_iso(result.timestamp_ms)}",
            f"variant: {result.variant.dk_endianness}/{result.variant.block_input}",
            f"protocol_id: {envelope.protocol_id}",
            f"plaintext: {len(result.plaintext)} bytes"
            + ("" if result.json is not None else " (not JSON)"),
        )
        return DecodedView(title=TITLE, text=_plaintext_text(result), ok=True, notes=notes)


__all__ = [
    "AppLovinMediateDecoder", "is_mediate_request", "is_mediate_target",
    "MEDIATE_HOST_SUFFIX", "MEDIATE_PATH_PREFIX", "TITLE",
]
