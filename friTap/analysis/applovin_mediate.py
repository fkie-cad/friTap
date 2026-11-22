"""
AppLovinMediateAnalyzer — decrypt AppLovin MAX ``/1.0/mediate`` payloads.

The AppLovin MAX SDK wraps its ad-mediation request (device identifiers,
installed adapters, timing data, ...) in an app-layer cipher on top of TLS
(``POST ms4.applovin.com/1.0/mediate``). This analyzer finds such requests,
decrypts them with an :class:`AppLovinKeyring` (SDK key + salt from CLI flags,
``FRITAP_APPLOVIN_*`` environment variables or an app bundle) and reports the
plaintext JSON. Envelopes it cannot decrypt are still reported, with the reason
and protocol_id, so the user knows which key material to supply.

Cheap on captures without AppLovin traffic: a flow is only examined further
when its host/path names the mediate endpoint or the request carries a
base64 value that decodes to an envelope header.

Identifier values (IDFA, IDFV, ...) are masked unless ``reveal_pii=True``
(``fritap analyze --show-pii``), following the privacy analyzer's convention.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Iterable
from urllib.parse import unquote, urlsplit

from friTap.analysis import Finding, Severity
from friTap.analysis._json_walk import CONTAINER, FIELD, iter_json
from friTap.analysis.filtering import with_category
from friTap.analysis.redaction import mask
from friTap.parsers.app_ciphers.applovin_mediate import (
    MEDIATE_HOST_SUFFIX as MEDIATE_HOST_SUFFIX,
)
from friTap.parsers.app_ciphers.applovin_mediate import (
    MEDIATE_PATH_PREFIX as MEDIATE_PATH_PREFIX,
)
from friTap.parsers.app_ciphers.applovin_mediate import (
    is_mediate_request,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow
    from friTap.parsers.app_ciphers.applovin_keyring import AppLovinKeyring
    from friTap.parsers.app_ciphers.applovin_mediate import (
        DecryptResult,
        MediateEnvelope,
    )

TITLE_DECRYPTED = "AppLovin mediate payload decrypted"
TITLE_NOT_DECRYPTED = "AppLovin mediate envelope (not decrypted)"
MAX_JSON_EVIDENCE_CHARS = 64 * 1024
MAX_MASK_DEPTH = 64

SUMMARY_KEYS = (
    "idfa", "idfv", "api_did", "bt_ms_2", "revision", "os", "tm", "kb",
    "locale", "tz_offset",
)
SIGNAL_DATA_KEY = "signal_data"
# Keys whose values identify a device or user; masked unless reveal_pii.
IDENTIFIER_KEYS = frozenset({
    "idfa", "idfv", "api_did", "ifa", "gaid", "adid", "advertising_id",
    "android_id", "device_id", "user_id", "imei", "email", "phone",
})

# Envelope header "<digit>:<40 hex>:" (43 bytes) base64-encodes to ~58 chars;
# a p= value must be at least _HINT_CHARS long, and up to _HINT_WINDOW chars
# (room for %-escapes) are decoded to test it.
_HINT_CHARS = 64
_HINT_WINDOW = 96
_HINT_SCAN_CHARS = 8 * 1024
_URLSAFE_TO_STD = str.maketrans("-_", "+/")
_FORM_P_RE = re.compile(r"(?:^|&)p=([A-Za-z0-9+/_%%-]{%d,})" % _HINT_CHARS)


def _request_target(flow: "Flow") -> tuple[str, str, str]:
    """``(host, path, query)`` of the flow's request (lower-cased host)."""
    request = flow.request
    parts = urlsplit(request.url or "")
    host = request.host or parts.hostname or flow.display_host or ""
    return host.split(":")[0].lower(), parts.path, parts.query


# Alias of the parsers-layer predicate (used by tests).
is_mediate_target = is_mediate_request


def _decodes_to_envelope_head(text: str) -> bool:
    """True when the first base64 block of *text* decodes to an envelope header."""
    from friTap.parsers.app_ciphers.applovin_mediate import looks_like_envelope

    window = unquote(text[:_HINT_WINDOW]).translate(_URLSAFE_TO_STD)
    window = window[:len(window) - len(window) % 4]
    try:
        head = base64.b64decode(window, validate=True)
    except (binascii.Error, ValueError):
        return False
    return looks_like_envelope(head)


def has_envelope_hint(body: bytes, query: str) -> bool:
    """Cheap check: does a ``p=`` value or the body start like an envelope?"""
    body_text = body[:_HINT_SCAN_CHARS].decode("ascii", "ignore").strip()
    candidates = [m.group(1) for m in _FORM_P_RE.finditer(query)]
    candidates += [m.group(1) for m in _FORM_P_RE.finditer(body_text)]
    candidates.append(body_text[:_HINT_WINDOW])
    return any(len(c) >= _HINT_CHARS and _decodes_to_envelope_head(c) for c in candidates)


def find_mediate_envelope(flow: "Flow") -> "MediateEnvelope | None":
    """Parse the mediate envelope carried by *flow*'s request, if any.

    Shared by the analyzer, the HAR exporter and ``example/applovin_decrypt.py``.
    """
    if flow.request is None:
        return None
    from friTap.parsers.app_ciphers.applovin_mediate import (
        extract_envelope_payload,
        parse_envelope,
    )
    host, path, query = _request_target(flow)
    body = flow.get_decompressed_request_body()
    if not (is_mediate_request(host, path) or has_envelope_hint(body, query)):
        return None
    raw = extract_envelope_payload(body, query)
    if raw is None:
        return None
    try:
        return parse_envelope(raw)
    except ValueError:
        return None


# Backwards-compatible private name (pre-dates the public helper).
_find_envelope = find_mediate_envelope


def _mask_identifiers(obj: Any, depth: int = 0) -> Any:
    """Copy of JSON *obj* with identifier values masked (depth-bounded)."""
    if depth > MAX_MASK_DEPTH:
        return "<truncated>"
    if isinstance(obj, dict):
        return {k: _mask_value(k, v, depth) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_identifiers(item, depth + 1) for item in obj]
    return obj


def _mask_value(key: Any, value: Any, depth: int) -> Any:
    if isinstance(key, str) and key.lower() in IDENTIFIER_KEYS and isinstance(value, (str, int)):
        return mask(str(value))
    return _mask_identifiers(value, depth + 1)


def summarize_payload(payload: Any) -> dict[str, Any]:
    """Notable fields of a decrypted payload (first occurrence of each key)."""
    summary: dict[str, Any] = {}
    for node in iter_json(payload):
        if node.kind == FIELD and node.key in SUMMARY_KEYS:
            summary.setdefault(node.key, node.value)
        elif node.kind == CONTAINER and node.key == SIGNAL_DATA_KEY and isinstance(node.value, list):
            summary.setdefault("signal_data_adapters", len(node.value))
    return summary


def pretty_json(payload: Any, limit: int = MAX_JSON_EVIDENCE_CHARS) -> tuple[str, bool]:
    """Indented JSON text capped at *limit* chars; returns ``(text, truncated)``."""
    text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    return (text[:limit], True) if len(text) > limit else (text, False)


def _plaintext_text(result: "DecryptResult") -> Any:
    """The JSON payload, or the plaintext as text when it is not JSON."""
    if result.json is not None:
        return result.json
    return result.plaintext[:MAX_JSON_EVIDENCE_CHARS].decode("utf-8", "replace")


def variant_label(result: "DecryptResult") -> str:
    """Human-readable cipher variant, e.g. ``little/counter_plus_block``."""
    return f"{result.variant.dk_endianness}/{result.variant.block_input}"


_variant_label = variant_label


def _iso_utc(timestamp_ms: int) -> str:
    try:
        return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


class AppLovinMediateAnalyzer:
    """Decrypts AppLovin MAX /1.0/mediate app-layer payloads (needs SDK key + salt)."""

    name = "applovin_mediate"
    description = "Decrypts AppLovin MAX /1.0/mediate payloads (needs SDK key + salt)."

    def __init__(
        self,
        *,
        keyring: "AppLovinKeyring | None" = None,
        sdk_keys: Iterable[str] = (),
        salts_hex: Iterable[str] = (),
        bundle_paths: Iterable[str] = (),
        reveal_pii: bool = False,
    ) -> None:
        self._keyring = keyring
        self._sources = (tuple(sdk_keys), tuple(salts_hex), tuple(bundle_paths))
        self._reveal_pii = reveal_pii

    @property
    def keyring(self) -> "AppLovinKeyring":
        """The keyring, built lazily (bundles are only mined when needed)."""
        if self._keyring is None:
            from friTap.parsers.app_ciphers.applovin_keyring import AppLovinKeyring
            sdk_keys, salts_hex, bundle_paths = self._sources
            self._keyring = AppLovinKeyring.from_sources(sdk_keys, salts_hex, bundle_paths)
        return self._keyring

    def analyze_flow(self, flow: "Flow") -> list[Finding]:
        if flow.request is None:
            return []
        envelope = find_mediate_envelope(flow)
        if envelope is None:
            return []
        result, reason = self.keyring.try_decrypt(envelope)
        if result is None:
            return [self._not_decrypted(flow, envelope, reason)]
        return [self._decrypted(flow, envelope, result)]

    def _base_evidence(self, flow: "Flow", envelope: "MediateEnvelope") -> dict[str, Any]:
        host, path, _query = _request_target(flow)
        return {
            "host": host,
            "location": path,
            "protocol_id": envelope.protocol_id,
            "envelope_version": envelope.version,
        }

    def _decrypted(self, flow, envelope, result: "DecryptResult") -> Finding:
        payload = _plaintext_text(result)
        summary = summarize_payload(payload)
        if not self._reveal_pii:
            payload, summary = _mask_identifiers(payload), _mask_identifiers(summary)
        text, truncated = pretty_json(payload)
        evidence = {
            **self._base_evidence(flow, envelope),
            "timestamp_ms": result.timestamp_ms,
            "timestamp_utc": _iso_utc(result.timestamp_ms),
            "variant": _variant_label(result),
            "sdk_key_suffix_match": result.sdk_key_matches_suffix,
            "summary": summary,
            "decrypted_json": text,
            "truncated": truncated,
            "redacted": not self._reveal_pii,
        }
        finding = Finding(
            severity=Severity.LOW,
            title=TITLE_DECRYPTED,
            description=(
                f"Decrypted the AppLovin MAX mediate request to {flow.display_host} "
                f"({len(result.plaintext)} bytes of plaintext, fields: "
                f"{', '.join(sorted(summary)) or 'none of the notable ones'})."
            ),
            source=self.name,
            flow_id=flow.flow_id,
            confidence=1.0,
            evidence=evidence,
        )
        return with_category(finding, category="pii", extra_metadata={"app_cipher": "applovin_mediate"})

    def _not_decrypted(self, flow, envelope, reason: str) -> Finding:
        finding = Finding(
            severity=Severity.INFO,
            title=TITLE_NOT_DECRYPTED,
            description=(
                f"AppLovin MAX mediate envelope to {flow.display_host} could not be "
                f"decrypted: {reason}. protocol_id={envelope.protocol_id}"
            ),
            source=self.name,
            flow_id=flow.flow_id,
            confidence=0.9,
            evidence={**self._base_evidence(flow, envelope), "reason": reason},
        )
        return with_category(finding, category="protocol", extra_metadata={"app_cipher": "applovin_mediate"})


__all__ = [
    "AppLovinMediateAnalyzer",
    "TITLE_DECRYPTED",
    "TITLE_NOT_DECRYPTED",
    "find_mediate_envelope",
    "has_envelope_hint",
    "is_mediate_request",
    "is_mediate_target",
    "summarize_payload",
    "variant_label",
]
