"""
Shared resource limits for analyzers.

Analyzer input is attacker-controlled (decrypted traffic, possibly malware),
so every analyzer bounds the work it does per body and the number of findings
it emits per flow. The constants and small helpers here are the single source
of truth for those bounds.
"""

from __future__ import annotations

import json
from typing import Any

from friTap.analysis import Finding, Severity

# Maximum number of body bytes scanned by text/regex detectors.
MAX_SCAN_BYTES = 1024 * 1024
# Bodies larger than this are not parsed as JSON at all.
MAX_JSON_BYTES = 1024 * 1024
# Maximum findings one analyzer may emit for a single flow.
MAX_FINDINGS_PER_FLOW = 200
# Maximum length of an attacker-controlled string embedded in a title/description.
MAX_DISPLAY_CHARS = 120

# Binary-sniffing window and threshold for free-text scans.
_BINARY_SNIFF_BYTES = 4096
_BINARY_NONPRINTABLE_RATIO = 0.30
# Media/compressed types whose bytes only yield regex noise for free-text PII
# scans. Protobuf, gRPC, octet-stream and unknown types are deliberately NOT
# listed: PII often sits in their string fields (DoS is bounded by the scan cap).
_NOISE_MEDIA_PREFIXES = ("image/", "video/", "audio/", "font/")
_NOISE_MEDIA_TYPES = frozenset({
    "application/zip", "application/gzip", "application/x-gzip",
    "application/zstd", "application/x-brotli", "application/pdf",
    "application/wasm", "application/x-7z-compressed", "application/x-tar",
})
_PRINTABLE_CONTROL_BYTES = frozenset({9, 10, 13})


def bounded_text(body: bytes | str, limit: int = MAX_SCAN_BYTES) -> str:
    """Return at most *limit* units of *body* as text (UTF-8, lossy)."""
    if isinstance(body, str):
        return body[:limit]
    return body[:limit].decode("utf-8", errors="replace")


def clip(value: Any, limit: int = MAX_DISPLAY_CHARS) -> str:
    """Coerce *value* to ``str`` and truncate it to *limit* chars (with '...')."""
    text = value if isinstance(value, str) else str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _is_noise_media_type(content_type: str) -> bool:
    """True for media/compressed content types (``image/*``, zip, pdf, ...)."""
    mime = (content_type or "").split(";", 1)[0].strip().lower()
    return mime.startswith(_NOISE_MEDIA_PREFIXES) or mime in _NOISE_MEDIA_TYPES


def _is_protobuf_like(data: bytes) -> bool:
    """Cheap protobuf sniff (the parser only inspects the first 512 bytes)."""
    from friTap.parsers.protobuf.wire import is_likely_protobuf
    try:
        return is_likely_protobuf(data)
    except Exception:  # noqa: BLE001 - a sniff must never break analysis
        return False


def looks_binary(data: bytes) -> bool:
    """True when more than 30% of the first 4 KiB are non-printable.

    Counted on the UTF-8 decoding so multi-byte text (non-ASCII languages)
    stays "printable" while invalid byte sequences count as binary.
    """
    window = data[:_BINARY_SNIFF_BYTES].decode("utf-8", errors="replace")
    if not window:
        return False
    nonprintable = sum(1 for ch in window if _is_nonprintable_char(ch))
    return nonprintable / len(window) > _BINARY_NONPRINTABLE_RATIO


def _is_nonprintable_char(ch: str) -> bool:
    code = ord(ch)
    if code == 0xFFFD:  # undecodable byte
        return True
    if code < 32:
        return code not in _PRINTABLE_CONTROL_BYTES
    return 0x7F <= code <= 0x9F


def is_binary_body(body: bytes, content_type: str = "") -> bool:
    """Decide whether *body* should be skipped by free-text detectors.

    Only media/compressed types are skipped when a content type is declared;
    every other declared type (text, protobuf, gRPC, octet-stream, unknown)
    stays in scope. Without a content type, a body is skipped only when it
    looks binary (>30% non-printable) and is not protobuf-like.
    """
    if not body:
        return False
    if content_type:
        return _is_noise_media_type(content_type)
    return looks_binary(body) and not _is_protobuf_like(body)


def safe_json_loads(data: bytes | str, max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Parse JSON defensively; return ``None`` when oversized or invalid.

    Catches ``RecursionError`` (deeply nested input) and ``ValueError`` (which
    covers ``JSONDecodeError`` and Python's int-string-length limit).
    """
    if len(data) > max_bytes:
        return None
    try:
        text = data if isinstance(data, str) else data.decode("utf-8", errors="replace")
        return json.loads(text)
    except (RecursionError, ValueError, TypeError):
        return None


def cap_findings(
    findings: list[Finding],
    source: str,
    flow_id: str = "",
    limit: int = MAX_FINDINGS_PER_FLOW,
) -> list[Finding]:
    """Keep the first *limit* findings and append one summary for the rest."""
    if len(findings) <= limit:
        return findings
    suppressed = len(findings) - limit
    summary = Finding(
        severity=Severity.INFO,
        title="Finding limit reached",
        description=(
            f"{suppressed} additional '{source}' findings for this flow were "
            f"suppressed (limit {limit} per flow)"
        ),
        source=source,
        flow_id=flow_id,
        confidence=1.0,
        evidence={"suppressed": suppressed, "limit": limit},
    )
    return findings[:limit] + [summary]


__all__ = [
    "MAX_SCAN_BYTES",
    "MAX_JSON_BYTES",
    "MAX_FINDINGS_PER_FLOW",
    "MAX_DISPLAY_CHARS",
    "bounded_text",
    "clip",
    "looks_binary",
    "is_binary_body",
    "safe_json_loads",
    "cap_findings",
]
