"""
Value-shape, path-templating and untrusted-string helpers for the capture digest.

Everything here turns attacker-controlled traffic into a *bounded*, value-free
description: a URL path becomes a template (``/users/{id}``), a JSON body
becomes a list of ``key:shape`` strings (``email:str(email-like)``) and every
string that is copied out of the payload is control-char escaped, scrubbed of
long hex runs (possible key material) and length-capped. The scrubbing rules
themselves live in :mod:`friTap.analysis.redaction` (shared with the reporters).

Used by :mod:`friTap.analysis.digest`; kept separate so the shape rules can be
unit-tested and extended without touching the digest assembly.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from friTap.analysis._json_walk import FIELD, iter_json
from friTap.analysis._limits import safe_json_loads
from friTap.analysis.redaction import DIGITS_VALUE_RE as _DIGITS_RE
from friTap.analysis.redaction import EMAIL_VALUE_RE as _EMAIL_RE
from friTap.analysis.redaction import JWT_VALUE_RE as _JWT_RE
from friTap.analysis.redaction import PLUMBING_HEADERS, scrub_key_material
from friTap.analysis.redaction import UUID_VALUE_RE as _UUID_RE
from friTap.analysis.reporters import _sanitize_text

# Caps for strings copied out of captured traffic (prompt-injection surface).
MAX_HOST_CHARS = 80
MAX_PATH_CHARS = 120
MAX_KEY_CHARS = 48
MAX_TEXT_CHARS = 120
MAX_KEYS_PER_LOCATION = 20

# Bounds on how much JSON a single body may contribute.
_MAX_BODY_JSON_BYTES = 256 * 1024
_MAX_JSON_NODES = 2_000
_MAX_JSON_DEPTH = 6

ID_PLACEHOLDER = "{id}"

_HEX_RE = re.compile(r"^(0x)?[0-9a-f]{8,}$", re.I)
_OPAQUE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-=.~%]{24,}$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_PHONE_RE = re.compile(r"^\+?[\d\s\-()]{7,20}$")
_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")
_FLOAT_RE = re.compile(r"^-?\d+\.\d+$")
_AUTH_SCHEME_RE = re.compile(r"^(bearer|basic|token|digest|negotiate)\s+\S+", re.I)

# Headers that carry no app-specific signal; omitted to save tokens.
_BORING_HEADERS = PLUMBING_HEADERS | frozenset({
    "upgrade-insecure-requests", "priority", "dnt", "keep-alive", "origin",
    "referer", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "if-none-match",
    "if-modified-since", "range", "dpr", "viewport-width",
})


def safe_untrusted(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    """Return a single-line, scrubbed, length-capped copy of a payload string."""
    text = scrub_key_material(_sanitize_text(value, single_line=True))
    if len(text) > limit:
        return text[: max(limit - 1, 0)] + "…"
    return text


def _is_id_segment(segment: str) -> bool:
    """True when a path segment looks like an identifier rather than a route word."""
    if not segment:
        return False
    if _DIGITS_RE.match(segment) or _UUID_RE.match(segment):
        return True
    if _HEX_RE.match(segment) and any(ch.isdigit() for ch in segment):
        return True
    has_digit = any(ch.isdigit() for ch in segment)
    has_alpha = any(ch.isalpha() for ch in segment)
    return bool(_OPAQUE_TOKEN_RE.match(segment) and has_digit and has_alpha)


def split_url(url: str) -> tuple[str, str]:
    """Split *url* (absolute or origin-form) into ``(path, query)``."""
    if not url:
        return "", ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.split("?", 1)[0], ""
    path = parts.path if (parts.scheme or url.startswith("/")) else url.split("?", 1)[0]
    return path, parts.query


def template_path(path: str) -> str:
    """Collapse numeric / uuid / hex / opaque-token path segments to ``{id}``."""
    if not path:
        return ""
    segments = path.split("/")
    templated = [ID_PLACEHOLDER if _is_id_segment(seg) else seg for seg in segments]
    return safe_untrusted("/".join(templated), MAX_PATH_CHARS)


def _string_shape(value: str) -> str:
    """Classify a string value by shape without revealing it."""
    stripped = value.strip()
    if not stripped:
        return "str(empty)"
    auth = _AUTH_SCHEME_RE.match(stripped)
    if auth:
        return f"str({auth.group(1).lower()}-auth)"
    for label, pattern in _STRING_SHAPES:
        if pattern.match(stripped):
            return f"str({label})"
    if _HEX_RE.match(stripped):
        return f"str(hex{len(stripped)})"
    if _B64_RE.match(stripped) and any(ch.isdigit() for ch in stripped):
        return "str(token)"
    return "str"


# Ordered: the first matching label wins.
_STRING_SHAPES: tuple[tuple[str, re.Pattern], ...] = (
    ("email-like", _EMAIL_RE),
    ("jwt", _JWT_RE),
    ("uuid", _UUID_RE),
    ("url", _URL_RE),
    ("ipv4", _IPV4_RE),
    ("num", _DIGITS_RE),
    ("float", _FLOAT_RE),
    ("phone-like", _PHONE_RE),
)


def value_shape(value: object) -> str:
    """Return a short type/shape label for *value* (never the value itself)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, (bytes, bytearray)):
        return "bytes"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "obj"
    return _string_shape(str(value))


def _key_entry(key: str, shape: str) -> str:
    return f"{safe_untrusted(key, MAX_KEY_CHARS)}:{shape}"


def _dedupe_capped(entries: list[str]) -> list[str]:
    """Order-preserving dedupe, sorted for a stable cluster signature, capped."""
    unique = sorted(set(entries))
    if len(unique) > MAX_KEYS_PER_LOCATION:
        extra = len(unique) - MAX_KEYS_PER_LOCATION
        return unique[:MAX_KEYS_PER_LOCATION] + [f"+{extra} more"]
    return unique


def pairs_shapes(pairs: list[tuple[str, str]]) -> list[str]:
    """Shape a list of ``(key, value)`` pairs (query string / form body)."""
    return _dedupe_capped([_key_entry(k, value_shape(v)) for k, v in pairs])


def query_shapes(query: str) -> list[str]:
    """Return ``key:shape`` entries for a URL query string."""
    if not query:
        return []
    try:
        return pairs_shapes(parse_qsl(query, keep_blank_values=True))
    except ValueError:
        return []


def _normalize_json_path(path: str) -> str:
    """Collapse list indices (``items[3].id`` -> ``items[].id``)."""
    return re.sub(r"\[\d+\]", "[]", path)


def json_shapes(root: object) -> list[str]:
    """Return ``dotted.key:shape`` entries for a parsed JSON document."""
    entries = [
        _key_entry(_normalize_json_path(node.path), value_shape(node.value))
        for node in iter_json(root, max_depth=_MAX_JSON_DEPTH, max_nodes=_MAX_JSON_NODES)
        if node.kind == FIELD
    ]
    return _dedupe_capped(entries)


def header_shapes(headers: dict) -> list[str]:
    """Return ``name:shape`` entries for the app-specific request headers."""
    entries = []
    for name, value in (headers or {}).items():
        lname = str(name).lower()
        if lname.startswith(":") or lname in _BORING_HEADERS:
            continue
        entries.append(_key_entry(lname, value_shape(value)))
    return _dedupe_capped(entries)


def classify_body(body: bytes, content_type: str) -> tuple[str, list[str]]:
    """Return ``(body_kind, key_shapes)`` for a request body.

    ``body_kind`` is one of ``""`` (no body), ``json``, ``form``, ``grpc``,
    ``protobuf``, ``multipart``, ``text`` or ``binary``.
    """
    if not body:
        return "", []
    ctype = (content_type or "").lower()
    if "grpc" in ctype:
        return "grpc", []
    if "protobuf" in ctype:
        return "protobuf", []
    if "multipart" in ctype:
        return "multipart", []
    if "x-www-form-urlencoded" in ctype:
        text = body[:_MAX_BODY_JSON_BYTES].decode("utf-8", errors="replace")
        return "form", query_shapes(text)
    if "json" in ctype or body[:1] in (b"{", b"["):
        parsed = safe_json_loads(body, max_bytes=_MAX_BODY_JSON_BYTES)
        if isinstance(parsed, (dict, list)):
            return "json", json_shapes(parsed)
    return ("text" if ctype.startswith("text/") else "binary"), []


__all__ = [
    "ID_PLACEHOLDER",
    "MAX_HOST_CHARS",
    "MAX_PATH_CHARS",
    "MAX_TEXT_CHARS",
    "safe_untrusted",
    "split_url",
    "template_path",
    "value_shape",
    "pairs_shapes",
    "query_shapes",
    "json_shapes",
    "header_shapes",
    "classify_body",
]
