"""Canary known-value search: prove that a specific planted value leaks.

Unlike the generic PII / credential detectors, this answers "does this exact
value leave the device, and in what shape?". Each canary (email, advertising
id, GPS fix, free string, ...) is normalized, expanded into common obfuscations
(URL-encoding, base64, hex, md5/sha1/sha256) and searched in decoded request and
response traffic. Pure and offline: it only consumes captured :class:`Flow` objects.

Security / privacy contract (see ``AGENTS.md``):
  * Raw canary values are *never* logged or printed.
  * The matched span is held on the hit object but is only serialized when the
    caller explicitly opts in (``show_values=True`` in :func:`hit_to_row`).
  * Every string copied out of captured traffic (host, matched span) is pushed
    through :func:`safe_untrusted` and placed under an ``untrusted`` key.
  * Captured traffic is untrusted input: all scans are byte/length bounded.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterable
from urllib.parse import parse_qs, quote, quote_plus, urlparse

from friTap.analysis._digest_shapes import (
    MAX_HOST_CHARS,
    MAX_TEXT_CHARS,
    safe_untrusted,
)
from friTap.analysis._limits import MAX_SCAN_BYTES, bounded_text
from friTap.analysis.credentials import _shannon_entropy

if TYPE_CHECKING:
    from friTap.flow.models import Flow

#: Canary ``kind`` values understood by :func:`expand` (the canonical vocabulary).
CANARY_KINDS: frozenset[str] = frozenset(
    {"email", "phone", "aaid", "android_id", "imei", "gps", "ip", "free"}
)

#: Aliases -> canonical kind, mirroring the PII detector's names
#: (``privacy._AD_ID_KEYS`` and its geo vocabulary).
CANARY_KIND_ALIASES: dict[str, str] = {
    "advertising_id": "aaid",
    "idfa": "aaid",
    "gaid": "aaid",
    "adid": "aaid",
    "idfv": "aaid",
    "geo": "gps",
    "geolocation": "gps",
    "location": "gps",
}


def canonical_kind(kind: str) -> str:
    """Lower-case, strip and alias-resolve a canary *kind*; unknown values pass through (:func:`parse_canaries` coerces them to ``free``)."""
    kind = str(kind or "").strip().lower()
    return CANARY_KIND_ALIASES.get(kind, kind)

#: Confidence tiers, highest first (used for de-duplication ranking).
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

#: Kind of a canary given without one (bare-string shorthand, missing ``kind``).
DEFAULT_CANARY_KIND = "free"

#: Separator of the ``KIND=VALUE`` shorthand. ``=`` (not ``:``) so IPv6
#: addresses, URLs and ``host:port`` values never parse as a kind prefix.
CANARY_SHORTHAND_SEP = "="

#: Hard caps so a hostile or careless caller cannot cause an explosion.
MAX_CANARIES = 64
MAX_CANDIDATES_PER_CANARY = 512

#: Plaintext-confidence thresholds (short / low-entropy plaintext is noisy).
_MIN_UNIQUE_PLAINTEXT_LEN = 8
_LONG_PLAINTEXT_LEN = 12
_LOW_ENTROPY_THRESHOLD = 2.5
_HIGH_ENTROPY_THRESHOLD = 3.0

#: Shorter needles give rampant false positives (only truncated GPS approaches it).
_MIN_NEEDLE_LEN = 3

#: Context captured on either side of a match (held internally only).
_SPAN_CONTEXT = 16

#: GPS coordinates are commonly rounded; apps send 1..5 decimal places.
_GPS_PRECISIONS = (1, 2, 3, 4, 5)



@dataclass(frozen=True)
class Canary:
    """A known value to trace through traffic; ``warning`` is set for short or low-entropy values (false-positive prone)."""

    value: str
    kind: str
    label: str
    warning: str = ""


@dataclass(frozen=True)
class Candidate:
    """A needle derived from a canary; ``transform`` is ``plain``, ``base64``, ``sha256`` ...; ``confidence`` is high/medium/low."""

    needle: str
    transform: str
    confidence: str


@dataclass(frozen=True)
class CanaryHit:
    """One place a canary candidate was found; ``raw_span`` (match plus context) is not serialized by default, see :func:`hit_to_row`."""

    label: str
    kind: str
    transform: str
    confidence: str
    direction: str  # request | response
    where: str  # header | query | path | body
    host: str
    flow_id: str
    raw_span: str = field(repr=False, default="")



def _canary_warning(value: str) -> str:
    """Warning for a noisy plaintext canary, else ``""``."""
    if len(value) < _MIN_UNIQUE_PLAINTEXT_LEN:
        return "short plaintext canary (prone to false positives)"
    if _shannon_entropy(value) < _LOW_ENTROPY_THRESHOLD:
        return "low-entropy canary (prone to false positives)"
    return ""


def canary_spec_from_text(text: str, position: int) -> dict:
    """Expand the string shorthand into a ``{value, kind, label}`` spec.

    ``"KIND=VALUE"`` (aliases included) sets the kind; any other string, even
    one like ``token=abc`` with an unknown prefix, is a whole
    :data:`DEFAULT_CANARY_KIND` value. The label is ``<kind>-<position>`` so the
    value never appears in results.
    """
    prefix, sep, rest = text.partition(CANARY_SHORTHAND_SEP)
    kind = canonical_kind(prefix) if sep else ""
    if kind not in CANARY_KINDS or not rest.strip():
        kind, rest = DEFAULT_CANARY_KIND, text
    return {"value": rest, "kind": kind, "label": f"{kind}-{position}"}


def parse_canaries(specs: list[dict | str]) -> list[Canary]:
    """Validate raw specs (mapping with ``value``/``kind``/``label``, or the shorthand string) into :class:`Canary` objects.

    Empty ``value``/``label`` specs are dropped, kind goes through
    :func:`canonical_kind` (unknown becomes ``free``), the list is capped at
    :data:`MAX_CANARIES`, and noisy values are kept with :attr:`Canary.warning`.
    """
    canaries: list[Canary] = []
    for position, spec in enumerate(specs or [], start=1):
        if isinstance(spec, str):
            spec = canary_spec_from_text(spec, position)
        if not isinstance(spec, dict):
            continue
        value = str(spec.get("value", "")).strip()
        label = str(spec.get("label", "")).strip()
        if not value or not label:
            continue
        kind = canonical_kind(spec.get("kind", DEFAULT_CANARY_KIND))
        if kind not in CANARY_KINDS:
            kind = DEFAULT_CANARY_KIND
        canaries.append(Canary(value=value, kind=kind, label=label, warning=_canary_warning(value)))
        if len(canaries) >= MAX_CANARIES:
            break
    return canaries



def _ordered_unique(values: Iterable[str]) -> list[str]:
    """De-dup while preserving first-seen order, dropping empties."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _normalize_email(value: str) -> list[str]:
    """Lower/trim, plus a Gmail-style dot/``+tag``-stripped local-part variant."""
    base = value.strip().lower()
    variants = [base]
    local, sep, domain = base.partition("@")
    if sep:
        local = local.split("+", 1)[0].replace(".", "")
        if local:
            variants.append(f"{local}@{domain}")
    return _ordered_unique(variants)


def _normalize_phone(value: str) -> list[str]:
    """E.164 (``+`` plus digits) and the national digits-only form."""
    digits = "".join(ch for ch in value if ch.isdigit())
    if not digits:
        return _ordered_unique([value.strip()])
    return _ordered_unique([f"+{digits}", digits])


def _normalize_ad_id(value: str) -> list[str]:
    """Advertising id (AAID/IDFA): hyphenated-lower, non-hyphenated, uppercase."""
    lower = value.strip().lower()
    return _ordered_unique([lower, lower.replace("-", ""), value.strip().upper()])


def _normalize_android_id(value: str) -> list[str]:
    """Android id: canonical 16-hex lowercase."""
    return _ordered_unique([value.strip().lower()])


def _normalize_imei(value: str) -> list[str]:
    """IMEI: digits only."""
    return _ordered_unique(["".join(ch for ch in value if ch.isdigit())])


def _truncate_decimal(value: str, places: int) -> str:
    """Truncate (not round) a decimal string to *places* fractional digits."""
    sign = "-" if value.startswith("-") else ""
    body = value[1:] if sign else value
    if "." not in body:
        return value
    integer, frac = body.split(".", 1)
    frac = frac[:places]
    return f"{sign}{integer}.{frac}" if frac else f"{sign}{integer}"


def _normalize_gps(value: str) -> list[str]:
    """Emit the coordinate truncated to 1..5 decimals (apps round coords)."""
    base = value.strip()
    variants = [base] + [_truncate_decimal(base, places) for places in _GPS_PRECISIONS]
    return _ordered_unique(variants)


_NORMALIZERS = {
    "email": _normalize_email,
    "phone": _normalize_phone,
    "aaid": _normalize_ad_id,
    "android_id": _normalize_android_id,
    "imei": _normalize_imei,
    "gps": _normalize_gps,
}


def _normalize(value: str, kind: str) -> list[str]:
    """Return the normalized variants of *value* for *kind* (``ip``/``free`` as-is)."""
    normalizer = _NORMALIZERS.get(kind)
    if normalizer is None:
        return _ordered_unique([value.strip()])
    return normalizer(value)



def _plaintext_confidence(needle: str) -> str:
    """Confidence for a plaintext needle: long+unique is high, short/flat is low."""
    length = len(needle)
    if length < _MIN_UNIQUE_PLAINTEXT_LEN:
        return "low"
    entropy = _shannon_entropy(needle)
    if entropy < _LOW_ENTROPY_THRESHOLD:
        return "low"
    if length >= _LONG_PLAINTEXT_LEN and entropy >= _HIGH_ENTROPY_THRESHOLD:
        return "high"
    return "medium"


def _transforms(variant: str) -> list[tuple[str, str, str]]:
    """``(needle, transform, confidence)`` triples for one variant; hashes and encodings are always ``high``."""
    data = variant.encode("utf-8")
    standard_b64 = base64.b64encode(data).decode("ascii")
    urlsafe_b64 = base64.urlsafe_b64encode(data).decode("ascii")
    hex_lower = data.hex()
    return [
        (variant, "plain", _plaintext_confidence(variant)),
        (quote(variant, safe=""), "url", "high"),
        (quote_plus(variant), "url_plus", "high"),
        (standard_b64, "base64", "high"),
        (standard_b64.rstrip("="), "base64_nopad", "high"),
        (urlsafe_b64, "base64url", "high"),
        (urlsafe_b64.rstrip("="), "base64url_nopad", "high"),
        (hex_lower, "hex", "high"),
        (hex_lower.upper(), "hex_upper", "high"),
        (hashlib.md5(data, usedforsecurity=False).hexdigest(), "md5", "high"),
        (hashlib.sha1(data, usedforsecurity=False).hexdigest(), "sha1", "high"),
        (hashlib.sha256(data).hexdigest(), "sha256", "high"),
    ]


def expand(value: str, kind: str) -> list[Candidate]:
    """Expand a canary into :class:`Candidate` needles (normalize per *kind*, then every transform); duplicates keep the highest confidence."""
    best: dict[str, Candidate] = {}
    for variant in _normalize(value, kind):
        for needle, transform, confidence in _transforms(variant):
            if len(needle) < _MIN_NEEDLE_LEN:
                continue
            existing = best.get(needle)
            if existing is None or _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[existing.confidence]:
                best[needle] = Candidate(needle=needle, transform=transform, confidence=confidence)
            if len(best) >= MAX_CANDIDATES_PER_CANARY:
                break
    return list(best.values())



def _context_bounds(total: int, offset: int, length: int) -> tuple[int, int]:
    """Slice bounds for a match at ``[offset, offset+length)`` with context on each side."""
    return max(0, offset - _SPAN_CONTEXT), min(total, offset + length + _SPAN_CONTEXT)


def _window(text: str, index: int, length: int) -> str:
    """Return *text* around a match ``[index, index+length)`` with context."""
    start, end = _context_bounds(len(text), index, length)
    return text[start:end]


def _match_span(needle: str, text: str, data: bytes | None) -> str | None:
    """Matched span with context if *needle* is in the text, else in the raw bytes (finds hashes/hex/base64 inside binary or protobuf bodies)."""
    index = text.find(needle)
    if index != -1:
        return _window(text, index, len(needle))
    if data is not None:
        needle_bytes = needle.encode("utf-8", errors="ignore")
        if needle_bytes:
            offset = data.find(needle_bytes)
            if offset != -1:
                start, end = _context_bounds(len(data), offset, len(needle_bytes))
                return data[start:end].decode("utf-8", errors="replace")
    return None


@dataclass(frozen=True)
class _Location:
    """One searchable slice of a flow."""

    direction: str  # request | response
    where: str  # header | query | path | body
    text: str
    data: bytes | None = None


def _iter_locations(flow: "Flow") -> list[_Location]:
    """Collect every searchable location of *flow* (bounded by MAX_SCAN_BYTES)."""
    locations: list[_Location] = []
    request = flow.request
    response = flow.response

    if request is not None:
        for name, value in (request.headers or {}).items():
            if value:
                locations.append(_Location("request", "header", str(value)))
        if request.url:
            parsed = _safe_urlparse(request.url)
            if parsed is not None:
                if parsed.path:
                    locations.append(_Location("request", "path", parsed.path))
                if parsed.query:
                    locations.append(_Location("request", "query", parsed.query))
                    for values in _safe_parse_qs(parsed.query).values():
                        for value in values:
                            if value:
                                locations.append(_Location("request", "query", value))
        body = flow.get_decompressed_request_body()
        if body:
            locations.append(_Location("request", "body", bounded_text(body), body[:MAX_SCAN_BYTES]))

    if response is not None:
        for name, value in (response.headers or {}).items():
            if value:
                locations.append(_Location("response", "header", str(value)))
        body = flow.get_decompressed_response_body()
        if body:
            locations.append(_Location("response", "body", bounded_text(body), body[:MAX_SCAN_BYTES]))

    return locations


def _safe_urlparse(url: str):
    """urlparse that never raises on hostile input."""
    try:
        return urlparse(url)
    except ValueError:
        return None


def _safe_parse_qs(query: str) -> dict[str, list[str]]:
    """parse_qs that never raises on hostile input."""
    try:
        return parse_qs(query, keep_blank_values=True)
    except ValueError:
        return {}


def _hit_host(flow: "Flow") -> str:
    """Destination host only, never the request line.

    ``flow.display_host`` appends ``host/path?query``, which would echo a canary
    from the path/query into ``host`` even when redacted. Matched text belongs in
    ``raw_span`` (gated by ``show_values``); non-HTTP flows fall back to ``display_host``.
    """
    request = flow.request
    host = getattr(request, "host", "") if request is not None else ""
    return host or flow.display_host


def scan_flow(
    flow: "Flow",
    candidates_by_canary: dict[Canary, list[Candidate]],
) -> list[CanaryHit]:
    """Search one *flow* for every candidate, returning de-duplicated hits.

    Scans request + response headers, the URL path and query (raw and decoded)
    and decoded+decompressed bodies (as both text and raw bytes). A canary that
    appears in several candidate forms at one location yields one hit per
    ``(label, transform, confidence, direction, where)``.
    """
    locations = _iter_locations(flow)
    host = _hit_host(flow)
    flow_id = flow.flow_id
    hits: dict[tuple, CanaryHit] = {}

    for canary, candidates in candidates_by_canary.items():
        for candidate in candidates:
            needle = candidate.needle
            for location in locations:
                span = _match_span(needle, location.text, location.data)
                if span is None:
                    continue
                key = (
                    canary.label,
                    candidate.transform,
                    candidate.confidence,
                    location.direction,
                    location.where,
                )
                if key not in hits:
                    hits[key] = CanaryHit(
                        label=canary.label,
                        kind=canary.kind,
                        transform=candidate.transform,
                        confidence=candidate.confidence,
                        direction=location.direction,
                        where=location.where,
                        host=host,
                        flow_id=flow_id,
                        raw_span=span,
                    )
    return list(hits.values())


def build_candidates(canaries: list[Canary]) -> dict[Canary, list[Candidate]]:
    """Expand each canary once into its candidate needles."""
    return {canary: expand(canary.value, canary.kind) for canary in canaries}


def search_flows(
    flows: Iterable["Flow"],
    canaries: list[Canary],
) -> list[CanaryHit]:
    """Search *flows* for *canaries*, returning all hits across all flows."""
    candidates_by_canary = build_candidates(canaries)
    if not candidates_by_canary:
        return []
    hits: list[CanaryHit] = []
    for flow in flows:
        hits.extend(scan_flow(flow, candidates_by_canary))
    return hits



def hit_to_row(hit: CanaryHit, show_values: bool = False) -> dict:
    """Serialize a :class:`CanaryHit` into an output row.

    Traffic-derived strings (``host``, and the matched ``raw_span``) sit under
    an ``untrusted`` key and pass through :func:`safe_untrusted`. ``raw_span`` is
    included *only* when *show_values* is true; otherwise it is omitted entirely
    (not even a masked echo).
    """
    untrusted: dict[str, str] = {"host": safe_untrusted(hit.host, MAX_HOST_CHARS)}
    if show_values and hit.raw_span:
        untrusted["raw_span"] = safe_untrusted(hit.raw_span, MAX_TEXT_CHARS)
    return {
        "label": hit.label,
        "kind": hit.kind,
        "transform": hit.transform,
        "confidence": hit.confidence,
        "direction": hit.direction,
        "where": hit.where,
        "flow_id": hit.flow_id,
        "untrusted": untrusted,
    }


__all__ = [
    "CANARY_KINDS",
    "CANARY_KIND_ALIASES",
    "canonical_kind",
    "DEFAULT_CANARY_KIND",
    "CANARY_SHORTHAND_SEP",
    "MAX_CANARIES",
    "canary_spec_from_text",
    "Canary",
    "Candidate",
    "CanaryHit",
    "parse_canaries",
    "expand",
    "scan_flow",
    "search_flows",
    "build_candidates",
    "hit_to_row",
]
