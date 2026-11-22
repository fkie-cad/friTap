"""Shared redaction primitives that make captured text safe to share.

* :func:`scrub_values` keeps URL structure and parameter keys but drops query,
  fragment and userinfo values, e-mail addresses and known raw values.
* :func:`scrub_key_material` replaces NSS keylog lines and long hex runs.
* :func:`redact_finding` masks pii/secret evidence and scrubs the text and
  evidence of every finding (IOC URL findings are ``network`` yet carry query values).

Reporters, the privacy/credentials analyzers and the digest all use these so
the rules cannot drift apart.
"""

from __future__ import annotations

import dataclasses
import re
from typing import TYPE_CHECKING, Any, Iterable

from friTap.offline.tls.keylog import TLS_KEYLOG_LABELS

if TYPE_CHECKING:
    from friTap.analysis import Finding

REDACTED = "<redacted>"
EMAIL_REDACTED = "<email>"

# Shorter raw values would mangle unrelated substrings in free text; they are
# still masked in evidence.
MIN_SCRUB_LEN = 5

# ``?k=v`` / ``&k=v`` / ``;k=v`` pairs in free text. Keys exclude every
# delimiter so runs never overlap (linear time). Values run to ``&``/``#``/
# whitespace, quotes included: over-masking a quote beats leaking ``d'Artagnan``.
_QUERY_PAIR_RE = re.compile(r"([?&;][^=\s&#?;]*)=([^&\s#]*)")
_QUERY_PAIR_STARTS = frozenset("?&;")
# Bounded (RFC 5321 sizes) against backtracking on attacker-controlled runs.
# ``*`` is excluded so an already-masked ``j****@example.com`` is not re-masked.
_EMAIL_IN_TEXT_RE = re.compile(
    r"[^@\s\"'<>()/?&=*]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}")
# ``scheme://user:pass@host``: the userinfo is a credential.
_USERINFO_RE = re.compile(r"(://)[^/\s@?#<>\"']{1,256}@")
# URL-looking tokens are scrubbed per token (no backtracking over untrusted URLs).
_TOKEN_RE = re.compile(r"\S+")
_URL_SEPARATORS = frozenset("/?=&")
# A whole path segment that is a long digit run (phone, PAN, IMEI, account).
# Dots are not separators, so IPv4 hosts and versions are kept.
_DIGIT_SEGMENT_RE = re.compile(r"^\+?\d[\d-]*\d$")
_MIN_SEGMENT_DIGITS = 7

# Long hex runs (>= 32 bytes) are the shape of TLS secrets / keylog values.
_LONG_HEX_RUN_RE = re.compile(r"[0-9a-fA-F]{64,}")
# A keylog line must never leak into shared output. Derived from the pipeline's
# label set so labels cannot drift; ``*_TRAFFIC_SECRET_0`` is generalised to
# every key-update generation.
_EXTRA_KEYLOG_LABELS = ("EARLY_EXPORTER_SECRET",)


def _keylog_label_alternation() -> str:
    labels = sorted(set(TLS_KEYLOG_LABELS) | set(_EXTRA_KEYLOG_LABELS), key=lambda s: (-len(s), s))
    return "|".join(re.escape(label).replace("_TRAFFIC_SECRET_0", r"_TRAFFIC_SECRET_\d+")
                    for label in labels)


_KEYLOG_LABEL_RE = re.compile(rf"\b({_keylog_label_alternation()})\b\s+\S+(\s+\S+)?")

UUID_VALUE_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
EMAIL_VALUE_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$")
JWT_VALUE_RE = re.compile(r"^eyJ[\w-]+\.[\w-]+\.[\w-]*$")
DIGITS_VALUE_RE = re.compile(r"^\d+$")
# Phone / card / IMEI / SSN / date-like digit runs inside free text.
DIGIT_RUN_IN_TEXT_RE = re.compile(r"\+?\d(?:[\s\-./]?\d){5,}")

# Headers describing protocol plumbing, never the user. The digest omits them
# from endpoint shapes; ``--flow`` shows their values verbatim.
PLUMBING_HEADERS = frozenset({
    "accept", "accept-encoding", "accept-language", "cache-control", "connection",
    "content-encoding", "content-length", "content-type", "host", "pragma", "te",
    "upgrade",
})


def _is_digit_segment(segment: str) -> bool:
    return (_DIGIT_SEGMENT_RE.match(segment) is not None
            and sum(ch.isdigit() for ch in segment) >= _MIN_SEGMENT_DIGITS)


def _scrub_url_token(token: str, placeholder: str) -> str:
    """Mask the ``#fragment`` and digit-run path segments of a URL-looking *token*."""
    head, sep, fragment = token.partition("#")
    if _URL_SEPARATORS.isdisjoint(head):
        return token
    path, qsep, query = head.partition("?")
    if "/" in path:
        path = "/".join(placeholder if _is_digit_segment(seg) else seg
                        for seg in path.split("/"))
    head = f"{path}{qsep}{query}"
    return f"{head}#{placeholder}" if sep and fragment else f"{head}{sep}"


def _mask_query_pair(match: re.Match, placeholder: str) -> str:
    return f"{match.group(1)}={placeholder}" if match.group(2) else match.group(0)


def scrub_values(
    text: str,
    *,
    placeholder: str = REDACTED,
    raw_values: Iterable[str] = (),
) -> str:
    """Mask values inside free text while keeping its structure and keys.

    Masks URL query values (``?email=<redacted>``), fragments, digit-run path
    segments (``/card/<redacted>``), userinfo and e-mail addresses (``<email>``),
    plus every string in *raw_values* of at least :data:`MIN_SCRUB_LEN` chars.
    """
    if not text:
        return text
    if "://" in text and "@" in text:
        text = _USERINFO_RE.sub(lambda m: f"{m.group(1)}{placeholder}@", text)
    if "/" in text or "#" in text:
        text = _TOKEN_RE.sub(lambda m: _scrub_url_token(m.group(0), placeholder), text)
    if "=" in text and not _QUERY_PAIR_STARTS.isdisjoint(text):
        text = _QUERY_PAIR_RE.sub(lambda m: _mask_query_pair(m, placeholder), text)
    if "@" in text:
        text = _EMAIL_IN_TEXT_RE.sub(EMAIL_REDACTED, text)
    for raw in sorted({r for r in raw_values if r and len(r) >= MIN_SCRUB_LEN},
                      key=len, reverse=True):
        text = text.replace(raw, placeholder)
    return text


def scrub_key_material(text: str) -> str:
    """Replace NSS keylog lines and long hex runs (possible secrets) in *text*."""
    text = _KEYLOG_LABEL_RE.sub("<keylog-redacted>", text)
    return _LONG_HEX_RUN_RE.sub(lambda m: f"<hex:{len(m.group(0)) // 2}B>", text)


# Categories whose evidence values are sensitive and masked by default.
SENSITIVE_CATEGORIES = frozenset({"pii", "secret"})

# Deny-by-default: for a pii/secret finding every string evidence value is
# masked unless its key is in this allowlist of purely descriptive context
# (never the matched content), so a new analyzer key is masked, not leaked.
# Safe keys are still scrubbed (``host`` may embed a URL).
SAFE_EVIDENCE_KEYS = frozenset({
    "location", "host", "type", "header", "field", "context", "content_type",
    "cwe", "scheme", "port", "algorithm", "pii_type", "pattern", "parameter",
    "method", "direction", "charset", "category", "id_type", "card_scheme",
    "status", "kty", "redacted", "redactable", "confidence", "length", "size",
    "entropy", "suppressed", "reasons", "locations", "issues",
})


def mask(value: str, keep: int = 4) -> str:
    """Mask a sensitive string, keeping only the first ``keep`` characters."""
    if len(value) <= keep:
        return "****"
    return value[:keep] + "****"


def _sensitive_raw_values(finding: "Finding") -> list[str]:
    """Raw non-safe evidence strings of a pii/secret finding; ``[]`` if already redacted or non-sensitive."""
    if finding.category not in SENSITIVE_CATEGORIES or finding.evidence.get("redacted"):
        return []
    return [val for key, val in finding.evidence.items()
            if key not in SAFE_EVIDENCE_KEYS and isinstance(val, str) and val]


def _mask_raw_in_text(text: str, raw_values: list[str]) -> str:
    """Replace each raw value (longest first, >= MIN_SCRUB_LEN) by its mask."""
    for raw in sorted(set(raw_values), key=len, reverse=True):
        if len(raw) >= MIN_SCRUB_LEN:
            text = text.replace(raw, mask(raw))
    return text


def _mask_sensitive_evidence(finding: "Finding") -> "Finding":
    """Mask non-safe evidence strings of a pii/secret finding and their echoes in title/description."""
    raw_values = _sensitive_raw_values(finding)
    if not raw_values:
        return finding
    evidence = dict(finding.evidence)
    for key, val in finding.evidence.items():
        if key not in SAFE_EVIDENCE_KEYS and isinstance(val, str) and val:
            evidence[key] = mask(val)
    evidence["redacted"] = True
    return dataclasses.replace(
        finding,
        title=_mask_raw_in_text(finding.title, raw_values),
        description=_mask_raw_in_text(finding.description, raw_values),
        evidence=evidence,
    )


def _scrub_nested(value: Any, placeholder: str) -> tuple[Any, bool]:
    """:func:`scrub_values` every string in a JSON-like value; returns ``(scrubbed, changed)``."""
    if isinstance(value, str):
        scrubbed = scrub_values(value, placeholder=placeholder)
        return scrubbed, scrubbed != value
    if isinstance(value, dict):
        out, changed = {}, False
        for key, item in value.items():
            out[key], item_changed = _scrub_nested(item, placeholder)
            changed = changed or item_changed
        return out, changed
    if isinstance(value, (list, tuple)):
        results = [_scrub_nested(item, placeholder) for item in value]
        return type(value)(item for item, _ in results), any(c for _, c in results)
    return value, False


def redact_title(finding: "Finding", *, placeholder: str = REDACTED) -> str:
    """The title :func:`redact_finding` would produce, cheaply (for clustering before full redaction)."""
    title = _mask_raw_in_text(finding.title, _sensitive_raw_values(finding))
    return scrub_values(title, placeholder=placeholder)


def redact_finding(finding: "Finding", *, placeholder: str = REDACTED) -> "Finding":
    """Return a share-safe copy of *finding* (egress-layer redaction).

    Analyzers keep full fidelity; every path serialising findings for users or
    agents calls this unless PII display was requested. pii/secret evidence is
    masked (:data:`SAFE_EVIDENCE_KEYS`), then title, description and evidence of
    every finding go through :func:`scrub_values`. Sets ``evidence["redacted"]``
    when evidence changed; an unchanged finding is returned as-is.
    """
    masked = _mask_sensitive_evidence(finding)
    title = scrub_values(masked.title, placeholder=placeholder)
    description = scrub_values(masked.description, placeholder=placeholder)
    evidence, evidence_changed = _scrub_nested(masked.evidence, placeholder)
    if evidence_changed:
        evidence["redacted"] = True
    elif title == masked.title and description == masked.description:
        return masked
    return dataclasses.replace(masked, title=title, description=description, evidence=evidence)


__all__ = [
    "REDACTED",
    "EMAIL_REDACTED",
    "MIN_SCRUB_LEN",
    "SENSITIVE_CATEGORIES",
    "SAFE_EVIDENCE_KEYS",
    "scrub_values",
    "scrub_key_material",
    "mask",
    "redact_finding",
    "redact_title",
    "UUID_VALUE_RE",
    "EMAIL_VALUE_RE",
    "JWT_VALUE_RE",
    "DIGITS_VALUE_RE",
    "DIGIT_RUN_IN_TEXT_RE",
    "PLUMBING_HEADERS",
]
