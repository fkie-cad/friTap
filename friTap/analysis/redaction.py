"""
Shared redaction primitives for presenting analysis output.

Analyzer findings and the capture digest both copy text out of captured
traffic: request URLs (query strings, fragments, userinfo), e-mail addresses,
header values and, occasionally, key material. This module is the single place
that decides how such text is made safe to share:

* :func:`scrub_values` keeps URL structure and parameter *keys* but drops
  query / fragment / userinfo *values*, e-mail addresses and any known raw
  values (``api.example.com/signup?email=<redacted>``).
* :func:`scrub_key_material` replaces NSS keylog lines and long hex runs.
* :func:`redact_finding` is the reporter-layer redaction of a
  :class:`~friTap.analysis.Finding`: it masks sensitive (pii/secret) evidence
  values and scrubs the text and evidence of *every* finding, whatever its
  category (IOC URL findings are ``network`` but still carry query values).

Used by the reporters (``fritap analyze`` and its findings sidecar), the
privacy and credentials analyzers (their own descriptions) and the digest
(``fritap report``), so the rules cannot drift apart.
"""

from __future__ import annotations

import dataclasses
import re
from typing import TYPE_CHECKING, Any, Iterable

from friTap.pipeline import TLS_KEYLOG_LABELS

if TYPE_CHECKING:
    from friTap.analysis import Finding

REDACTED = "<redacted>"
EMAIL_REDACTED = "<email>"

# Raw values shorter than this are not scrubbed out of free text — a 1-4 char
# value would mangle unrelated substrings. Such values are still masked in
# evidence.
MIN_SCRUB_LEN = 5

# ``?key=value`` / ``&key=value`` / ``;key=value`` pairs embedded in free text.
# Keys exclude every pair delimiter, so key runs never overlap (linear time,
# any key length). Values run to the next ``&``/``#``/whitespace — quotes
# included: over-masking a closing quote beats leaking ``d'Artagnan``.
_QUERY_PAIR_RE = re.compile(r"([?&;][^=\s&#?;]*)=([^&\s#]*)")
_QUERY_PAIR_STARTS = frozenset("?&;")
# Bounded (RFC 5321 sizes) so attacker-controlled runs cannot backtrack badly.
# ``*`` is excluded from the local part so an already-masked address
# (``j****@example.com``, the privacy analyzer's form) is not re-masked.
_EMAIL_IN_TEXT_RE = re.compile(
    r"[^@\s\"'<>()/?&=*]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}")
# ``scheme://user:pass@host`` — the userinfo is a credential.
_USERINFO_RE = re.compile(r"(://)[^/\s@?#<>\"']{1,256}@")
# Whitespace-delimited tokens; URL-looking tokens are scrubbed per token
# (linear, no regex backtracking over attacker-controlled URLs).
_TOKEN_RE = re.compile(r"\S+")
_URL_SEPARATORS = frozenset("/?=&")
# A whole path segment that is a long digit run (phone, PAN, IMEI, account
# number): ``/v1/card/4111111111111111/charge``. Dots are not separators, so
# IPv4 hosts and versions are kept.
_DIGIT_SEGMENT_RE = re.compile(r"^\+?\d[\d-]*\d$")
_MIN_SEGMENT_DIGITS = 7

# Long hex runs (>= 32 bytes) are the shape of TLS secrets / keylog values.
_LONG_HEX_RUN_RE = re.compile(r"[0-9a-fA-F]{64,}")
# NSS keylog labels: a keylog line must never leak into shared output. Derived
# from the pipeline's label set (so new labels cannot drift out of sync), with
# ``*_TRAFFIC_SECRET_0`` generalised to every key-update generation, plus
# ``EARLY_EXPORTER_SECRET`` (an NSS label the pipeline does not route).
_EXTRA_KEYLOG_LABELS = ("EARLY_EXPORTER_SECRET",)


def _keylog_label_alternation() -> str:
    labels = sorted(set(TLS_KEYLOG_LABELS) | set(_EXTRA_KEYLOG_LABELS), key=lambda s: (-len(s), s))
    return "|".join(re.escape(label).replace("_TRAFFIC_SECRET_0", r"_TRAFFIC_SECRET_\d+")
                    for label in labels)


_KEYLOG_LABEL_RE = re.compile(rf"\b({_keylog_label_alternation()})\b\s+\S+(\s+\S+)?")

# ---------------------------------------------------------------------------
# Shared value-shape patterns (digest shapes and free-text masking)
# ---------------------------------------------------------------------------

# Whole-value shapes, matched against one (stripped) value or path segment.
UUID_VALUE_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
EMAIL_VALUE_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$")
JWT_VALUE_RE = re.compile(r"^eyJ[\w-]+\.[\w-]+\.[\w-]*$")
DIGITS_VALUE_RE = re.compile(r"^\d+$")
# Phone / card / IMEI / SSN / date-like digit runs inside free text.
DIGIT_RUN_IN_TEXT_RE = re.compile(r"\+?\d(?:[\s\-./]?\d){5,}")

# Header names whose values describe protocol plumbing (software, format,
# caching, transport), never the user. The digest omits them from endpoint
# shapes; ``--flow`` shows their values verbatim. Each adds its own extras.
PLUMBING_HEADERS = frozenset({
    "accept", "accept-encoding", "accept-language", "cache-control", "connection",
    "content-encoding", "content-length", "content-type", "host", "pragma", "te",
    "upgrade",
})


# ---------------------------------------------------------------------------
# Free-text scrubbing
# ---------------------------------------------------------------------------

def _is_digit_segment(segment: str) -> bool:
    return (_DIGIT_SEGMENT_RE.match(segment) is not None
            and sum(ch.isdigit() for ch in segment) >= _MIN_SEGMENT_DIGITS)


def _scrub_url_token(token: str, placeholder: str) -> str:
    """Mask the ``#fragment`` and digit-run path segments of a URL-looking *token*.

    ``/app#tok`` -> ``/app#…``; ``/card/4111111111111111/x`` -> ``/card/…/x``.
    """
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

    * URL query values: ``?email=alice@x.org&lang=en`` -> ``?email=<redacted>&lang=<redacted>``
    * URL fragments: ``/app#access_token=…`` -> ``/app#<redacted>``
    * URL path segments that are long digit runs (phone, card, IMEI):
      ``/card/4111111111111111`` -> ``/card/<redacted>``
    * URL userinfo: ``https://user:pw@host`` -> ``https://<redacted>@host``
    * e-mail addresses anywhere -> ``<email>``
    * every string in *raw_values* (at least :data:`MIN_SCRUB_LEN` chars)

    Analyzer titles/descriptions often embed the full request URL; this is
    what keeps them shareable when values are not shown.
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


# ---------------------------------------------------------------------------
# Finding redaction (reporter layer)
# ---------------------------------------------------------------------------

# Categories whose evidence values are sensitive and masked by default.
SENSITIVE_CATEGORIES = frozenset({"pii", "secret"})

# Redaction is deny-by-default: for a sensitive (pii/secret) finding, EVERY
# string evidence value is masked unless its key names purely-descriptive
# context (a name/type/location/metric/flag — never the matched content). This
# allowlist is the safe set; any other key (``value``, ``payload``, ``bearer``,
# a future analyzer's new key, …) is treated as sensitive and masked. This is
# the robust inverse of an easily-outgrown denylist of "sensitive" key names.
# Safe keys are still :func:`scrub_values`-ed (``host`` may embed a URL).
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
    """Raw non-safe evidence strings of a pii/secret finding (``[]`` if none apply).

    Findings already redacted by their analyzer (``evidence["redacted"]``) and
    non-sensitive categories have nothing to mask.
    """
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
    """Mask non-safe evidence strings of a pii/secret finding (and echo sites).

    Each masked raw value is also replaced in the title/description so a value
    embedded in free text (e.g. the IOC e-mail title) does not leak.
    """
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
    """:func:`scrub_values` every string inside a JSON-like evidence value.

    Returns ``(scrubbed, changed)``; ``changed`` is True when any string changed.
    """
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
    """The title :func:`redact_finding` would produce, without the full redaction.

    Cheap enough to cluster many findings by their shared-safe title and run
    :func:`redact_finding` only on each cluster's representative.
    """
    title = _mask_raw_in_text(finding.title, _sensitive_raw_values(finding))
    return scrub_values(title, placeholder=placeholder)


def redact_finding(finding: "Finding", *, placeholder: str = REDACTED) -> "Finding":
    """Return a share-safe copy of *finding* for presentation.

    This is the egress-layer redaction: analyzers keep full fidelity (in-memory,
    TUI and ``.tap`` findings), and every path that serialises findings for
    users or agents (reporters, findings sidecar, live ``--scan`` report,
    ``fritap report`` digest) calls this unless PII display was requested:

    1. pii/secret findings get their non-safe evidence values masked
       (deny-by-default, see :data:`SAFE_EVIDENCE_KEYS`);
    2. every finding — any category, analyzer-redacted or not — has its
       title, description and evidence strings passed through
       :func:`scrub_values`, so embedded URLs keep their keys but lose query /
       fragment / userinfo values and e-mail addresses.

    ``evidence["redacted"]`` is set when evidence changed. A finding that
    needs no change is returned as-is.
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
