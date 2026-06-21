"""
Findings filtering — a reusable, presentation-agnostic filter layer.

This is the single filtering primitive shared by the CLI (``fritap analyze``),
the live-scan path, the public API, and the TUI findings viewer. It composes
the four orthogonal dimensions a finding can be filtered on:

* **severity** — a floor (``min_severity``); keep findings at least this severe.
* **source** — the producing analyzer name (``credentials``/``ioc``/``privacy``/...).
* **category** — the finding's taxonomy bucket (see below).
* **confidence** — a floor (``min_confidence``).
* **text** — a case-insensitive substring over title/description/evidence.

All criteria are ANDed together; a ``None``/empty criterion is a no-op, so an
empty :class:`FindingFilter` matches everything.

Category taxonomy
-----------------
Findings carry their category in ``Finding.metadata["category"]`` (a string),
exposed read-only via :attr:`friTap.analysis.Finding.category`. The canonical
values are:

* ``secret``   — credentials, API keys, tokens, private key material.
* ``pii``      — personal data (emails, phone, PAN, device IDs, geolocation, ...).
* ``network``  — network indicators (IPs, domains, URLs, hashes, server banners).
* ``protocol`` — protocol-level observations (gRPC/protobuf structure, ...).

Compliance tags ride alongside in ``metadata["compliance"]`` (a list, e.g.
``["GDPR", "PCI-DSS"]``) and an optional ``metadata["cwe"]``. None of this adds a
dataclass field, so :class:`~friTap.analysis.Finding` stays frozen and its
serialization contract is unchanged.

Usage::

    from friTap.analysis.filtering import FindingFilter, apply, summarize

    flt = FindingFilter(min_severity="high", sources=frozenset({"credentials"}))
    important = apply(findings, flt)
    print(summarize(important))
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from friTap.analysis import Finding, Severity, severity_rank

# Canonical category strings. Kept as plain strings (not an enum) so external
# analyzers can introduce their own categories without a code change here.
KNOWN_CATEGORIES: frozenset[str] = frozenset({"secret", "pii", "network", "protocol"})

_UNCATEGORIZED = "uncategorized"


def split_csv(value: str | None) -> frozenset[str] | None:
    """Parse a comma-separated CLI value into a frozenset (or ``None``).

    The single source of truth for turning ``--source a,b`` / ``--category x``
    style options into a :class:`FindingFilter` criterion. Blank/empty input
    yields ``None`` (a no-op criterion).
    """
    if not value:
        return None
    names = {part.strip() for part in value.split(",") if part.strip()}
    return frozenset(names) or None


@dataclass(frozen=True)
class FindingFilter:
    """An immutable, composable predicate over :class:`~friTap.analysis.Finding`.

    Every criterion defaults to a no-op, so ``FindingFilter()`` matches all
    findings. Criteria are ANDed in :meth:`matches`.

    Attributes:
        min_severity: Keep findings at least this severe (string or
            :class:`~friTap.analysis.Severity`). Unknown values are treated as
            ``info`` (matching :func:`~friTap.analysis.severity_rank`). This is a
            *floor* — use ``severities`` for an exact-bucket match.
        severities: Keep only findings whose exact severity value is in this set
            (e.g. ``{"high"}`` matches high only, not critical). Complements the
            ``min_severity`` floor for per-bucket selection.
        sources: Keep only findings whose ``source`` is in this set.
        categories: Keep only findings whose ``category`` is in this set.
        min_confidence: Keep findings with ``confidence`` at or above this value.
        text: Case-insensitive substring required in title, description, or
            (recursively) the evidence dict.
    """

    min_severity: str | Severity | None = None
    severities: frozenset[str] | None = None
    sources: frozenset[str] | None = None
    categories: frozenset[str] | None = None
    min_confidence: float | None = None
    text: str | None = None

    def is_active(self) -> bool:
        """True when at least one criterion would actually constrain results.

        An all-default ``FindingFilter()`` is a no-op (matches everything), so it
        reports ``False`` here — callers use this to distinguish "showing all"
        from "a real filter is applied". Mirrors the criteria used in
        :meth:`matches` (``text`` counts only when non-empty).
        """
        return (
            self.min_severity is not None
            or self.severities is not None
            or self.sources is not None
            or self.categories is not None
            or self.min_confidence is not None
            or bool(self.text)
        )

    def matches(self, finding: Finding) -> bool:
        """Return ``True`` if *finding* satisfies every active criterion."""
        if self.min_severity is not None:
            # Lower rank == more severe; keep findings at or above the floor.
            if severity_rank(finding.severity) > severity_rank(self.min_severity):
                return False

        if self.severities is not None and finding.severity.value not in self.severities:
            return False

        if self.sources is not None and finding.source not in self.sources:
            return False

        if self.categories is not None:
            if (finding.category or _UNCATEGORIZED) not in self.categories:
                return False

        if self.min_confidence is not None and finding.confidence < self.min_confidence:
            return False

        if self.text:
            needle = self.text.lower()
            if not _text_hit(finding, needle):
                return False

        return True


def _text_hit(finding: Finding, needle: str) -> bool:
    """Case-insensitive substring search over title, description, and evidence."""
    if needle in finding.title.lower() or needle in finding.description.lower():
        return True
    return _walk_contains(finding.evidence, needle)


def _walk_contains(value: Any, needle: str) -> bool:
    """Recursively check whether *needle* appears in any string within *value*."""
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, str):
        return needle in value.lower()
    if isinstance(value, dict):
        return any(_walk_contains(v, needle) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_walk_contains(v, needle) for v in value)
    # Numbers and other scalars: compare their string form.
    return needle in str(value).lower()


def apply(findings: list[Finding], flt: FindingFilter | None) -> list[Finding]:
    """Return the order-preserving subset of *findings* matching *flt*.

    A ``None`` filter is a no-op and returns the list unchanged (new list).
    """
    if flt is None:
        return list(findings)
    return [f for f in findings if flt.matches(f)]


def summarize(findings: list[Finding]) -> dict[str, Any]:
    """Summarize *findings* by total, severity, source, and category.

    The ``total``/``by_severity``/``by_source`` shape matches
    :class:`~friTap.analysis.reporters.JsonReporter`'s summary; ``by_category``
    is additive. Findings without a category are bucketed as ``uncategorized``.
    """
    return {
        "total": len(findings),
        "by_severity": dict(Counter(f.severity.value for f in findings)),
        "by_source": dict(Counter(f.source for f in findings)),
        "by_category": dict(Counter(f.category or _UNCATEGORIZED for f in findings)),
    }


def with_category(
    finding: Finding,
    category: str,
    *,
    compliance: list[str] | None = None,
    cwe: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> Finding:
    """Return a copy of *finding* tagged with a category (and optional tags).

    :class:`~friTap.analysis.Finding` is frozen, so this builds a new instance
    via :func:`dataclasses.replace` with a merged ``metadata`` dict. An existing
    ``category`` is preserved (not clobbered) so analyzers that already tag a
    finding keep their more specific value.
    """
    from dataclasses import replace

    merged: dict[str, Any] = dict(finding.metadata)
    merged.setdefault("category", category)
    if compliance is not None:
        merged.setdefault("compliance", compliance)
    if cwe is not None:
        merged.setdefault("cwe", cwe)
    if extra_metadata:
        for k, v in extra_metadata.items():
            merged.setdefault(k, v)
    return replace(finding, metadata=merged)


__all__ = [
    "FindingFilter",
    "apply",
    "summarize",
    "with_category",
    "split_csv",
    "KNOWN_CATEGORIES",
]
