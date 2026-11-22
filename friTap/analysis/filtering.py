"""
Findings filtering shared by the CLI, live scan, public API and TUI.

Criteria (all ANDed; ``None``/empty is a no-op): severity floor, exact
severities, source, category, confidence floor, and a case-insensitive text
substring over title/description/evidence.

Category taxonomy (``Finding.metadata["category"]``):

* ``secret``   credentials, API keys, tokens, private key material.
* ``pii``      personal data (emails, phone, PAN, device IDs, geolocation).
* ``network``  network indicators (IPs, domains, URLs, hashes, banners).
* ``protocol`` protocol-level observations (gRPC/protobuf structure).

Compliance tags live in ``metadata["compliance"]`` and ``metadata["cwe"]``.

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
    """Parse ``--source a,b`` style input into a frozenset; blank gives ``None``."""
    if not value:
        return None
    names = {part.strip() for part in value.split(",") if part.strip()}
    return frozenset(names) or None


@dataclass(frozen=True)
class FindingFilter:
    """Immutable predicate over findings; criteria are ANDed in :meth:`matches`.

    Attributes:
        min_severity: Severity floor; unknown values count as ``info``.
        severities: Exact severity values (``{"high"}`` excludes critical).
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
        """True when at least one criterion constrains results (empty ``text`` does not)."""
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
    """Order-preserving subset matching *flt*; ``None`` returns a copy."""
    if flt is None:
        return list(findings)
    return [f for f in findings if flt.matches(f)]


def summarize(findings: list[Finding]) -> dict[str, Any]:
    """Count findings by severity, source and category (none -> ``uncategorized``).

    ``total``/``by_severity``/``by_source`` match ``JsonReporter``'s summary.
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
    """Return a copy tagged with a category; existing metadata keys are never overwritten."""
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
