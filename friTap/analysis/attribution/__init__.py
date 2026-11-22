"""Offline destination-attribution for friTap.

Maps a captured host to its owner, tracker category and first-/third-party
verdict from a bundled tracker seed plus a Public Suffix List snapshot. A
local-only DuckDuckGo Tracker Radar map (``data/trackers_full.json``,
CC BY-NC-SA 4.0, never shipped) is preferred over the seed when present.

Typical use::

    from friTap.analysis.attribution import classify

    att = classify("www.google-analytics.com", first_party_domains=["myapp.com"])
    att.owner      # -> "Google"
    att.category   # -> "analytics"
    att.party      # -> "third"

:func:`classify` lazily builds one cached default :class:`TrackerResolver`;
nothing is read at import time.
"""

from __future__ import annotations

from typing import Callable, Iterable, Optional

from friTap.analysis.attribution.resolver import (
    PARTY_FIRST,
    PARTY_THIRD,
    PARTY_UNKNOWN,
    Attribution,
    TrackerResolver,
)

#: ``first_party`` sentinel: infer the set via :func:`infer_first_party`.
AUTO_FIRST_PARTY = "auto"

__all__ = [
    "Attribution",
    "TrackerResolver",
    "classify",
    "make_classifier",
    "infer_first_party",
    "normalize_first_party",
    "AUTO_FIRST_PARTY",
    "PARTY_FIRST",
    "PARTY_THIRD",
    "PARTY_UNKNOWN",
]

_default_resolver: Optional[TrackerResolver] = None


def normalize_first_party(first_party):
    """Normalize ``first_party`` to ``None``, ``"auto"`` or a stripped domain list.

    A string is split on commas (``"a.com, b.com"``), never per character.
    """
    if first_party is None or first_party == AUTO_FIRST_PARTY:
        return first_party
    if isinstance(first_party, str):
        first_party = first_party.split(",")
    return [domain.strip() for domain in first_party if str(domain).strip()]


def _resolver() -> TrackerResolver:
    """Return the cached default resolver, building it on first use."""
    global _default_resolver
    if _default_resolver is None:
        _default_resolver = TrackerResolver()
    return _default_resolver


def classify(host: str, first_party_domains: Iterable[str] = ()) -> Attribution:
    """Classify ``host`` with the cached default resolver (:meth:`TrackerResolver.classify`)."""
    return _resolver().classify(host, first_party_domains)


def make_classifier(first_party=()):
    """A cached host -> attribution-dict classifier (first-party normalized once)."""
    fp = tuple(first_party)
    cache: dict[str, dict] = {}

    def classify_host(host: str) -> dict:
        if host not in cache:
            cache[host] = classify(host, fp).as_dict()
        return cache[host]

    return classify_host


def infer_first_party(host_counts, classify: Callable[[str], dict]) -> list:
    """Infer the app's first-party registrable domains from contacted hosts.

    Heuristic (kept stable): reduce each host to its eTLD+1 via *classify*,
    skipping known trackers (``owner`` or ``category`` set; a tracker is never
    the app's backend). Sum counts per domain; return the top domain plus every
    domain with at least 50% of the top count, sorted. ``[]`` if none qualify.

    ``host_counts`` is ``{host: count}`` or ``(host, count)`` pairs;
    ``classify`` is a ``host -> dict`` callable (see :func:`make_classifier`).
    """
    items = host_counts.items() if hasattr(host_counts, "items") else host_counts
    totals: dict[str, int] = {}
    for host, count in items:
        info = classify(host)
        if not isinstance(info, dict):
            continue
        registrable = info.get("registrable_domain")
        if not registrable or info.get("owner") or info.get("category"):
            continue  # unresolvable, or a known tracker -> never first-party
        totals[registrable] = totals.get(registrable, 0) + int(count or 0)
    if not totals:
        return []
    top = max(totals.values())
    if top <= 0:
        return []
    # count >= 50% of top, kept as integer math (2*count >= top).
    return sorted(domain for domain, count in totals.items() if 2 * count >= top)
