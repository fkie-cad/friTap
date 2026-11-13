"""Offline destination-attribution for friTap.

Maps a captured host to its owning entity, a tracker category and a
first-/third-party verdict, using offline datasets: a bundled friTap-curated
tracker seed plus a Public Suffix List snapshot. A local-only full DuckDuckGo
Tracker Radar map (``data/trackers_full.json``, CC BY-NC-SA 4.0, never
shipped) is preferred over the seed when present.

Typical use::

    from friTap.analysis.attribution import classify

    att = classify("www.google-analytics.com", first_party_domains=["myapp.com"])
    att.owner      # -> "Google"
    att.category   # -> "analytics"
    att.party      # -> "third"

The module-level :func:`classify` lazily builds and caches a single default
:class:`TrackerResolver`. Nothing is read from disk or the network at import
time; the data files are opened on the first call only.
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

#: Sentinel ``first_party`` value asking callers to infer the set (see
#: :func:`infer_first_party`) from the hosts in scope instead of supplying one.
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
    """Normalize a ``first_party`` argument to ``None``, ``"auto"`` or a domain list.

    ``"auto"`` (:data:`AUTO_FIRST_PARTY`) and ``None`` are returned unchanged.
    Any other string is a comma-separated domain list (``"a.com, b.com"`` ->
    ``["a.com", "b.com"]``) -- never iterated character by character. A list
    or tuple keeps its domains; in both cases entries are stripped and empties
    dropped.
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
    """Classify ``host`` using the cached default :class:`TrackerResolver`.

    See :meth:`TrackerResolver.classify`. The default resolver is created on
    the first call (lazy, offline) and reused thereafter.
    """
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
    """Infer the app's own first-party registrable domains from contacted hosts.

    Heuristic (documented so it stays stable): reduce every contacted host to
    its registrable domain (eTLD+1) via *classify*, **excluding** any host the
    classifier marks as a known tracker (an ``owner`` or ``category`` is set) —
    a tracker is never the app's own backend, even when it is contacted most.
    Sum request counts per surviving registrable domain and return the
    most-contacted one, plus every other non-tracker domain whose count is at
    least 50% of that top count (so an app that talks to one or two backends is
    captured, while far-less-contacted domains are left out). Ties break
    lexicographically. Returns ``[]`` when nothing qualifies (no hosts, or every
    contacted domain is a known tracker).

    :param host_counts: a mapping ``{host: count}`` or an iterable of
        ``(host, count)`` pairs (e.g. a digest's host rows).
    :param classify: a ``host -> dict`` callable (see :func:`make_classifier`)
        exposing ``registrable_domain`` and the tracker ``owner``/``category``.
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
