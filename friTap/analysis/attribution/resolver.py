"""Offline destination attribution: map a captured host to its owner.

:class:`TrackerResolver` returns owner, category and first-/third-party verdict
from two offline datasets: the friTap-curated ``data/trackers.json``
(``domain -> {owner, category}``, see ``data/README.md``) and a Mozilla Public
Suffix List snapshot (``data/public_suffix_list.dat``) for the eTLD+1. A local,
never published ``data/trackers_full.json`` (DuckDuckGo Tracker Radar,
CC BY-NC-SA 4.0, from ``dev/update_tracker_radar.py``) is preferred when present
(:func:`default_trackers_path`).

No network and no I/O at import; data files load once on construction.

Trust model: owner and category come from the bundled list and are trusted
(no ``untrusted`` envelope). The captured host is untrusted; callers escape and
cap it before display. It is normalised and only its registrable domain,
computed from the trusted PSL, is returned.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

_DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_TRACKERS_PATH = _DATA_DIR / "trackers.json"
#: Local-only full Tracker Radar map (CC BY-NC-SA 4.0); never shipped.
FULL_TRACKERS_PATH = _DATA_DIR / "trackers_full.json"
DEFAULT_PSL_PATH = _DATA_DIR / "public_suffix_list.dat"


def default_trackers_path() -> Path:
    """The local full map (:data:`FULL_TRACKERS_PATH`) if present, else the shipped seed.

    Globals are read at call time so tests can monkeypatch them.
    """
    if FULL_TRACKERS_PATH.is_file():
        return FULL_TRACKERS_PATH
    return DEFAULT_TRACKERS_PATH

#: Party classification values.
PARTY_FIRST = "first"
PARTY_THIRD = "third"
PARTY_UNKNOWN = "unknown"


@dataclass(frozen=True)
class Attribution:
    """Classification of one host.

    ``registrable_domain`` is the eTLD+1 (``None`` for a bare public suffix);
    ``owner``/``category`` (e.g. ``advertising``, ``analytics``, ``cdn``) are ``None`` if
    unknown; ``party`` is one of the ``PARTY_*`` values.
    """

    registrable_domain: Optional[str]
    owner: Optional[str]
    category: Optional[str]
    party: str

    def as_dict(self) -> Dict[str, Optional[str]]:
        """Plain dict view (stable key order)."""
        return {
            "registrable_domain": self.registrable_domain,
            "owner": self.owner,
            "category": self.category,
            "party": self.party,
        }


def normalize_hostname(host: str) -> str:
    """Lowercase and strip whitespace and a trailing dot; a ``:port`` is kept (tracker matching relies on it).

    :func:`friTap.analysis.attribution.sdk.normalize_host` is the port/IPv6-aware wrapper.
    """
    return host.strip().rstrip(".").lower()


def _split_labels(host: str) -> List[str]:

    return [label for label in host.split(".") if label]


class _PublicSuffixList:
    """Minimal Public Suffix List matcher (exact, ``*`` and ``!`` rules, per https://publicsuffix.org/list/)."""

    def __init__(self, exact: set, wildcards: set, exceptions: set) -> None:
        self._exact = exact
        self._wildcards = wildcards
        self._exceptions = exceptions

    @classmethod
    def from_file(cls, path: Path) -> "_PublicSuffixList":
        exact: set = set()
        wildcards: set = set()
        exceptions: set = set()
        with open(path, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("//"):
                    continue
                rule = line.lower()
                if rule.startswith("!"):
                    exceptions.add(tuple(_split_labels(rule[1:])))
                elif rule.startswith("*."):
                    wildcards.add(tuple(_split_labels(rule[2:])))
                else:
                    exact.add(tuple(_split_labels(rule)))
        return cls(exact, wildcards, exceptions)

    def _public_suffix_labels(self, labels: List[str]) -> List[str]:
        """Public-suffix labels of a normalised host."""
        count = len(labels)
        # Exception rules win: suffix is the rule minus its leftmost label.
        for i in range(count):
            suffix = tuple(labels[i:])
            if suffix in self._exceptions:
                return list(suffix[1:])

        best: Optional[List[str]] = None
        # Longest matching exact rule wins.
        for i in range(count):
            suffix = tuple(labels[i:])
            if suffix in self._exact and (best is None or len(suffix) > len(best)):
                best = list(suffix)
        # ``*.base`` matches one arbitrary label plus base.
        for i in range(count):
            base = tuple(labels[i + 1:])
            if base in self._wildcards:
                match = labels[i:]
                if best is None or len(match) > len(best):
                    best = list(match)

        if best is None:
            # Default rule "*": rightmost label.
            return labels[-1:]
        return best

    def registrable_domain(self, host: str) -> Optional[str]:
        """eTLD+1 of ``host``, or ``None``."""
        labels = _split_labels(normalize_hostname(host))
        if not labels:
            return None
        suffix_len = len(self._public_suffix_labels(labels))
        if len(labels) <= suffix_len:
            # Host is itself a public suffix (``co.uk``).
            return None
        return ".".join(labels[-(suffix_len + 1):])


class TrackerResolver:
    """Resolve hosts to ``{registrable_domain, owner, category, party}``.

    Datasets load once on construction; ``trackers_path=None`` uses :func:`default_trackers_path`.
    """

    def __init__(
        self,
        trackers_path: Path | str | None = None,
        psl_path: Path | str = DEFAULT_PSL_PATH,
    ) -> None:
        if trackers_path is None:
            trackers_path = default_trackers_path()
        self._trackers = self._load_trackers(Path(trackers_path))
        self._psl = _PublicSuffixList.from_file(Path(psl_path))

    @staticmethod
    def _load_trackers(path: Path) -> Dict[str, Dict[str, Optional[str]]]:
        """Load the ``domain -> {owner, category}`` map."""
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        entries = payload.get("entries", {}) if isinstance(payload, dict) else {}
        normalized: Dict[str, Dict[str, Optional[str]]] = {}
        for domain, meta in entries.items():
            if not isinstance(meta, dict):
                continue
            normalized[normalize_hostname(domain)] = {
                "owner": meta.get("owner"),
                "category": meta.get("category"),
            }
        return normalized

    def _lookup(self, host: str, registrable: Optional[str]) -> Optional[Dict[str, Optional[str]]]:
        """Most specific tracker entry for ``host``, walking inward to the registrable domain (``graph.facebook.com`` before ``facebook.com``)."""
        if registrable is None:
            return None
        labels = _split_labels(host)
        reg_len = registrable.count(".") + 1
        for i in range(0, len(labels) - reg_len + 1):
            candidate = ".".join(labels[i:])
            entry = self._trackers.get(candidate)
            if entry is not None:
                return entry
        return None

    def _first_party_domains(self, first_party_domains: Iterable[str]) -> set:

        result: set = set()
        for raw in first_party_domains:
            registrable = self._psl.registrable_domain(raw)
            result.add(registrable if registrable else normalize_hostname(raw))
        return result

    def classify(self, host: str, first_party_domains: Iterable[str] = ()) -> Attribution:
        """Classify an (untrusted) host; first-party domains are reduced to their registrable domain."""
        normalized = normalize_hostname(host)
        registrable = self._psl.registrable_domain(normalized)
        entry = self._lookup(normalized, registrable)
        owner = entry["owner"] if entry else None
        category = entry["category"] if entry else None

        first_party = self._first_party_domains(first_party_domains)
        if registrable is not None and registrable in first_party:
            party = PARTY_FIRST
        elif owner is not None or category is not None:
            party = PARTY_THIRD
        else:
            party = PARTY_UNKNOWN

        return Attribution(
            registrable_domain=registrable,
            owner=owner,
            category=category,
            party=party,
        )
