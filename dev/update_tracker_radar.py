#!/usr/bin/env python3

"""Regenerate the attribution datasets from upstream, deterministically.

Produces, under ``friTap/analysis/attribution/data/``:

* ``trackers_full.json`` — a compact, distilled ``domain -> {owner, category}``
  map derived from the DuckDuckGo Tracker Radar
  (https://github.com/duckduckgo/tracker-radar). The full ``domains/`` tree is
  distilled down to one entry per domain: the owner's display name and a single
  normalised category slug. Tracker Radar is licensed CC BY-NC-SA 4.0, so this
  file is LOCAL-ONLY: it is gitignored and never committed, published or
  packaged. The runtime resolver prefers it over the shipped friTap-curated
  seed (``trackers.json``, which this script never touches) when present.
* ``public_suffix_list.dat`` — a verbatim snapshot of the Mozilla Public Suffix
  List from https://publicsuffix.org/list/public_suffix_list.dat .

This is the ONLY place in the attribution package that touches the network;
the runtime resolver is fully offline. Output is deterministic: entries are
sorted and categories are chosen by a fixed priority, so re-running against the
same upstream commit yields a byte-identical ``trackers_full.json``.

Usage::

    python dev/update_tracker_radar.py                 # full distillation
    python dev/update_tracker_radar.py --psl-only      # refresh only the PSL
    python dev/update_tracker_radar.py --ref <sha>     # pin a tracker-radar ref

Requires network access and the standard library only (no third-party deps).
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import tarfile
import urllib.request
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Optional

DATA_DIR = Path(__file__).resolve().parent.parent / "friTap" / "analysis" / "attribution" / "data"
TRACKERS_PATH = DATA_DIR / "trackers_full.json"  # local-only, never published
PSL_PATH = DATA_DIR / "public_suffix_list.dat"

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
TRACKER_RADAR_REPO = "duckduckgo/tracker-radar"
SCHEMA = "fritap.trackers/1"

# Tracker Radar uses many fine-grained categories. Map them to a small, stable
# set of slugs, chosen by priority (first match in this list wins). Categories
# not listed fall back to ``other``.
#
# Order: most *specific / defining* categories first, with the broad advertising
# bucket LAST. DDG tags almost every tracker with "Advertising" / "Ad Motivated
# Tracking" even when its defining purpose is analytics or social (e.g.
# google-analytics.com carries both Advertising and Analytics; facebook.com
# carries Advertising, Analytics and Social Network). Ranking advertising first
# would collapse nearly everything to "advertising" and bury the informative
# label, so it is the fallback for pure ad-tech (e.g. doubleclick.net).
CATEGORY_PRIORITY = (
    ("social", ("Social Network", "Social - Comment", "Social - Share", "Federated Login",
                "SSO", "Oauth")),
    ("analytics", ("Analytics", "Audience Measurement", "Third-Party Analytics Marketing",
                   "Action Pixels", "Session Replay", "Online Payment", "Ad Fraud - Prevention")),
    ("tag_manager", ("Tag Manager",)),
    ("cdn", ("CDN", "Embedded Content", "Non-Tracking", "Malware")),
    ("advertising", ("Advertising", "Ad Motivated Tracking", "Ad Fraud", "Badware Risk")),
    ("crash_reporting", ("Obscure Ownership",)),
)


def _http_get(url: str) -> bytes:
    """Fetch a URL and return its raw bytes (network use is confined here)."""
    request = urllib.request.Request(url, headers={"User-Agent": "friTap-tracker-radar-updater"})
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 (fixed https URLs)
        return response.read()


def _normalize_category(categories) -> str:
    """Reduce Tracker Radar's category list to a single stable slug."""
    present = {c for c in (categories or []) if isinstance(c, str)}
    for slug, names in CATEGORY_PRIORITY:
        if present & set(names):
            return slug
    return "other"


def _tarball_url(ref: str) -> str:
    return f"https://codeload.github.com/{TRACKER_RADAR_REPO}/tar.gz/{ref}"


def distill_trackers(ref: str) -> "OrderedDict[str, Dict[str, Optional[str]]]":
    """Download the tracker-radar tarball and distill its ``domains/`` tree.

    Returns an ordered ``domain -> {owner, category}`` map, sorted by domain.
    """
    blob = _http_get(_tarball_url(ref))
    entries: Dict[str, Dict[str, Optional[str]]] = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            # Paths look like ``tracker-radar-<ref>/domains/<REGION>/<domain>.json``.
            parts = member.name.split("/")
            if len(parts) < 4 or parts[1] != "domains" or not parts[-1].endswith(".json"):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            try:
                data = json.loads(handle.read().decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            domain = (data.get("domain") or "").strip().lower()
            owner = (data.get("owner") or {}).get("displayName") or (data.get("owner") or {}).get("name")
            if not domain or not owner:
                continue
            entries[domain] = {
                "owner": owner,
                "category": _normalize_category(data.get("categories")),
            }
    return OrderedDict((d, entries[d]) for d in sorted(entries))


def write_trackers(entries: "OrderedDict[str, Dict[str, Optional[str]]]", ref: str) -> None:
    """Serialise the distilled map to ``trackers_full.json`` deterministically."""
    payload: "OrderedDict[str, object]" = OrderedDict()
    payload["schema"] = SCHEMA
    payload["source"] = "DuckDuckGo Tracker Radar"
    payload["source_url"] = f"https://github.com/{TRACKER_RADAR_REPO}"
    payload["source_ref"] = ref
    payload["license"] = (
        "CC BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/), "
        "derived from DuckDuckGo Tracker Radar. Local-only: never commit, "
        "publish or package this file."
    )
    payload["kind"] = "full"
    payload["entry_count"] = len(entries)
    payload["entries"] = entries
    with open(TRACKERS_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=False)
        handle.write("\n")
    print(f"wrote {TRACKERS_PATH} ({len(entries)} entries, ref={ref})")


def write_psl() -> None:
    """Snapshot the Public Suffix List verbatim."""
    blob = _http_get(PSL_URL)
    with open(PSL_PATH, "wb") as handle:
        handle.write(blob)
    print(f"wrote {PSL_PATH} ({len(blob)} bytes)")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="main", help="tracker-radar git ref (branch/tag/sha)")
    parser.add_argument("--psl-only", action="store_true", help="refresh only the PSL snapshot")
    parser.add_argument("--trackers-only", action="store_true", help="refresh only the local-only trackers_full.json")
    args = parser.parse_args(argv)
    if args.psl_only and args.trackers_only:
        print("error: --psl-only and --trackers-only are mutually exclusive", file=sys.stderr)
        return 2

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not args.trackers_only:
        write_psl()
    if not args.psl_only:
        entries = distill_trackers(args.ref)
        if not entries:
            print("error: no tracker entries distilled from upstream", file=sys.stderr)
            return 1
        write_trackers(entries, args.ref)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
