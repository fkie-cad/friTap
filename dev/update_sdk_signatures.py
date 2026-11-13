#!/usr/bin/env python3

"""Regenerate / extend the bundled SDK signature table, deterministically.

Produces ``friTap/analysis/attribution/data/sdk_signatures.json`` — the
``prefix -> {sdk, vendor, category}`` table used by
:class:`friTap.analysis.attribution.sdk.SdkResolver` to map a captured call
stack to its owning SDK.

By default this script is **offline**: it re-serialises the existing curated
seed in a canonical, sorted form (useful after hand-editing the seed). With
``--merge-exodus`` it OPTIONALLY fetches the Exodus Privacy tracker list and
merges each tracker's package signatures into the same JSON shape.

    python dev/update_sdk_signatures.py                 # canonicalise the seed
    python dev/update_sdk_signatures.py --merge-exodus  # + merge Exodus packages
    python dev/update_sdk_signatures.py --out /tmp/x.json

This is the ONLY place in the SDK-attribution feature that touches the
network, and only when ``--merge-exodus`` is passed; the runtime resolver is
fully offline and the fetched Exodus data is NEVER bundled into the repository
automatically. Output is deterministic: entries are sorted, so re-running
against the same inputs yields a byte-identical file. Standard library plus
friTap's own pattern validators.

License note: Exodus Privacy's tracker definitions are distributed under the
GNU AGPL. Merging them is the operator's explicit, on-demand opt-in via
``--merge-exodus``; the curated seed itself contains no Exodus-derived data.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections import OrderedDict
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Same validation the resolver applies, so a regenerate never keeps an item it would drop.
from friTap.analysis.attribution.sdk import (  # noqa: E402
    _browser_patterns,
    _internal_host_patterns,
)

DATA_DIR = PROJECT_ROOT / "friTap" / "analysis" / "attribution" / "data"
SIGNATURES_PATH = DATA_DIR / "sdk_signatures.json"

SCHEMA = "fritap.sdk_signatures/1"
EXODUS_TRACKERS_URL = "https://reports.exodus-privacy.eu.org/api/trackers"
#: Top-level key listing the Chromium-based browsers (see the data README).
BROWSER_PACKAGES_KEY = "chromium_browser_packages"
#: Top-level key listing Chromium's background-service hosts (see the data README).
INTERNAL_HOSTS_KEY = "chromium_internal_hosts"

#: Exodus tags trackers with a free-text ``category`` string; fold the common
#: ones onto our stable slugs. Anything unlisted falls back to ``other``.
_EXODUS_CATEGORY_MAP = {
    "advertisement": "advertising",
    "advertising": "advertising",
    "ads": "advertising",
    "analytics": "analytics",
    "crash reporting": "crash_reporting",
    "crash_reporting": "crash_reporting",
    "profiling": "analytics",
    "identification": "attribution",
    "location": "maps",
}


def _canonical_entry(
    sdk: str, vendor: str, category: str, transport_kind: str = ""
) -> "OrderedDict[str, str]":
    """Build one signature value with a stable key order.

    ``transport_kind`` (transport-module entries only) is kept when non-empty
    so a regenerate never drops the transport/originator split.
    """
    entry = OrderedDict([("sdk", sdk), ("vendor", vendor), ("category", category)])
    if transport_kind:
        entry["transport_kind"] = transport_kind
    return entry


def load_entries(path: Path) -> "OrderedDict[str, OrderedDict[str, str]]":
    """Load the existing signature entries (empty if the file is absent)."""
    if not path.exists():
        return OrderedDict()
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    entries = payload.get("entries", {}) if isinstance(payload, dict) else {}
    result: "OrderedDict[str, OrderedDict[str, str]]" = OrderedDict()
    for prefix, meta in entries.items():
        if not isinstance(meta, dict):
            continue
        result[prefix] = _canonical_entry(
            meta.get("sdk", ""),
            meta.get("vendor", ""),
            meta.get("category", "other"),
            meta.get("transport_kind", ""),
        )
    return result


def load_browser_packages(path: Path) -> "Optional[list[str]]":
    """Load the ``chromium_browser_packages`` list, deduplicated and sorted.

    ``None`` when the file or key is absent. Preserved (only canonicalised) so
    a regenerate never drops the Chromium browser list that ``SdkResolver``
    uses to resolve ``chrome-or-webview`` modules.
    """
    return _load_pattern_list(path, BROWSER_PACKAGES_KEY, _browser_patterns)


def load_internal_hosts(path: Path) -> "Optional[list[str]]":
    """Load the ``chromium_internal_hosts`` list, deduplicated and sorted.

    ``None`` when the file or key is absent. Preserved (only canonicalised) so
    a regenerate never drops the hosts that bucket Chromium's own background
    traffic as ``chromium-internal``.
    """
    return _load_pattern_list(path, INTERNAL_HOSTS_KEY, _internal_host_patterns)


def _load_pattern_list(path: Path, key: str, valid_patterns) -> "Optional[list[str]]":
    """The valid items of *path*'s top-level *key* list, sorted; ``None`` when absent.

    A present but empty list stays ``[]``: dropping the key would bring back the resolver's defaults.
    """
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or key not in payload:
        return None
    return sorted(set(valid_patterns(payload, path)))


def _normalize_exodus_category(raw: Optional[str]) -> str:
    """Fold an Exodus category string onto a stable slug."""
    if not raw:
        return "other"
    return _EXODUS_CATEGORY_MAP.get(raw.strip().lower(), "other")


def _iter_exodus_prefixes(code_signature: str):
    """Yield clean package prefixes from an Exodus ``code_signature`` field.

    The field is a ``|``-separated list of (possibly regex-escaped) package
    prefixes, e.g. ``"com\\.google\\.android\\.gms\\.ads|com\\.inmobi\\."``.
    """
    for raw in (code_signature or "").split("|"):
        prefix = raw.replace("\\", "").strip().strip(".")
        if prefix:
            yield prefix


def fetch_exodus_trackers(url: str = EXODUS_TRACKERS_URL) -> dict:
    """Fetch the Exodus Privacy tracker list (network; opt-in only)."""
    request = urllib.request.Request(url, headers={"User-Agent": "friTap-sdk-updater"})
    with urllib.request.urlopen(request) as response:  # noqa: S310 - fixed https URL
        return json.loads(response.read().decode("utf-8"))


def merge_exodus(
    entries: "OrderedDict[str, OrderedDict[str, str]]",
    payload: dict,
) -> int:
    """Merge Exodus tracker package signatures into ``entries`` in place.

    Existing (curated) prefixes are never overwritten, so the seed always wins.
    Returns the number of newly added prefixes.
    """
    trackers = payload.get("trackers", {})
    if isinstance(trackers, dict):
        records = trackers.values()
    else:
        records = trackers  # some snapshots use a list
    added = 0
    for record in records:
        if not isinstance(record, dict):
            continue
        name = (record.get("name") or "").strip()
        if not name:
            continue
        category = _normalize_exodus_category(record.get("category"))
        for prefix in _iter_exodus_prefixes(record.get("code_signature", "")):
            if prefix in entries:
                continue
            entries[prefix] = _canonical_entry(name, name, category)
            added += 1
    return added


def write_signatures(
    entries: "OrderedDict[str, OrderedDict[str, str]]",
    path: Path,
    merged_exodus: bool,
    browser_packages: "Optional[list[str]]" = None,
    internal_hosts: "Optional[list[str]]" = None,
) -> None:
    """Serialise the signature table deterministically (sorted by prefix)."""
    ordered = OrderedDict((p, entries[p]) for p in sorted(entries))
    payload: "OrderedDict[str, object]" = OrderedDict()
    payload["schema"] = SCHEMA
    payload["source"] = (
        "friTap curated SDK signature seed + Exodus Privacy"
        if merged_exodus
        else "friTap curated SDK signature seed"
    )
    payload["source_url"] = EXODUS_TRACKERS_URL
    payload["license"] = (
        "Curated seed (friTap); optional Exodus Privacy merge is AGPL — see data/README.md"
    )
    payload["kind"] = "merged" if merged_exodus else "seed"
    payload["entry_count"] = len(ordered)
    if browser_packages is not None:
        payload[BROWSER_PACKAGES_KEY] = list(browser_packages)
    if internal_hosts is not None:
        payload[INTERNAL_HOSTS_KEY] = list(internal_hosts)
    payload["entries"] = ordered
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=False)
        handle.write("\n")
    print(f"wrote {path} ({len(ordered)} entries, kind={payload['kind']})")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--merge-exodus",
        action="store_true",
        help="fetch Exodus Privacy trackers (AGPL; network) and merge package signatures",
    )
    parser.add_argument(
        "--exodus-url",
        default=EXODUS_TRACKERS_URL,
        help="override the Exodus trackers API URL",
    )
    parser.add_argument(
        "--out",
        default=str(SIGNATURES_PATH),
        help="output path (defaults to the bundled sdk_signatures.json)",
    )
    args = parser.parse_args(argv)

    out_path = Path(args.out)
    entries = load_entries(SIGNATURES_PATH)
    if not entries:
        print("error: no existing seed entries to build on", file=sys.stderr)
        return 1

    if args.merge_exodus:
        payload = fetch_exodus_trackers(args.exodus_url)
        added = merge_exodus(entries, payload)
        print(f"merged Exodus: {added} new prefixes")

    write_signatures(
        entries,
        out_path,
        merged_exodus=args.merge_exodus,
        browser_packages=load_browser_packages(SIGNATURES_PATH),
        internal_hosts=load_internal_hosts(SIGNATURES_PATH),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
