"""Well-formedness checks for the bundled, friTap-authored tracker seed.

The shipped ``data/trackers.json`` must be the curated GPL seed, never the
non-commercial DuckDuckGo Tracker Radar distillation (that one stays local as
``trackers_full.json``). These tests guard the shape and the provenance.
"""

import json

import pytest

from friTap.analysis.attribution.resolver import DEFAULT_TRACKERS_PATH

ALLOWED_CATEGORIES = {
    "advertising",
    "analytics",
    "social",
    "tag_manager",
    "cdn",
    "crash_reporting",
    "other",
}

REQUIRED_ENTRIES = {
    "google-analytics.com": ("Google", "analytics"),
    "doubleclick.net": ("Google", "advertising"),
    "facebook.com": ("Facebook", "social"),
}


@pytest.fixture(scope="module")
def seed():
    with open(DEFAULT_TRACKERS_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def test_seed_declares_seed_kind_and_schema(seed):
    assert seed["kind"] == "seed"
    assert seed["schema"] == "fritap.trackers/1"


def test_seed_entry_count_matches_entries(seed):
    assert seed["entry_count"] == len(seed["entries"])


def test_seed_is_not_the_non_commercial_dataset(seed):
    assert "tracker radar" not in seed["source"].lower()
    assert "by-nc" not in seed["license"].lower()


def test_seed_categories_are_known_slugs(seed):
    unknown = {
        domain: meta["category"]
        for domain, meta in seed["entries"].items()
        if meta["category"] not in ALLOWED_CATEGORIES
    }
    assert unknown == {}


def test_seed_owners_are_non_empty_strings(seed):
    for domain, meta in seed["entries"].items():
        assert isinstance(meta["owner"], str) and meta["owner"].strip(), domain


def test_seed_keys_are_normalized_hosts(seed):
    for domain in seed["entries"]:
        assert domain == domain.lower(), domain
        assert domain == domain.strip(), domain
        assert not domain.startswith(".") and not domain.endswith("."), domain


@pytest.mark.parametrize("domain,expected", sorted(REQUIRED_ENTRIES.items()))
def test_seed_contains_required_entry(seed, domain, expected):
    meta = seed["entries"][domain]
    assert (meta["owner"], meta["category"]) == expected
