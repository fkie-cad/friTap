"""Unit tests for the offline destination-attribution package.

Covers eTLD+1 computation against the bundled Public Suffix List (multi-level
suffixes, private suffixes, plain domains, PSL ``*``/``!`` rules), tracker
owner/category resolution, first-/third-/unknown-party classification, and the
guarantee that classification performs no network I/O.

Pure Python — no device/Frida/tshark, and (asserted below) no network.
"""

from __future__ import annotations

import importlib.util
import json
import socket
from pathlib import Path

import pytest

import friTap.analysis.attribution.resolver as resolver_module
from friTap.analysis import attribution
from friTap.analysis.attribution import (
    Attribution,
    TrackerResolver,
    infer_first_party,
    make_classifier,
)
from friTap.analysis.attribution.resolver import _PublicSuffixList


@pytest.fixture(scope="module")
def resolver() -> TrackerResolver:
    """A resolver built once from the bundled seed + PSL snapshot."""
    return TrackerResolver()


# --------------------------------------------------------------------------- #
# eTLD+1 (registrable domain)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "host, expected",
    [
        ("example.com", "example.com"),
        ("www.example.com", "example.com"),
        ("a.b.example.com", "example.com"),
        # Multi-level ICANN suffix: co.uk is the eTLD.
        ("foo.co.uk", "foo.co.uk"),
        ("www.foo.co.uk", "foo.co.uk"),
        # Private suffix from the PSL (github.io is a public suffix).
        ("a.b.github.io", "b.github.io"),
        ("project.github.io", "project.github.io"),
        # Trailing dot and casing are normalised.
        ("WWW.Example.CoM.", "example.com"),
    ],
)
def test_registrable_domain(resolver: TrackerResolver, host: str, expected: str) -> None:
    assert resolver.classify(host).registrable_domain == expected


def test_bare_public_suffix_has_no_registrable_domain(resolver: TrackerResolver) -> None:
    # The host is itself a public suffix -> no eTLD+1.
    assert resolver.classify("co.uk").registrable_domain is None
    assert resolver.classify("com").registrable_domain is None


def test_psl_wildcard_and_exception_rules(tmp_path) -> None:
    # Synthetic PSL exercising '*' wildcard and '!' exception handling.
    psl_file = tmp_path / "mini_psl.dat"
    psl_file.write_text(
        "// test list\n"
        "com\n"
        "*.ck\n"          # wildcard: any <label>.ck is a public suffix
        "!www.ck\n",      # exception: www.ck is NOT a public suffix
        encoding="utf-8",
    )
    psl = _PublicSuffixList.from_file(psl_file)
    # Wildcard: public suffix is foo.ck -> registrable adds one more label.
    assert psl.registrable_domain("a.foo.ck") == "a.foo.ck"
    assert psl.registrable_domain("foo.ck") is None  # host is the public suffix
    # Exception: www.ck is a registrable domain, not a suffix.
    assert psl.registrable_domain("www.ck") == "www.ck"
    assert psl.registrable_domain("example.com") == "example.com"


# --------------------------------------------------------------------------- #
# Owner / category resolution
# --------------------------------------------------------------------------- #

def test_known_tracker_resolves_owner_and_category(resolver: TrackerResolver) -> None:
    att = resolver.classify("www.google-analytics.com")
    assert att.registrable_domain == "google-analytics.com"
    assert att.owner == "Google"
    assert att.category == "analytics"
    assert att.party == "third"


def test_subdomain_tracker_resolves_via_registrable_domain(resolver: TrackerResolver) -> None:
    # doubleclick.net is advertising; a subdomain maps to it via eTLD+1.
    att = resolver.classify("ad.g.doubleclick.net")
    assert att.owner == "Google"
    assert att.category == "advertising"


# --------------------------------------------------------------------------- #
# Party classification
# --------------------------------------------------------------------------- #

def test_first_vs_third_party_split(resolver: TrackerResolver) -> None:
    first_party = ["myapp.com", "www.myapp.com"]
    # A first-party host (reg domain in the first-party set).
    own = resolver.classify("api.myapp.com", first_party_domains=first_party)
    assert own.registrable_domain == "myapp.com"
    assert own.party == "first"
    # A known tracker is third-party even if first-party domains are supplied.
    tracker = resolver.classify("google-analytics.com", first_party_domains=first_party)
    assert tracker.party == "third"


def test_first_party_entries_are_reduced_to_registrable_domain(resolver: TrackerResolver) -> None:
    # Passing a full host as first-party still matches its eTLD+1.
    att = resolver.classify("static.example.org", first_party_domains=["cdn.example.org"])
    assert att.party == "first"


def test_unknown_host_is_unknown_party(resolver: TrackerResolver) -> None:
    att = resolver.classify("no-such-host.example")
    assert att.registrable_domain == "no-such-host.example"
    assert att.owner is None
    assert att.category is None
    assert att.party == "unknown"


def test_attribution_as_dict_shape(resolver: TrackerResolver) -> None:
    att = resolver.classify("facebook.com")
    assert att.as_dict() == {
        "registrable_domain": "facebook.com",
        "owner": "Facebook",
        "category": "social",
        "party": "third",
    }


# --------------------------------------------------------------------------- #
# Module-level API + offline guarantee
# --------------------------------------------------------------------------- #

def test_module_level_classify_uses_cached_resolver() -> None:
    a = attribution.classify("www.google-analytics.com")
    b = attribution.classify("www.google-analytics.com")
    assert isinstance(a, Attribution)
    assert a.owner == "Google" and a.category == "analytics"
    assert attribution._resolver() is attribution._resolver()  # cached singleton
    assert a == b


# --------------------------------------------------------------------------- #
# First-party inference (infer_first_party)
# --------------------------------------------------------------------------- #

def test_infer_first_party_picks_dominant_non_tracker() -> None:
    classify = make_classifier(())
    # myapp.com dominates (10 + 6 = 16); the far-less-contacted cdn (2, <50% of
    # 16) is left out.
    counts = {"api.myapp.com": 10, "cdn.myapp.com": 6, "assets.other-cdn.net": 2}
    assert infer_first_party(counts, classify) == ["myapp.com"]


def test_infer_first_party_captures_second_backend_above_half() -> None:
    classify = make_classifier(())
    # partner.com (6) is >= 50% of the top (myapp.com, 10) -> both are kept.
    counts = {"api.myapp.com": 10, "api.partner.com": 6}
    assert infer_first_party(counts, classify) == ["myapp.com", "partner.com"]


def test_infer_first_party_excludes_known_tracker_even_if_most_contacted() -> None:
    classify = make_classifier(())
    # A known analytics tracker is contacted far more than the app's backend,
    # yet it is never chosen as first-party.
    counts = {"google-analytics.com": 100, "api.myapp.com": 5}
    assert infer_first_party(counts, classify) == ["myapp.com"]


def test_infer_first_party_accepts_pairs_iterable_and_empty() -> None:
    classify = make_classifier(())
    assert infer_first_party([("api.myapp.com", 3)], classify) == ["myapp.com"]
    # Nothing but trackers -> no inference.
    assert infer_first_party({"google-analytics.com": 9}, classify) == []
    assert infer_first_party({}, classify) == []


def test_no_network_during_classification(monkeypatch) -> None:
    """Building a resolver and classifying must not open any socket."""

    def _blocked(*args, **kwargs):  # pragma: no cover - only runs on failure
        raise AssertionError("attribution performed network I/O")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)

    local_resolver = TrackerResolver()
    att = local_resolver.classify("www.google-analytics.com", first_party_domains=["myapp.com"])
    assert att.owner == "Google"
    assert att.party == "third"


# --------------------------------------------------------------------------- #
# Tracker map selection: shipped seed vs. local-only full map
# --------------------------------------------------------------------------- #

_FAKE_FULL_HOST = "fake-tracker-zz.com"


def _write_tracker_map(path: Path, host: str, owner: str, category: str) -> Path:
    """Write a minimal tracker map file with a single entry."""
    entries = {host: {"owner": owner, "category": category}}
    path.write_text(json.dumps({"entries": entries}), encoding="utf-8")
    return path


@pytest.fixture
def fake_full_map(tmp_path, monkeypatch) -> Path:
    """Point ``FULL_TRACKERS_PATH`` at a present, one-entry fake full map."""
    full = _write_tracker_map(tmp_path / "trackers_full.json", _FAKE_FULL_HOST, "X", "analytics")
    monkeypatch.setattr(resolver_module, "FULL_TRACKERS_PATH", full)
    return full


def test_default_trackers_path_prefers_present_full_map(fake_full_map: Path) -> None:
    assert resolver_module.default_trackers_path() == fake_full_map


def test_default_trackers_path_falls_back_to_seed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(resolver_module, "FULL_TRACKERS_PATH", tmp_path / "absent.json")
    assert resolver_module.default_trackers_path() == resolver_module.DEFAULT_TRACKERS_PATH


def test_resolver_without_trackers_path_loads_full_map(fake_full_map: Path) -> None:
    local = TrackerResolver(psl_path=resolver_module.DEFAULT_PSL_PATH)
    att = local.classify("cdn." + _FAKE_FULL_HOST)
    assert (att.owner, att.category, att.party) == ("X", "analytics", "third")
    # Only the fake full map was loaded, not the seed.
    assert local.classify("www.google-analytics.com").owner is None


def test_explicit_trackers_path_wins_over_full_map(fake_full_map: Path, tmp_path) -> None:
    explicit = _write_tracker_map(tmp_path / "explicit.json", "explicit-zz.com", "Y", "cdn")
    local = TrackerResolver(trackers_path=explicit, psl_path=resolver_module.DEFAULT_PSL_PATH)
    assert local.classify("explicit-zz.com").owner == "Y"
    assert local.classify(_FAKE_FULL_HOST).owner is None


def test_tracker_radar_updater_writes_local_only_full_map() -> None:
    # The updater only defines things at import time (network use is in main()).
    script = Path(__file__).resolve().parents[3] / "dev" / "update_tracker_radar.py"
    if not script.is_file():
        pytest.skip("dev/update_tracker_radar.py not present")
    spec = importlib.util.spec_from_file_location("_update_tracker_radar_under_test", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.TRACKERS_PATH.name == "trackers_full.json"
