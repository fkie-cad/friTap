"""Unit tests for the reusable findings filtering layer.

Covers :class:`friTap.analysis.filtering.FindingFilter` (per-criterion and
combined), :func:`apply`, :func:`summarize`, :func:`with_category`, and the
backward-compatibility of the ``_filter_min_severity`` wrapper.
"""

from __future__ import annotations

from friTap.analysis import Finding, Severity
from friTap.analysis.filtering import (
    FindingFilter,
    apply,
    summarize,
    with_category,
)


def _f(severity, source, category=None, confidence=1.0, title="t", description="d", evidence=None):
    meta = {"category": category} if category else {}
    return Finding(
        severity=severity,
        title=title,
        description=description,
        source=source,
        confidence=confidence,
        evidence=evidence or {},
        metadata=meta,
    )


def _sample():
    return [
        _f(Severity.CRITICAL, "credentials", "secret", 1.0, title="Basic auth"),
        _f(Severity.LOW, "privacy", "pii", 0.7, title="Email", evidence={"value": "a@b.com"}),
        _f(Severity.INFO, "ioc", "network", 1.0, title="Dest IP"),
        _f(Severity.MEDIUM, "privacy", "pii", 0.45, title="Geolocation"),
    ]


# --- per-criterion ---------------------------------------------------------

def test_empty_filter_matches_all():
    findings = _sample()
    assert apply(findings, FindingFilter()) == findings
    assert apply(findings, None) == findings


def test_min_severity_floor():
    out = apply(_sample(), FindingFilter(min_severity="medium"))
    titles = {f.title for f in out}
    assert titles == {"Basic auth", "Geolocation"}


def test_unknown_min_severity_keeps_all():
    out = apply(_sample(), FindingFilter(min_severity="bogus"))
    assert len(out) == 4


def test_sources_filter():
    out = apply(_sample(), FindingFilter(sources=frozenset({"credentials"})))
    assert [f.title for f in out] == ["Basic auth"]


def test_categories_filter():
    out = apply(_sample(), FindingFilter(categories=frozenset({"pii"})))
    assert {f.title for f in out} == {"Email", "Geolocation"}


def test_uncategorized_bucket():
    f = _f(Severity.INFO, "x")  # no category
    out = apply([f], FindingFilter(categories=frozenset({"uncategorized"})))
    assert out == [f]


def test_min_confidence_filter():
    out = apply(_sample(), FindingFilter(min_confidence=0.7))
    assert {f.title for f in out} == {"Basic auth", "Email", "Dest IP"}


def test_text_filter_matches_title_and_evidence():
    out = apply(_sample(), FindingFilter(text="EMAIL"))
    assert [f.title for f in out] == ["Email"]
    # Evidence substring match (case-insensitive).
    out2 = apply(_sample(), FindingFilter(text="a@b.com"))
    assert [f.title for f in out2] == ["Email"]


# --- combined (AND) --------------------------------------------------------

def test_combined_criteria_and():
    flt = FindingFilter(
        min_severity="low",
        sources=frozenset({"privacy"}),
        categories=frozenset({"pii"}),
        min_confidence=0.5,
    )
    out = apply(_sample(), flt)
    assert [f.title for f in out] == ["Email"]  # Geolocation drops on confidence 0.45


# --- summarize -------------------------------------------------------------

def test_summarize_shape():
    s = summarize(_sample())
    assert s["total"] == 4
    assert s["by_severity"] == {"critical": 1, "low": 1, "info": 1, "medium": 1}
    assert s["by_source"] == {"credentials": 1, "privacy": 2, "ioc": 1}
    assert s["by_category"] == {"secret": 1, "pii": 2, "network": 1}


def test_summarize_uncategorized():
    s = summarize([_f(Severity.INFO, "x")])
    assert s["by_category"] == {"uncategorized": 1}


# --- with_category ---------------------------------------------------------

def test_with_category_sets_metadata():
    f = _f(Severity.INFO, "ioc")
    tagged = with_category(f, "network", compliance=["GDPR"], cwe="CWE-200")
    assert tagged.category == "network"
    assert tagged.metadata["compliance"] == ["GDPR"]
    assert tagged.metadata["cwe"] == "CWE-200"
    # Original is untouched (frozen + copy).
    assert f.category is None


def test_with_category_does_not_clobber_existing():
    f = _f(Severity.LOW, "privacy", category="pii")
    tagged = with_category(f, "network")
    assert tagged.category == "pii"  # existing category preserved


# --- backward-compat of _filter_min_severity wrapper -----------------------

def test_filter_min_severity_wrapper_parity():
    from friTap.commands.analyze import _filter_min_severity, _SEVERITY_ORDER

    findings = _sample()
    for threshold in list(_SEVERITY_ORDER) + ["bogus"]:
        normalized = threshold if threshold in _SEVERITY_ORDER else "info"
        expected = [
            f for f in findings
            if _SEVERITY_ORDER.get(f.severity.value, _SEVERITY_ORDER["info"])
            <= _SEVERITY_ORDER[normalized]
        ]
        assert _filter_min_severity(findings, threshold) == expected


# --- category property is not a dataclass field ----------------------------

def test_category_is_property_not_field():
    import dataclasses

    field_names = {f.name for f in dataclasses.fields(Finding)}
    assert "category" not in field_names  # must stay a property, not a field
    # Round-trips through serialization via metadata.
    f = _f(Severity.LOW, "privacy", category="pii")
    restored = Finding.from_dict(f.to_dict())
    assert restored.category == "pii"
