"""Unit tests for Finding.from_dict severity coercion.

Pure Python — no device/Frida/tshark. Ensures Finding.from_dict is total over
arbitrary input: unknown or empty severity strings (e.g. from a .tap written by
a different friTap version, hand-edited, or a future analyzer) must not raise.
"""

import dataclasses

from friTap.analysis import Finding, Severity


def test_to_dict_covers_every_dataclass_field():
    """#34: to_dict is derived from the dataclass, so every field appears.

    Guards the maintainability fix — adding a new Finding field should not
    require editing to_dict/from_dict in three places.
    """
    finding = Finding(Severity.LOW, "t", "d", "s")
    serialized = finding.to_dict()
    field_names = {f.name for f in dataclasses.fields(Finding)}
    assert field_names == set(serialized), (
        "to_dict must expose exactly the dataclass fields"
    )
    # severity is serialized as its string value, not the enum.
    assert serialized["severity"] == "low"


def test_full_round_trip_preserves_all_fields():
    """A fully-populated Finding survives to_dict/from_dict unchanged (#34)."""
    original = Finding(
        severity=Severity.CRITICAL,
        title="title",
        description="desc",
        source="src",
        flow_id="flow-9",
        confidence=0.42,
        timestamp=1234.5,
        evidence={"matched": "secret", "nested": {"k": [1, 2]}},
        metadata={"cve": "CVE-2026-0001"},
    )
    restored = Finding.from_dict(original.to_dict())
    assert restored == original


def test_from_dict_ignores_unknown_keys():
    """Unknown keys are ignored rather than passed to the constructor (#34)."""
    finding = Finding.from_dict(
        {"severity": "high", "title": "t", "bogus_field": "x", "extra": 1}
    )
    assert finding.severity is Severity.HIGH
    assert finding.title == "t"


def test_from_dict_unknown_severity_falls_back_to_info():
    """An unknown severity value coerces to INFO instead of raising ValueError."""
    finding = Finding.from_dict({"severity": "warning", "title": "t"})
    assert finding.severity is Severity.INFO


def test_from_dict_empty_severity_falls_back_to_info():
    """An empty severity string coerces to INFO instead of raising ValueError."""
    finding = Finding.from_dict({"severity": "", "title": "t"})
    assert finding.severity is Severity.INFO


def test_from_dict_valid_severity_round_trips():
    """A valid severity survives a to_dict / from_dict round trip unchanged."""
    original = Finding(
        severity=Severity.HIGH,
        title="title",
        description="desc",
        source="src",
    )
    restored = Finding.from_dict(original.to_dict())
    assert restored.severity is Severity.HIGH
    assert restored.title == "title"
    assert restored.description == "desc"
    assert restored.source == "src"
