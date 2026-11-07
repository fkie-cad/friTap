"""Tests for the OWASP MASVS v2.1 finding->control mapping."""

from __future__ import annotations

from friTap.analysis import Finding, Severity
from friTap.analysis.masvs import MASVS_CONTROLS, classify_masvs


def _finding(category, *, title="x", description="y", check=None):
    metadata = {"category": category}
    if check is not None:
        metadata["check"] = check
    return Finding(severity=Severity.MEDIUM, title=title, description=description,
                   source="test", metadata=metadata)


def test_weak_cipher_maps_to_network_and_crypto():
    controls = classify_masvs(_finding("network", check="weak_cipher"))
    assert controls == ["MASVS-CRYPTO-1", "MASVS-NETWORK-1"]


def test_cleartext_maps_to_network():
    assert classify_masvs(_finding("network", check="cleartext_transport")) == ["MASVS-NETWORK-1"]


def test_weak_tls_version_maps_to_network():
    assert classify_masvs(_finding("network", check="weak_tls_version")) == ["MASVS-NETWORK-1"]


def test_plain_network_ioc_has_no_control():
    assert classify_masvs(_finding("network")) == []


def test_protocol_finding_has_no_control():
    assert classify_masvs(_finding("protocol")) == []


def test_secret_defaults_to_crypto():
    assert classify_masvs(_finding("secret", title="AWS secret key")) == ["MASVS-CRYPTO-1"]


def test_secret_auth_token_adds_auth():
    controls = classify_masvs(_finding("secret", title="Bearer token in Authorization header"))
    assert controls == ["MASVS-AUTH-1", "MASVS-CRYPTO-1"]


def test_jwt_secret_adds_auth():
    controls = classify_masvs(_finding("secret", title="JWT with alg=none"))
    assert "MASVS-AUTH-1" in controls


def test_pii_defaults_to_privacy_1():
    assert classify_masvs(_finding("pii", title="Email address in body")) == ["MASVS-PRIVACY-1"]


def test_device_identifier_pii_adds_privacy_2():
    controls = classify_masvs(_finding("pii", title="Advertising ID (AAID) leaked"))
    assert controls == ["MASVS-PRIVACY-1", "MASVS-PRIVACY-2"]


def test_uncategorized_finding_has_no_control():
    assert classify_masvs(Finding(severity=Severity.INFO, title="t", description="d",
                                   source="s")) == []


def test_referenced_controls_are_documented():
    # Every control the mapper can emit must appear in the human-readable table.
    emitted = set()
    for cat, check in (("network", "weak_cipher"), ("network", "cleartext_transport"),
                       ("secret", None), ("pii", None)):
        emitted.update(classify_masvs(_finding(cat, title="Bearer AAID", check=check)))
    assert emitted <= set(MASVS_CONTROLS)
