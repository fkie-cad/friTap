"""Unit tests for the PrivacyAnalyzer (PII detection).

Pure Python — no device/Frida/tshark. Covers positive + negative detection
cases, redaction defaults vs. reveal_pii, metadata round-tripping, and registry
resolution. The HTTP-flow helper mirrors test_analysis_exposure so bodies are
reconstructed from raw chunks through the de-dup path the analyzer runs against.
"""

import json

from friTap.analysis import Finding, Severity
from friTap.analysis.privacy import PrivacyAnalyzer, _iban_ok, _luhn
from friTap.analysis.registry import resolve_analyzers
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.parsers.base import ParseResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_http_flow(
    body_bytes: bytes,
    *,
    flow_id: str = "flow-1",
    headers: dict | None = None,
    method: str = "POST",
    host: str = "api.example.com",
    url: str = "/upload",
    content_type: str = "text/plain",
) -> Flow:
    """Build an HTTP/1.1 request Flow whose body is recoverable from chunks."""
    hdrs = dict(headers or {})
    all_headers = {"Host": host, "Content-Type": content_type, **hdrs}
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in all_headers.items())
    request_bytes = (
        f"{method} {url} HTTP/1.1\r\n"
        f"{header_lines}"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"\r\n"
    ).encode("utf-8") + body_bytes

    flow = Flow(
        flow_id=flow_id,
        connection_id="conn-1",
        src_addr="10.0.0.2",
        src_port=51000,
        dst_addr="93.184.216.34",
        dst_port=443,
        state=FlowState.COMPLETE,
        started=1000.0,
        ended=1001.0,
    )
    flow.request = ParseResult(
        protocol="HTTP/1.1",
        method=method,
        url=url,
        host=host,
        headers={**all_headers, "Content-Length": str(len(body_bytes))},
        body=b"",
        content_type=content_type,
        is_request=True,
        is_complete=True,
    )
    flow.chunks.append(FlowChunk(
        data=request_bytes,
        direction="write",
        timestamp=1000.0,
        function="SSL_write",
    ))
    flow._total_bytes = len(request_bytes)
    return flow


def _make_json_flow(payload: dict, *, flow_id="flow-json", host="api.example.com") -> Flow:
    """Build a JSON-bodied request flow."""
    body = json.dumps(payload).encode("utf-8")
    return _make_http_flow(
        body, flow_id=flow_id, host=host, content_type="application/json"
    )


def _categories(findings) -> set[str]:
    return {f.metadata.get("category_pii") or f.evidence.get("category") for f in findings}


def _of_type(findings, pii_type):
    return [f for f in findings if f.evidence.get("category") == pii_type]


# ---------------------------------------------------------------------------
# Module-level validators
# ---------------------------------------------------------------------------

def test_luhn():
    assert _luhn("4111111111111111")        # Visa test
    assert _luhn("378282246310005")         # Amex test
    assert _luhn("490154203237518")         # IMEI test
    assert not _luhn("4111111111111112")
    assert not _luhn("")
    assert not _luhn("abc")


def test_iban_ok():
    assert _iban_ok("DE89370400440532013000")
    assert _iban_ok("DE89 3704 0044 0532 0130 00")
    assert not _iban_ok("DE00370400440532013000")
    assert not _iban_ok("XX")


# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------

def _assert_redaction(findings, pii_type, raw_value):
    """The raw value must never be in the description, and evidence is redacted."""
    matched = _of_type(findings, pii_type)
    assert matched, f"expected a {pii_type} finding"
    for f in matched:
        assert raw_value not in f.description, f"raw value leaked in description for {pii_type}"
        assert f.evidence.get("redacted") is True
        assert f.evidence.get("value") != raw_value, f"value not redacted for {pii_type}"
    return matched


def test_visa_pan():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"card=4111111111111111", flow_id="visa")
    findings = a.analyze_flow(f)
    m = _assert_redaction(findings, "credit_card_pan", "4111111111111111")
    assert all(x.severity == Severity.HIGH for x in m)
    assert "PCI-DSS" in m[0].metadata["compliance"]


def test_amex_pan():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"card=378282246310005", flow_id="amex")
    findings = a.analyze_flow(f)
    _assert_redaction(findings, "credit_card_pan", "378282246310005")


def test_iban():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"iban=DE89370400440532013000", flow_id="iban")
    findings = a.analyze_flow(f)
    m = _assert_redaction(findings, "iban", "DE89370400440532013000")
    assert all(x.severity == Severity.MEDIUM for x in m)


def test_iban_with_spaces():
    # Regression: real IBANs are commonly displayed space-grouped; the pattern
    # must match them (``_iban_ok`` strips the spaces before mod-97).
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"iban=DE89 3704 0044 0532 0130 00", flow_id="iban-spaced")
    findings = a.analyze_flow(f)
    assert _of_type(findings, "iban"), "spaced IBAN should be detected"


def test_imei():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"imei=490154203237518", flow_id="imei")
    findings = a.analyze_flow(f)
    _assert_redaction(findings, "imei", "490154203237518")


def test_geolocation_boundary_float_not_rejected():
    # Regression: 90.0/180.0 are valid boundary coordinates and must not be
    # rejected as "integer-only" just because their fractional part is zero.
    a = PrivacyAnalyzer()
    f = _make_json_flow({"lat": 90.0, "lon": 180.0}, flow_id="geo-boundary")
    assert _of_type(a.analyze_flow(f), "geolocation"), "boundary float coords should detect"


def test_geolocation_integer_ids_rejected():
    # Integer-valued lat/lon (no decimal point in source) are likely IDs, not a fix.
    a = PrivacyAnalyzer()
    f = _make_json_flow({"lat": 52, "lon": 13}, flow_id="geo-int")
    assert not _of_type(a.analyze_flow(f), "geolocation"), "integer coords should be rejected"


def test_e164_phone():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"x=+14155552671", flow_id="e164")
    findings = a.analyze_flow(f)
    _assert_redaction(findings, "phone_e164", "+14155552671")


def test_loose_phone_under_key():
    # phone_loose has confidence 0.4 (< the 0.5 floor) so it only surfaces in
    # verbose mode by design; non-verbose suppresses it.
    a = PrivacyAnalyzer(verbose=True)
    f = _make_json_flow({"phone": "(415) 555-2671"}, flow_id="phone")
    findings = a.analyze_flow(f)
    m = _of_type(findings, "phone_loose")
    assert m, [x.evidence.get("category") for x in findings]
    # Non-verbose suppresses it (confidence floor).
    assert not _of_type(
        PrivacyAnalyzer().analyze_flow(_make_json_flow({"phone": "(415) 555-2671"}, flow_id="p2")),
        "phone_loose",
    )


def test_email_in_body():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"contact alice@example.com here", flow_id="email")
    findings = a.analyze_flow(f)
    _assert_redaction(findings, "email", "alice@example.com")


# A genuine v4 UUID (version nibble == 4, variant nibble in [89ab]).
_GAID_V4 = "f47ac10b-58cc-4372-a567-0e02b2c3d479"


def test_gaid_uuid():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"gaid": _GAID_V4}, flow_id="gaid")
    findings = a.analyze_flow(f)
    m = _of_type(findings, "advertising_id")
    assert m
    assert all(x.severity == Severity.MEDIUM for x in m)


def test_mac_address():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"mac 01:23:45:67:89:ab present", flow_id="mac")
    findings = a.analyze_flow(f)
    _assert_redaction(findings, "mac_address", "01:23:45:67:89:ab")


def test_ssn():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"ssn 123-45-6789 record", flow_id="ssn")
    findings = a.analyze_flow(f)
    m = _of_type(findings, "ssn_us")
    assert m
    assert all(x.severity == Severity.MEDIUM for x in m)


def test_geolocation_keyed():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"lat": 52.520, "lng": 13.405}, flow_id="geo")
    findings = a.analyze_flow(f)
    m = _of_type(findings, "geolocation")
    assert m
    assert all(x.severity == Severity.MEDIUM for x in m)


def test_dob():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"dob": "1985-07-12"}, flow_id="dob")
    findings = a.analyze_flow(f)
    m = _assert_redaction(findings, "date_of_birth", "1985-07-12")
    assert all(x.severity == Severity.MEDIUM for x in m)


def test_passport():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"passport": "X1234567"}, flow_id="passport")
    findings = a.analyze_flow(f)
    _assert_redaction(findings, "passport", "X1234567")


def test_health_hipaa():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"diagnosis": "E11.9"}, flow_id="health")
    findings = a.analyze_flow(f)
    m = _of_type(findings, "health")
    assert m
    assert all(x.severity == Severity.HIGH for x in m)
    assert "HIPAA" in m[0].metadata["compliance"]


def test_ip_in_xff_header():
    a = PrivacyAnalyzer()
    # 8.8.8.8 is a genuinely public/routable IP (203.0.113.x is reserved
    # TEST-NET-3, which Python's ipaddress treats as private).
    f = _make_http_flow(
        b"", flow_id="xff", headers={"X-Forwarded-For": "8.8.8.8"}
    )
    findings = a.analyze_flow(f)
    m = _of_type(findings, "ip_pii")
    assert m
    assert m[0].evidence["value"] != "8.8.8.8"  # redacted


def test_reveal_pii_stores_raw():
    a = PrivacyAnalyzer(reveal_pii=True)
    f = _make_http_flow(b"contact alice@example.com", flow_id="reveal")
    findings = a.analyze_flow(f)
    m = _of_type(findings, "email")
    assert m
    assert any(x.evidence["value"] == "alice@example.com" for x in m)
    assert all(x.evidence["redacted"] is False for x in m)
    # Description still must not contain the raw value.
    assert all("alice@example.com" not in x.description for x in m)


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

def test_luhn_fail_pan_not_detected():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"card=4111111111111112", flow_id="luhnfail")
    assert not _of_type(a.analyze_flow(f), "credit_card_pan")


def test_non_iin_luhn_valid_not_detected():
    a = PrivacyAnalyzer()
    # Luhn-valid 16-digit number starting with 1 (no known IIN).
    # 1234567812345670 is Luhn-valid.
    f = _make_http_flow(b"card=1234567812345670", flow_id="noniin")
    assert not _of_type(a.analyze_flow(f), "credit_card_pan")


def test_all_same_digit_not_detected():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"card=0000000000000000", flow_id="zeros")
    assert not _of_type(a.analyze_flow(f), "credit_card_pan")


def test_bad_iban_not_detected():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"iban=DE00370400440532013000", flow_id="badiban")
    assert not _of_type(a.analyze_flow(f), "iban")


def test_non_luhn_imei_not_detected():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"imei=490154203237519", flow_id="badimei")
    assert not _of_type(a.analyze_flow(f), "imei")


def test_bare_uuid_under_request_id_not_ad():
    a = PrivacyAnalyzer()
    f = _make_json_flow(
        {"request_id": _GAID_V4}, flow_id="reqid"
    )
    assert not _of_type(a.analyze_flow(f), "advertising_id")


def test_broadcast_mac_not_detected():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"mac ff:ff:ff:ff:ff:ff bcast", flow_id="bcast")
    assert not _of_type(a.analyze_flow(f), "mac_address")


def test_version_not_dob():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"version": "1.2.3"}, flow_id="ver")
    assert not _of_type(a.analyze_flow(f), "date_of_birth")


def test_geo_zero_zero_not_detected():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"lat": 0, "lon": 0}, flow_id="geozero")
    assert not _of_type(a.analyze_flow(f), "geolocation")


def test_geo_integer_only_not_detected():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"lat": 52, "lon": 13}, flow_id="geoint")
    assert not _of_type(a.analyze_flow(f), "geolocation")


# --- geohash / Plus Code / common-key geolocation ---------------------------

def test_geo_coordinates_array():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"coordinates": [13.405, 52.520]}, flow_id="geoarr")
    assert _of_type(a.analyze_flow(f), "geolocation"), "numeric coord array should detect"


def test_geo_common_key_string_pair():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"location": "48.8584,2.2945"}, flow_id="geokey")
    assert _of_type(a.analyze_flow(f), "geolocation")


def test_geohash_under_explicit_key():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"geohash": "u33dc0cpke"}, flow_id="ghash")
    m = _of_type(a.analyze_flow(f), "geolocation")
    assert m and m[0].evidence.get("context", "").endswith("geohash")


def test_plus_code_under_key():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"plus_code": "849VCWC8+R9"}, flow_id="plus1")
    assert _of_type(a.analyze_flow(f), "geolocation")


def test_plus_code_in_free_text():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"meet at 8FVC9G8F+6X tonight", flow_id="plus2")
    m = _of_type(a.analyze_flow(f), "geolocation")
    assert m and m[0].evidence.get("context") == "plus_code"


# FP guards for the new encodings

def test_geohash_not_detected_in_free_text():
    # A bare geohash-shaped token with no geohash key must NOT fire.
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"session token u33dc0cpke here", flow_id="ghashfp")
    assert not _of_type(a.analyze_flow(f), "geolocation")


def test_geohash_charset_word_under_generic_geo_key_not_detected():
    # 'secret' is in the geohash alphabet but must not be read as a geohash
    # under a generic geo key (geohash only trusted under an explicit key).
    a = PrivacyAnalyzer()
    f = _make_json_flow({"geo": "secret"}, flow_id="ghashfp2")
    assert not _of_type(a.analyze_flow(f), "geolocation")


def test_common_key_non_coordinate_value_not_detected():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"location": "Berlin, Germany"}, flow_id="geofp")
    assert not _of_type(a.analyze_flow(f), "geolocation")


def test_integer_coordinate_array_not_detected():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"coordinates": [1, 2]}, flow_id="geoarrfp")
    assert not _of_type(a.analyze_flow(f), "geolocation")


def test_dashless_not_ssn():
    a = PrivacyAnalyzer()
    f = _make_http_flow(b"id 123456789 here", flow_id="dashless")
    assert not _of_type(a.analyze_flow(f), "ssn_us")


def test_single_city_key_not_address():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"city": "Berlin"}, flow_id="city")
    assert not _of_type(a.analyze_flow(f), "postal_address")


# ---------------------------------------------------------------------------
# Metadata round-trip + registry
# ---------------------------------------------------------------------------

def test_metadata_round_trip():
    a = PrivacyAnalyzer()
    f = _make_json_flow({"diagnosis": "E11.9"}, flow_id="rt")
    findings = a.analyze_flow(f)
    health = _of_type(findings, "health")[0]
    restored = Finding.from_dict(health.to_dict())
    assert restored.category == "pii"
    assert restored.metadata["compliance"] == health.metadata["compliance"]
    assert restored.evidence["category"] == "health"


def test_registry_resolution():
    resolved = resolve_analyzers("privacy")
    assert len(resolved) == 1
    assert resolved[0].name == "privacy"


def test_confidence_floor_drops_low():
    """Non-verbose drops <0.5 confidence (postal_address at 0.4); verbose keeps it."""
    payload = {"street": "Main St 1", "city": "Berlin", "zip": "10115"}
    default = PrivacyAnalyzer().analyze_flow(_make_json_flow(payload, flow_id="pa1"))
    assert not _of_type(default, "postal_address")
    verbose = PrivacyAnalyzer(verbose=True).analyze_flow(_make_json_flow(payload, flow_id="pa2"))
    assert _of_type(verbose, "postal_address")
