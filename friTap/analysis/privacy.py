"""
PrivacyAnalyzer — detect personally identifiable information (PII) in HTTP flows.

Scans HTTP headers, request/response bodies (JSON + form-encoded), the URL
path and query string for personal data that has privacy / compliance
implications. Detections are deliberately conservative: free-text regex matches
are gated either by a known PII context (header name, JSON key, form field,
query parameter) or by an algorithmic check (Luhn for cards/IMEI, mod-97 for
IBAN) so the default-on noise stays bounded.

Detected categories (see the taxonomy table in the project docs):
  - email, phone_e164, phone_loose
  - credit_card_pan (Luhn + IIN), iban (mod-97), ssn_us, imei (Luhn)
  - mac_address, android_id, advertising_id, ip_pii
  - geolocation, postal_address, date_of_birth, passport, health

``geolocation`` covers: sibling lat/lon keys; a lat/lon pair or numeric array
under a geo-ish key (coordinates/geo/position/location/...); Plus Codes / Open
Location Codes (the ``+``-separated form, also matched in free text); and
geohashes (only under an explicit ``geohash`` key — a bare geohash is
indistinguishable from an ordinary token, so it is never matched in free text).

Raw values are redacted by default and never appear in a finding's
``description``. Set ``reveal_pii=True`` to store the raw value in evidence
(still kept out of the description).
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from friTap.analysis import Finding, Severity
from friTap.analysis.filtering import with_category
# Reuse the IOC analyzer's vetted primitives rather than redefining them.
from friTap.analysis.ioc import _EMAIL_PATTERN, _IPV4_PATTERN, _is_private_ip

if TYPE_CHECKING:
    from friTap.flow.models import Flow


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# E.164: leading '+', no leading zero, total 8-15 digits.
_PHONE_E164_PATTERN = re.compile(r"\+[1-9]\d{7,14}\b")

# Loose phone: only trusted when the surrounding key is phone-ish.
_PHONE_LOOSE_PATTERN = re.compile(r"[+(]?\d[\d\s().\-]{6,18}\d")
_PHONE_KEY_HINTS = ("phone", "tel", "mobile", "msisdn", "contact")

# Credit-card candidate: 13-19 digits, optionally separated by space/dash.
_PAN_CANDIDATE_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# IBAN: country code + 2 check digits + 11-30 BBAN chars, optionally grouped in
# space-separated blocks (the common display form, e.g. "DE89 3704 0044 ...").
# ``_iban_ok`` strips the spaces and enforces the real length + mod-97 check, so
# the pattern can afford to be permissive about internal whitespace.
_IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,32}\b")
# Whitespace-stripped structural check used by _iban_ok (compiled once).
_IBAN_STRUCTURE_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]+$")

# US SSN, dashed form only, with the standard invalid-range exclusions.
_SSN_PATTERN = re.compile(
    r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
)

# IMEI: 15 digits, word-bounded, Luhn-validated downstream.
_IMEI_PATTERN = re.compile(r"\b\d{15}\b")

# MAC address: six hex pairs separated by ':' or '-'.
_MAC_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

# UUID v4 (advertising IDs).
_UUID_V4_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}"
    r"-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)

# 16-hex Android ID value.
_ANDROID_ID_PATTERN = re.compile(r"\b[0-9a-fA-F]{16}\b")

# Loose "lat,lon" decimal pair (both with >=3 fractional digits).
_GEO_PAIR_PATTERN = re.compile(
    r"-?\d{1,3}\.\d{3,},\s*-?\d{1,3}\.\d{3,}"
)

# Geohash: base-32 alphabet that excludes a/i/l/o. It has no internal structure,
# so it is only trusted under an explicit geohash-named key (never free text).
# Length 5-12 covers the useful precision range.
_GEOHASH_VALUE_RE = re.compile(r"\A[0-9bcdefghjkmnpqrstuvwxyz]{5,12}\Z")

# Open Location Code / Plus Code. The '+' separator plus a restricted 20-char
# alphabet (no vowels, no easily-confused letters) make the full 8+2/3 form
# specific enough to detect in free text.
_PLUSCODE_FULL_RE = re.compile(r"\b[23456789CFGHJMPQRVWX]{8}\+[23456789CFGHJMPQRVWX]{2,3}\b")
# Under an explicit geo key, also accept "short" codes (locality-relative): an
# even 4/6/8-char prefix is canonical, but we allow 4-8 for robustness.
_PLUSCODE_KEYED_RE = re.compile(r"\A[23456789CFGHJMPQRVWX]{4,8}\+[23456789CFGHJMPQRVWX]{2,3}\Z")

# ICD-10 diagnosis code.
_ICD10_PATTERN = re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,2})?\b")

# Date formats accepted for date-of-birth.
_DOB_PATTERNS = (
    re.compile(r"^(\d{4})-(\d{2})-(\d{2})$"),          # YYYY-MM-DD
    re.compile(r"^(\d{2})\.(\d{2})\.(\d{4})$"),        # DD.MM.YYYY
    re.compile(r"^(\d{2})/(\d{2})/(\d{4})$"),          # MM/DD/YYYY
)

_PASSPORT_PATTERN = re.compile(r"^[A-Za-z0-9]{6,9}$")


# ---------------------------------------------------------------------------
# Context key hints (lower-cased comparisons)
# ---------------------------------------------------------------------------

_ANDROID_ID_KEYS = ("android_id",)
_AD_ID_KEYS = ("gaid", "idfa", "advertising_id", "adid", "idfv")
_AD_HOSTS = ("doubleclick", "adjust", "appsflyer", "googleadservices")
_IP_KEYS = ("ip", "client_ip", "user_ip", "remote_addr")
_IP_HEADERS = ("x-forwarded-for", "x-real-ip", "forwarded")
_LAT_KEYS = ("lat", "latitude")
_LON_KEYS = ("lon", "lng", "long", "longitude")
# Keys whose VALUE may pack a whole location (coord pair / Plus Code / geohash).
# The value is always validated, so broad keys like "location"/"position" can be
# included without false-positives on non-coordinate values.
_GEO_EXACT_KEYS = frozenset({
    "geo", "geoloc", "geolocation", "position", "location", "loc",
    "coordinates", "coordinate", "coords", "plus_code", "pluscode", "olc",
    "open_location_code",
})
# Substrings that strongly imply a geo value even inside a compound key name.
_GEO_STRONG_TOKENS = ("coord", "latlng", "latlon", "geopoint", "geo_point", "gps")
# Keys that explicitly hold a geohash (only context where a geohash is trusted).
_GEOHASH_KEYS = ("geohash", "geo_hash", "ghash")
_STREET_KEYS = ("street", "address", "addr", "address_line", "address1", "strasse", "straße")
_CITY_KEYS = ("city", "town", "stadt", "ort")
_ZIP_KEYS = ("zip", "zipcode", "postal", "postal_code", "postcode", "plz")
_DOB_KEYS = ("dob", "birth", "birthdate", "birthday", "geburtsdatum", "date_of_birth")
_PASSPORT_KEYS = ("passport", "passport_no", "passport_number")
_HEALTH_KEYS = ("diagnosis", "icd10", "icd_10", "prescription", "blood_type", "medical_record")


# ---------------------------------------------------------------------------
# Module-level validators
# ---------------------------------------------------------------------------

def _luhn(digits: str) -> bool:
    """Return ``True`` if *digits* (a string of digits) passes the Luhn check."""
    if not digits or not digits.isdigit():
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_ok(s: str) -> bool:
    """Validate an IBAN via the ISO 7064 mod-97 check (==1)."""
    s = s.replace(" ", "").upper()
    if len(s) < 15 or len(s) > 34:
        return False
    if not _IBAN_STRUCTURE_RE.match(s):
        return False
    # Move the first four chars to the end, then map letters to numbers.
    rearranged = s[4:] + s[:4]
    digits = "".join(
        str(ord(ch) - 55) if ch.isalpha() else ch
        for ch in rearranged
    )
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


def _redact_pii(value: str, category: str) -> str:
    """Redact a PII value according to its category.

    PAN -> first6+last4, email -> first char + domain, phone -> country code +
    last2, ssn/dob/passport/national/health -> "****", everything else uses the
    credentials-style ``value[:8]+"****"`` shape.
    """
    if category == "credit_card_pan":
        digits = re.sub(r"[ -]", "", value)
        if len(digits) >= 10:
            return digits[:6] + "*" * (len(digits) - 10) + digits[-4:]
        return "****"

    if category == "email":
        local, _, domain = value.partition("@")
        if local and domain:
            return f"{local[0]}***@{domain}"
        return "****"

    if category in ("phone_e164", "phone_loose"):
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 4:
            cc = value[:3] if value.startswith("+") else digits[:2]
            return f"{cc}***{digits[-2:]}"
        return "****"

    if category in ("ssn_us", "date_of_birth", "passport", "health"):
        return "****"

    if len(value) <= 8:
        return "****"
    return value[:8] + "****"


class PrivacyAnalyzer:
    """Analyzer that detects personally identifiable information in HTTP flows."""

    name = "privacy"

    def __init__(self, *, reveal_pii: bool = False, verbose: bool = False) -> None:
        self._reveal_pii = reveal_pii
        self._verbose = verbose

    # -- public entry point -------------------------------------------------

    def analyze_flow(self, flow: "Flow") -> list[Finding]:
        findings: list[Finding] = []
        # De-dup per (category, value) within a single flow.
        seen: set[tuple[str, str]] = set()

        req_body = flow.get_decompressed_request_body() if flow.request else b""
        resp_body = flow.get_decompressed_response_body() if flow.response else b""

        self._check_headers(flow, findings, seen)
        self._check_url(flow, findings, seen)
        self._check_body(flow, req_body, flow.request_content_type, "request_body", findings, seen)
        self._check_body(flow, resp_body, flow.response_content_type, "response_body", findings, seen)

        # Confidence floor: drop low-confidence emissions unless verbose.
        if not self._verbose:
            findings = [f for f in findings if f.confidence >= 0.5]
        return findings

    # -- finding construction ----------------------------------------------

    def _emit(
        self,
        flow: "Flow",
        findings: list[Finding],
        seen: set[tuple[str, str]],
        *,
        category: str,
        value: str,
        severity: Severity,
        confidence: float,
        compliance: list[str],
        location: str,
        context: str = "",
    ) -> None:
        """Build a categorized PII Finding, de-duping per (category, value)."""
        key = (category, value)
        if key in seen:
            return
        seen.add(key)

        if self._reveal_pii:
            stored_value = value
            redacted = False
        else:
            stored_value = _redact_pii(value, category)
            redacted = True

        ctx = f" ({context})" if context else ""
        description = (
            f"PII of type '{category}' detected in {location}{ctx} "
            f"for {flow.display_host}"
        )

        finding = Finding(
            severity=severity,
            title=f"PII: {category}",
            description=description,
            source=self.name,
            flow_id=flow.flow_id,
            confidence=confidence,
            evidence={
                "category": category,
                "location": location,
                "context": context,
                "value": stored_value,
                "redacted": redacted,
                "host": flow.display_host,
            },
        )
        findings.append(with_category(finding, category="pii", compliance=compliance, extra_metadata={"pii_type": category}))

    # -- headers ------------------------------------------------------------

    def _check_headers(self, flow: "Flow", findings: list[Finding], seen) -> None:
        if flow.request is not None:
            for name, value in flow.request.headers.items():
                self._scan_header(flow, name, value, "request_header", findings, seen)
        if flow.response is not None:
            for name, value in flow.response.headers.items():
                self._scan_header(flow, name, value, "response_header", findings, seen)

    def _scan_header(self, flow, name, value, location, findings, seen) -> None:
        lower = name.lower()
        # IP in PII-relevant forwarding headers only.
        if lower in _IP_HEADERS:
            for m in _IPV4_PATTERN.finditer(value):
                ip = m.group(0)
                if not _is_private_ip(ip):
                    self._emit(
                        flow, findings, seen,
                        category="ip_pii", value=ip,
                        severity=Severity.LOW, confidence=0.5,
                        compliance=["GDPR", "CCPA"],
                        location=location, context=name,
                    )
        # Generic free-text scans over header values (email/phone_e164).
        self._scan_freetext(flow, value, location, findings, seen, context=name)

    # -- URL ----------------------------------------------------------------

    def _check_url(self, flow: "Flow", findings: list[Finding], seen) -> None:
        if flow.request is None or not flow.request.url:
            return
        url = flow.request.url
        try:
            parsed = urlparse(url)
        except Exception:
            return

        # Free-text over the path.
        if parsed.path:
            self._scan_freetext(flow, parsed.path, "url_path", findings, seen, context="path")

        # Query params get key-aware treatment.
        if parsed.query:
            try:
                params = parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                params = {}
            for key, values in params.items():
                for value in values:
                    if value:
                        self._scan_keyed(flow, key, value, "url_query", findings, seen)
                        self._scan_freetext(flow, value, "url_query", findings, seen, context=key)

    # -- bodies -------------------------------------------------------------

    def _check_body(self, flow, body, content_type, location, findings, seen) -> None:
        if not body:
            return
        # Decode the body once; all three scans below reuse the decoded text.
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return
        ct = (content_type or "").lower()

        if "json" in ct:
            self._scan_json(text, flow, location, findings, seen)
        elif "x-www-form-urlencoded" in ct:
            self._scan_form(text, flow, location, findings, seen)
        else:
            # Only unstructured bodies need a whole-body free-text sweep.
            # Structured bodies (json/form) are already scanned per-value by
            # _scan_keyed, so a second whole-body pass would just re-run every
            # regex over the same text (findings are deduped, so it is pure waste).
            self._scan_freetext(flow, text, location, findings, seen, context="body")

    def _scan_form(self, text, flow, location, findings, seen) -> None:
        params = parse_qs(text, keep_blank_values=True)
        for key, values in params.items():
            for value in values:
                if value:
                    self._scan_keyed(flow, key, value, location, findings, seen)

    def _scan_json(self, text, flow, location, findings, seen) -> None:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return
        self._walk_json(data, flow, location, findings, seen)

    def _walk_json(self, obj, flow, location, findings, seen) -> None:
        """Recursively walk a JSON structure looking for keyed PII + sibling pairs."""
        if isinstance(obj, dict):
            # Object-scoped multi-key heuristics (geo / postal address).
            self._check_geolocation(obj, flow, location, findings, seen)
            self._check_postal_address(obj, flow, location, findings, seen)
            for key, value in obj.items():
                if isinstance(value, str):
                    self._scan_keyed(flow, key, value, location, findings, seen)
                elif isinstance(value, (int, float)) and not isinstance(value, bool):
                    self._scan_keyed(flow, key, str(value), location, findings, seen)
                elif isinstance(value, (dict, list)):
                    self._walk_json(value, flow, location, findings, seen)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._walk_json(item, flow, location, findings, seen)

    # -- keyed (context-gated) detections ----------------------------------

    def _scan_keyed(self, flow, key, value, location, findings, seen) -> None:
        """Run all context-gated detectors for a (key, value) pair."""
        lkey = key.lower()
        sval = value.strip()
        if not sval:
            return

        # Loose phone: only under phone-ish keys.
        if any(h in lkey for h in _PHONE_KEY_HINTS):
            if _PHONE_E164_PATTERN.fullmatch(sval) or _PHONE_LOOSE_PATTERN.fullmatch(sval):
                self._emit(
                    flow, findings, seen,
                    category="phone_loose", value=sval,
                    severity=Severity.LOW, confidence=0.4,
                    compliance=["GDPR", "CCPA"],
                    location=location, context=key,
                )

        # Android ID: only under android_id key.
        if lkey in _ANDROID_ID_KEYS and _ANDROID_ID_PATTERN.fullmatch(sval):
            self._emit(
                flow, findings, seen,
                category="android_id", value=sval,
                severity=Severity.LOW, confidence=0.6,
                compliance=["GDPR", "CCPA"],
                location=location, context=key,
            )

        # Advertising ID: UUID-v4 under an ad key OR an ad host.
        if _UUID_V4_PATTERN.fullmatch(sval):
            if any(k == lkey for k in _AD_ID_KEYS) or self._is_ad_host(flow):
                self._emit(
                    flow, findings, seen,
                    category="advertising_id", value=sval,
                    severity=Severity.MEDIUM, confidence=0.8,
                    compliance=["GDPR", "CCPA"],
                    location=location, context=key,
                )

        # IP in PII context: keys like ip/client_ip/user_ip/remote_addr.
        if lkey in _IP_KEYS:
            for m in _IPV4_PATTERN.finditer(sval):
                ip = m.group(0)
                if not _is_private_ip(ip):
                    self._emit(
                        flow, findings, seen,
                        category="ip_pii", value=ip,
                        severity=Severity.LOW, confidence=0.5,
                        compliance=["GDPR", "CCPA"],
                        location=location, context=key,
                    )

        # Date of birth: keyed only.
        if any(h in lkey for h in _DOB_KEYS):
            if self._is_birth_date(sval):
                self._emit(
                    flow, findings, seen,
                    category="date_of_birth", value=sval,
                    severity=Severity.MEDIUM, confidence=0.6,
                    compliance=["GDPR", "HIPAA"],
                    location=location, context=key,
                )

        # Passport: keyed + alnum 6-9.
        if any(h in lkey for h in _PASSPORT_KEYS):
            if _PASSPORT_PATTERN.fullmatch(sval):
                self._emit(
                    flow, findings, seen,
                    category="passport", value=sval,
                    severity=Severity.MEDIUM, confidence=0.6,
                    compliance=["GDPR"],
                    location=location, context=key,
                )

        # Health: medical key (value), or ICD-10 value under a medical key.
        if any(h == lkey for h in _HEALTH_KEYS):
            self._emit(
                flow, findings, seen,
                category="health", value=sval,
                severity=Severity.HIGH, confidence=0.6,
                compliance=["HIPAA", "GDPR"],
                location=location, context=key,
            )

        # Packed geolocation under a geo-ish key (coord pair / Plus Code, plus
        # geohash under an explicit geohash key). Value is validated, so even
        # broad keys ("location"/"position") don't fire on non-coordinate text.
        self._maybe_emit_geo_value(flow, key, sval, location, findings, seen)

        # Run free-text detectors over the value too (email/cards/iban/etc.).
        self._scan_freetext(flow, sval, location, findings, seen, context=key)

    # -- free-text (self-validating) detections ----------------------------

    def _scan_freetext(self, flow, text, location, findings, seen, *, context="") -> None:
        """Run detectors that validate themselves (no key context required)."""
        if not text:
            return

        # Email.
        for m in _EMAIL_PATTERN.finditer(text):
            self._emit(
                flow, findings, seen,
                category="email", value=m.group(0),
                severity=Severity.LOW, confidence=0.7,
                compliance=["GDPR", "CCPA"],
                location=location, context=context,
            )

        # E.164 phone.
        for m in _PHONE_E164_PATTERN.finditer(text):
            self._emit(
                flow, findings, seen,
                category="phone_e164", value=m.group(0),
                severity=Severity.LOW, confidence=0.6,
                compliance=["GDPR", "CCPA"],
                location=location, context=context,
            )

        # Credit card PAN.
        for m in _PAN_CANDIDATE_PATTERN.finditer(text):
            self._maybe_emit_pan(flow, m.group(0), location, findings, seen, context)

        # IBAN.
        for m in _IBAN_PATTERN.finditer(text):
            candidate = m.group(0)
            if _iban_ok(candidate):
                self._emit(
                    flow, findings, seen,
                    category="iban", value=candidate,
                    severity=Severity.MEDIUM, confidence=0.85,
                    compliance=["GDPR"],
                    location=location, context=context,
                )

        # US SSN (dashed).
        for m in _SSN_PATTERN.finditer(text):
            self._emit(
                flow, findings, seen,
                category="ssn_us", value=m.group(0),
                severity=Severity.MEDIUM, confidence=0.55,
                compliance=["GDPR", "CCPA", "HIPAA"],
                location=location, context=context,
            )

        # IMEI (15-digit + Luhn).
        for m in _IMEI_PATTERN.finditer(text):
            imei = m.group(0)
            if _luhn(imei):
                self._emit(
                    flow, findings, seen,
                    category="imei", value=imei,
                    severity=Severity.MEDIUM, confidence=0.8,
                    compliance=["GDPR", "CCPA"],
                    location=location, context=context,
                )

        # MAC address.
        for m in _MAC_PATTERN.finditer(text):
            mac = m.group(0)
            norm = mac.lower().replace("-", ":")
            if norm not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                self._emit(
                    flow, findings, seen,
                    category="mac_address", value=mac,
                    severity=Severity.LOW, confidence=0.7,
                    compliance=["GDPR"],
                    location=location, context=context,
                )

        # Loose geolocation pair.
        for m in _GEO_PAIR_PATTERN.finditer(text):
            self._maybe_emit_geo_pair(flow, m.group(0), location, findings, seen, context)

        # Plus Code (Open Location Code) — full canonical form only in free text
        # (the '+' separator + restricted alphabet keep false positives low).
        # Geohashes are intentionally NOT scanned in free text: they have no
        # distinguishing structure and would match ordinary tokens.
        for m in _PLUSCODE_FULL_RE.finditer(text):
            self._emit(
                flow, findings, seen,
                category="geolocation", value=m.group(0).upper(),
                severity=Severity.MEDIUM, confidence=0.6,
                compliance=["GDPR", "CCPA"],
                location=location, context="plus_code",
            )

    def _maybe_emit_pan(self, flow, candidate, location, findings, seen, context) -> None:
        digits = re.sub(r"[ -]", "", candidate)
        if not (13 <= len(digits) <= 19) or not digits.isdigit():
            return
        # Reject all-same-digit sequences.
        if len(set(digits)) == 1:
            return
        if not _luhn(digits):
            return
        if not self._has_known_iin(digits):
            return
        self._emit(
            flow, findings, seen,
            category="credit_card_pan", value=candidate,
            severity=Severity.HIGH, confidence=0.9,
            compliance=["PCI-DSS", "GDPR"],
            location=location, context=context,
        )

    @staticmethod
    def _has_known_iin(digits: str) -> bool:
        """Match a known card IIN prefix: 4 / 5[1-5] / 2[2-7] / 3[47] / 6(011|5)."""
        if digits.startswith("4"):
            return True
        if len(digits) >= 2:
            two = digits[:2]
            if two in ("51", "52", "53", "54", "55"):
                return True
            if two in ("22", "23", "24", "25", "26", "27"):
                return True
            if two in ("34", "37"):
                return True
            if two == "65":
                return True
        if digits.startswith("6011"):
            return True
        return False

    def _maybe_emit_geo_pair(self, flow, pair, location, findings, seen, context) -> None:
        try:
            lat_s, lon_s = pair.split(",")
            lat = float(lat_s.strip())
            lon = float(lon_s.strip())
        except (ValueError, AttributeError):
            return
        if not self._is_valid_geo(lat, lon):
            return
        self._emit(
            flow, findings, seen,
            category="geolocation", value=pair,
            severity=Severity.MEDIUM, confidence=0.45,
            compliance=["GDPR", "CCPA"],
            location=location, context=context,
        )

    # -- multi-key object heuristics ---------------------------------------

    def _check_geolocation(self, obj: dict, flow, location, findings, seen) -> None:
        """Detect geolocation in an object: sibling lat/lon keys, plus a packed
        value (coord pair / Plus Code / geohash) under a geo-ish key."""
        self._check_lat_lon_siblings(obj, flow, location, findings, seen)

        # Packed geolocation under a geo-ish key with an ARRAY value, e.g.
        # {"coordinates": [13.405, 52.520]}. String values under such keys are
        # handled by _scan_keyed (covers query/form/header/JSON-string leaves).
        for k, v in obj.items():
            if isinstance(v, (list, tuple)):
                self._maybe_emit_geo_value(flow, k, v, location, findings, seen)

    def _check_lat_lon_siblings(self, obj: dict, flow, location, findings, seen) -> None:
        """Detect sibling lat/lon keys with valid coordinate values."""
        lower_map = {k.lower(): v for k, v in obj.items()}
        lat_val = next((lower_map[k] for k in _LAT_KEYS if k in lower_map), None)
        lon_val = next((lower_map[k] for k in _LON_KEYS if k in lower_map), None)
        if lat_val is None or lon_val is None:
            return
        try:
            lat = float(lat_val)
            lon = float(lon_val)
        except (ValueError, TypeError):
            return
        # Reject integer-only coordinates (low precision -> not a fix).
        if self._is_integer_coord(lat_val) and self._is_integer_coord(lon_val):
            return
        if not self._is_valid_geo(lat, lon):
            return
        self._emit(
            flow, findings, seen,
            category="geolocation", value=f"{lat},{lon}",
            severity=Severity.MEDIUM, confidence=0.7,
            compliance=["GDPR", "CCPA"],
            location=location, context="lat/lon",
        )

    @staticmethod
    def _geo_key_kind(lkey: str) -> str | None:
        """Classify a lowercased key: 'geohash', generic 'geo', or None."""
        if any(tok in lkey for tok in _GEOHASH_KEYS):
            return "geohash"
        if any(tok in lkey for tok in _GEO_STRONG_TOKENS):
            return "geo"
        if lkey in _GEO_EXACT_KEYS:
            return "geo"
        return None

    def _parse_coord_pair(self, s: str) -> "tuple[float, float] | None":
        """Parse 'lat,lon' (or whitespace-separated) into a valid coordinate pair.

        Requires at least one decimal point so integer 'id pairs' (e.g. '1,2')
        are not mistaken for coordinates; accepts either ordering as long as the
        ranges are valid.
        """
        parts = s.split(",") if "," in s else s.split()
        if len(parts) != 2:
            return None
        p0, p1 = parts[0].strip(), parts[1].strip()
        if "." not in p0 and "." not in p1:
            return None
        try:
            a, b = float(p0), float(p1)
        except ValueError:
            return None
        if self._is_valid_geo(a, b):
            return (a, b)
        if self._is_valid_geo(b, a):
            return (b, a)
        return None

    def _classify_geo_value(self, value, *, allow_geohash: bool):
        """Return (encoding, normalized) if *value* encodes a location, else None.

        encoding is one of 'coordinates' / 'plus_code' / 'geohash'. Geohash is
        only attempted when *allow_geohash* is set (explicit geohash key), since
        a bare geohash is indistinguishable from an ordinary token.
        """
        # Two-element numeric array, e.g. {"coordinates": [13.405, 52.520]}.
        if isinstance(value, (list, tuple)):
            if len(value) != 2:
                return None
            if any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in value):
                return None
            a, b = float(value[0]), float(value[1])
            # Require a fractional part so integer arrays/indices are ignored.
            if a == int(a) and b == int(b):
                return None
            if self._is_valid_geo(a, b):
                return ("coordinates", f"{a},{b}")
            if self._is_valid_geo(b, a):
                return ("coordinates", f"{b},{a}")
            return None
        if not isinstance(value, str):
            return None
        s = value.strip()
        if not s:
            return None
        pair = self._parse_coord_pair(s)
        if pair is not None:
            return ("coordinates", f"{pair[0]},{pair[1]}")
        if _PLUSCODE_KEYED_RE.fullmatch(s.upper()):
            return ("plus_code", s.upper())
        if allow_geohash and _GEOHASH_VALUE_RE.fullmatch(s.lower()):
            return ("geohash", s.lower())
        return None

    def _maybe_emit_geo_value(self, flow, key, value, location, findings, seen) -> None:
        """Emit a geolocation finding if *value* under geo-ish *key* encodes a location."""
        kind = self._geo_key_kind(key.lower())
        if kind is None:
            return
        res = self._classify_geo_value(value, allow_geohash=(kind == "geohash"))
        if res is None:
            return
        encoding, normalized = res
        self._emit(
            flow, findings, seen,
            category="geolocation", value=normalized,
            severity=Severity.MEDIUM, confidence=0.75,
            compliance=["GDPR", "CCPA"],
            location=location, context=f"{key}:{encoding}",
        )

    def _check_postal_address(self, obj: dict, flow, location, findings, seen) -> None:
        """Require >=2 of {street, city, zip} keys co-occurring in one object."""
        lkeys = {k.lower() for k in obj.keys()}
        has_street = any(any(s in k for s in _STREET_KEYS) for k in lkeys)
        has_city = any(any(c in k for c in _CITY_KEYS) for k in lkeys)
        has_zip = any(any(z in k for z in _ZIP_KEYS) for k in lkeys)
        if sum((has_street, has_city, has_zip)) < 2:
            return
        # Build a stable signature value for de-dup (parts present, not raw data).
        parts = [k for k in ("street", "city", "zip")
                 if (k == "street" and has_street) or (k == "city" and has_city) or (k == "zip" and has_zip)]
        self._emit(
            flow, findings, seen,
            category="postal_address", value="+".join(sorted(parts)),
            severity=Severity.LOW, confidence=0.4,
            compliance=["GDPR", "CCPA"],
            location=location, context="address",
        )

    # -- small helpers ------------------------------------------------------

    @staticmethod
    def _is_valid_geo(lat: float, lon: float) -> bool:
        if lat == 0.0 and lon == 0.0:
            return False
        return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0

    @staticmethod
    def _is_integer_coord(value) -> bool:
        """True when the value is an integer with no decimal notation.

        The goal is to reject low-precision integer IDs stored in lat/lon-named
        fields (``{"lat": 52}``), not legitimate boundary coordinates like
        ``90.0``. After ``json.loads`` an ``int`` came from a source with no
        decimal point, whereas a ``float`` (even an integer-valued one) came from
        a decimal literal and signals an intended coordinate — so floats are
        never treated as integer coords. Strings are integer coords only when
        they contain no decimal point.
        """
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        if isinstance(value, str):
            return "." not in value
        return False

    @staticmethod
    def _is_birth_date(value: str) -> bool:
        """True when *value* parses as a date with a plausible birth year."""
        for pat in _DOB_PATTERNS:
            m = pat.match(value)
            if not m:
                continue
            groups = m.groups()
            # Year is the 4-digit group.
            year = next((int(g) for g in groups if len(g) == 4), None)
            if year is not None and 1900 <= year <= 2025:
                return True
        return False

    def _is_ad_host(self, flow: "Flow") -> bool:
        host = (flow.display_host or "").lower()
        return any(ad in host for ad in _AD_HOSTS)


__all__ = ["PrivacyAnalyzer", "_luhn", "_iban_ok", "_redact_pii"]
