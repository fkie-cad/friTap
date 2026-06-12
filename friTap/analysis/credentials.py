"""
CredentialAnalyzer — detect secrets and credentials in HTTP flows.

Scans HTTP headers, request bodies, query parameters, and URLs for:
  - Bearer tokens and Basic auth (auto-decoded)
  - JWT tokens (decoded claims, flags alg:none and expired)
  - API keys for AWS, GCP, Stripe, GitHub, GitLab, Slack, etc.
  - Password fields in form data and JSON bodies
  - High-entropy strings that may be unknown secret formats
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from friTap.analysis import Finding, Severity

if TYPE_CHECKING:
    from friTap.flow.models import Flow


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values()
    )


# --- Entropy de-noising helpers ---------------------------------------------

_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_BASE64_RE = re.compile(r"\A[A-Za-z0-9+/_\-]+={0,2}\Z")
_BASE62_RE = re.compile(r"\A[A-Za-z0-9]+\Z")
_UUID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
# Common cryptographic hash digest hex lengths: md5(32), sha1(40), ripemd(56),
# sha256(64), sha384(96), sha512(128).
_KNOWN_HASH_HEX_LENS = frozenset({32, 40, 56, 64, 96, 128})

# Key-hint / location substrings that put an entropy candidate "in context"
# (i.e. the surrounding key name strongly implies a secret).
_SECRET_HINT_SUBSTRINGS = (
    "secret", "token", "key", "auth", "password", "passwd", "pwd",
    "signature", "credential", "api", "private",
)

# Charset-aware Shannon-entropy thresholds. Higher bars apply out of context
# (a high-entropy string with no secret-ish key around it must be *very* random
# to flag). Module-level so they aren't rebuilt on every candidate string.
_ENTROPY_THRESHOLDS_IN_CONTEXT = {"hex": 4.0, "base64": 4.5, "base62": 4.3}
_ENTROPY_DEFAULT_IN_CONTEXT = 4.2
_ENTROPY_THRESHOLDS_OUT_OF_CONTEXT = {"hex": 4.5, "base64": 5.0, "base62": 4.7}
_ENTROPY_DEFAULT_OUT_OF_CONTEXT = 4.7


def _classify_charset(s: str) -> str:
    """Classify a candidate string's character set: hex/base64/base62/other."""
    if _HEX_RE.match(s):
        return "hex"
    if _BASE62_RE.match(s):
        return "base62"
    if _BASE64_RE.match(s):
        return "base64"
    return "other"


def _is_uuid(s: str) -> bool:
    """Return True if *s* is a canonical (8-4-4-4-12) UUID."""
    return bool(_UUID_RE.match(s))


def _is_known_hash(s: str) -> bool:
    """Return True if *s* is pure hex of a common crypto-digest length."""
    return bool(_HEX_RE.match(s)) and len(s) in _KNOWN_HASH_HEX_LENS


def _decodes_clean(s: str, charset: str) -> bool:
    """Return True if *s* decodes (base64/hex) to mostly-printable bytes.

    Used to spot encoded payloads (e.g. base64'd JSON/text) which look
    high-entropy but are not novel secrets worth flagging.
    """
    raw: bytes | None = None
    try:
        if charset == "hex" and len(s) % 2 == 0:
            raw = binascii.unhexlify(s)
        elif charset in ("base64", "base62"):
            padded = s + "=" * (-len(s) % 4)
            raw = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return False
    if not raw:
        return False
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(raw)) > 0.70


def _redact(value: str, keep: int = 8) -> str:
    """Redact a secret value, keeping only the first ``keep`` characters."""
    if len(value) <= 8:
        return "****"
    return value[:keep] + "****"


def _try_decode_jwt(token: str) -> dict | None:
    """Attempt to decode a JWT without verification. Returns claims or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        # Decode header
        header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        # Decode payload
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return {"header": header, "payload": payload}
    except Exception:
        return None


@dataclass(frozen=True)
class SecretRule:
    """A declarative pattern-based secret detection rule.

    Attributes:
        name: Human-readable detector name (used in finding titles).
        pattern: Compiled regular expression matched against flow text.
        severity: Severity assigned to a match.
        confidence: Confidence score (0..1) for a pattern match.
        cwe: Optional CWE identifier recorded in finding metadata.
        entropy_min: Optional gate — only flag when the matched value's
            Shannon entropy is at least this value.
        keywords: Optional gate — only flag when one of these keywords is
            present in the surrounding text/location (case-insensitive).
    """
    name: str
    pattern: re.Pattern
    severity: Severity
    confidence: float = 0.9
    cwe: str | None = None
    entropy_min: float | None = None
    keywords: tuple[str, ...] = ()


# CWE-798: Use of Hard-coded Credentials. Applied to all token/key patterns.
_CWE_HARDCODED = "CWE-798"
# CWE-321: Use of Hard-coded Cryptographic Key (private-key material).
_CWE_CRYPTO_KEY = "CWE-321"

_SECRET_RULES: list[SecretRule] = [
    # --- Existing 14 detections, preserved 1:1 -----------------------------
    SecretRule("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.HIGH, confidence=0.9, cwe=_CWE_HARDCODED),
    SecretRule("AWS Secret Key", re.compile(r"(?:aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.IGNORECASE), Severity.CRITICAL, confidence=0.95, cwe=_CWE_HARDCODED),
    SecretRule("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"), Severity.HIGH, confidence=0.9, cwe=_CWE_HARDCODED),
    SecretRule("GitHub Classic Token", re.compile(r"ghp_[A-Za-z0-9]{36}"), Severity.HIGH, confidence=0.9, cwe=_CWE_HARDCODED),
    SecretRule("GitLab Token", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), Severity.HIGH, confidence=0.9, cwe=_CWE_HARDCODED),
    SecretRule("Slack Token", re.compile(r"xox[boaprs]-[0-9]{10,13}-[A-Za-z0-9\-]+"), Severity.HIGH, confidence=0.9, cwe=_CWE_HARDCODED),
    SecretRule("Stripe Secret Key", re.compile(r"sk_live_[A-Za-z0-9]{24,}"), Severity.CRITICAL, confidence=0.95, cwe=_CWE_HARDCODED),
    SecretRule("Stripe Publishable Key", re.compile(r"pk_live_[A-Za-z0-9]{24,}"), Severity.MEDIUM, confidence=0.9, cwe=_CWE_HARDCODED),
    SecretRule("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.HIGH, confidence=0.9, cwe=_CWE_HARDCODED),
    SecretRule("GCP Service Account", re.compile(r'"type"\s*:\s*"service_account"'), Severity.CRITICAL, confidence=0.95, cwe=_CWE_HARDCODED),
    SecretRule("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}"), Severity.HIGH, confidence=0.9, cwe=_CWE_HARDCODED),
    SecretRule("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"), Severity.HIGH, confidence=0.9, cwe=_CWE_HARDCODED),
    SecretRule("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL, confidence=0.95, cwe=_CWE_CRYPTO_KEY),
    # --- Task 2: additional key-material detections ------------------------
    SecretRule("Encrypted Private Key", re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"), Severity.CRITICAL, confidence=0.95, cwe=_CWE_CRYPTO_KEY),
    SecretRule("PGP Private Key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), Severity.CRITICAL, confidence=0.95, cwe=_CWE_CRYPTO_KEY),
    SecretRule("PuTTY Private Key", re.compile(r"PuTTY-User-Key-File-[23]:"), Severity.CRITICAL, confidence=0.9, cwe=_CWE_CRYPTO_KEY),
    SecretRule("SSH2 Encrypted Private Key", re.compile(r"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"), Severity.CRITICAL, confidence=0.9, cwe=_CWE_CRYPTO_KEY),
    SecretRule("X.509 Certificate", re.compile(r"-----BEGIN CERTIFICATE-----"), Severity.INFO, confidence=0.95),
    # --- Task 3: additional token detections -------------------------------
    SecretRule("Google OAuth Access Token", re.compile(r"ya29\.[0-9A-Za-z\-_]{50,}"), Severity.HIGH, confidence=0.95, cwe=_CWE_HARDCODED),
    SecretRule("Google OAuth Refresh Token", re.compile(r"1//[0-9A-Za-z\-_]{30,}"), Severity.HIGH, confidence=0.85, cwe=_CWE_HARDCODED, keywords=("refresh", "oauth", "token")),
    SecretRule("npm Access Token", re.compile(r"npm_[A-Za-z0-9]{36}"), Severity.HIGH, confidence=0.95, cwe=_CWE_HARDCODED),
    SecretRule("PyPI Token", re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}"), Severity.HIGH, confidence=0.95, cwe=_CWE_HARDCODED),
    SecretRule("Docker Personal Access Token", re.compile(r"dckr_pat_[A-Za-z0-9\-_]{27,}"), Severity.HIGH, confidence=0.9, cwe=_CWE_HARDCODED),
    SecretRule("GitHub Fine-Grained PAT", re.compile(r"github_pat_[A-Za-z0-9_]{82}"), Severity.HIGH, confidence=0.95, cwe=_CWE_HARDCODED),
    SecretRule("Slack Webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"), Severity.HIGH, confidence=0.9, cwe=_CWE_HARDCODED),
]

# Backward-compat alias: the legacy (name, pattern, severity) tuple list.
_API_KEY_PATTERNS = [(r.name, r.pattern, r.severity) for r in _SECRET_RULES]

_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

_PASSWORD_FIELDS = frozenset({
    "password", "passwd", "pass", "pwd", "secret",
    "old_password", "new_password", "confirm_password",
    "current_password", "user_password", "login_password",
})

_ENTROPY_THRESHOLD = 4.5
_MIN_SECRET_LENGTH = 20
_ENTROPY_PATTERN = re.compile(r'["\']([A-Za-z0-9+/=_\-]{20,256})["\']')

_SENSITIVE_PARAM_NAMES = frozenset({
    "token", "access_token", "api_key", "apikey", "key",
    "secret", "password", "auth", "session_id", "sid",
    "client_secret", "refresh_token",
})

# CSRF / anti-forgery token field names (request bodies / forms / JSON).
_CSRF_FIELDS = frozenset({
    "csrf", "csrf_token", "xsrf", "_csrf",
    "authenticity_token", "__requestverificationtoken",
})

# JSON keys treated as token/key carriers (kept as a named set so it can be
# referenced consistently across _walk_json).
_TOKEN_JSON_FIELDS = frozenset({
    "token", "access_token", "refresh_token", "id_token",
    "api_key", "apikey", "secret", "client_secret",
    "auth_token", "session_token",
})


class CredentialAnalyzer:
    """Analyzer that detects secrets and credentials in HTTP flows."""

    name = "credentials"

    def analyze_flow(self, flow: "Flow") -> list[Finding]:
        findings: list[Finding] = []
        # Per-flow state for entropy de-noising (suppressed counter + dedup set).
        self._entropy_suppressed = 0
        self._entropy_seen: set[str] = set()
        # Decompress bodies once and reuse across all checks
        req_body = flow.get_decompressed_request_body() if flow.request else b""
        resp_body = flow.get_decompressed_response_body() if flow.response else b""
        self._check_auth_headers(flow, findings)
        self._check_query_params(flow, findings)
        self._check_request_body(flow, req_body, findings)
        self._check_response_body(flow, resp_body, findings)
        self._check_api_key_patterns(flow, req_body, resp_body, findings)
        self._check_binary_key_material(flow, req_body, resp_body, findings)

        # Emit a single trailing INFO finding summarizing entropy suppression.
        if self._entropy_suppressed > 0:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Entropy scan suppressed low-signal strings",
                description=(
                    f"Suppressed {self._entropy_suppressed} low-signal "
                    f"high-entropy strings (UUIDs, hashes, encoded payloads) "
                    f"for {flow.display_host}"
                ),
                source=self.name,
                flow_id=flow.flow_id,
                confidence=1.0,
                evidence={
                    "suppressed": self._entropy_suppressed,
                    "host": flow.display_host,
                },
            ))

        findings = self._dedup_findings(findings)
        from friTap.analysis.filtering import with_category
        return [with_category(f, "secret") for f in findings]

    @staticmethod
    def _dedup_findings(findings: list[Finding]) -> list[Finding]:
        """Merge findings sharing a (title-class, redacted-value) into one.

        When the same secret appears in multiple locations (e.g. a JWT in both
        the Authorization header and the response body) we keep a single
        finding and record all ``locations`` in its evidence rather than
        emitting one finding per location.
        """
        from dataclasses import replace

        # dict preserves first-seen insertion order (Python 3.7+), so it doubles
        # as the ordering structure — no separate order list needed.
        merged: dict[tuple[str, str], Finding] = {}
        out: list[Finding] = []

        for f in findings:
            value = f.evidence.get("value")
            location = f.evidence.get("location")
            # Only dedup value-bearing findings; pass others straight through.
            if not value or not location:
                out.append(f)
                continue
            dedup_key = (f.title, value)
            if dedup_key not in merged:
                merged[dedup_key] = f
            else:
                existing = merged[dedup_key]
                locations = existing.evidence.get("locations")
                if not locations:
                    locations = [existing.evidence.get("location")]
                if location not in locations:
                    locations = locations + [location]
                new_evidence = dict(existing.evidence)
                new_evidence["locations"] = locations
                merged[dedup_key] = replace(existing, evidence=new_evidence)

        # Merged value-findings (first-seen order) then passthrough findings.
        return list(merged.values()) + out

    def _check_auth_headers(self, flow: "Flow", findings: list[Finding]) -> None:
        """Check Authorization and other auth-related headers."""
        if flow.request is None:
            return

        for header_name, header_value in flow.request.headers.items():
            lower_name = header_name.lower()

            # Bearer token
            if lower_name == "authorization":
                scheme, _, credential = header_value.partition(" ")
                scheme_lower = scheme.lower()
                if scheme_lower == "bearer":
                    token = credential.strip()
                    jwt_claims = _try_decode_jwt(token)

                    if jwt_claims:
                        self._add_jwt_finding(flow, token, jwt_claims, "Authorization header", findings)
                    else:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            title="Bearer token in Authorization header",
                            description=f"Bearer token found in request to {flow.display_host}",
                            source=self.name,
                            flow_id=flow.flow_id,
                            confidence=0.9,
                            evidence={
                                "location": "request_header",
                                "header": "Authorization",
                                "value": _redact(token),
                                "host": flow.display_host,
                            },
                        ))

                # Basic auth — decode and extract credentials
                elif scheme_lower == "basic":
                    try:
                        decoded = base64.b64decode(credential.strip()).decode("utf-8", errors="replace")
                        user, _, passwd = decoded.partition(":")
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            title="Basic auth credentials in request",
                            description=f"Username '{user}' with password sent to {flow.display_host}",
                            source=self.name,
                            flow_id=flow.flow_id,
                            confidence=1.0,
                            evidence={
                                "location": "request_header",
                                "header": "Authorization",
                                "username": user,
                                "password": _redact(passwd),
                                "host": flow.display_host,
                            },
                        ))
                    except Exception:
                        pass

                # Digest / NTLM / Negotiate — standard but credential-bearing.
                elif scheme_lower in ("digest", "ntlm", "negotiate"):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Digest/NTLM/Negotiate auth in request",
                        description=f"{scheme} authentication sent to {flow.display_host}",
                        source=self.name,
                        flow_id=flow.flow_id,
                        confidence=0.7,
                        evidence={
                            "location": "request_header",
                            "header": "Authorization",
                            "scheme": scheme,
                            "value": _redact(credential.strip()),
                            "host": flow.display_host,
                        },
                    ))

                # Any other scheme with a non-empty credential.
                elif scheme and credential.strip():
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"Non-standard Authorization scheme '{scheme}'",
                        description=(
                            f"Authorization scheme '{scheme}' with credential "
                            f"sent to {flow.display_host}"
                        ),
                        source=self.name,
                        flow_id=flow.flow_id,
                        confidence=0.7,
                        evidence={
                            "location": "request_header",
                            "header": "Authorization",
                            "scheme": scheme,
                            "value": _redact(credential.strip()),
                            "host": flow.display_host,
                        },
                    ))

            # CSRF / anti-forgery token headers
            elif lower_name in ("x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken"):
                if header_value.strip():
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title=f"CSRF token in {header_name} header",
                        description=f"CSRF/anti-forgery token sent to {flow.display_host}",
                        source=self.name,
                        flow_id=flow.flow_id,
                        confidence=0.7,
                        evidence={
                            "location": "request_header",
                            "header": header_name,
                            "value": _redact(header_value),
                            "host": flow.display_host,
                        },
                    ))

            # API key headers
            elif lower_name in ("x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token"):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"API key in {header_name} header",
                    description=f"API key sent to {flow.display_host}",
                    source=self.name,
                    flow_id=flow.flow_id,
                    confidence=0.7,
                    evidence={
                        "location": "request_header",
                        "header": header_name,
                        "value": _redact(header_value),
                        "host": flow.display_host,
                    },
                ))

            # Cookie with session tokens
            elif lower_name == "cookie" and any(
                kw in header_value.lower()
                for kw in ("session", "token", "auth", "jwt", "sid")
            ):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Session/auth cookie in request",
                    description=f"Cookie with session data sent to {flow.display_host}",
                    source=self.name,
                    flow_id=flow.flow_id,
                    confidence=0.7,
                    evidence={
                        "location": "request_header",
                        "header": "Cookie",
                        "value": _redact(header_value, keep=30),
                        "host": flow.display_host,
                    },
                ))

    def _check_query_params(self, flow: "Flow", findings: list[Finding]) -> None:
        """Check URL query parameters for tokens/keys."""
        if flow.request is None or not flow.request.url:
            return

        url = flow.request.url
        if "?" not in url:
            return

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return

        for param_name, values in params.items():
            if param_name.lower() in _SENSITIVE_PARAM_NAMES:
                for value in values:
                    if value:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            title=f"Sensitive parameter '{param_name}' in URL",
                            description=f"URL parameter '{param_name}' contains sensitive data for {flow.display_host}",
                            source=self.name,
                            flow_id=flow.flow_id,
                            confidence=0.6,
                            evidence={
                                "location": "query_parameter",
                                "parameter": param_name,
                                "value": _redact(value),
                                "host": flow.display_host,
                            },
                        ))

    def _check_request_body(self, flow: "Flow", body: bytes, findings: list[Finding]) -> None:
        """Check request body for passwords and credentials."""
        if not body:
            return

        content_type = flow.request_content_type.lower()

        # JSON body
        if "json" in content_type:
            self._scan_json_for_secrets(body, flow, "request_body", findings)

        # Form data
        elif "x-www-form-urlencoded" in content_type:
            self._scan_form_for_secrets(body, flow, findings)

        # Scan raw body for JWTs
        self._scan_text_for_jwts(body, flow, "request_body", findings)

    def _check_response_body(self, flow: "Flow", body: bytes, findings: list[Finding]) -> None:
        """Check response body for leaked secrets (tokens in JSON responses)."""
        if not body:
            return

        content_type = flow.response_content_type.lower()

        if "json" in content_type:
            self._scan_json_for_secrets(body, flow, "response_body", findings)

        self._scan_text_for_jwts(body, flow, "response_body", findings)

    def _scan_json_for_secrets(
        self, body: bytes, flow: "Flow", location: str, findings: list[Finding]
    ) -> None:
        """Scan a JSON body for password fields and token values."""
        try:
            text = body.decode("utf-8", errors="replace")
            data = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        if not isinstance(data, dict):
            return

        self._walk_json(data, flow, location, findings, path="")

    def _walk_json(
        self,
        obj: dict | list,
        flow: "Flow",
        location: str,
        findings: list[Finding],
        path: str,
    ) -> None:
        """Recursively walk a JSON structure looking for sensitive fields."""
        if isinstance(obj, dict):
            # Private JWK: a JSON Web Key carrying private material.
            self._check_private_jwk(obj, flow, location, findings, path)

            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                key_lower = key.lower()

                if isinstance(value, str) and key_lower in _PASSWORD_FIELDS:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title=f"Password in JSON field '{key}'",
                        description=f"Password value found in {location} at '{current_path}' for {flow.display_host}",
                        source=self.name,
                        flow_id=flow.flow_id,
                        confidence=0.9,
                        evidence={
                            "location": location,
                            "field": current_path,
                            "value": _redact(value),
                            "host": flow.display_host,
                        },
                    ))
                elif isinstance(value, str) and key_lower in _CSRF_FIELDS:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title=f"CSRF token in JSON field '{key}'",
                        description=f"CSRF/anti-forgery token in {location} at '{current_path}' for {flow.display_host}",
                        source=self.name,
                        flow_id=flow.flow_id,
                        confidence=0.7,
                        evidence={
                            "location": location,
                            "field": current_path,
                            "value": _redact(value),
                            "host": flow.display_host,
                        },
                    ))
                elif isinstance(value, str) and key_lower in _TOKEN_JSON_FIELDS:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"Token/key in JSON field '{key}'",
                        description=f"Sensitive value in {location} at '{current_path}' for {flow.display_host}",
                        source=self.name,
                        flow_id=flow.flow_id,
                        confidence=0.6,
                        evidence={
                            "location": location,
                            "field": current_path,
                            "value": _redact(value),
                            "host": flow.display_host,
                        },
                    ))
                elif isinstance(value, str):
                    # Entropy scan on the string leaf, keyed by its field name.
                    self._check_entropy(
                        f'"{value}"', flow, location, findings, key_hint=key
                    )
                elif isinstance(value, (dict, list)):
                    self._walk_json(value, flow, location, findings, current_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    self._walk_json(item, flow, location, findings, f"{path}[{i}]")

    def _check_private_jwk(
        self,
        obj: dict,
        flow: "Flow",
        location: str,
        findings: list[Finding],
        path: str,
    ) -> None:
        """Flag a JSON object that is a JWK carrying private key material.

        A JWK is private when it has ``kty`` and either a ``d`` parameter
        (RSA/EC private exponent) or a ``k`` symmetric key with ``kty == "oct"``.
        Public JWKs (``kty`` + ``n``/``e`` only) are NOT flagged.
        """
        kty = obj.get("kty")
        if not isinstance(kty, str):
            return
        has_private = ("d" in obj) or ("k" in obj and kty == "oct")
        if not has_private:
            return
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Private JWK detected",
            description=f"Private JSON Web Key found in {location} for {flow.display_host}",
            source=self.name,
            flow_id=flow.flow_id,
            confidence=1.0,
            metadata={"cwe": _CWE_CRYPTO_KEY},
            evidence={
                "location": location,
                "field": path or "(root)",
                "kty": kty,
                "host": flow.display_host,
            },
        ))

    def _scan_form_for_secrets(
        self, body: bytes, flow: "Flow", findings: list[Finding]
    ) -> None:
        """Scan URL-encoded form data for password fields."""
        try:
            text = body.decode("utf-8", errors="replace")
            params = parse_qs(text, keep_blank_values=True)
        except Exception:
            return

        for key, values in params.items():
            key_lower = key.lower()
            if key_lower in _PASSWORD_FIELDS:
                for value in values:
                    if value:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            title=f"Password in form field '{key}'",
                            description=f"Password submitted via form to {flow.display_host}",
                            source=self.name,
                            flow_id=flow.flow_id,
                            confidence=0.9,
                            evidence={
                                "location": "request_body",
                                "content_type": "application/x-www-form-urlencoded",
                                "field": key,
                                "value": _redact(value),
                                "host": flow.display_host,
                            },
                        ))
            elif key_lower in _CSRF_FIELDS:
                for value in values:
                    if value:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title=f"CSRF token in form field '{key}'",
                            description=f"CSRF/anti-forgery token submitted via form to {flow.display_host}",
                            source=self.name,
                            flow_id=flow.flow_id,
                            confidence=0.7,
                            evidence={
                                "location": "request_body",
                                "content_type": "application/x-www-form-urlencoded",
                                "field": key,
                                "value": _redact(value),
                                "host": flow.display_host,
                            },
                        ))

    def _scan_text_for_jwts(
        self, body: bytes, flow: "Flow", location: str, findings: list[Finding]
    ) -> None:
        """Scan text for JWT tokens."""
        text = body.decode("utf-8", errors="replace")
        for match in _JWT_PATTERN.finditer(text):
            token = match.group(0)
            claims = _try_decode_jwt(token)
            if claims:
                self._add_jwt_finding(flow, token, claims, location, findings)

    def _add_jwt_finding(
        self,
        flow: "Flow",
        token: str,
        claims: dict,
        location: str,
        findings: list[Finding],
    ) -> None:
        """Add a finding for a detected JWT with security analysis."""
        header = claims.get("header", {})
        payload = claims.get("payload", {})

        issues: list[str] = []
        severity = Severity.HIGH

        # Check for alg:none vulnerability
        alg = header.get("alg", "")
        if alg.lower() == "none":
            issues.append("CRITICAL: Algorithm set to 'none' (JWT bypass vulnerability)")
            severity = Severity.CRITICAL

        # Check expiration
        exp = payload.get("exp")
        if exp is not None:
            try:
                if float(exp) < time.time():
                    issues.append("Token is expired")
            except (ValueError, TypeError):
                pass

        description = f"JWT found in {location} for {flow.display_host}"
        if issues:
            description += ". Issues: " + "; ".join(issues)

        findings.append(Finding(
            severity=severity,
            title="JWT token detected",
            description=description,
            source=self.name,
            flow_id=flow.flow_id,
            evidence={
                "location": location,
                "value": _redact(token, keep=20),
                "algorithm": alg,
                "issuer": payload.get("iss", ""),
                "subject": payload.get("sub", ""),
                "issues": issues,
                "host": flow.display_host,
            },
        ))

    def _check_api_key_patterns(
        self, flow: "Flow", req_body: bytes, resp_body: bytes, findings: list[Finding]
    ) -> None:
        """Scan entire flow text for known API key / secret patterns."""
        texts: list[tuple[str, str]] = []
        req_is_json = False
        resp_is_json = False

        if flow.request is not None:
            req_is_json = "json" in flow.request_content_type.lower()
            for k, v in flow.request.headers.items():
                texts.append((f"request_header:{k}", v))
            if flow.request.url:
                texts.append(("request_url", flow.request.url))
            if req_body:
                texts.append(("request_body", req_body.decode("utf-8", errors="replace")))

        if resp_body:
            resp_is_json = "json" in flow.response_content_type.lower()
            texts.append(("response_body", resp_body.decode("utf-8", errors="replace")))

        seen_patterns: set[str] = set()

        for location, text in texts:
            for rule in _SECRET_RULES:
                if rule.name in seen_patterns:
                    continue
                match = rule.pattern.search(text)
                if not match:
                    continue
                matched_value = match.group(0)
                # Optional entropy gate.
                if rule.entropy_min is not None and _shannon_entropy(matched_value) < rule.entropy_min:
                    continue
                # Optional keyword gate (case-insensitive over text + location).
                if rule.keywords:
                    haystack = (text + " " + location).lower()
                    if not any(kw in haystack for kw in rule.keywords):
                        continue
                seen_patterns.add(rule.name)
                metadata = {"cwe": rule.cwe} if rule.cwe else {}
                findings.append(Finding(
                    severity=rule.severity,
                    title=f"{rule.name} detected",
                    description=f"{rule.name} found in {location} for {flow.display_host}",
                    source=self.name,
                    flow_id=flow.flow_id,
                    confidence=rule.confidence,
                    metadata=metadata,
                    evidence={
                        "location": location,
                        "pattern": rule.name,
                        "value": _redact(matched_value),
                        "host": flow.display_host,
                    },
                ))

            # Body-level entropy scan for NON-JSON bodies only; JSON bodies are
            # scanned per-string-leaf in _walk_json (with the field name as
            # key_hint) so we avoid double-counting here.
            if location == "request_body" and not req_is_json:
                self._check_entropy(text, flow, location, findings)
            elif location == "response_body" and not resp_is_json:
                self._check_entropy(text, flow, location, findings)

    def _check_binary_key_material(
        self, flow: "Flow", req_body: bytes, resp_body: bytes, findings: list[Finding]
    ) -> None:
        """Detect PKCS#12 / PFX key-store binaries in raw request/response bodies."""
        bodies = [
            ("request_body", req_body, flow.request_content_type if flow.request else "",
             flow.request.url if (flow.request and flow.request.url) else ""),
            ("response_body", resp_body, flow.response_content_type if flow.response else "", ""),
        ]
        for location, body, content_type, url in bodies:
            if not body:
                continue
            ct = (content_type or "").lower()
            url_lower = (url or "").lower()

            is_pkcs12_ct = "x-pkcs12" in ct or "x-pfx" in ct or "pkcs12" in ct
            is_pkcs12_name = url_lower.endswith(".p12") or url_lower.endswith(".pfx")
            is_octet_or_empty = ct == "" or "octet-stream" in ct
            starts_der = body[:2] == b"\x30\x82"

            confidence: float | None = None
            if is_pkcs12_ct or is_pkcs12_name:
                confidence = 0.85
            elif starts_der and is_octet_or_empty:
                confidence = 0.6

            if confidence is None:
                continue

            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="PKCS#12 / PFX key store detected",
                description=f"Binary PKCS#12/PFX key-store material found in {location} for {flow.display_host}",
                source=self.name,
                flow_id=flow.flow_id,
                confidence=confidence,
                metadata={"cwe": _CWE_CRYPTO_KEY},
                evidence={
                    "location": location,
                    "content_type": content_type or "",
                    "host": flow.display_host,
                },
            ))

    def _check_entropy(
        self,
        text: str,
        flow: "Flow",
        location: str,
        findings: list[Finding],
        key_hint: str = "",
    ) -> None:
        """Detect high-entropy strings that may be unknown secrets.

        De-noises common false positives (UUIDs, crypto-hash digests, encoded
        payloads) and applies charset- and context-aware entropy thresholds.
        Suppressed candidates are counted on ``self._entropy_suppressed`` and a
        single trailing INFO finding is emitted by ``analyze_flow``.
        """
        in_context = self._is_secret_context(key_hint, location)

        for match in _ENTROPY_PATTERN.finditer(text):
            value = match.group(1)
            if len(value) < _MIN_SECRET_LENGTH:
                continue

            # Per-flow dedup by full value (avoids collapsing distinct strings
            # that merely share a redaction prefix).
            redacted = _redact(value)
            if value in self._entropy_seen:
                continue
            self._entropy_seen.add(value)

            # Skip structural non-secrets outright (not counted as suppressed —
            # they are simply not secret candidates).
            if _is_uuid(value):
                self._entropy_suppressed += 1
                continue
            if _is_known_hash(value):
                self._entropy_suppressed += 1
                continue

            charset = _classify_charset(value)

            # Out-of-context encoded payloads (base64/hex of printable text)
            # are noise, not novel secrets — suppress regardless of entropy.
            if not in_context and _decodes_clean(value, charset):
                self._entropy_suppressed += 1
                continue

            threshold = self._entropy_threshold(charset, in_context)
            entropy = _shannon_entropy(value)

            if entropy < threshold:
                continue

            confidence = 0.4
            if in_context:
                confidence += 0.2
            if len(value) >= 40:
                confidence += 0.1
            confidence = min(confidence, 0.7)

            findings.append(Finding(
                severity=Severity.LOW,
                title="High-entropy string (potential secret)",
                description=f"String with entropy {entropy:.2f} found in {location}",
                source=self.name,
                flow_id=flow.flow_id,
                confidence=round(confidence, 2),
                evidence={
                    "location": location,
                    "value": redacted,
                    "entropy": round(entropy, 2),
                    "length": len(value),
                    "charset": charset,
                    "host": flow.display_host,
                },
            ))

    @staticmethod
    def _is_secret_context(key_hint: str, location: str) -> bool:
        """Return True when the key name / location implies a secret value."""
        hint = (key_hint or "").lower()
        loc = (location or "").lower()
        if any(sub in hint for sub in _SECRET_HINT_SUBSTRINGS):
            return True
        # Auth-like locations (e.g. request_header:Authorization) count too.
        return "auth" in loc

    @staticmethod
    def _entropy_threshold(charset: str, in_context: bool) -> float:
        """Charset- and context-aware Shannon-entropy threshold."""
        if in_context:
            return _ENTROPY_THRESHOLDS_IN_CONTEXT.get(charset, _ENTROPY_DEFAULT_IN_CONTEXT)
        return _ENTROPY_THRESHOLDS_OUT_OF_CONTEXT.get(charset, _ENTROPY_DEFAULT_OUT_OF_CONTEXT)
