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
import json
import math
import re
import time
from collections import Counter
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


_API_KEY_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.HIGH),
    ("AWS Secret Key", re.compile(r"(?:aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.IGNORECASE), Severity.CRITICAL),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"), Severity.HIGH),
    ("GitHub Classic Token", re.compile(r"ghp_[A-Za-z0-9]{36}"), Severity.HIGH),
    ("GitLab Token", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), Severity.HIGH),
    ("Slack Token", re.compile(r"xox[boaprs]-[0-9]{10,13}-[A-Za-z0-9\-]+"), Severity.HIGH),
    ("Stripe Secret Key", re.compile(r"sk_live_[A-Za-z0-9]{24,}"), Severity.CRITICAL),
    ("Stripe Publishable Key", re.compile(r"pk_live_[A-Za-z0-9]{24,}"), Severity.MEDIUM),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.HIGH),
    ("GCP Service Account", re.compile(r'"type"\s*:\s*"service_account"'), Severity.CRITICAL),
    ("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}"), Severity.HIGH),
    ("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"), Severity.HIGH),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL),
]

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


class CredentialAnalyzer:
    """Analyzer that detects secrets and credentials in HTTP flows."""

    name = "credentials"

    def analyze_flow(self, flow: "Flow") -> list[Finding]:
        findings: list[Finding] = []
        # Decompress bodies once and reuse across all checks
        req_body = flow.get_decompressed_request_body() if flow.request else b""
        resp_body = flow.get_decompressed_response_body() if flow.response else b""
        self._check_auth_headers(flow, findings)
        self._check_query_params(flow, findings)
        self._check_request_body(flow, req_body, findings)
        self._check_response_body(flow, resp_body, findings)
        self._check_api_key_patterns(flow, req_body, resp_body, findings)
        return findings

    def _check_auth_headers(self, flow: "Flow", findings: list[Finding]) -> None:
        """Check Authorization and other auth-related headers."""
        if flow.request is None:
            return

        for header_name, header_value in flow.request.headers.items():
            lower_name = header_name.lower()

            # Bearer token
            if lower_name == "authorization":
                if header_value.lower().startswith("bearer "):
                    token = header_value[7:].strip()
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
                            evidence={
                                "location": "request_header",
                                "header": "Authorization",
                                "value": _redact(token),
                                "host": flow.display_host,
                            },
                        ))

                # Basic auth — decode and extract credentials
                elif header_value.lower().startswith("basic "):
                    try:
                        decoded = base64.b64decode(header_value[6:].strip()).decode("utf-8", errors="replace")
                        user, _, passwd = decoded.partition(":")
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            title="Basic auth credentials in request",
                            description=f"Username '{user}' with password sent to {flow.display_host}",
                            source=self.name,
                            flow_id=flow.flow_id,
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

            # API key headers
            elif lower_name in ("x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token"):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"API key in {header_name} header",
                    description=f"API key sent to {flow.display_host}",
                    source=self.name,
                    flow_id=flow.flow_id,
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
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key

                if isinstance(value, str) and key.lower() in _PASSWORD_FIELDS:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title=f"Password in JSON field '{key}'",
                        description=f"Password value found in {location} at '{current_path}' for {flow.display_host}",
                        source=self.name,
                        flow_id=flow.flow_id,
                        evidence={
                            "location": location,
                            "field": current_path,
                            "value": _redact(value),
                            "host": flow.display_host,
                        },
                    ))
                elif isinstance(value, str) and key.lower() in (
                    "token", "access_token", "refresh_token", "id_token",
                    "api_key", "apikey", "secret", "client_secret",
                    "auth_token", "session_token",
                ):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"Token/key in JSON field '{key}'",
                        description=f"Sensitive value in {location} at '{current_path}' for {flow.display_host}",
                        source=self.name,
                        flow_id=flow.flow_id,
                        evidence={
                            "location": location,
                            "field": current_path,
                            "value": _redact(value),
                            "host": flow.display_host,
                        },
                    ))
                elif isinstance(value, (dict, list)):
                    self._walk_json(value, flow, location, findings, current_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    self._walk_json(item, flow, location, findings, f"{path}[{i}]")

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
            if key.lower() in _PASSWORD_FIELDS:
                for value in values:
                    if value:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            title=f"Password in form field '{key}'",
                            description=f"Password submitted via form to {flow.display_host}",
                            source=self.name,
                            flow_id=flow.flow_id,
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
        """Scan entire flow text for known API key patterns."""
        texts: list[tuple[str, str]] = []

        if flow.request is not None:
            for k, v in flow.request.headers.items():
                texts.append((f"request_header:{k}", v))
            if flow.request.url:
                texts.append(("request_url", flow.request.url))
            if req_body:
                texts.append(("request_body", req_body.decode("utf-8", errors="replace")))

        if resp_body:
            texts.append(("response_body", resp_body.decode("utf-8", errors="replace")))

        seen_patterns: set[str] = set()

        for location, text in texts:
            for pattern_name, pattern, severity in _API_KEY_PATTERNS:
                if pattern_name in seen_patterns:
                    continue
                match = pattern.search(text)
                if match:
                    seen_patterns.add(pattern_name)
                    findings.append(Finding(
                        severity=severity,
                        title=f"{pattern_name} detected",
                        description=f"{pattern_name} found in {location} for {flow.display_host}",
                        source=self.name,
                        flow_id=flow.flow_id,
                        evidence={
                            "location": location,
                            "pattern": pattern_name,
                            "value": _redact(match.group(0)),
                            "host": flow.display_host,
                        },
                    ))

            if "body" in location:
                self._check_entropy(text, flow, location, findings)

    def _check_entropy(
        self, text: str, flow: "Flow", location: str, findings: list[Finding]
    ) -> None:
        """Detect high-entropy strings that may be unknown secrets."""
        for match in _ENTROPY_PATTERN.finditer(text):
            value = match.group(1)
            if len(value) < _MIN_SECRET_LENGTH:
                continue
            entropy = _shannon_entropy(value)
            if entropy >= _ENTROPY_THRESHOLD:
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="High-entropy string (potential secret)",
                    description=f"String with entropy {entropy:.2f} found in {location}",
                    source=self.name,
                    flow_id=flow.flow_id,
                    confidence=0.4,
                    evidence={
                        "location": location,
                        "value": _redact(value),
                        "entropy": round(entropy, 2),
                        "length": len(value),
                        "host": flow.display_host,
                    },
                ))
                break  # One entropy finding per location is enough
