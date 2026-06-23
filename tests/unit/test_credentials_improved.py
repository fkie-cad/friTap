"""Unit tests for the improved CredentialAnalyzer (additive features).

Covers the additive 2026-06 improvements:
  - SecretRule refactor + backward-compat ``_API_KEY_PATTERNS`` alias
  - New key-material detections (encrypted PK, PGP, PuTTY, SSH2, X.509, JWK, PKCS#12)
  - New token detections (Google OAuth, npm, PyPI, Docker, GitHub PAT, Slack webhook)
  - CSRF + generic Authorization scheme handling
  - Entropy de-noising (UUID/hash/encoded suppression + suppressed INFO record)
  - Cross-finding dedup (same secret in multiple locations -> one finding)

Pure Python — no device/Frida/tshark.
"""

import base64
import json
import re
import uuid

from friTap.analysis import Severity
from friTap.analysis.credentials import (
    CredentialAnalyzer,
    SecretRule,
    _API_KEY_PATTERNS,
    _SECRET_RULES,
)
from friTap.flow.models import Flow, FlowState
from friTap.parsers.base import ParseResult


# ---------------------------------------------------------------------------
# Flow builders that set request/response bodies directly on ParseResult.
# ---------------------------------------------------------------------------

def _flow(
    *,
    req_body: bytes = b"",
    resp_body: bytes = b"",
    req_headers: dict | None = None,
    req_content_type: str = "text/plain",
    resp_content_type: str = "application/json",
    url: str = "/upload",
    host: str = "api.example.com",
    flow_id: str = "flow-x",
) -> Flow:
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
    hdrs = {"Host": host, "Content-Type": req_content_type, **(req_headers or {})}
    flow.request = ParseResult(
        protocol="HTTP/1.1",
        method="POST",
        url=url,
        host=host,
        headers=hdrs,
        body=req_body,
        content_type=req_content_type,
        is_request=True,
        is_complete=True,
    )
    if resp_body:
        flow.response = ParseResult(
            protocol="HTTP/1.1",
            method="",
            url=url,
            host=host,
            headers={"Content-Type": resp_content_type},
            body=resp_body,
            content_type=resp_content_type,
            is_request=False,
            is_complete=True,
        )
    return flow


def _titles(findings):
    return [f.title for f in findings]


def _by_title_fragment(findings, fragment):
    return [f for f in findings if fragment in f.title]


ANALYZER = CredentialAnalyzer()


# ---------------------------------------------------------------------------
# 1. Backward compatibility
# ---------------------------------------------------------------------------

def test_api_key_patterns_alias_preserved():
    assert len(_API_KEY_PATTERNS) >= 14
    # Each entry is the legacy (name, pattern, severity) tuple.
    for entry in _API_KEY_PATTERNS:
        assert len(entry) == 3
        name, pattern, severity = entry
        assert isinstance(name, str)
        assert isinstance(severity, Severity)
    # The alias is derived 1:1 from the rules.
    assert len(_API_KEY_PATTERNS) == len(_SECRET_RULES)
    names = {n for n, _, _ in _API_KEY_PATTERNS}
    for legacy in ("AWS Access Key", "GitHub Token", "Stripe Secret Key", "Private Key"):
        assert legacy in names


def test_secret_rule_dataclass_shape():
    r = SecretRule("x", re.compile("x"), Severity.HIGH)
    assert r.confidence == 0.9
    assert r.cwe is None
    assert r.entropy_min is None
    assert r.keywords == ()


# ---------------------------------------------------------------------------
# 2. New key material
# ---------------------------------------------------------------------------

def test_encrypted_private_key_critical():
    body = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB...\n-----END ENCRYPTED PRIVATE KEY-----"
    fs = ANALYZER.analyze_flow(_flow(req_body=body))
    m = _by_title_fragment(fs, "Encrypted Private Key")
    assert m and m[0].severity == Severity.CRITICAL


def test_pgp_private_key_critical():
    body = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nxyz\n-----END PGP PRIVATE KEY BLOCK-----"
    fs = ANALYZER.analyze_flow(_flow(req_body=body))
    m = _by_title_fragment(fs, "PGP Private Key")
    assert m and m[0].severity == Severity.CRITICAL


def test_putty_private_key_critical():
    body = b"PuTTY-User-Key-File-3: ssh-rsa\nEncryption: aes256-cbc\n"
    fs = ANALYZER.analyze_flow(_flow(req_body=body))
    m = _by_title_fragment(fs, "PuTTY Private Key")
    assert m and m[0].severity == Severity.CRITICAL


def test_x509_certificate_is_info_only():
    body = b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
    fs = ANALYZER.analyze_flow(_flow(req_body=body))
    certs = _by_title_fragment(fs, "X.509 Certificate")
    assert len(certs) == 1
    assert certs[0].severity == Severity.INFO
    # Must NOT be flagged as CRITICAL key material.
    assert not any(f.severity == Severity.CRITICAL for f in fs)


def test_private_jwk_critical():
    jwk = {"kty": "RSA", "n": "abc", "e": "AQAB", "d": "secret-private-exponent"}
    fs = ANALYZER.analyze_flow(
        _flow(req_body=json.dumps(jwk).encode(), req_content_type="application/json")
    )
    m = _by_title_fragment(fs, "Private JWK")
    assert m and m[0].severity == Severity.CRITICAL


def test_private_jwk_oct_symmetric_critical():
    jwk = {"kty": "oct", "k": "c2VjcmV0LXN5bW1ldHJpYy1rZXk"}
    fs = ANALYZER.analyze_flow(
        _flow(req_body=json.dumps(jwk).encode(), req_content_type="application/json")
    )
    assert _by_title_fragment(fs, "Private JWK")


def test_public_jwk_no_key_material_finding():
    jwk = {"kty": "RSA", "n": "abc", "e": "AQAB"}  # no "d"
    fs = ANALYZER.analyze_flow(
        _flow(req_body=json.dumps(jwk).encode(), req_content_type="application/json")
    )
    assert not _by_title_fragment(fs, "JWK")
    assert not any(f.severity == Severity.CRITICAL for f in fs)


def test_pkcs12_with_content_type_critical():
    body = b"\x30\x82\x0a\x00" + b"\x01" * 64
    fs = ANALYZER.analyze_flow(
        _flow(req_body=body, req_content_type="application/x-pkcs12")
    )
    m = _by_title_fragment(fs, "PKCS#12")
    assert m and m[0].severity == Severity.CRITICAL


def test_pkcs12_magic_with_text_html_not_flagged():
    body = b"\x30\x82\x0a\x00" + b"\x01" * 64
    fs = ANALYZER.analyze_flow(
        _flow(req_body=body, req_content_type="text/html")
    )
    assert not _by_title_fragment(fs, "PKCS#12")


# ---------------------------------------------------------------------------
# 3. New tokens
# ---------------------------------------------------------------------------

def test_new_token_patterns_high():
    cases = {
        "Google OAuth Access Token": "ya29." + "A" * 60,
        "npm Access Token": "npm_" + "a" * 36,
        "PyPI Token": "pypi-AgEIcHlwaS5vcmc" + "b" * 60,
        "Docker Personal Access Token": "dckr_pat_" + "c" * 30,
        "GitHub Fine-Grained PAT": "github_pat_" + "d" * 82,
        "Slack Webhook URL": "https://hooks.slack.com/services/T00000000/B11111111/abcdefghijklmnop",
    }
    for title_frag, token in cases.items():
        fs = ANALYZER.analyze_flow(_flow(req_body=f"x={token}".encode()))
        m = _by_title_fragment(fs, title_frag)
        assert m, f"no finding for {title_frag}: {_titles(fs)}"
        assert m[0].severity == Severity.HIGH


def test_google_refresh_token_keyword_gated():
    token = "1//" + "e" * 40
    # Without a keyword in context -> gated out.
    fs_no = ANALYZER.analyze_flow(_flow(req_body=f"value={token}".encode()))
    assert not _by_title_fragment(fs_no, "Refresh Token")
    # With a keyword present -> flagged.
    fs_yes = ANALYZER.analyze_flow(_flow(req_body=f"refresh_token={token}".encode()))
    assert _by_title_fragment(fs_yes, "Refresh Token")


# ---------------------------------------------------------------------------
# 4. CSRF + generic Authorization schemes
# ---------------------------------------------------------------------------

def test_csrf_header_medium():
    fs = ANALYZER.analyze_flow(_flow(req_headers={"X-CSRF-Token": "abc123token"}))
    m = _by_title_fragment(fs, "CSRF token")
    assert m and m[0].severity == Severity.MEDIUM


def test_authorization_digest_medium():
    fs = ANALYZER.analyze_flow(
        _flow(req_headers={"Authorization": 'Digest username="x", realm="y"'})
    )
    m = _by_title_fragment(fs, "Digest/NTLM/Negotiate")
    assert m and m[0].severity == Severity.MEDIUM


def test_authorization_nonstandard_scheme_high():
    fs = ANALYZER.analyze_flow(_flow(req_headers={"Authorization": "Token abc123"}))
    m = _by_title_fragment(fs, "Non-standard Authorization scheme")
    assert m and m[0].severity == Severity.HIGH


def test_bearer_and_basic_still_work():
    bearer = ANALYZER.analyze_flow(_flow(req_headers={"Authorization": "Bearer plainopaquetoken123"}))
    assert _by_title_fragment(bearer, "Bearer token")
    basic = ANALYZER.analyze_flow(
        _flow(req_headers={"Authorization": "Basic dXNlcjpwYXNzd29yZA=="})
    )
    m = _by_title_fragment(basic, "Basic auth")
    assert m and m[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# 5. Entropy de-noising
# ---------------------------------------------------------------------------

def test_entropy_denoising_suppresses_uuids_hashes_encoded():
    uuids = [str(uuid.uuid4()) for _ in range(4)]
    hashes = [
        "d41d8cd98f00b204e9800998ecf8427e",                                  # md5
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",                          # sha1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256
    ]
    encoded = [
        base64.b64encode(f"this is printable payload number {i} with text".encode()).decode()
        for i in range(5)
    ]
    payload = {f"u{i}": v for i, v in enumerate(uuids)}
    payload.update({f"h{i}": v for i, v in enumerate(hashes)})
    payload.update({f"e{i}": v for i, v in enumerate(encoded)})

    fs = ANALYZER.analyze_flow(
        _flow(req_body=json.dumps(payload).encode(), req_content_type="application/json")
    )

    assert not _by_title_fragment(fs, "High-entropy string"), _titles(fs)
    suppressed = _by_title_fragment(fs, "Entropy scan suppressed")
    assert len(suppressed) == 1
    assert suppressed[0].evidence["suppressed"] == 12


def test_entropy_real_secret_still_emitted():
    secret = "Zq9XvL2pWm7Kd4Rn8Tf6Yh1Bc3Js5Gv0Ae2Wq8Lo4Pi6Un"  # 47 chars, no clean decode
    body = json.dumps({"api_signature": secret}).encode()
    fs = ANALYZER.analyze_flow(_flow(req_body=body, req_content_type="application/json"))
    assert _by_title_fragment(fs, "High-entropy string"), _titles(fs)


# ---------------------------------------------------------------------------
# 6. Cross-finding dedup
# ---------------------------------------------------------------------------

def test_same_jwt_in_header_and_body_dedups_to_one():
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"1234567890","name":"alice"}').decode().rstrip("=")
    jwt = f"{header}.{payload}.signaturepartxxxxxxxxxx"

    resp = json.dumps({"data": "see token " + jwt}).encode()
    fs = ANALYZER.analyze_flow(
        _flow(
            req_headers={"Authorization": f"Bearer {jwt}"},
            resp_body=resp,
            resp_content_type="application/json",
        )
    )
    jwts = _by_title_fragment(fs, "JWT")
    assert len(jwts) == 1, _titles(fs)
    locations = jwts[0].evidence.get("locations")
    assert locations and len(locations) >= 2
