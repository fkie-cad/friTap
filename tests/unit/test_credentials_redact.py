"""Boundary tests for CredentialAnalyzer secret redaction.

Rule under test: values of <= 8 chars are fully masked; longer values reveal
``min(keep, len // 4)`` chars + ``"****"`` — never the whole secret. Cookie
headers keep cookie names and redact each value.
"""

import base64

import pytest

from friTap.analysis.credentials import (
    CredentialAnalyzer,
    _redact,
    _redact_cookie_header,
)
from friTap.flow.models import Flow, FlowState
from friTap.parsers.base import ParseResult

BOUNDARY_LENGTHS = (0, 1, 8, 9, 30, 31, 100)
# keep values used by the call sites: default (tokens/passwords/keys), JWT.
CALL_SITE_KEEPS = (8, 20)


def _secret(length: int) -> str:
    """A secret with distinct-looking chars so prefixes are unambiguous."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return (alphabet * 2)[:length]


def _expected_prefix_len(length: int, keep: int) -> int:
    return 0 if length <= 8 else min(keep, length // 4)


@pytest.mark.parametrize("keep", CALL_SITE_KEEPS)
@pytest.mark.parametrize("length", BOUNDARY_LENGTHS)
def test_redact_reveals_only_safe_prefix(length, keep):
    secret = _secret(length)
    redacted = _redact(secret, keep=keep)
    prefix_len = _expected_prefix_len(length, keep)
    assert redacted == secret[:prefix_len] + "****"
    assert prefix_len <= length // 4
    if length:
        assert secret not in redacted


@pytest.mark.parametrize("length", BOUNDARY_LENGTHS)
def test_redact_large_keep_is_capped(length):
    secret = _secret(length)
    assert _redact(secret, keep=1000) == secret[:_expected_prefix_len(length, 1000)] + "****"


@pytest.mark.parametrize("length", BOUNDARY_LENGTHS)
def test_redact_cookie_header_keeps_names_hides_values(length):
    secret = _secret(length)
    redacted = _redact_cookie_header(f"sessionid={secret}; theme=dark")
    assert redacted == f"sessionid={_redact(secret)}; theme=****"
    if length:
        assert f"={secret}" not in redacted


def test_redact_cookie_header_pair_without_equals_is_masked():
    assert _redact_cookie_header("barevaluewithoutname") == _redact("barevaluewithoutname")


# ---------------------------------------------------------------------------
# End-to-end through the analyzer (each header call-site kind)
# ---------------------------------------------------------------------------

def _flow(headers: dict) -> Flow:
    flow = Flow(
        flow_id="f", connection_id="c", src_addr="10.0.0.2", src_port=51000,
        dst_addr="93.184.216.34", dst_port=443, state=FlowState.COMPLETE,
        started=1000.0, ended=1001.0,
    )
    flow.request = ParseResult(
        protocol="HTTP/1.1", method="GET", url="/", host="api.example.com",
        headers={"Host": "api.example.com", **headers}, body=b"",
        content_type="text/plain", is_request=True, is_complete=True,
    )
    return flow


def _evidence(headers: dict, title_fragment: str) -> dict:
    findings = CredentialAnalyzer().analyze_flow(_flow(headers))
    matches = [f for f in findings if title_fragment in f.title]
    assert matches, [f.title for f in findings]
    return matches[0].evidence


@pytest.mark.parametrize("length", [n for n in BOUNDARY_LENGTHS if n])
def test_cookie_finding_never_contains_secret(length):
    secret = _secret(length)
    ev = _evidence({"Cookie": f"session={secret}"}, "Session/auth cookie")
    assert ev["value"] == f"session={_redact(secret)}"
    assert f"={secret}" not in ev["value"]


@pytest.mark.parametrize("length", [n for n in BOUNDARY_LENGTHS if n])
def test_api_key_finding_never_contains_secret(length):
    secret = _secret(length)
    ev = _evidence({"X-Api-Key": secret}, "API key in")
    assert ev["value"] == _redact(secret)
    assert secret not in ev["value"]


@pytest.mark.parametrize("length", [n for n in BOUNDARY_LENGTHS if n])
def test_bearer_token_finding_never_contains_secret(length):
    secret = _secret(length)
    ev = _evidence({"Authorization": f"Bearer {secret}"}, "Bearer token")
    assert ev["value"] == _redact(secret)
    assert secret not in ev["value"]


@pytest.mark.parametrize("length", [n for n in BOUNDARY_LENGTHS if n])
def test_basic_auth_password_never_contained(length):
    password = _secret(length)
    cred = base64.b64encode(f"alice:{password}".encode()).decode()
    ev = _evidence({"Authorization": f"Basic {cred}"}, "Basic auth")
    assert ev["password"] == _redact(password)
    assert password not in ev["password"]
