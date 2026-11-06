"""Unit tests for the offline canary known-value search module.

Pure Python — no device/Frida/tshark. Covers canary parsing/validation,
per-kind expansion (normalization + transforms), flow scanning across
headers/url/body as text and bytes, and the untrusted-output contract of
``hit_to_row`` (raw span withheld unless explicitly allowed).

The HTTP-flow helper mirrors ``test_privacy_analyzer`` so bodies are
reconstructed from raw chunks through the same de-dup path the real scan runs
against.
"""

import base64
import hashlib
import json
from urllib.parse import quote_plus

from friTap.analysis.canary import (
    Canary,
    Candidate,
    canonical_kind,
    expand,
    hit_to_row,
    parse_canaries,
    scan_flow,
    search_flows,
)
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
    content_type: str = "application/json",
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


def _needles(candidates: list[Candidate]) -> set[str]:
    return {c.needle for c in candidates}


def _by_transform(candidates: list[Candidate]) -> dict[str, Candidate]:
    return {c.transform: c for c in candidates}


# ---------------------------------------------------------------------------
# expand(): normalization + transforms
# ---------------------------------------------------------------------------


def test_expand_email_yields_sha256_of_lowercased_value():
    email = "User@Example.COM"
    candidates = expand(email, "email")
    expected = hashlib.sha256(email.lower().encode("utf-8")).hexdigest()
    assert expected in _needles(candidates)
    assert _by_transform(candidates)["sha256"].confidence == "high"


def test_expand_email_includes_encoded_and_hex_variants():
    email = "user@example.com"
    candidates = expand(email, "email")
    needles = _needles(candidates)
    data = email.encode("utf-8")

    # url-encoded form of '@' is present (quote_plus -> %40).
    assert quote_plus(email) in needles
    # standard + urlsafe base64 present.
    assert base64.b64encode(data).decode() in needles
    assert base64.urlsafe_b64encode(data).decode() in needles
    # base64 without padding present.
    assert base64.b64encode(data).decode().rstrip("=") in needles
    # hex lower + upper present.
    assert data.hex() in needles
    assert data.hex().upper() in needles


def test_expand_email_gmail_dot_and_tag_stripped_variant():
    candidates = expand("First.Last+promo@gmail.com", "email")
    needles = _needles(candidates)
    # plain lowercased plus the canonical gmail form (dots + tag removed).
    assert hashlib.sha256(b"firstlast@gmail.com").hexdigest() in needles


def test_expand_gps_truncation_yields_multiple_precisions():
    candidates = expand("37.7749295", "gps")
    needles = _needles(candidates)
    for truncated in ("37.7", "37.77", "37.774", "37.7749", "37.77492"):
        assert truncated in needles


def test_expand_dedup_keeps_highest_confidence():
    # A free value whose plain and url forms are identical (no special chars).
    candidates = expand("abcdefghijklmnop", "free")
    plain_like = [c for c in candidates if c.needle == "abcdefghijklmnop"]
    assert len(plain_like) == 1
    # url/plain collapse to one needle; the kept labelling is high confidence.
    assert plain_like[0].confidence == "high"


# ---------------------------------------------------------------------------
# parse_canaries(): validation + warn flags
# ---------------------------------------------------------------------------


def test_parse_canaries_rejects_empty_value_or_label():
    out = parse_canaries([
        {"value": "", "kind": "email", "label": "a"},
        {"value": "x@y.com", "kind": "email", "label": ""},
        {"value": "keep@y.com", "kind": "email", "label": "good"},
    ])
    assert [c.label for c in out] == ["good"]


def test_parse_canaries_flags_low_entropy_and_short():
    out = parse_canaries([
        {"value": "aaaaaaaaaaaa", "kind": "free", "label": "flat"},
        {"value": "123", "kind": "free", "label": "tiny"},
    ])
    warnings = {c.label: c.warning for c in out}
    assert warnings["flat"]  # low-entropy -> non-empty warning
    assert warnings["tiny"]  # short -> non-empty warning


def test_parse_canaries_coerces_unknown_kind_and_caps_length():
    out = parse_canaries([{"value": "v", "kind": "bogus", "label": "l"}])
    assert out[0].kind == "free"
    many = [{"value": f"val{i}longenough", "kind": "free", "label": f"l{i}"} for i in range(200)]
    assert len(parse_canaries(many)) == 64


# ---------------------------------------------------------------------------
# kind aliases: privacy.py vocabulary maps onto the canonical canary kinds
# ---------------------------------------------------------------------------


def test_canonical_kind_resolves_known_aliases():
    for alias in ("advertising_id", "IDFA", " gaid ", "adid", "idfv"):
        assert canonical_kind(alias) == "aaid"
    for alias in ("geo", "Geolocation", "location"):
        assert canonical_kind(alias) == "gps"
    # An already-canonical kind and an unknown one pass through unchanged.
    assert canonical_kind("gps") == "gps"
    assert canonical_kind("bogus") == "bogus"


def test_parse_canaries_normalizes_aliased_kind_to_canonical():
    out = parse_canaries([
        {"value": "38400000-8cf0-11bd-b23e-10b96e40000d", "kind": "advertising_id", "label": "ad"},
        {"value": "37.7749295", "kind": "geo", "label": "loc"},
    ])
    assert [c.kind for c in out] == ["aaid", "gps"]


def test_advertising_id_alias_expands_identically_to_aaid():
    aaid = "38400000-8cf0-11bd-b23e-10b96e40000d"
    via_alias = parse_canaries([{"value": aaid, "kind": "advertising_id", "label": "a"}])[0]
    assert _needles(expand(via_alias.value, via_alias.kind)) == _needles(expand(aaid, "aaid"))


def test_geo_alias_expands_identically_to_gps():
    value = "37.7749295"
    via_alias = parse_canaries([{"value": value, "kind": "geo", "label": "g"}])[0]
    assert _needles(expand(via_alias.value, via_alias.kind)) == _needles(expand(value, "gps"))


# ---------------------------------------------------------------------------
# scan_flow(): find planted values
# ---------------------------------------------------------------------------


def test_scan_flow_finds_sha256_email_in_json_body():
    email = "victim@example.com"
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
    body = json.dumps({"device": {"hashed_email": digest}}).encode("utf-8")
    flow = _make_http_flow(body)

    canary = Canary(value=email, kind="email", label="my-email")
    hits = scan_flow(flow, {canary: expand(email, "email")})

    sha_hits = [h for h in hits if h.transform == "sha256"]
    assert sha_hits, "expected the sha256 form to be found"
    hit = sha_hits[0]
    assert hit.where == "body"
    assert hit.direction == "request"
    assert hit.label == "my-email"


def test_scan_flow_finds_plaintext_in_header_and_query():
    email = "victim@example.com"
    flow = _make_http_flow(
        b"{}",
        headers={"X-User": email},
        url=f"/t?email={quote_plus(email)}",
    )
    canary = Canary(value=email, kind="email", label="e")
    hits = scan_flow(flow, {canary: expand(email, "email")})
    wheres = {h.where for h in hits}
    assert "header" in wheres
    assert "query" in wheres


def test_scan_flow_finds_hash_in_binary_body():
    # A value hashed and embedded as raw bytes inside a protobuf-ish body.
    aaid = "38400000-8cf0-11bd-b23e-10b96e40000d"
    digest = hashlib.md5(aaid.lower().encode(), usedforsecurity=False).hexdigest()
    body = b"\x0a\x10prefix" + digest.encode("ascii") + b"\x12\x04tail"
    flow = _make_http_flow(body, content_type="application/octet-stream")
    canary = Canary(value=aaid, kind="aaid", label="ad")
    hits = scan_flow(flow, {canary: expand(aaid, "aaid")})
    assert any(h.transform == "md5" and h.where == "body" for h in hits)


def test_search_flows_aggregates_across_flows():
    email = "trace@example.com"
    f1 = _make_http_flow(json.dumps({"e": email}).encode(), flow_id="f1")
    f2 = _make_http_flow(b"{}", flow_id="f2")
    canaries = [Canary(value=email, kind="email", label="e")]
    hits = search_flows([f1, f2], canaries)
    assert {h.flow_id for h in hits} == {"f1"}


# ---------------------------------------------------------------------------
# hit_to_row(): untrusted-output contract
# ---------------------------------------------------------------------------


def test_hit_to_row_withholds_raw_span_by_default():
    email = "victim@example.com"
    body = json.dumps({"e": email}).encode("utf-8")
    flow = _make_http_flow(body)
    canary = Canary(value=email, kind="email", label="e")
    hit = scan_flow(flow, {canary: expand(email, "email")})[0]

    hidden = hit_to_row(hit, show_values=False)
    assert "raw_span" not in hidden["untrusted"]
    assert "host" in hidden["untrusted"]
    # The plaintext value must not leak anywhere in the default row.
    assert email not in json.dumps(hidden)

    shown = hit_to_row(hit, show_values=True)
    assert "raw_span" in shown["untrusted"]
    assert shown["untrusted"]["raw_span"]
