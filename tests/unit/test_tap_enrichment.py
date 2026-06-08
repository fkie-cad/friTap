"""Unit tests for the enriched Flow model + .tap persistence (Workstream C).

Covers schema v2 enrichment fields, body de-duplication (bodies stored once,
reconstructed from chunks on read), the finding records, and backward
compatibility with v1-shaped FLOW metadata. Pure Python — no device/Frida.
"""

import json

from friTap.analysis import Finding, Severity
from friTap.flow.models import Flow, FlowChunk, FlowState, TlsMetadata
from friTap.flow.tap_format import (
    FLOW_SCHEMA_VERSION,
    FORMAT_VERSION,
    _MAX_EVIDENCE_STR,
    TapMeta,
    _bound_finding_dict,
    decode_finding_record,
    decode_flow,
    decode_meta,
    encode_finding_record,
    encode_flow,
    encode_meta,
    resolve_flow_schema_version,
)
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter
from friTap.parsers.base import ParseResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_http_flow(
    body_bytes: bytes,
    *,
    flow_id: str = "flow-1",
    parse_body: bytes = b"",
    headers: dict | None = None,
    method: str = "POST",
    host: str = "api.example.com",
    url: str = "/upload",
) -> Flow:
    """Build an HTTP/1.1 request Flow whose body lives in a write chunk.

    The raw bytes of a complete HTTP/1.1 request (headers + body) live in a
    single 'write' FlowChunk so Flow.reconstruct_body('write') can recover the
    body via h11. ``parse_body`` controls what ParseResult.body holds (empty by
    default, exercising the de-dup path).
    """
    hdrs = headers or {}
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
    request_bytes = (
        f"{method} {url} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"{header_lines}\r\n"
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
        headers={"Host": host, "Content-Length": str(len(body_bytes)), **hdrs},
        body=parse_body,
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


# ---------------------------------------------------------------------------
# 1. Version constants
# ---------------------------------------------------------------------------

def test_version_constants():
    assert FORMAT_VERSION == 1
    assert FLOW_SCHEMA_VERSION == 3


# ---------------------------------------------------------------------------
# 2. Enrichment round-trip
# ---------------------------------------------------------------------------

def test_enrichment_roundtrip(tmp_path):
    flow = _make_http_flow(b"hello", flow_id="enriched-1")
    flow.set_layer(TlsMetadata(
        library="BoringSSL",
        version="TLS 1.3",
        sni="api.example.com",
        alpn="h2",
        cipher="TLS_AES_128_GCM_SHA256",
    ))
    flow.process_name = "com.example.app"
    flow.package_name = "com.example.app"
    flow.local_addr = "10.0.0.2"
    flow.local_port = 51000
    flow.remote_addr = "93.184.216.34"
    flow.remote_port = 443
    flow.hook_function = "SSL_write"
    flow.tags = ["x"]
    flow.notes = "n"

    tap_file = str(tmp_path / "enriched.tap")
    writer = TapWriter()
    writer.open(tap_file, target="com.example.app")
    writer.write_flow(flow)
    writer.close()

    reader = TapReader(tap_file)
    reader.open()
    try:
        decoded = reader.read_flow("enriched-1")
        assert decoded is not None
        assert decoded.tls.library == "BoringSSL"
        assert decoded.tls.version == "TLS 1.3"
        assert decoded.tls.sni == "api.example.com"
        assert decoded.tls.alpn == "h2"
        assert decoded.tls.cipher == "TLS_AES_128_GCM_SHA256"
        assert decoded.process_name == "com.example.app"
        assert decoded.package_name == "com.example.app"
        assert decoded.local_addr == "10.0.0.2"
        assert decoded.local_port == 51000
        assert decoded.remote_addr == "93.184.216.34"
        assert decoded.remote_port == 443
        assert decoded.hook_function == "SSL_write"
        assert decoded.tags == ["x"]
        assert decoded.notes == "n"

        summaries = reader.read_flow_summaries()
        assert len(summaries) == 1
        summary = summaries[0]
        assert summary.tls_sni == "api.example.com"
        assert summary.tls_alpn == "h2"
        assert summary.process_name == "com.example.app"
        assert summary.tag_count == 1
        assert summary.has_notes is True
    finally:
        reader.close()


# ---------------------------------------------------------------------------
# 3. Body de-dup reconstructs from chunks
# ---------------------------------------------------------------------------

def test_body_dedup_reconstructs(tmp_path):
    body = b"the-secret-payload-body"
    flow = _make_http_flow(body, flow_id="dedup-1", parse_body=b"")

    tap_file = str(tmp_path / "dedup.tap")
    writer = TapWriter()
    writer.open(tap_file)
    writer.write_flow(flow)
    writer.close()

    reader = TapReader(tap_file)
    reader.open()
    try:
        decoded = reader.read_flow("dedup-1")
        assert decoded is not None
        # ParseResult.body was NOT duplicated into the blob section.
        assert decoded.request.body == b""
        # But the body is fully reconstructable from the raw write chunk.
        assert decoded.request_body == body
        assert decoded.get_decompressed_request_body() == body
    finally:
        reader.close()


# ---------------------------------------------------------------------------
# 4. Body de-dup means the body is stored exactly once
# ---------------------------------------------------------------------------

def test_body_dedup_smaller_file(tmp_path):
    body = b"A" * (100 * 1024)  # 100 KB, large enough to detect double-storage
    flow = _make_http_flow(body, flow_id="big-1", parse_body=b"")

    tap_file = str(tmp_path / "big.tap")
    writer = TapWriter()
    writer.open(tap_file)
    writer.write_flow(flow)
    writer.close()

    raw = (tmp_path / "big.tap").read_bytes()
    # The body lives in the write chunk exactly once; the de-dup optimization
    # means ParseResult.body did NOT add a second copy.
    assert raw.count(body) == 1
    # File size must be well under 2x the body (single copy + small overhead).
    assert len(raw) < 2 * len(body)


# ---------------------------------------------------------------------------
# 5. Finding.to_dict / from_dict round-trip
# ---------------------------------------------------------------------------

def test_finding_to_dict_roundtrip():
    original = Finding(
        severity=Severity.CRITICAL,
        title="Test finding",
        description="A described finding",
        source="credentials",
        flow_id="flow-42",
        confidence=0.83,
        evidence={"location": "request_body", "value": "AKIA****"},
        metadata={"mitre": "T1552"},
    )
    restored = Finding.from_dict(original.to_dict())
    assert restored.severity == Severity.CRITICAL
    assert restored.title == "Test finding"
    assert restored.description == "A described finding"
    assert restored.source == "credentials"
    assert restored.flow_id == "flow-42"
    assert restored.confidence == 0.83
    assert restored.evidence == {"location": "request_body", "value": "AKIA****"}
    assert restored.metadata == {"mitre": "T1552"}


# ---------------------------------------------------------------------------
# 6. REC_FINDING record round-trip via writer/reader
# ---------------------------------------------------------------------------

def test_rec_finding_roundtrip(tmp_path):
    flow = _make_http_flow(b"data", flow_id="find-1")
    finding = Finding(
        severity=Severity.HIGH,
        title="AWS Access Key detected",
        description="key in body",
        source="credentials",
        flow_id="find-1",
        evidence={"value": "AKIA****"},
    )

    tap_file = str(tmp_path / "findings.tap")
    writer = TapWriter()
    writer.open(tap_file)
    writer.write_flow(flow)
    writer.write_findings("find-1", [finding])
    writer.close()

    reader = TapReader(tap_file)
    reader.open()
    try:
        assert reader.has_findings() is True
        findings = reader.read_findings("find-1")
        assert len(findings) == 1
        assert findings[0].title == "AWS Access Key detected"
        assert findings[0].severity == Severity.HIGH

        decoded = reader.read_flow("find-1")
        assert decoded is not None
        assert len(decoded.findings) == 1
        assert decoded.findings[0].title == "AWS Access Key detected"

        # A flow_id with no findings yields an empty list.
        assert reader.read_findings("nonexistent") == []
    finally:
        reader.close()


def test_rec_finding_absent_when_none_written(tmp_path):
    flow = _make_http_flow(b"clean", flow_id="clean-1")
    tap_file = str(tmp_path / "no_findings.tap")
    writer = TapWriter()
    writer.open(tap_file)
    writer.write_flow(flow)
    writer.close()

    reader = TapReader(tap_file)
    reader.open()
    try:
        assert reader.has_findings() is False
        assert reader.read_findings("clean-1") == []
    finally:
        reader.close()


# ---------------------------------------------------------------------------
# 7. Oversized evidence strings are bounded
# ---------------------------------------------------------------------------

def test_evidence_bounded():
    huge = "Z" * (_MAX_EVIDENCE_STR + 500)
    finding = Finding(
        severity=Severity.LOW,
        title="big evidence",
        description="d",
        source="credentials",
        flow_id="f1",
        evidence={"value": huge, "small": "ok"},
    )
    payload = encode_finding_record("f1", [finding.to_dict()])
    flow_id, finding_dicts = decode_finding_record(payload)
    assert flow_id == "f1"
    assert len(finding_dicts) == 1
    stored = finding_dicts[0]["evidence"]["value"]
    assert stored.endswith("…[truncated]")
    assert len(stored) == _MAX_EVIDENCE_STR + len("…[truncated]")
    # Short values pass through untouched.
    assert finding_dicts[0]["evidence"]["small"] == "ok"

    # _bound_finding_dict directly should behave the same.
    bounded = _bound_finding_dict(finding.to_dict())
    assert bounded["evidence"]["value"].endswith("…[truncated]")


# ---------------------------------------------------------------------------
# 8. Backward compatibility with v1-shaped FLOW metadata
# ---------------------------------------------------------------------------

def test_backward_compat_old_meta():
    # A minimal Flow with no v2 enrichment set: encode_flow only writes v2 keys
    # when non-default, so the round-trip exercises the "absent v2 keys" path.
    flow = _make_http_flow(b"x", flow_id="minimal-1")
    payload = encode_flow(flow)
    decoded = decode_flow(payload)
    assert decoded.tls.is_empty()
    assert decoded.tags == []
    assert decoded.notes == ""
    assert decoded.process_name == ""
    assert decoded.package_name == ""
    assert decoded.hook_function == ""

    # Simulate an OLD v1 record: rebuild a FLOW payload whose JSON meta lacks
    # ALL v2 keys entirely, and confirm decode_flow tolerates it cleanly.
    from friTap.flow.tap_format import _META_LEN

    meta_len = _META_LEN.unpack(payload[:4])[0]
    meta = json.loads(payload[4:4 + meta_len].decode("utf-8"))
    blob_section = payload[4 + meta_len:]
    # Strip every additive v2 key and the schema version marker.
    for key in (
        "_v", "tls", "tags", "notes", "process_name", "package_name",
        "hook_function", "hook_stack", "local_addr", "local_port",
        "remote_addr", "remote_port",
    ):
        meta.pop(key, None)
    new_meta_bytes = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    new_payload = _META_LEN.pack(len(new_meta_bytes)) + new_meta_bytes + blob_section

    v1_decoded = decode_flow(new_payload)
    assert v1_decoded.tls.is_empty()
    assert v1_decoded.tags == []
    assert v1_decoded.notes == ""
    assert v1_decoded.process_name == ""
    # Core fields still decode.
    assert v1_decoded.flow_id == "minimal-1"
    assert v1_decoded.request is not None


# ---------------------------------------------------------------------------
# 9. META version defaults are consistent (#56)
# ---------------------------------------------------------------------------

def test_meta_flow_fields_version_consistent():
    # The encode default and the decode fallback must agree, so an unset
    # flow_fields_version is a round-trip fixed point at FLOW_SCHEMA_VERSION
    # rather than silently downgrading to 1.
    assert TapMeta().flow_fields_version == FLOW_SCHEMA_VERSION
    decoded = decode_meta(encode_meta(TapMeta()))
    assert decoded.flow_fields_version == FLOW_SCHEMA_VERSION

    # A META payload that omits the key entirely still resolves to the baseline.
    decoded_missing = decode_meta(json.dumps({"schema_version": 1}).encode("utf-8"))
    assert decoded_missing.flow_fields_version == FLOW_SCHEMA_VERSION


def test_resolve_flow_schema_version():
    # Current records stamp _v with FLOW_SCHEMA_VERSION.
    assert resolve_flow_schema_version({"_v": FLOW_SCHEMA_VERSION}) == FLOW_SCHEMA_VERSION
    assert resolve_flow_schema_version({"_v": 5}) == 5
    # Legacy/v1 records have no _v -> treated as schema version 1.
    assert resolve_flow_schema_version({}) == 1


# ---------------------------------------------------------------------------
# 10. body_from_chunks flag is recoverable on read (#20)
# ---------------------------------------------------------------------------

def test_body_from_chunks_flag_recoverable():
    # Request body lives in the write chunk (parse_body empty) -> de-dup path
    # sets body_from_chunks=True at encode time; the reader must surface it.
    flow = _make_http_flow(b"payload-in-chunk", flow_id="bfc-1", parse_body=b"")
    decoded = decode_flow(encode_flow(flow))
    assert decoded.request is not None
    assert decoded.request.body == b""
    assert decoded.request.body_from_chunks is True
    # And the body is still recoverable from the chunk.
    assert decoded.request_body == b"payload-in-chunk"


def test_body_from_chunks_flag_false_when_body_stored():
    # When ParseResult.body is set, the writer stores it directly (no de-dup),
    # so body_from_chunks must be False on read.
    flow = _make_http_flow(b"x", flow_id="bfc-2", parse_body=b"inline-body")
    decoded = decode_flow(encode_flow(flow))
    assert decoded.request is not None
    assert decoded.request.body == b"inline-body"
    assert decoded.request.body_from_chunks is False


# ---------------------------------------------------------------------------
# 11. local_/remote_ role-labeled endpoints read back src/dst values (#38)
# ---------------------------------------------------------------------------

def test_local_remote_endpoints_read_src_dst():
    flow = _make_http_flow(b"hello", flow_id="lr-1")
    # The collector populates local/remote from src/dst; emulate that.
    flow.local_addr = flow.src_addr
    flow.local_port = flow.src_port
    flow.remote_addr = flow.dst_addr
    flow.remote_port = flow.dst_port

    decoded = decode_flow(encode_flow(flow))
    assert decoded.local_addr == decoded.src_addr == "10.0.0.2"
    assert decoded.local_port == decoded.src_port == 51000
    assert decoded.remote_addr == decoded.dst_addr == "93.184.216.34"
    assert decoded.remote_port == decoded.dst_port == 443
