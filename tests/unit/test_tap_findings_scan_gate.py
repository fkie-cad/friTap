"""Unit tests for the findings-scan performance gate in TapReader.

A findings-free .tap previously paid a full O(filesize) linear scan on every
read_findings() call, even when the file demonstrably contained zero findings.
These tests verify:

  (a) Correctness — a .tap WITH findings still returns them via read_findings.
  (b) Short-circuit — a findings-free .tap returns [] without running the full
      record-by-record findings scan (the open-time flag proves there are none).

Pure Python — no device/Frida.
"""

from friTap.analysis import Finding, Severity
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.tap_format import FLAG_HAS_FINDINGS, FLAG_HAS_INDEX
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter
from friTap.parsers.base import ParseResult


def _make_flow(flow_id: str) -> Flow:
    """Minimal HTTP/1.1 flow with one write chunk."""
    request_bytes = (
        b"GET /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
    )
    flow = Flow(
        flow_id=flow_id,
        connection_id="c1",
        src_addr="10.0.0.2",
        src_port=51000,
        dst_addr="93.184.216.34",
        dst_port=443,
        state=FlowState.COMPLETE,
        started=1000.0,
        ended=1001.0,
    )
    flow.request = ParseResult(
        protocol="HTTP/1.1", method="GET", url="/x", host="example.com",
        headers={"Host": "example.com"}, body=b"",
        is_request=True, is_complete=True,
    )
    flow.chunks.append(FlowChunk(
        data=request_bytes, direction="write", timestamp=1000.0, function="SSL_write",
    ))
    return flow


def _write_tap(path: str, *, with_findings: bool) -> None:
    writer = TapWriter()
    writer.open(path)
    writer.write_flow(_make_flow("flow-1"))
    if with_findings:
        writer.write_findings("flow-1", [Finding(
            severity=Severity.HIGH,
            title="AWS Access Key detected",
            description="key in body",
            source="credentials",
            flow_id="flow-1",
            evidence={"value": "AKIA****"},
        )])
    writer.close()


def _clear_header_flags(path: str, mask: int) -> None:
    """Clear the given header flag bits in-place to force a reader code path.

    ``flags`` is a u16 at header offset 6 (after magic(4)+version(2)); these
    tests only touch the low byte, so clearing ``raw[6] & ~mask`` is sufficient
    to drop FLAG_HAS_INDEX / FLAG_HAS_FINDINGS and exercise the linear-scan and
    findings-scan fallbacks."""
    raw = bytearray(open(path, "rb").read())
    raw[6] = raw[6] & ~mask
    with open(path, "wb") as fh:
        fh.write(bytes(raw))


# ---------------------------------------------------------------------------
# (a) Correctness: a file WITH findings still returns them after the change.
# ---------------------------------------------------------------------------

def test_findings_still_returned_with_gate(tmp_path):
    tap_file = str(tmp_path / "with.tap")
    _write_tap(tap_file, with_findings=True)

    reader = TapReader(tap_file)
    reader.open()
    try:
        # The closed file records finding presence in the header flag.
        assert reader.header.flags & FLAG_HAS_FINDINGS
        assert reader._saw_finding_record is True

        assert reader.has_findings() is True
        findings = reader.read_findings("flow-1")
        assert len(findings) == 1
        assert findings[0].title == "AWS Access Key detected"
        assert findings[0].severity == Severity.HIGH

        # Findings also attach to the decoded flow.
        decoded = reader.read_flow("flow-1")
        assert decoded is not None
        assert len(decoded.findings) == 1
    finally:
        reader.close()


# ---------------------------------------------------------------------------
# (b) Short-circuit: a findings-free file returns [] without the full scan.
# ---------------------------------------------------------------------------

def test_findings_free_short_circuits(tmp_path, monkeypatch):
    tap_file = str(tmp_path / "clean.tap")
    _write_tap(tap_file, with_findings=False)

    reader = TapReader(tap_file)
    reader.open()
    try:
        # Indexed file, no findings flag -> open-time flag proves zero findings.
        assert reader.header.flags & FLAG_HAS_INDEX
        assert not (reader.header.flags & FLAG_HAS_FINDINGS)
        assert reader._saw_finding_record is False

        # Spy on the file's seek to ensure read_findings does NOT re-position to
        # the data region for a full record-by-record scan.
        seeks: list[int] = []
        orig_seek = reader._file.seek

        def spy_seek(offset, whence=0):
            seeks.append((offset, whence))
            return orig_seek(offset, whence)

        monkeypatch.setattr(reader._file, "seek", spy_seek)

        assert reader.read_findings("flow-1") == []
        assert reader.has_findings() is False

        # The short-circuit means the findings index was built without seeking
        # back to the start of the data region (no full scan).
        assert (reader._data_start, 0) not in seeks

        # Idempotent: second call uses the cached empty index.
        assert reader.read_findings("flow-1") == []
    finally:
        reader.close()


# ---------------------------------------------------------------------------
# (c) Partial/unclosed capture (linear-scan path) records presence for free.
# ---------------------------------------------------------------------------

def test_linear_scan_records_finding_offsets(tmp_path):
    """An unindexed file (no footer) must still gate correctly via the linear
    scan that runs at open(), capturing finding offsets directly."""
    tap_file = str(tmp_path / "partial.tap")
    _write_tap(tap_file, with_findings=True)

    # Simulate a partial capture: clear FLAG_HAS_INDEX so the reader takes the
    # linear-scan path instead of the footer path.
    _clear_header_flags(tap_file, FLAG_HAS_INDEX | FLAG_HAS_FINDINGS)

    reader = TapReader(tap_file)
    reader.open()
    try:
        # Linear scan walked every record and captured the finding offset(s).
        assert reader._saw_finding_record is True
        assert len(reader._finding_offsets) == 1

        findings = reader.read_findings("flow-1")
        assert len(findings) == 1
        assert findings[0].title == "AWS Access Key detected"
    finally:
        reader.close()


def test_linear_scan_findings_free_sets_false(tmp_path):
    tap_file = str(tmp_path / "partial_clean.tap")
    _write_tap(tap_file, with_findings=False)

    _clear_header_flags(tap_file, FLAG_HAS_INDEX)

    reader = TapReader(tap_file)
    reader.open()
    try:
        assert reader._saw_finding_record is False
        assert reader._finding_offsets == []
        assert reader.read_findings("flow-1") == []
    finally:
        reader.close()


# ---------------------------------------------------------------------------
# (#14) Findings-index isolation: a corrupt/undecodable findings record must
# NEVER suppress otherwise-valid flow data from read_all_flows()/read_flow().
# ---------------------------------------------------------------------------

def test_corrupt_findings_record_does_not_drop_flows(tmp_path):
    """A .tap whose findings record is corrupt on disk still returns its valid
    flows; findings just come back empty/partial."""
    tap_file = str(tmp_path / "corrupt_findings.tap")
    _write_tap(tap_file, with_findings=True)

    # Surgically corrupt ONLY the REC_FINDING record's payload so its CRC fails
    # / it cannot be decoded, leaving the FLOW record, FLOW_INDEX and footer
    # intact. We locate the finding record via the reader's own linear scan.
    probe = TapReader(tap_file)
    probe.open()
    try:
        probe._build_index_linear_scan()  # populates _finding_offsets
        assert len(probe._finding_offsets) == 1
        finding_offset = probe._finding_offsets[0]
    finally:
        probe.close()

    raw = bytearray((tmp_path / "corrupt_findings.tap").read_bytes())
    # Flip a few bytes a little past the envelope so the envelope still parses
    # as REC_FINDING but the payload (and its CRC) is broken.
    target = finding_offset + 12
    for i in range(target, min(target + 8, len(raw) - 16)):
        raw[i] ^= 0xFF
    (tmp_path / "corrupt_findings.tap").write_bytes(bytes(raw))

    reader = TapReader(tap_file)
    reader.open()
    try:
        # The valid flow must still come back, despite the broken findings data.
        flows = reader.read_all_flows()
        assert len(flows) == 1
        assert flows[0].flow_id == "flow-1"
        # read_flow likewise returns the flow (findings may be empty/partial).
        single = reader.read_flow("flow-1")
        assert single is not None
        assert single.flow_id == "flow-1"
    finally:
        reader.close()


def test_findings_index_exception_does_not_drop_flows(tmp_path, monkeypatch):
    """Even if read_findings() raises outright, read_all_flows()/read_flow()
    must still return the valid flows (findings isolated in their own try)."""
    tap_file = str(tmp_path / "raising_findings.tap")
    _write_tap(tap_file, with_findings=True)

    reader = TapReader(tap_file)
    reader.open()
    try:
        def boom(_flow_id):
            raise RuntimeError("simulated corrupt findings index")

        monkeypatch.setattr(reader, "read_findings", boom)

        flows = reader.read_all_flows()
        assert len(flows) == 1
        assert flows[0].flow_id == "flow-1"
        assert flows[0].findings == []  # no findings attached, flow intact

        single = reader.read_flow("flow-1")
        assert single is not None
        assert single.flow_id == "flow-1"
        assert single.findings == []
    finally:
        reader.close()


# ---------------------------------------------------------------------------
# (#19) Shared record iterator: after extracting _iter_records, both a
# findings-bearing and a findings-free file still round-trip flows AND findings
# correctly, proving the shared iterator preserves behaviour.
# ---------------------------------------------------------------------------

def test_shared_iterator_roundtrip_with_findings(tmp_path):
    tap_file = str(tmp_path / "rt_with.tap")
    _write_tap(tap_file, with_findings=True)

    # Force the linear-scan + findings-scan fallback paths (both consume the
    # shared _iter_records) by clearing the index/findings header flags.
    _clear_header_flags(tap_file, FLAG_HAS_INDEX | FLAG_HAS_FINDINGS)

    reader = TapReader(tap_file)
    reader.open()
    try:
        # Linear scan (shared iterator) still finds the flow and finding offset.
        assert reader._saw_finding_record is True
        assert len(reader._finding_offsets) == 1

        flows = reader.read_all_flows()
        assert len(flows) == 1
        assert flows[0].flow_id == "flow-1"
        assert len(flows[0].findings) == 1
        assert flows[0].findings[0].title == "AWS Access Key detected"
    finally:
        reader.close()


def test_shared_iterator_roundtrip_with_findings_footer_fallback(tmp_path):
    """Findings-scan fallback (presence undetermined) also consumes the shared
    iterator: clear only FLAG_HAS_FINDINGS so the footer index path leaves
    _saw_finding_record undetermined, forcing the full findings scan."""
    tap_file = str(tmp_path / "rt_fallback.tap")
    _write_tap(tap_file, with_findings=True)

    _clear_header_flags(tap_file, FLAG_HAS_FINDINGS)  # keep index, drop findings flag

    reader = TapReader(tap_file)
    reader.open()
    try:
        # Footer-index path: findings flag cleared -> _saw_finding_record False,
        # which would short-circuit. To exercise the *fallback* full scan we
        # force the undetermined state, mirroring a real footer-only open where
        # presence is unknown.
        reader._saw_finding_record = None
        findings = reader.read_findings("flow-1")
        assert len(findings) == 1
        assert findings[0].title == "AWS Access Key detected"

        flows = reader.read_all_flows()
        assert len(flows) == 1
        assert flows[0].flow_id == "flow-1"
    finally:
        reader.close()


def test_shared_iterator_roundtrip_findings_free(tmp_path):
    tap_file = str(tmp_path / "rt_clean.tap")
    _write_tap(tap_file, with_findings=False)

    _clear_header_flags(tap_file, FLAG_HAS_INDEX)

    reader = TapReader(tap_file)
    reader.open()
    try:
        assert reader._saw_finding_record is False
        flows = reader.read_all_flows()
        assert len(flows) == 1
        assert flows[0].flow_id == "flow-1"
        assert flows[0].findings == []
        assert reader.read_findings("flow-1") == []
    finally:
        reader.close()
