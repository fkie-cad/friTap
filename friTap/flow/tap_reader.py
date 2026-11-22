"""Indexed .tap file reader with two-tier loading.

Fast metadata-only summaries for the flow list, on-demand full flows, a linear-scan
fallback when the FLOW_INDEX is missing (partial capture), and sync-marker corruption recovery.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, Optional

from friTap.binary_bounds import (
    BoundsError,
    check_length,
    read_bounded,
    remaining_bytes,
)
from friTap.flow.tap_format import (
    _FOOTER_STRUCT,
    _HEADER_STRUCT,
    _RECORD_ENVELOPE,
    FLAG_HAS_FINDINGS,
    FLAG_HAS_INDEX,
    FLAG_HAS_REQUEST_CONTEXTS,
    FOOTER_MAGIC,
    REC_FINDING,
    REC_FLOW,
    REC_KEYLOG,
    REC_META,
    REC_REQUEST_CONTEXT,
    FlowSummary,
    TapHeader,
    TapMeta,
    decode_finding_record,
    decode_flow,
    decode_flow_index,
    decode_flow_summary,
    decode_header,
    decode_keylog,
    decode_meta,
    decode_record_envelope,
    decode_request_context,
    find_sync_marker,
    verify_payload_crc,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow

logger = logging.getLogger(__name__)

#: Sanity ceiling for one record's payload (the envelope's u32 allows ~4 GiB). The collector caps a
#: flow's retained chunks at 64 MiB, so a record claiming more is treated as corrupt.
MAX_RECORD_PAYLOAD = 1 << 30  # 1 GiB
_KEYLOG_ONLY = frozenset({REC_KEYLOG})
_REQUEST_CONTEXT_ONLY = frozenset({REC_REQUEST_CONTEXT})


class TapReader:
    """Indexed reader for .tap capture files.

    Usage: ``reader = TapReader(path); reader.open(); reader.read_flow_summaries()``
    (fast, metadata only); ``reader.read_flow(flow_id)`` (full, on demand); ``reader.close()``.
    """

    def __init__(self, path: str) -> None:
        self._path = str(Path(path).resolve())
        self._file = None
        self._header: Optional[TapHeader] = None
        self._meta: Optional[TapMeta] = None
        self._data_start: int = 0  # byte offset where records begin
        # Index: flow_id -> file_offset of the FLOW record envelope
        self._flow_offsets: dict[str, int] = {}
        # Lazily-built findings index: flow_id -> list[Finding]. None = not built.
        self._findings_index: Optional[dict[str, list]] = None
        # Finding presence, determined cheaply at open(): None = undetermined (the footer-index path
        # does not walk records), False = the open-time scan saw no REC_FINDING (read_findings
        # returns [] without a second scan), True = seen; offsets are captured below.
        self._saw_finding_record: Optional[bool] = None
        # Byte offsets of REC_FINDING envelopes from the open-time scan, so read_findings can seek to them.
        self._finding_offsets: list[int] = []
        self._opened: bool = False
        # Serializes every seek+read on the shared file handle: get_flow runs on the UI thread,
        # the analyzer worker and the filter content index, and an interleaved seek would read the
        # wrong bytes (CRC mismatch). Re-entrant: open() and the findings-index build nest record reads.
        self._io_lock = threading.RLock()

    @property
    def path(self) -> str:
        return self._path

    @property
    def header(self) -> Optional[TapHeader]:
        return self._header

    @property
    def meta(self) -> Optional[TapMeta]:
        return self._meta

    @property
    def flow_count(self) -> int:
        return len(self._flow_offsets)

    def open(self) -> TapMeta:
        """Open the .tap file, parse the header, build the flow index and return the file-level TapMeta."""
        with self._io_lock:
            self._file = open(self._path, "rb")
            self._opened = True

            try:
                # Read header
                header_raw = self._file.read(_HEADER_STRUCT.size + 4096)  # read extra for ext
                self._header, self._data_start = decode_header(header_raw)

                # Try to read META record (should be the first record)
                self._file.seek(self._data_start)
                self._meta = self._try_read_meta()

                # Build flow index
                if self._header.flags & FLAG_HAS_INDEX:
                    self._build_index_from_footer()
                else:
                    logger.info("No index in .tap file, performing linear scan")
                    self._build_index_linear_scan()
            except Exception:
                self.close()
                raise

            logger.info(
                "TapReader opened: %s (%d flows)",
                self._path, len(self._flow_offsets),
            )
            return self._meta or TapMeta()

    def read_flow_summaries(self) -> list[FlowSummary]:
        """Read lightweight flow metadata for all flows (no chunks/bodies), sorted by start timestamp."""
        self._ensure_open()
        summaries = []

        for flow_id, offset in self._flow_offsets.items():
            try:
                payload = self._read_record_payload_at(offset)
                if payload is not None:
                    summary = decode_flow_summary(payload, file_offset=offset)
                    summaries.append(summary)
            except Exception:
                logger.debug("Failed to read flow summary at offset %d", offset, exc_info=True)

        # Enrich finding_count: findings live in separate REC_FINDING records, so decode_flow_summary
        # leaves it 0. has_findings() is a cheap no-op for findings-free captures; only captures with
        # findings pay for the (cached) index build.
        if self.has_findings():
            for summary in summaries:
                summary.finding_count = len(self.read_findings(summary.flow_id))

        summaries.sort(key=lambda s: s.started)
        return summaries

    def iter_flows(self) -> Iterator[tuple[int, FlowSummary, "Flow"]]:
        """Yield ``(ordinal, summary, flow)`` for every decodable flow, in summary order.

        ``ordinal`` is the 1-based position in :meth:`read_flow_summaries` (the ``f<N>`` flow-ref
        numbering), counted even for flows that cannot be decoded (skipped).
        """
        # Each FLOW meta is parsed twice (summaries, then read_flow) on purpose: holding all parsed metas would raise
        # peak memory ~10x on large taps (12.7 MB -> 142.5 MB on a 68 MB tap), and avoiding it needs a .tap format change.
        for ordinal, summary in enumerate(self.read_flow_summaries(), start=1):
            flow = self.read_flow(summary.flow_id)
            if flow is not None:
                yield ordinal, summary, flow

    def read_flow(self, flow_id: str) -> Optional["Flow"]:
        """Read a full Flow (with chunks/bodies) by flow_id; None if not in the index."""
        self._ensure_open()
        offset = self._flow_offsets.get(flow_id)
        if offset is None:
            return None

        try:
            payload = self._read_record_payload_at(offset)
            if payload is None:
                return None
            flow = decode_flow(payload)
        except Exception:
            logger.error("Failed to read flow %s at offset %d", flow_id, offset, exc_info=True)
            return None

        # Findings are best-effort: a corrupt findings index must NEVER suppress an already-decoded valid flow.
        try:
            findings = self.read_findings(flow_id)
            if findings:
                flow.findings = list(findings)
        except Exception:
            logger.warning(
                "Failed to read findings for flow %s; returning flow without findings",
                flow_id, exc_info=True,
            )
        return flow

    def read_all_flows(self) -> list["Flow"]:
        """Read all flows fully (large captures: prefer summaries + :meth:`read_flow`)."""
        self._ensure_open()
        flows = []

        for flow_id, offset in self._flow_offsets.items():
            try:
                payload = self._read_record_payload_at(offset)
                if payload is None:
                    continue
                flow = decode_flow(payload)
            except Exception:
                logger.debug("Failed to read flow at offset %d", offset, exc_info=True)
                continue

            # Best-effort findings: a corrupt index must NEVER drop a decoded valid flow.
            try:
                findings = self.read_findings(flow.flow_id)
                if findings:
                    flow.findings = list(findings)
            except Exception:
                logger.warning(
                    "Failed to read findings for flow %s; flow kept without findings",
                    flow.flow_id, exc_info=True,
                )
            flows.append(flow)

        flows.sort(key=lambda f: f.started)
        return flows

    def read_findings(self, flow_id: str) -> list:
        """Return analysis findings persisted for *flow_id*; the index is built lazily (one linear pass) and cached."""
        self._ensure_open()
        return self._ensure_findings_index().get(flow_id, [])

    def iter_keylogs(self) -> Iterator[tuple[str, float]]:
        """Yield ``(key_data, timestamp)`` for every intact REC_KEYLOG record.

        Key material: callers must gate this behind an explicit secrets opt-in. Records are read in
        file order under the I/O lock before the first item is yielded; bad-CRC/undecodable ones are skipped.
        """
        self._ensure_open()
        for payload in self._intact_payloads(_KEYLOG_ONLY):
            try:
                key_data, timestamp = decode_keylog(payload)
            except (ValueError, AttributeError, RecursionError):  # bad/deep JSON, not an object
                logger.debug("Skipping undecodable KEYLOG record")
                continue
            if not isinstance(key_data, str):  # untrusted file: callers expect text
                logger.debug("Skipping KEYLOG record whose key_data is not a string")
                continue
            yield key_data, timestamp if isinstance(timestamp, (int, float)) else 0.0

    def iter_request_contexts(self) -> Iterator[dict]:
        """Yield intact REC_REQUEST_CONTEXT records, re-bounded; skipped for a
        closed file without FLAG_HAS_REQUEST_CONTEXTS."""
        self._ensure_open()
        if not self._may_hold_request_contexts():
            return
        for payload in self._intact_payloads(_REQUEST_CONTEXT_ONLY):
            record = decode_request_context(payload)
            if record is None:
                logger.debug("Skipping undecodable REQUEST_CONTEXT record")
                continue
            yield record

    def _intact_payloads(self, rec_types: frozenset) -> list[bytes]:
        """CRC-valid payloads of *rec_types*, read in one pass under the I/O lock."""
        with self._io_lock:
            return [
                payload
                for _offset, _rec_type, payload, stored_crc in self._iter_records(
                    self._data_start, rec_types=rec_types)
                if verify_payload_crc(payload, stored_crc)
            ]

    def _may_hold_request_contexts(self) -> bool:
        """False only for an indexed file written without request contexts."""
        flags = self._header.flags if self._header is not None else 0
        return not (flags & FLAG_HAS_INDEX) or bool(flags & FLAG_HAS_REQUEST_CONTEXTS)

    def has_findings(self) -> bool:
        """True if the file contains any persisted findings."""
        self._ensure_open()
        return bool(self._ensure_findings_index())

    def _ensure_findings_index(self) -> dict:
        """Build the findings index once under the I/O lock; returns the index itself so a concurrent ``close()`` (resetting ``_findings_index`` to None) cannot turn the caller's lookup into ``None.get``."""
        index = self._findings_index
        if index is not None:
            return index
        with self._io_lock:
            if self._findings_index is None:
                self._build_findings_index()
            return self._findings_index or {}

    def close(self) -> None:
        """Close the file. Safe to call multiple times."""
        with self._io_lock:
            if self._file is not None:
                try:
                    self._file.close()
                except Exception:
                    pass
                self._file = None
            self._opened = False
            self._flow_offsets.clear()
            self._findings_index = None
            self._saw_finding_record = None
            self._finding_offsets = []

    def __enter__(self) -> "TapReader":
        self.open()
        return self

    def __exit__(self, *args) -> None:
        self.close()


    def _build_index_from_footer(self) -> None:
        """Read the FLOW_INDEX from the footer pointer."""
        assert self._file is not None

        # Findings presence is in the header flags: a closed/indexed file (FLAG_HAS_INDEX, this path)
        # without FLAG_HAS_FINDINGS provably has no REC_FINDING records.
        if self._header is not None and self._header.flags & FLAG_HAS_FINDINGS:
            # Findings exist; offsets unknown on this path, so _build_findings_index scans once, lazily.
            self._saw_finding_record = True
        else:
            self._saw_finding_record = False

        # Read footer (last 16 bytes)
        self._file.seek(0, 2)  # seek to end
        file_size = self._file.tell()

        if file_size < _HEADER_STRUCT.size + _FOOTER_STRUCT.size:
            logger.warning("File too small for footer, falling back to linear scan")
            self._build_index_linear_scan()
            return

        self._file.seek(file_size - _FOOTER_STRUCT.size)
        footer_raw = self._file.read(_FOOTER_STRUCT.size)

        try:
            footer_magic, index_offset = _FOOTER_STRUCT.unpack(footer_raw)
        except Exception:
            logger.warning("Footer unpack failed, falling back to linear scan")
            self._build_index_linear_scan()
            return

        if footer_magic != FOOTER_MAGIC:
            logger.warning("Footer magic mismatch, falling back to linear scan")
            self._build_index_linear_scan()
            return

        # Read FLOW_INDEX record at index_offset
        payload = self._read_record_payload_at(index_offset)
        if payload is None:
            logger.warning("Failed to read FLOW_INDEX, falling back to linear scan")
            self._build_index_linear_scan()
            return

        entries = decode_flow_index(payload)
        for entry in entries:
            self._flow_offsets[entry["flow_id"]] = entry["offset"]

    def _build_index_linear_scan(self) -> None:
        """Scan all records sequentially to build the flow index (FLOW_INDEX missing: partial capture / crash); keeps the last FLOW record per flow_id."""
        assert self._file is not None

        # This pass visits every record, so capture finding presence/offsets here: afterwards the
        # flag is authoritative (False if none seen) and _build_findings_index skips a second scan.
        self._saw_finding_record = False
        self._finding_offsets = []

        for offset, rec_type, payload, stored_crc in self._iter_records(self._data_start):
            # Record finding presence/offset only; the payload is decoded lazily on first read_findings.
            if rec_type == REC_FINDING:
                self._saw_finding_record = True
                self._finding_offsets.append(offset)
                continue

            if rec_type == REC_FLOW:
                if verify_payload_crc(payload, stored_crc):
                    try:
                        summary = decode_flow_summary(payload)
                        self._flow_offsets[summary.flow_id] = offset
                    except Exception:
                        logger.debug("Skipping corrupt FLOW at offset %d", offset)
                else:
                    logger.debug("CRC mismatch for FLOW at offset %d, skipping", offset)
            elif rec_type == REC_META and self._meta is None:
                if verify_payload_crc(payload, stored_crc):
                    try:
                        self._meta = decode_meta(payload)
                    except Exception:
                        pass

    def _build_findings_index(self) -> None:
        """Build the lazy flow_id -> [Finding] index from REC_FINDING records, cached in ``_findings_index``.

        Performance gate on the open-time scan results:

          * ``_saw_finding_record is False``: no findings seen, short-circuit to an empty index
            without re-reading the (potentially large) file (the common case).
          * ``_finding_offsets`` populated: seek directly to each known finding record.
          * ``_saw_finding_record is None``: undetermined (footer-index path), fall back to a full linear pass.
        """
        assert self._file is not None

        # Short-circuit: open-time scan proved there are no findings.
        if self._saw_finding_record is False:
            self._findings_index = {}
            return

        index: dict[str, list] = {}
        # Lazy import to avoid an import cycle (analysis imports flow.models).
        try:
            from friTap.analysis import Finding
        except Exception:
            Finding = None  # type: ignore

        def add_record(payload: bytes, stored_crc: int, offset: int) -> None:
            if not verify_payload_crc(payload, stored_crc):
                logger.debug("CRC mismatch for REC_FINDING at offset %d, skipping", offset)
                return
            try:
                flow_id, finding_dicts = decode_finding_record(payload)
            except Exception:
                logger.debug("Skipping corrupt REC_FINDING at offset %d", offset)
                return
            bucket = index.setdefault(flow_id, [])
            for fd in finding_dicts:
                bucket.append(Finding.from_dict(fd) if Finding is not None else fd)

        # Fast path: seek directly to the offsets captured at open() time.
        if self._saw_finding_record is True and self._finding_offsets:
            for offset in self._finding_offsets:
                self._file.seek(offset)
                envelope_raw = self._file.read(_RECORD_ENVELOPE.size)
                if len(envelope_raw) < _RECORD_ENVELOPE.size:
                    continue
                try:
                    rec_type, payload_len, stored_crc, _ = decode_record_envelope(envelope_raw)
                except ValueError:
                    continue
                if rec_type != REC_FINDING or payload_len == 0:
                    continue
                try:
                    payload = self._read_payload(payload_len)
                except BoundsError:
                    logger.debug("Skipping REC_FINDING at offset %d: bad length", offset)
                    continue
                add_record(payload, stored_crc, offset)
            self._findings_index = index
            return

        # Fallback (presence undetermined, e.g. footer-index path): full scan.
        for offset, rec_type, payload, stored_crc in self._iter_records(self._data_start):
            if rec_type != REC_FINDING:
                continue
            add_record(payload, stored_crc, offset)

        self._findings_index = index

    def _iter_records(self, start_offset: int, rec_types: Optional[frozenset] = None):
        """Yield ``(offset, rec_type, payload, stored_crc)`` for every record.

        With *rec_types*, other records' payloads are seeked past unread (same bounds/truncation
        checks, so the scan ends at the same point). Shared by ``_build_index_linear_scan`` and the
        findings fallback; recovers via sync marker on a corrupt envelope and skips zero-length
        records. The CRC is yielded unverified so each caller applies its own policy.
        """
        assert self._file is not None
        self._file.seek(start_offset)

        while True:
            offset = self._file.tell()
            envelope_raw = self._file.read(_RECORD_ENVELOPE.size)

            if len(envelope_raw) < _RECORD_ENVELOPE.size:
                break  # EOF or truncated

            try:
                rec_type, payload_len, stored_crc, _ = decode_record_envelope(envelope_raw)
            except ValueError:
                # Try to find next sync marker for recovery
                recovered = self._recover_from(offset + 1)
                if recovered < 0:
                    break
                continue

            if payload_len == 0:
                continue

            wanted = rec_types is None or rec_type in rec_types
            try:
                if not wanted:
                    self._skip_payload(payload_len)
                    continue
                payload = self._read_payload(payload_len)
            except BoundsError as exc:
                # Truncated payload at EOF, or a length no record can have.
                logger.debug("Ending record scan at offset %d: %s", offset, exc)
                break

            yield offset, rec_type, payload, stored_crc

    def _recover_from(self, start_offset: int) -> int:
        """Scan forward from start_offset for the next valid sync marker; its offset, or -1."""
        assert self._file is not None
        self._file.seek(start_offset)

        # Read in 4KB chunks to find sync marker
        while True:
            chunk_start = self._file.tell()
            chunk = self._file.read(4096)
            if not chunk:
                return -1

            idx = find_sync_marker(chunk)
            if idx >= 0:
                recovered_offset = chunk_start + idx
                self._file.seek(recovered_offset)
                return recovered_offset


    def _read_record_payload_at(self, offset: int) -> Optional[bytes]:
        """Read and verify one record's payload at *offset*; None if invalid. Thread-safe (seek+read under ``_io_lock``)."""
        with self._io_lock:
            raw = self._read_record_raw_at(offset)
        if raw is None:
            return None
        payload, stored_crc = raw

        if not verify_payload_crc(payload, stored_crc):
            logger.warning("CRC mismatch at offset %d", offset)
            return None

        return payload

    def _read_record_raw_at(self, offset: int) -> Optional[tuple[bytes, int]]:
        """Seek to *offset* and read ``(payload, stored_crc)``; caller holds the lock."""
        if self._file is None:
            return None
        self._file.seek(offset)

        envelope_raw = self._file.read(_RECORD_ENVELOPE.size)
        if len(envelope_raw) < _RECORD_ENVELOPE.size:
            return None

        try:
            _, payload_len, stored_crc, _ = decode_record_envelope(envelope_raw)
            payload = self._read_payload(payload_len)
        except ValueError:  # bad envelope, or BoundsError on the payload length
            return None
        return payload, stored_crc

    def _read_payload(self, payload_len: int) -> bytes:
        """Read a *payload_len*-byte payload at the current position.

        Length is checked against :data:`MAX_RECORD_PAYLOAD` and the bytes left in the file *before*
        allocating, so a crafted u32 cannot trigger a multi-GiB ``read()``. Raises
        :class:`~friTap.binary_bounds.BoundsError` (a ``ValueError``) on an implausible or truncated payload.
        """
        assert self._file is not None
        return read_bounded(self._file, payload_len, "tap record payload", MAX_RECORD_PAYLOAD)

    def _skip_payload(self, payload_len: int) -> None:
        """Advance past a payload without reading it, with :meth:`_read_payload`'s bounds checks (bounded read fallback when the file size is unknown)."""
        assert self._file is not None
        remaining = remaining_bytes(self._file)
        if remaining is None:
            self._read_payload(payload_len)
            return
        check_length(payload_len, "tap record payload", MAX_RECORD_PAYLOAD, remaining)
        self._file.seek(payload_len, 1)

    def _try_read_meta(self) -> Optional[TapMeta]:
        """Try to read a META record at the current position."""
        assert self._file is not None
        pos = self._file.tell()

        envelope_raw = self._file.read(_RECORD_ENVELOPE.size)
        if len(envelope_raw) < _RECORD_ENVELOPE.size:
            self._file.seek(pos)
            return None

        try:
            rec_type, payload_len, stored_crc, _ = decode_record_envelope(envelope_raw)
        except ValueError:
            self._file.seek(pos)
            return None

        if rec_type != REC_META:
            self._file.seek(pos)
            return None

        try:
            payload = self._read_payload(payload_len)
        except BoundsError:
            self._file.seek(pos)
            return None

        if not verify_payload_crc(payload, stored_crc):
            self._file.seek(pos)
            return None

        return decode_meta(payload)

    def _ensure_open(self) -> None:
        if not self._opened or self._file is None:
            raise RuntimeError("TapReader is not open. Call open() first.")
