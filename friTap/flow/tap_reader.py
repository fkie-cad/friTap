"""
Indexed .tap file reader with two-tier loading.

TapReader provides:
  - Fast metadata-only loading for populating the TUI flow list
  - On-demand full flow loading (with chunks/bodies) for the detail view
  - Automatic fallback to linear scan if the FLOW_INDEX is missing (partial capture)
  - Corruption recovery via sync marker scanning
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from friTap.flow.tap_format import (
    FLAG_HAS_FINDINGS,
    FLAG_HAS_INDEX,
    FOOTER_MAGIC,
    REC_FINDING,
    REC_FLOW,
    REC_META,
    FlowSummary,
    TapHeader,
    TapMeta,
    _FOOTER_STRUCT,
    _HEADER_STRUCT,
    _RECORD_ENVELOPE,
    decode_finding_record,
    decode_flow,
    decode_flow_index,
    decode_flow_summary,
    decode_header,
    decode_meta,
    decode_record_envelope,
    find_sync_marker,
    verify_payload_crc,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow

logger = logging.getLogger(__name__)


class TapReader:
    """Indexed reader for .tap capture files.

    Usage::

        reader = TapReader("capture.tap")
        meta = reader.open()
        summaries = reader.read_flow_summaries()   # fast, metadata only
        flow = reader.read_flow("10.0.0.1:443-...:0")  # full load on demand
        reader.close()
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
        # Finding-presence flag determined cheaply at open() time.
        #   None  = undetermined (footer-index path does not walk records, so we
        #           cannot know without a scan — fall back to lazy full scan)
        #   False = open-time scan walked every record and saw NO REC_FINDING
        #           (read_findings short-circuits to [] with no second scan)
        #   True  = at least one REC_FINDING was seen; offsets captured below
        self._saw_finding_record: Optional[bool] = None
        # Byte offsets of REC_FINDING record envelopes captured during the
        # open-time linear scan, so read_findings can seek directly to them
        # instead of re-scanning the whole file.
        self._finding_offsets: list[int] = []
        self._opened: bool = False

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
        """Open the .tap file, parse the header, and build the flow index.

        Returns the file-level TapMeta.
        """
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
        """Read lightweight flow metadata for all flows (no chunks/bodies).

        Returns summaries sorted by start timestamp.
        """
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

        summaries.sort(key=lambda s: s.started)
        return summaries

    def read_flow(self, flow_id: str) -> Optional["Flow"]:
        """Read a full Flow object by flow_id (on-demand, with chunks/bodies).

        Returns None if the flow_id is not in the index.
        """
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

        # Findings are best-effort enrichment: a corrupt/undecodable findings
        # index must NEVER suppress an already-decoded valid flow. Isolate it.
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
        """Read all flows fully (with chunks and bodies).

        For large captures, prefer read_flow_summaries() + read_flow() on demand.
        """
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

            # Findings are best-effort enrichment: a corrupt/undecodable
            # findings index must NEVER drop an already-decoded valid flow.
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
        """Return analysis findings persisted for *flow_id* (REC_FINDING records).

        The findings index is built lazily on first call (one linear pass over
        the file) and cached. Returns an empty list if the file carries none.
        """
        self._ensure_open()
        if self._findings_index is None:
            self._build_findings_index()
        return self._findings_index.get(flow_id, [])

    def has_findings(self) -> bool:
        """True if the file contains any persisted findings."""
        self._ensure_open()
        if self._findings_index is None:
            self._build_findings_index()
        return bool(self._findings_index)

    def close(self) -> None:
        """Close the file. Safe to call multiple times."""
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

    # ------------------------------------------------------------------
    # Internal: index building
    # ------------------------------------------------------------------

    def _build_index_from_footer(self) -> None:
        """Read the FLOW_INDEX from the footer pointer."""
        assert self._file is not None

        # Findings presence is recorded in the header flags at close() time, so
        # we can decide cheaply (no record walk) whether the findings scan is
        # worth running. A closed/indexed file (FLAG_HAS_INDEX, this path) that
        # lacks FLAG_HAS_FINDINGS provably contains no REC_FINDING records.
        if self._header is not None and self._header.flags & FLAG_HAS_FINDINGS:
            # Findings exist; offsets unknown on this path, so _build_findings_index
            # will scan once (lazily, only if findings are actually requested).
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
        """Scan all records sequentially to build the flow index.

        Used when the FLOW_INDEX is missing (partial capture / crash).
        Keeps only the last FLOW record per flow_id.
        """
        assert self._file is not None

        # This pass already visits every record, so capture finding presence
        # and offsets here for free. After this method completes, the flag is
        # authoritative (False if no REC_FINDING was seen), letting
        # _build_findings_index short-circuit instead of scanning a second time.
        self._saw_finding_record = False
        self._finding_offsets = []

        for offset, rec_type, payload, stored_crc in self._iter_records(self._data_start):
            # Record finding presence/offset cheaply (payload is decoded lazily
            # on first read_findings, not here).
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
        """Build the lazy flow_id -> [Finding] index from REC_FINDING records.

        Performance gate: the open-time scan records whether any REC_FINDING
        record exists (``self._saw_finding_record``) and, when so, their byte
        offsets (``self._finding_offsets``):

          * ``_saw_finding_record is False`` — the open-time linear scan walked
            every record and saw no findings, so we short-circuit to an empty
            index without re-reading the (potentially large) file. This is the
            common case for findings-free captures.
          * ``_finding_offsets`` populated — seek directly to each known finding
            record instead of scanning the whole file.
          * ``_saw_finding_record is None`` — undetermined (the footer-index
            path does not walk records, so presence is unknown without a scan).
            Fall back to the original full linear pass, preserving behaviour.

        The result is cached in ``self._findings_index``.
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
                payload = self._file.read(payload_len)
                if len(payload) < payload_len:
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

    def _iter_records(self, start_offset: int):
        """Yield ``(offset, rec_type, payload, stored_crc)`` for every record.

        Single shared sequential record iterator used by both
        ``_build_index_linear_scan`` and ``_build_findings_index`` (fallback
        path). It handles sync-marker recovery on a corrupt envelope and skips
        zero-length records exactly as the prior duplicated loops did. The
        CRC is yielded unverified so each caller can apply its own
        verify/decode policy per record type (behaviour-preserving).
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

            payload = self._file.read(payload_len)
            if len(payload) < payload_len:
                break  # Truncated payload at EOF

            yield offset, rec_type, payload, stored_crc

    def _recover_from(self, start_offset: int) -> int:
        """Scan forward from start_offset to find the next valid sync marker.

        Returns the offset of the next record, or -1 if not found.
        """
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

    # ------------------------------------------------------------------
    # Internal: record reading
    # ------------------------------------------------------------------

    def _read_record_payload_at(self, offset: int) -> Optional[bytes]:
        """Read and verify a single record's payload at the given file offset.

        Returns the raw payload bytes, or None if the record is invalid.
        """
        assert self._file is not None
        self._file.seek(offset)

        envelope_raw = self._file.read(_RECORD_ENVELOPE.size)
        if len(envelope_raw) < _RECORD_ENVELOPE.size:
            return None

        try:
            rec_type, payload_len, stored_crc, _ = decode_record_envelope(envelope_raw)
        except ValueError:
            return None

        payload = self._file.read(payload_len)
        if len(payload) < payload_len:
            return None

        if not verify_payload_crc(payload, stored_crc):
            logger.warning("CRC mismatch at offset %d", offset)
            return None

        return payload

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

        payload = self._file.read(payload_len)
        if len(payload) < payload_len:
            self._file.seek(pos)
            return None

        if not verify_payload_crc(payload, stored_crc):
            self._file.seek(pos)
            return None

        return decode_meta(payload)

    def _ensure_open(self) -> None:
        if not self._opened or self._file is None:
            raise RuntimeError("TapReader is not open. Call open() first.")
