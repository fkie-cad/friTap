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
import warnings
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from friTap.flow.tap_format import (
    FLAG_HAS_INDEX,
    FOOTER_MAGIC,
    REC_FLOW,
    REC_FLOW_INDEX,
    REC_KEYLOG,
    REC_META,
    SYNC_MARKER,
    FlowSummary,
    TapHeader,
    TapMeta,
    _FOOTER_STRUCT,
    _HEADER_STRUCT,
    _RECORD_ENVELOPE,
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
            return decode_flow(payload)
        except Exception:
            logger.error("Failed to read flow %s at offset %d", flow_id, offset, exc_info=True)
            return None

    def read_all_flows(self) -> list["Flow"]:
        """Read all flows fully (with chunks and bodies).

        For large captures, prefer read_flow_summaries() + read_flow() on demand.
        """
        self._ensure_open()
        flows = []

        for flow_id, offset in self._flow_offsets.items():
            try:
                payload = self._read_record_payload_at(offset)
                if payload is not None:
                    flows.append(decode_flow(payload))
            except Exception:
                logger.debug("Failed to read flow at offset %d", offset, exc_info=True)

        flows.sort(key=lambda f: f.started)
        return flows

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
        self._file.seek(self._data_start)

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

            # Only read payloads we need; seek past the rest
            if rec_type not in (REC_FLOW, REC_META):
                self._file.seek(payload_len, 1)
                continue

            if rec_type == REC_META and self._meta is not None:
                self._file.seek(payload_len, 1)
                continue

            payload = self._file.read(payload_len)
            if len(payload) < payload_len:
                break  # Truncated payload at EOF

            if rec_type == REC_FLOW:
                if verify_payload_crc(payload, stored_crc):
                    try:
                        summary = decode_flow_summary(payload)
                        self._flow_offsets[summary.flow_id] = offset
                    except Exception:
                        logger.debug("Skipping corrupt FLOW at offset %d", offset)
                else:
                    logger.debug("CRC mismatch for FLOW at offset %d, skipping", offset)
            elif rec_type == REC_META:
                if verify_payload_crc(payload, stored_crc):
                    try:
                        self._meta = decode_meta(payload)
                    except Exception:
                        pass

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
