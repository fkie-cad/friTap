"""
Streaming .tap file writer.

TapWriter writes Flow objects to a .tap binary file during or after capture.
Records are appended as flows complete.  The FLOW_INDEX and footer are written
at close(), making the file fully indexed.  If the writer is not closed
(e.g. crash), the file is still readable via linear scan.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from friTap.flow.tap_format import (
    FLAG_HAS_FINDINGS,
    FLAG_HAS_INDEX,
    REC_FINDING,
    REC_FLOW,
    REC_FLOW_INDEX,
    REC_KEYLOG,
    REC_META,
    TapMeta,
    _HEADER_STRUCT,
    encode_finding_record,
    encode_flow,
    encode_flow_index,
    encode_footer,
    encode_header,
    encode_keylog,
    encode_meta,
    encode_record,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow

logger = logging.getLogger(__name__)


class TapWriter:
    """Streaming binary writer for the .tap capture format.

    Usage::

        writer = TapWriter()
        writer.open("capture.tap", target="com.example.app")
        writer.write_flow(flow)       # called per completed flow
        writer.close()                # writes index + footer
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._file = None
        self._path: str = ""
        self._flow_count: int = 0
        self._flow_index: list[dict] = []  # {"flow_id": str, "offset": int}
        self._wrote_findings: bool = False  # any REC_FINDING written this session
        self._capture_start: float = 0.0
        self._capture_target: str = ""
        self._closed: bool = True

    @property
    def path(self) -> str:
        return self._path

    @property
    def flow_count(self) -> int:
        return self._flow_count

    @property
    def written_flow_ids(self) -> set[str]:
        """Return the set of flow_ids already written to this file."""
        return {e["flow_id"] for e in self._flow_index}

    def open(self, path: str, target: str = "", capture_start: float = 0.0) -> None:
        """Open a .tap file for writing.

        Args:
            path: File path to write to.
            target: Capture target name (e.g. app name or PID).
            capture_start: Capture start timestamp (UTC epoch).
                           Defaults to current time.
        """
        if not self._closed:
            raise RuntimeError("TapWriter is already open")

        self._path = str(Path(path).resolve())
        self._capture_start = capture_start or time.time()
        self._capture_target = target
        self._flow_count = 0
        self._flow_index = []
        self._wrote_findings = False
        self._closed = False

        self._file = open(self._path, "wb")

        # Write header (flow_count=0, updated at close)
        header_bytes = encode_header(
            capture_start=self._capture_start,
            flow_count=0,
            flags=0,
            capture_target=target,
        )
        self._file.write(header_bytes)

        # Write META record
        from friTap import __version__
        meta = TapMeta(fritap_version=__version__)
        meta_payload = encode_meta(meta)
        self._file.write(encode_record(REC_META, meta_payload))
        self._file.flush()

        logger.info("TapWriter opened: %s", self._path)

    def write_flow(self, flow: "Flow") -> None:
        """Write a single Flow as a FLOW record.

        Should be called when a flow reaches COMPLETED state.
        Thread-safe.
        """
        # Encode outside the lock to minimize contention
        payload = encode_flow(flow)
        record = encode_record(REC_FLOW, payload)

        with self._lock:
            if self._closed or self._file is None:
                return

            offset = self._file.tell()
            self._file.write(record)

            self._flow_index.append({
                "flow_id": flow.flow_id,
                "offset": offset,
            })
            self._flow_count += 1

            if self._flow_count % 10 == 0:
                self._file.flush()

    def write_keylog(self, key_data: str, timestamp: float = 0.0) -> None:
        """Write a TLS key log line as a KEYLOG record. Thread-safe."""
        with self._lock:
            if self._closed or self._file is None:
                return

            payload = encode_keylog(key_data, timestamp or time.time())
            self._file.write(encode_record(REC_KEYLOG, payload))

    def write_findings(self, flow_id: str, findings: list) -> None:
        """Write analysis findings for a flow as a REC_FINDING record. Thread-safe.

        *findings* is a list of ``friTap.analysis.Finding`` objects (anything with
        a ``to_dict()`` method) or plain serialized dicts. Findings are stored in a
        separate record (not inside the FLOW record) so the metadata-only summary
        fast path stays lean and findings can be appended after the flow is written.
        """
        if not findings:
            return
        finding_dicts = [
            f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in findings
        ]
        payload = encode_finding_record(flow_id, finding_dicts)
        record = encode_record(REC_FINDING, payload)
        with self._lock:
            if self._closed or self._file is None:
                return
            self._file.write(record)
            self._wrote_findings = True

    def on_flow_event(self, flow: "Flow", event_type: str) -> None:
        """FlowCollector callback — writes COMPLETED flows.

        Subscribe this method via FlowCollector.subscribe(writer.on_flow_event).
        """
        if event_type == "completed":
            self.write_flow(flow)

    def flush(self) -> None:
        """Flush buffered data to disk. Thread-safe."""
        with self._lock:
            if self._file is not None and not self._closed:
                self._file.flush()

    def close(self) -> None:
        """Write FLOW_INDEX, footer, update header, and close the file.

        Safe to call multiple times. Thread-safe.
        """
        with self._lock:
            if self._closed or self._file is None:
                return

            self._close_locked()

    def _close_locked(self) -> None:
        """Internal close — must be called under self._lock."""
        try:
            # Collapse duplicate flow_ids to the LAST-written record. A flow may be
            # written twice — once when it "completes" mid-collection, then again
            # after post-collection metadata attachment — so without this the header
            # count and FLOW_INDEX would over-count and carry stale duplicate entries.
            # This matches the reader, which already keeps the last offset per id.
            deduped: dict[str, dict] = {}
            for entry in self._flow_index:
                deduped[entry["flow_id"]] = entry  # last wins
            flow_index = list(deduped.values())

            # Write FLOW_INDEX record
            index_offset = self._file.tell()
            index_payload = encode_flow_index(flow_index)
            self._file.write(encode_record(REC_FLOW_INDEX, index_payload))

            # Write footer
            self._file.write(encode_footer(index_offset))

            # Update header: distinct flow_count, flags, and preserve capture_target.
            # Record finding presence so readers can skip the findings scan.
            flags = FLAG_HAS_INDEX
            if self._wrote_findings:
                flags |= FLAG_HAS_FINDINGS
            header_bytes = encode_header(
                capture_start=self._capture_start,
                flow_count=len(flow_index),
                flags=flags,
                capture_target=self._capture_target,
            )
            self._file.seek(0)
            self._file.write(header_bytes[:_HEADER_STRUCT.size])

            self._file.flush()
            logger.info(
                "TapWriter closed: %s (%d flows)",
                self._path, self._flow_count,
            )
        except Exception:
            logger.error("Error closing TapWriter", exc_info=True)
        finally:
            self._closed = True
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None

    def __enter__(self) -> "TapWriter":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self) -> None:
        if not self._closed:
            self.close()
