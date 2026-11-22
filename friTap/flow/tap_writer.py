"""Streaming .tap file writer.

Flows are appended as they complete; the FLOW_INDEX and footer are written at close().
An unclosed file (crash) is still readable via linear scan.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from friTap.flow.tap_format import (
    _HEADER_STRUCT,
    FLAG_HAS_FINDINGS,
    FLAG_HAS_INDEX,
    FLAG_HAS_REQUEST_CONTEXTS,
    REC_FINDING,
    REC_FLOW,
    REC_FLOW_INDEX,
    REC_KEYLOG,
    REC_META,
    REC_REQUEST_CONTEXT,
    TapMeta,
    encode_finding_record,
    encode_flow,
    encode_flow_index,
    encode_footer,
    encode_header,
    encode_keylog,
    encode_meta,
    encode_record,
    encode_request_context,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow

logger = logging.getLogger(__name__)

#: Cap on REC_REQUEST_CONTEXT records per .tap; later ones are dropped so a chatty app cannot bloat the capture.
MAX_REQUEST_CONTEXT_RECORDS = 20_000


class TapWriter:
    """Streaming binary writer for the .tap capture format.

    Usage: ``open(path, target=...)``, ``write_flow(flow)`` per completed flow, ``close()`` (index + footer).
    """

    def __init__(
        self, defer_flow: Optional[Callable[["Flow"], bool]] = None,
    ) -> None:
        """*defer_flow* (optional) marks flows NOT to persist on "completed".

        Offline conversion folds metadata onto some flows after collection and writes them itself,
        so deferring keeps each to one FLOW record instead of an early stale copy.
        """
        self._lock = threading.Lock()
        self._file = None
        self._path: str = ""
        self._flow_count: int = 0  # FLOW records written (incl. rewrites)
        # flow_id -> {"flow_id", "offset"}; insertion order = first-write order, a rewrite updates the offset (last wins).
        self._flow_index: dict[str, dict] = {}
        self._defer_flow = defer_flow
        self._wrote_findings: bool = False  # any REC_FINDING written this session
        self._request_context_count: int = 0  # REC_REQUEST_CONTEXT written this session
        self._request_context_cap_logged: bool = False
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
        """flow_ids already written to this file."""
        with self._lock:
            return set(self._flow_index)

    def open(self, path: str, target: str = "", capture_start: float = 0.0) -> None:
        """Open a .tap file for writing (*capture_start*: UTC epoch, defaults to now)."""
        if not self._closed:
            raise RuntimeError("TapWriter is already open")

        self._path = str(Path(path).resolve())
        self._capture_start = capture_start or time.time()
        self._capture_target = target
        self._flow_count = 0
        self._flow_index = {}
        self._wrote_findings = False
        self._request_context_count = 0
        self._request_context_cap_logged = False
        self._closed = False

        self._file = open(self._path, "wb")

        # Header (flow_count=0, updated at close).
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

    def update_capture_start(self, ts: float) -> None:
        """Lower the header's capture_start to *ts* if it is an earlier real time (non-positive is ignored).

        Offline conversion learns true capture times only while emitting; the header is rewritten at
        :meth:`close`, so the earliest value recorded here lands on disk.
        """
        if ts <= 0:
            return
        with self._lock:
            if self._capture_start <= 0 or ts < self._capture_start:
                self._capture_start = ts

    def write_flow(self, flow: "Flow") -> None:
        """Write a Flow as a FLOW record (call when it reaches COMPLETED). Thread-safe."""
        # Encode outside the lock to minimize contention.
        payload = encode_flow(flow)
        record = encode_record(REC_FLOW, payload)

        with self._lock:
            if self._closed or self._file is None:
                return

            offset = self._file.tell()
            self._file.write(record)

            self._flow_index[flow.flow_id] = {
                "flow_id": flow.flow_id,
                "offset": offset,
            }
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
        """Write findings for a flow as a REC_FINDING record. Thread-safe.

        *findings* are ``friTap.analysis.Finding`` objects (anything with ``to_dict()``) or dicts. Stored
        separately from the FLOW record so the summary fast path stays lean and findings can follow the flow.
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

    def write_request_context(self, record: dict) -> bool:
        """Write one per-request Java context as a REC_REQUEST_CONTEXT record; True when written. Thread-safe.

        *record* is bounded by ``sanitize_request_context``; one without a ``req_id`` is dropped. At most
        :data:`MAX_REQUEST_CONTEXT_RECORDS` per file (one warning at the cap), checked before the
        sanitizing encode so a flood past it costs no encoding.
        """
        with self._lock:
            if not self._accepts_request_context():
                return False
        try:
            payload = encode_request_context(record)
        except ValueError:
            logger.debug("Dropping request context without a req_id")
            return False
        encoded = encode_record(REC_REQUEST_CONTEXT, payload)
        with self._lock:
            if not self._accepts_request_context():
                return False
            self._file.write(encoded)
            self._request_context_count += 1
            return True

    def _accepts_request_context(self) -> bool:
        """Whether one more request context may be written; caller holds the lock."""
        if self._closed or self._file is None:
            return False
        if self._request_context_count >= MAX_REQUEST_CONTEXT_RECORDS:
            self._log_request_context_cap_once()
            return False
        return True

    def _log_request_context_cap_once(self) -> None:
        """Warn once per file that further request contexts are dropped; caller holds the lock."""
        if self._request_context_cap_logged:
            return
        self._request_context_cap_logged = True
        logger.warning(
            "TapWriter: request-context cap (%d) reached for %s; dropping further ones",
            MAX_REQUEST_CONTEXT_RECORDS, self._path,
        )

    def on_flow_event(self, flow: "Flow", event_type: str) -> None:
        """FlowCollector callback (``FlowCollector.subscribe(writer.on_flow_event)``): writes COMPLETED flows."""
        if event_type == "completed":
            if self._defer_flow is None or not self._defer_flow(flow):
                self.write_flow(flow)
        elif event_type == "removed":
            self.forget_flow(flow.flow_id)
        elif event_type == "updated" and self.has_written(flow.flow_id):
            # Flow changed after persisting (e.g. orphan response merged at flush): append a fresh record, last wins.
            self.write_flow(flow)

    def has_written(self, flow_id: str) -> bool:
        """True when a FLOW record for *flow_id* is already indexed. Thread-safe."""
        with self._lock:
            return flow_id in self._flow_index

    def forget_flow(self, flow_id: str) -> None:
        """Drop *flow_id* from the FLOW_INDEX written at :meth:`close`. Thread-safe.

        For a flow the collector REMOVED after completing it (orphan merge): the record bytes stay,
        but without an index entry the reader no longer lists a ghost duplicate.
        """
        with self._lock:
            self._flow_index.pop(flow_id, None)

    def flush(self) -> None:
        """Flush buffered data to disk. Thread-safe."""
        with self._lock:
            if self._file is not None and not self._closed:
                self._file.flush()

    def close(self) -> None:
        """Write FLOW_INDEX, footer and header, then close. Idempotent and thread-safe."""
        with self._lock:
            if self._closed or self._file is None:
                return

            self._close_locked()

    def _close_locked(self) -> None:
        """Close; caller holds ``self._lock``."""
        try:
            # The index is keyed by flow_id, so a flow written twice is already collapsed to its LAST
            # record at its first-write position (matching the reader), and the header count stays distinct.
            flow_index = list(self._flow_index.values())

            # Write FLOW_INDEX record
            index_offset = self._file.tell()
            index_payload = encode_flow_index(flow_index)
            self._file.write(encode_record(REC_FLOW_INDEX, index_payload))

            # Write footer
            self._file.write(encode_footer(index_offset))

            # Update header: distinct flow_count, flags (finding presence lets readers skip the scan), capture_target kept.
            flags = FLAG_HAS_INDEX
            if self._wrote_findings:
                flags |= FLAG_HAS_FINDINGS
            if self._request_context_count:
                flags |= FLAG_HAS_REQUEST_CONTEXTS
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
