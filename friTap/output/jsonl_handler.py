#!/usr/bin/env python3

"""Streaming JSON Lines output handler for pipeline processing.

``KeylogEvent`` lines carry raw key material only on opt-in (``-k`` or
``--json-keys``); otherwise they are redacted, see :mod:`friTap.output.key_material`.
"""

from __future__ import annotations

import json
import logging
from typing import IO, TYPE_CHECKING, Optional

from .base import OutputHandler
from .key_material import apply_key_material_policy

if TYPE_CHECKING:
    from ..events import EventBus, FriTapEvent


#: Internal plumbing events that never reach a JSONL output (file or ``-j -``):
#: breadcrumbs are a crash-attribution aid, FlowEvent carries a live (non-JSON)
#: Flow object.
INTERNAL_EVENTS = frozenset({"HookBreadcrumbEvent", "FlowEvent"})


def is_internal_event(event: "FriTapEvent") -> bool:
    """True for events that are internal plumbing, not part of the JSONL output."""
    return type(event).__name__ in INTERNAL_EVENTS


class JsonlOutputHandler(OutputHandler):
    """Writes one JSON object per line for streaming pipelines."""

    # The JSON document is the primary machine-readable input (AI agents,
    # scripts) and serialises every data event, so -j alone turns the agent's
    # plaintext read/write hooks on.
    consumes_plaintext = True

    def __init__(self, output_path: str, include_key_material: bool = False) -> None:
        self._path = output_path
        self._file: Optional[IO] = None
        self._logger = logging.getLogger("friTap.output.jsonl")
        # Raw key_data/payload in KeylogEvent lines only on opt-in (-k / --json-keys).
        self._include_key_material = include_key_material

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import FriTapEvent
        from .shared_output_file import open_shared_output_file
        # Shared per path: the Windows LSASS session streams into the same
        # --json file; each line is one write, so lines never interleave.
        self._file, _created = open_shared_output_file(self._path, "w")
        event_bus.subscribe(FriTapEvent, self._on_any_event)

    def _on_any_event(self, event: "FriTapEvent") -> None:
        if not self._file or is_internal_event(event):
            return
        self._write_record(self._build_record(event))

    def _build_record(self, event: "FriTapEvent") -> dict:
        """One JSON-ready dict per event (bytes hex-encoded, key material per policy)."""
        record = {
            "event_type": type(event).__name__,
            "timestamp": event.timestamp,
            "protocol": event.protocol,
        }
        # Add all dataclass fields except timestamp/protocol (already added)
        for key, value in event.__dict__.items():
            if key.startswith("_") or key in ("timestamp", "protocol"):
                continue
            if isinstance(value, bytes):
                record[key] = value.hex()
            else:
                record[key] = value
        if type(event).__name__ == "KeylogEvent":
            record = apply_key_material_policy(record, self._include_key_material)
        return record

    def _write_record(self, record: dict) -> None:
        """Write *record* as one flushed line; errors are logged, never raised."""
        try:
            self._file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._file.flush()
        except Exception as e:
            self._logger.error("JSONL write error: %s", e)

    def close(self) -> None:
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None
