#!/usr/bin/env python3

"""Flow replay / overview source for ``.tap`` files.

Provides :class:`IFlowSource` and :class:`ReplayController`: lightweight flow
summaries plus on-demand full-flow detail, wrapping
:class:`~friTap.flow.tap_reader.TapReader` with no TUI dependency.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import TYPE_CHECKING, Optional, Protocol, runtime_checkable

from friTap.flow.tap_format import FlowSummary, TapMeta
from friTap.flow.tap_reader import TapReader

if TYPE_CHECKING:
    from friTap.flow.models import Flow
    from friTap.parsers.base import ParseResult

logger = logging.getLogger(__name__)


class _LRUCache(OrderedDict):
    """OrderedDict-based LRU cache with a fixed maximum size."""

    # Not output.bounded_lru.BoundedLRU: callers need dict assignment, move_to_end and clear().

    def __init__(self, maxsize: int = 128) -> None:
        super().__init__()
        self._maxsize = maxsize

    def get(self, key, default=None):
        try:
            self.move_to_end(key)
            return self[key]
        except KeyError:
            return default

    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        if len(self) > self._maxsize:
            self.popitem(last=False)


class IFlowSource(Protocol):
    """Minimal interface that MainScreen needs from either CaptureController or ReplayController."""

    def get_flows(self) -> list["Flow"]: ...
    def get_flow(self, flow_id: str) -> Optional["Flow"]: ...


@runtime_checkable
class TapSource(Protocol):
    """Contract a host can implement to feed the replay viewer (the members the viewer calls).

    :class:`ReplayController` is the reference implementation. The source must
    already be **loaded**: the viewer reads ``flow_count`` and ``get_summaries()``
    on mount and never loads it. ``close()`` is deliberately not a member: the
    viewer never closes a host-passed source, only controllers it opened itself.
    """

    @property
    def header(self): ...

    @property
    def flow_count(self) -> int: ...

    def get_summaries(self) -> list[FlowSummary]: ...
    def get_flow(self, flow_id: str) -> Optional["Flow"]: ...
    def get_flows(self) -> list["Flow"]: ...
    def store_reparse(
        self,
        flow_id: str,
        request: Optional["ParseResult"],
        response: Optional["ParseResult"],
        clear_trailing: bool = False,
    ) -> None: ...
    def read_all_findings(self) -> list: ...
    def read_request_contexts(self) -> list: ...


class ReplayController:
    """Loads and serves flows from a .tap file for replay mode (satisfies :class:`IFlowSource`)."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._reader: Optional[TapReader] = None
        self._meta: Optional[TapMeta] = None
        self._summaries: list[FlowSummary] = []
        self._flow_cache: _LRUCache = _LRUCache(maxsize=128)
        self._reparse_results: dict[str, tuple[Optional["ParseResult"], Optional["ParseResult"]]] = {}
        # Flow ids whose stale trailing-data segments are dropped on every (re)load
        # (e.g. decrypted TL flows once mis-parsed as WebSocket).
        self._clear_trailing_ids: set[str] = set()

    @property
    def replay_file(self) -> str:
        return self._path

    @property
    def flow_count(self) -> int:
        return len(self._summaries)

    @property
    def meta(self) -> Optional[TapMeta]:
        return self._meta

    @property
    def header(self):
        return self._reader.header if self._reader else None

    def load(self) -> TapMeta:
        """Open the .tap file, load flow summaries and return the file-level TapMeta."""
        self._reader = TapReader(self._path)
        self._meta = self._reader.open()
        self._summaries = self._reader.read_flow_summaries()
        logger.info(
            "Replay loaded: %s (%d flows)", self._path, len(self._summaries)
        )
        return self._meta

    def get_summaries(self) -> list[FlowSummary]:
        """Return all flow summaries (lightweight, no chunk/body data)."""
        return list(self._summaries)

    def get_flows(self) -> list["Flow"]:
        """Return all flows as full Flow objects (loads everything; prefer summaries + :meth:`get_flow`)."""
        if self._reader is None:
            return []
        return self._reader.read_all_flows()

    def get_flow(self, flow_id: str) -> Optional["Flow"]:
        """Load a full Flow by ID (on-demand from disk, LRU-cached)."""
        flow = self._flow_cache.get(flow_id)
        if flow is None:
            if self._reader is None:
                return None
            flow = self._reader.read_flow(flow_id)
            if flow is None:
                return None
            self._flow_cache[flow_id] = flow
        # Re-apply reparse results that survive cache eviction.
        if flow_id in self._reparse_results:
            req, resp = self._reparse_results[flow_id]
            if req is not None:
                flow.request = req
            if resp is not None:
                flow.response = resp
        if flow_id in self._clear_trailing_ids:
            from friTap.flow.reparse import clear_trailing_data
            clear_trailing_data(flow)
        return flow

    def store_reparse(
        self,
        flow_id: str,
        request: Optional["ParseResult"],
        response: Optional["ParseResult"],
        clear_trailing: bool = False,
    ) -> None:
        """Store reparse results so they survive cache eviction.

        With *clear_trailing*, every later :meth:`get_flow` also drops trailing-data state.
        """
        self._reparse_results[flow_id] = (request, response)
        if clear_trailing:
            self._clear_trailing_ids.add(flow_id)

    def read_all_findings(self) -> list:
        """Return persisted findings (dicts) across all flows (REC_FINDING records); empty if none."""
        if self._reader is None:
            return []
        findings: list = []
        for summary in self._summaries:
            findings.extend(self._reader.read_findings(summary.flow_id))
        return findings

    def read_request_contexts(self) -> list:
        """Return the persisted Java request contexts (REC_REQUEST_CONTEXT dicts); empty when none or not loaded."""
        if self._reader is None:
            return []
        return list(self._reader.iter_request_contexts())

    def has_findings(self) -> bool:
        """True if the .tap file contains any persisted findings."""
        if self._reader is None:
            return False
        return self._reader.has_findings()

    def close(self) -> None:
        """Close the reader and release resources."""
        if self._reader is not None:
            self._reader.close()
            self._reader = None
        self._flow_cache.clear()
        self._reparse_results.clear()
        self._clear_trailing_ids.clear()
        self._summaries.clear()

    def __enter__(self) -> "ReplayController":
        self.load()
        return self

    def __exit__(self, *args) -> None:
        self.close()
