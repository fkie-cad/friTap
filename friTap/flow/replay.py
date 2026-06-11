#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Flow replay / overview source for ``.tap`` files.

Provides the :class:`IFlowSource` protocol and a :class:`ReplayController` that
loads flows from a ``.tap`` file for a high-level overview (lightweight flow
summaries) plus on-demand full-flow detail. This is presentation-agnostic — it
wraps :class:`~friTap.flow.tap_reader.TapReader` and has **no** TUI dependency —
so external tools (web UIs, TUIs, plain CLIs, Sandroid) can consume it directly.

The friTap TUI imports these symbols from here via a thin back-compat shim at
:mod:`friTap.tui.replay_controller`.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Optional, Protocol, TYPE_CHECKING

from friTap.flow.tap_format import FlowSummary, TapMeta
from friTap.flow.tap_reader import TapReader

if TYPE_CHECKING:
    from friTap.flow.models import Flow
    from friTap.parsers.base import ParseResult

logger = logging.getLogger(__name__)


class _LRUCache(OrderedDict):
    """OrderedDict-based LRU cache with a fixed maximum size."""

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


class ReplayController:
    """Loads and serves flows from a .tap file for TUI replay mode.

    Satisfies the IFlowSource protocol so MainScreen can use it
    interchangeably with FlowCollector via CaptureController.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._reader: Optional[TapReader] = None
        self._meta: Optional[TapMeta] = None
        self._summaries: list[FlowSummary] = []
        self._flow_cache: _LRUCache = _LRUCache(maxsize=128)
        self._reparse_results: dict[str, tuple[Optional["ParseResult"], Optional["ParseResult"]]] = {}

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
        """Open the .tap file and load flow summaries.

        Returns the file-level TapMeta.
        """
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
        """Return all flows as full Flow objects.

        Note: For large captures this loads everything into memory.
        Prefer get_summaries() + get_flow() for on-demand loading.
        """
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
        # Re-apply reparse results that survive cache eviction
        if flow_id in self._reparse_results:
            req, resp = self._reparse_results[flow_id]
            if req is not None:
                flow.request = req
            if resp is not None:
                flow.response = resp
        return flow

    def store_reparse(
        self,
        flow_id: str,
        request: Optional["ParseResult"],
        response: Optional["ParseResult"],
    ) -> None:
        """Store reparse results so they survive cache eviction."""
        self._reparse_results[flow_id] = (request, response)

    def close(self) -> None:
        """Close the reader and release resources."""
        if self._reader is not None:
            self._reader.close()
            self._reader = None
        self._flow_cache.clear()
        self._reparse_results.clear()
        self._summaries.clear()

    def __enter__(self) -> "ReplayController":
        self.load()
        return self

    def __exit__(self, *args) -> None:
        self.close()
