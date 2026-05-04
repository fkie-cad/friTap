"""Filtered sink wrapper for headless mode display filtering."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.filter.evaluator import FilterEngine
    from friTap.schemas.canonical import DataCanonical, KeylogCanonical, MetaCanonical
    from friTap.sinks.base import Sink


class FilteredSink:
    """Wraps a Sink to apply network-level display filtering on DataCanonical events.

    Keylog and meta events pass through unfiltered. Data events are only
    forwarded if they match the filter engine (evaluated against DataCanonical
    network fields: ip.src, ip.dst, tcp.srcport, tcp.dstport, frame.protocol).

    For application-level filtering (HTTP fields, flow state, etc.), use
    FilterEngine.matches(flow) directly in the FlowCollector callback chain.
    """

    def __init__(self, inner: "Sink", engine: "FilterEngine") -> None:
        self._inner = inner
        self._engine = engine

    def open(self) -> None:
        self._inner.open()

    def on_keylog(self, event: "KeylogCanonical") -> None:
        self._inner.on_keylog(event)

    def on_data(self, event: "DataCanonical") -> None:
        if self._engine.matches_canonical(event):
            self._inner.on_data(event)

    def on_meta(self, event: "MetaCanonical") -> None:
        self._inner.on_meta(event)

    def flush(self) -> None:
        self._inner.flush()

    def close(self) -> None:
        self._inner.close()
