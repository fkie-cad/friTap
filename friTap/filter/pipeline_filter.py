"""Filtered sink wrapper for headless mode display filtering."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.filter.evaluator import FilterEngine
    from friTap.schemas.canonical import DataCanonical, KeylogCanonical, MetaCanonical
    from friTap.sinks.base import Sink


def _headless_fields_hint() -> str:
    """The fields a headless filter can use (those with a DataCanonical accessor)."""
    from friTap.filter.fields import CANONICAL_FIELDS

    return f"{', '.join(sorted(CANONICAL_FIELDS))} (e.g. protocol == telegram)"


def build_headless_filter(expression: str) -> "FilterEngine | str":
    """Parse *expression* once for headless capture: an engine, or an error message.

    Headless mode filters each data event on its own (no flows are built), so
    only fields with a DataCanonical accessor can be evaluated. Anything else
    (``telegram``, ``http.host``, ``frame contains x``, ``mtproto.*`` ...)
    would silently drop every data event, so it is rejected up front.
    """
    from friTap.filter.evaluator import FilterEngine
    from friTap.filter.fields import non_canonical_fields

    engine = FilterEngine.try_create(expression)
    if isinstance(engine, str):
        return f"Invalid filter expression: {engine}"
    unsupported = non_canonical_fields(engine.fields)
    if not unsupported:
        return engine
    return (
        f"Filter field(s) not available in headless mode: {', '.join(unsupported)}. "
        f"Headless capture filters single data events and supports only: "
        f"{_headless_fields_hint()}. Use the TUI (or offline replay) for "
        f"flow-level fields."
    )


def headless_filter_error(expression: str) -> str | None:
    """Validate *expression* for headless capture; return an error or None."""
    result = build_headless_filter(expression)
    return result if isinstance(result, str) else None


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
