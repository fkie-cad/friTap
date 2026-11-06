"""
Read services over a ``.tap`` capture: digest, endpoints, flow detail, findings.

Thin adapters around :mod:`friTap.analysis.digest` / ``digest_flow`` so the
agent tools share one implementation (and one safety contract) with
``fritap report``: payload strings stay under ``untrusted``, finding values
are redacted unless ``show_values``.
"""

from __future__ import annotations

import os
import threading
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any, Callable, Iterable

from friTap.agent_api.services.protocols import check_slice

FLOW_FIELDS = ("flow", "request", "response", "messages")
_FLOW_BASE_KEYS = ("schema", "source", "params", "notice")
_SLICE_KEYS = ("protocol", "app_protocol", "filter")
#: Scan results kept per process (an agent paging one capture hits the same entry).
SCAN_CACHE_SIZE = 4


class TapResultCache:
    """Small thread-safe LRU of results computed from a ``.tap`` file.

    Keyed by the file's real path, ``st_mtime_ns`` and ``st_size`` (a
    rewritten capture misses) plus the caller's parameters, so paging
    ``list_endpoints``/``list_findings`` or calling several read tools on one
    capture decodes it once instead of once per call. Cached values are
    shared: callers must not mutate them.
    """

    def __init__(self, maxsize: int = SCAN_CACHE_SIZE) -> None:
        self.maxsize = maxsize
        self._entries: OrderedDict[tuple, Any] = OrderedDict()
        self._lock = threading.Lock()

    def get_or_compute(self, tap: Path, params: tuple, compute: Callable[[], Any]) -> Any:
        key = (*_file_identity(tap), *params)
        with self._lock:
            if key in self._entries:
                self._entries.move_to_end(key)
                return self._entries[key]
        value = compute()
        with self._lock:
            self._entries[key] = value
            self._entries.move_to_end(key)
            while len(self._entries) > self.maxsize:
                self._entries.popitem(last=False)
        return value

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


def _file_identity(tap: Path) -> tuple:
    stat = os.stat(tap)
    return os.path.realpath(tap), stat.st_mtime_ns, stat.st_size


#: The process-wide cache of the read tools.
scan_cache = TapResultCache()


def slice_key(params: dict[str, Any]) -> tuple:
    """The ``protocol``/``app_protocol``/``filter`` values of ``params`` (a cache key part)."""
    return tuple(params.get(key) for key in _SLICE_KEYS)


def cached_scan(tap: Path, params: dict[str, Any], category: str | None = None,
                with_findings: bool = False):
    """``scan_tap`` of the sliced capture, memoized in :data:`scan_cache`.

    ``with_findings`` runs the built-in analyzers (only those able to emit
    ``category`` when one is given), revealing values when ``show_values``.
    """
    from friTap.analysis.digest import builtin_analyzers, scan_tap

    selector = selector_for(params)
    show_values = bool(params.get("show_values", False)) if with_findings else False

    def compute():
        analyzers = ()
        if with_findings:
            categories = frozenset({category}) if category else None
            analyzers = builtin_analyzers(show_values, categories=categories)
        return scan_tap(str(tap), selector, analyzers)

    key = ("scan", slice_key(params), with_findings, category, show_values)
    return scan_cache.get_or_compute(tap, key, compute)


def selector_for(params: dict[str, Any]):
    """:class:`FlowSelector` for the ``protocol`` / ``app_protocol`` / ``filter`` params.

    Raises ``unknown_protocol`` ToolError or ``FilterSyntaxError`` (-> bad_filter).
    """
    from friTap.analysis.digest import FlowSelector

    check_slice(params)
    return FlowSelector(protocol=params.get("protocol"), app_protocol=params.get("app_protocol"),
                        filter_expr=params.get("filter"))


def _source(tap: Path, scan: Any) -> dict[str, Any]:
    return {"file": tap.name, "flows_total": scan.flows_total, "flows_selected": scan.selected}


# ---------------------------------------------------------------------------
# Digest
# ---------------------------------------------------------------------------

def digest_scan(tap: Path, params: dict[str, Any]):
    """The digest's ``scan_tap`` pass (focus analyzers), memoized in :data:`scan_cache`.

    Its ``ordinals`` match :func:`cached_scan` of the same slice, so one pass can
    feed both the digest and per-flow selection (Markdown export).
    """
    from friTap.analysis.digest import builtin_analyzers, scan_tap

    selector = selector_for(params)
    focus = params.get("focus", "all")
    show_values = bool(params.get("show_values", False))
    key = ("digest_scan", slice_key(params), focus, show_values)
    return scan_cache.get_or_compute(
        tap, key, lambda: scan_tap(str(tap), selector, builtin_analyzers(show_values, focus)))


def digest(tap: Path, params: dict[str, Any]) -> dict[str, Any]:
    """The ``fritap.digest/2`` document (``build_digest``) for the sliced capture."""
    from friTap.analysis.digest import build_digest, validate_digest_args

    check_slice(params)
    focus = params.get("focus", "all")
    validate_digest_args(focus, params["budget"])
    return build_digest(
        str(tap), focus=focus, protocol=params.get("protocol"),
        app_protocol=params.get("app_protocol"), filter_expr=params.get("filter"),
        budget_tokens=params["budget"], show_values=params.get("show_values", False),
        attribute=params.get("attribute", False), first_party=params.get("first_party"),
        scan=digest_scan(tap, params),
    )


def digest_markdown(doc: dict[str, Any]) -> str:
    """Compact Markdown rendering of a digest document."""
    from friTap.analysis.digest_render import render_markdown

    return render_markdown(doc)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _flatten_endpoints(sections: dict[str, dict]) -> list[dict]:
    rows = [{"protocol": group, **row}
            for group, section in sections.items() for row in section["endpoints"]]
    return sorted(rows, key=lambda r: (-r["count"], -r["bytes"], r["protocol"], r["ref"]))


def endpoints(tap: Path, params: dict[str, Any]) -> tuple[dict[str, Any], list[dict]]:
    """``(source, rows)``: every endpoint cluster of the slice, busiest first.

    Rows carry keys and value shapes only (never values), like the digest.
    """
    from friTap.analysis.digest import protocol_sections

    scan = cached_scan(tap, params)
    return _source(tap, scan), _flatten_endpoints(protocol_sections(scan.agg))


# ---------------------------------------------------------------------------
# Flow detail
# ---------------------------------------------------------------------------

def project_flow_fields(detail: dict[str, Any], fields: Iterable[str] | None) -> dict[str, Any]:
    """Keep the envelope keys plus the requested ``fields`` (all when ``None``)."""
    if not fields:
        return detail
    wanted = set(fields)
    if "messages" in wanted:
        wanted.add("messages_total")
    return {key: value for key, value in detail.items()
            if key in _FLOW_BASE_KEYS or key in wanted}


def flow_detail(tap: Path, params: dict[str, Any]) -> dict[str, Any]:
    """``fritap.flow/1`` drill-down of ``params["ref"]``, projected to ``fields``."""
    from friTap.analysis.digest_flow import build_flow_detail

    detail = build_flow_detail(str(tap), params["ref"], max_bytes=params["max_bytes"],
                               show_values=params.get("show_values", False))
    return project_flow_fields(detail, params.get("fields"))


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _finding_filter(params: dict[str, Any]):
    from friTap.analysis.filtering import FindingFilter

    category = params.get("category")
    return FindingFilter(min_severity=params.get("min_severity"),
                         categories=frozenset({category}) if category else None)


def findings(tap: Path, params: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[dict]]:
    """``(source, stats, rows)``: clustered findings of the slice, most severe first.

    Values are redacted unless ``params["show_values"]``.
    """
    from friTap.analysis.digest import finding_rows
    from friTap.analysis.filtering import apply, summarize

    show_values = params.get("show_values", False)
    scan = cached_scan(tap, params, category=params.get("category"), with_findings=True)
    selected = apply(scan.findings, _finding_filter(params))
    stats = summarize(selected)
    summary = {"total": stats["total"], "by_severity": stats["by_severity"],
               "by_category": stats["by_category"]}
    return _source(tap, scan), summary, finding_rows(selected, show_values, scan.ordinals)


# ---------------------------------------------------------------------------
# Canary known-value search (find_values)
# ---------------------------------------------------------------------------

#: Confidence ranking for budget trimming (lowest-confidence rows drop first).
from friTap.analysis.canary import _CONFIDENCE_RANK


def _count_by(rows: list[dict], key: str) -> dict[str, int]:
    """Count rows grouped by ``row[key]`` (sorted for a stable document)."""
    return dict(sorted(Counter(str(r.get(key, "")) for r in rows).items()))


def _canary_warnings(canaries: list) -> list[dict]:
    """The non-empty ``Canary.warning`` notes, as serializable rows."""
    return [{"label": c.label, "kind": c.kind, "warning": c.warning}
            for c in canaries if c.warning]


def _find_values_body(tap: Path, flows_total: int,
                      canaries: list, rows: list[dict], budget: int | None) -> dict[str, Any]:
    """Assemble the (optionally budget-trimmed) ``find_values`` result body."""
    from friTap.analysis import digest

    warnings = _canary_warnings(canaries)

    def assemble(kept: list[dict]) -> dict[str, Any]:
        kept_ids = {id(row) for row in kept}
        in_order = [row for row in rows if id(row) in kept_ids]  # keep original order
        body: dict[str, Any] = {
            "source": {"file": tap.name, "flows_total": flows_total},
            "summary": {"hits": len(in_order), "canaries": len(canaries),
                        "by_label": _count_by(in_order, "label"),
                        "by_confidence": _count_by(in_order, "confidence")},
            "warnings": warnings,
            "rows": in_order,
        }
        dropped = len(rows) - len(in_order)
        if dropped:
            body["truncated"] = digest._truncated_marker(Counter({"rows": dropped}))
        return body

    if budget is None:
        return assemble(list(rows))

    # Drop lowest-confidence first; fit_budget measures each row's cost once.
    ordered = sorted(rows, key=lambda r: _CONFIDENCE_RANK.get(r.get("confidence", ""), 0))
    kept, _dropped = digest.fit_budget(ordered, assemble, budget,
                                       cost=digest.estimate_tokens)
    return assemble(kept)


def find_values(tap: Path, params: dict[str, Any]) -> dict[str, Any]:
    """Search a capture for the operator's known canary values.

    Expands each ``{value, kind, label}`` spec into its obvious obfuscations
    and scans every decoded flow. Matched spans stay under ``untrusted`` and
    are withheld unless ``show_values`` (gated by the registry / server policy).
    """
    from friTap.analysis import canary
    from friTap.analysis.digest import flow_ref
    from friTap.flow.tap_reader import TapReader

    canaries = canary.parse_canaries(params.get("values") or [])
    show_values = bool(params.get("show_values", False))
    candidates = canary.build_candidates(canaries)

    # Stream flows once (don't hold every decoded body in memory) and tag each
    # hit with the shared f<N> ref the other read tools emit, not the raw id.
    rows: list[dict] = []
    flows_total = 0
    with TapReader(str(tap)) as reader:
        for ordinal, _summary, flow in reader.iter_flows():
            flows_total += 1
            ref = flow_ref(ordinal)
            for hit in canary.scan_flow(flow, candidates):
                row = canary.hit_to_row(hit, show_values)
                row.pop("flow_id", None)
                row["ref"] = ref
                rows.append(row)
    return _find_values_body(tap, flows_total, canaries, rows, params.get("budget"))


__all__ = [
    "FLOW_FIELDS",
    "SCAN_CACHE_SIZE",
    "TapResultCache",
    "cached_scan",
    "scan_cache",
    "slice_key",
    "digest",
    "digest_scan",
    "digest_markdown",
    "endpoints",
    "findings",
    "find_values",
    "flow_detail",
    "project_flow_fields",
    "selector_for",
]
