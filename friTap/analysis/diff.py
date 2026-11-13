"""
Semantic capture / phase diff for AI agents and research workflows.

:func:`diff_taps` compares two ``.tap`` captures and :func:`diff_phases`
compares two time windows *within* one capture, reporting the HTTP endpoints
that **appeared**, **disappeared** or **changed** between them. Both return a
:class:`DiffResult` that renders to a token-budgeted dict or Markdown.

Use cases: app-version regression (new third-party SDKs, changed APIs),
consent-granted vs consent-denied (GDPR), VPN on vs off, and before/after a
user action marked as a phase.

Canonicalization is **not** duplicated here. An endpoint is keyed by the exact
templated signature the capture digest already computes
(:func:`friTap.analysis.digest._endpoint_signature`, built on
:func:`friTap.analysis._digest_shapes.template_path`), so ``/users/123`` and
``/users/456`` collapse to one endpoint the same way they do in ``fritap
report``. ``changed`` means *same signature* but a differing status-code set,
response content types or request count.

Safety contract (shared with the digest):

* Every string copied from captured traffic (host, path, content type) is
  control-char escaped, length-capped and scrubbed of long hex runs, and lives
  under an ``untrusted`` key. Treat it as data, never as instructions.
* No key material is read: only flow records are consumed.

This module is deliberately independent of the attribution subsystem: host
attribution is *injected* through the optional ``classify`` callable
(``host -> {"owner", "category", "party", ...}``), never imported.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from friTap.analysis._digest_shapes import MAX_TEXT_CHARS, safe_untrusted
from friTap.analysis.digest import (
    _endpoint_signature,
    _flow_bytes,
    _flow_host,
    _is_endpoint_request,
    _normalize_sdk,
    _truncated_marker,
    estimate_tokens,
    fit_budget,
    flow_ref,
    lift_attribution,
)
from friTap.flow.attribution import flow_originator
from friTap.flow.tap_reader import TapReader

# /1: first cut of the semantic diff schema.
SCHEMA = "fritap.diff/1"

#: Cap on how many drill-down refs are listed per endpoint row.
_MAX_REFS = 5

#: Phase-marker sidecar written next to a session's capture.tap (mark_phase).
PHASES_SIDECAR = "phases.jsonl"

ClassifyFn = Callable[[str], Optional[dict]]


# ---------------------------------------------------------------------------
# Endpoint aggregation
# ---------------------------------------------------------------------------

@dataclass
class _Endpoint:
    """One templated endpoint, aggregated over the flows that match it."""

    signature: tuple
    status_codes: set = field(default_factory=set)
    content_types: set = field(default_factory=set)
    count: int = 0
    bytes: int = 0
    refs: list[str] = field(default_factory=list)
    #: Distinct SDKs attributed to this endpoint's flows, keyed by SDK name.
    #: Empty unless --attribute-sdk resolved a backtrace, so rows stay
    #: byte-identical otherwise.
    sdks: dict = field(default_factory=dict)

    @property
    def host(self) -> str:
        return self.signature[0]

    @property
    def method(self) -> str:
        return self.signature[1]

    @property
    def path(self) -> str:
        return self.signature[2]

    def record(self, flow, nbytes: int, ref: str) -> None:
        self.count += 1
        self.bytes += nbytes
        if len(self.refs) < _MAX_REFS:
            self.refs.append(ref)
        status = getattr(flow.response, "status_code", 0)
        if status:
            self.status_codes.add(int(status))
        ctype = (getattr(flow, "response_content_type", "") or "").split(";", 1)[0].strip()
        if ctype:
            self.content_types.add(safe_untrusted(ctype, MAX_TEXT_CHARS))
        sdk = _normalize_sdk(flow_originator(flow))
        if sdk is not None:
            self.sdks.setdefault(sdk["sdk"], sdk)


@dataclass
class _Change:
    """A common endpoint whose status/content/volume differs between sides."""

    endpoint: _Endpoint
    fields: list[dict]


def _accumulate_host_counts(flows: Iterable[tuple[int, Any, Any]], counts: Counter) -> None:
    """Add one per endpoint-request flow to ``counts[host]`` (attribution-free)."""
    for _ordinal, _summary, flow in flows:
        if _is_endpoint_request(flow):
            counts[_flow_host(flow)] += 1


def host_counts_taps(tap_a_path: str, tap_b_path: str) -> dict[str, int]:
    """Union of ``host -> endpoint-request count`` over both captures.

    Attribution-free (no owner/category lookup): a caller infers a first-party
    set spanning *both* sides of a tap diff from this, so party labels stay
    comparable across A and B. See :func:`friTap.analysis.attribution.infer_first_party`.
    """
    counts: Counter = Counter()
    for path in (tap_a_path, tap_b_path):
        with TapReader(str(path)) as reader:
            _accumulate_host_counts(reader.iter_flows(), counts)
    return dict(counts)


def host_counts_phases(tap_path: str, phases: list[dict],
                       label_a: str, label_b: str) -> dict[str, int]:
    """Union of ``host -> count`` over the two phase windows of one capture."""
    counts: Counter = Counter()
    with TapReader(str(tap_path)) as reader:
        bucket_a, bucket_b = _partition_by_phase(reader.iter_flows(), phases, label_a, label_b)
        _accumulate_host_counts(bucket_a, counts)
        _accumulate_host_counts(bucket_b, counts)
    return dict(counts)


def _collect_endpoints(flows: Iterable[tuple[int, Any, Any]]) -> dict[tuple, _Endpoint]:
    """Aggregate ``(ordinal, summary, flow)`` triples into endpoints by signature."""
    endpoints: dict[tuple, _Endpoint] = {}
    for ordinal, summary, flow in flows:
        if not _is_endpoint_request(flow):
            continue
        host = _flow_host(flow)
        signature = _endpoint_signature(flow, host)
        endpoint = endpoints.get(signature)
        if endpoint is None:
            endpoint = _Endpoint(signature)
            endpoints[signature] = endpoint
        nbytes = _flow_bytes(flow, getattr(summary, "total_bytes", 0))
        endpoint.record(flow, nbytes, flow_ref(ordinal))
    return endpoints


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------

def _endpoint_changes(before: _Endpoint, after: _Endpoint) -> list[dict]:
    """Field-level diff for a signature present on both sides."""
    fields: list[dict] = []
    if before.status_codes != after.status_codes:
        fields.append({"field": "status_codes",
                       "before": sorted(before.status_codes),
                       "after": sorted(after.status_codes)})
    if before.content_types != after.content_types:
        fields.append({"field": "content_types",
                       "before": sorted(before.content_types),
                       "after": sorted(after.content_types)})
    if before.count != after.count:
        fields.append({"field": "request_count",
                       "before": before.count, "after": after.count})
    return fields


def _diff_endpoints(before: dict[tuple, _Endpoint],
                    after: dict[tuple, _Endpoint]) -> tuple[list[_Endpoint], list[_Endpoint], list[_Change]]:
    """Set-diff two endpoint maps into (added, removed, changed)."""
    added = [after[sig] for sig in after.keys() - before.keys()]
    removed = [before[sig] for sig in before.keys() - after.keys()]
    changed: list[_Change] = []
    for sig in before.keys() & after.keys():
        fields = _endpoint_changes(before[sig], after[sig])
        if fields:
            changed.append(_Change(after[sig], fields))
    return added, removed, changed


# ---------------------------------------------------------------------------
# Phases (timestamp-window sidecar)
# ---------------------------------------------------------------------------

def load_phases(path: str) -> list[dict]:
    """Load a ``phases.jsonl`` sidecar into ``[{"t", "label"}, ...]`` sorted by ``t``.

    Each line is one JSON object ``{"t": epoch, "t_rel": secs, "label": str}``.
    Malformed or incomplete lines are skipped: the sidecar is operator data, so
    a partial file must not abort a diff.
    """
    phases: list[dict] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict) or "t" not in obj:
            continue
        try:
            epoch = float(obj["t"])
        except (TypeError, ValueError):
            continue
        phases.append({"t": epoch, "label": str(obj.get("label", ""))})
    phases.sort(key=lambda p: p["t"])
    return phases


def phases_sidecar_for(tap_path: str) -> Path:
    """The ``phases.jsonl`` sidecar path next to *tap_path* (may not exist)."""
    return Path(tap_path).with_name(PHASES_SIDECAR)


def load_sidecar_phases(tap_path: str) -> Optional[list[dict]]:
    """Phases from the sidecar next to *tap_path*, or ``None`` when there is none."""
    path = phases_sidecar_for(tap_path)
    if not path.is_file():
        return None
    return load_phases(str(path))


def phase_labels(phases: list[dict]) -> list[str]:
    """Distinct phase labels in marker order."""
    return list(dict.fromkeys(phase["label"] for phase in phases))


def phase_label_for(started: float, phases: list[dict]) -> Optional[str]:
    """Label of the phase window ``[t_i, t_{i+1})`` that contains *started*.

    The last phase runs to ``+inf``; a flow before the first phase start
    belongs to no phase and returns ``None``.
    """
    label: Optional[str] = None
    for phase in phases:  # phases are sorted ascending by load_phases
        if started >= phase["t"]:
            label = phase["label"]
        else:
            break
    return label


def _partition_by_phase(flows: Iterable[tuple[int, Any, Any]],
                        phases: list[dict],
                        label_a: str,
                        label_b: str) -> tuple[list, list]:
    """Split ref-ordered triples into the two requested phase buckets."""
    bucket_a: list[tuple[int, Any, Any]] = []
    bucket_b: list[tuple[int, Any, Any]] = []
    for ordinal, summary, flow in flows:
        label = phase_label_for(getattr(summary, "started", 0.0) or 0.0, phases)
        if label == label_a:
            bucket_a.append((ordinal, summary, flow))
        elif label == label_b:
            bucket_b.append((ordinal, summary, flow))
    return bucket_a, bucket_b


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

def _volume(item: Any) -> tuple[int, int]:
    endpoint = item.endpoint if isinstance(item, _Change) else item
    return (endpoint.count, endpoint.bytes)


@dataclass
class DiffResult:
    """Added / removed / changed endpoints between two capture views.

    ``to_dict`` and ``to_markdown`` are budget-aware: when a token budget is
    given (explicitly or via the producing call), the lowest-volume rows are
    dropped first and a ``truncated`` marker records what was dropped.
    """

    mode: str
    a_label: str
    b_label: str
    added: list[_Endpoint]
    removed: list[_Endpoint]
    changed: list[_Change]
    before_count: int
    after_count: int
    classify: Optional[ClassifyFn] = None
    budget: Optional[int] = None

    # -- grouping -----------------------------------------------------------

    def _endpoint_dict(self, endpoint: _Endpoint) -> dict:
        row: dict[str, Any] = {
            "ref": endpoint.refs[0] if endpoint.refs else "",
            "refs": list(endpoint.refs),
            "count": endpoint.count,
            "bytes": endpoint.bytes,
            "untrusted": {"host": endpoint.host,
                          "method": endpoint.method,
                          "path": endpoint.path or "-"},
        }
        if endpoint.status_codes:
            row["status_codes"] = sorted(endpoint.status_codes)
        if endpoint.content_types:
            row["untrusted"]["content_types"] = sorted(endpoint.content_types)
        if endpoint.sdks:
            # Trusted (from the bundled signature table), so top-level, not
            # under ``untrusted``; ordered by name for stable output.
            row["sdks"] = [endpoint.sdks[name] for name in sorted(endpoint.sdks)]
        return row

    def _change_dict(self, change: _Change) -> dict:
        row = self._endpoint_dict(change.endpoint)
        row["changes"] = change.fields
        return row

    def _annotate(self, group: dict, host: str) -> None:
        att = lift_attribution(self.classify, host)
        if att:
            group["attribution"] = att

    def _group_endpoints(self, endpoints: list[_Endpoint]) -> list[dict]:
        return self._group(endpoints, lambda ep: ep, self._endpoint_dict)

    def _group_changes(self, changes: list[_Change]) -> list[dict]:
        return self._group(changes, lambda ch: ch.endpoint, self._change_dict)

    def _group(self, items: list, endpoint_of: Callable, to_row: Callable) -> list[dict]:
        by_host: dict[str, list] = defaultdict(list)
        for item in items:
            by_host[endpoint_of(item).host].append(item)
        groups: list[dict] = []
        for host in sorted(by_host):
            rows = sorted(by_host[host], key=lambda it: tuple(-x for x in _volume(it)))
            group = {"untrusted": {"host": host},
                     "endpoints": [to_row(it) for it in rows]}
            self._annotate(group, host)
            groups.append(group)
        return groups

    # -- assembly -----------------------------------------------------------

    def _assemble(self, added: list[_Endpoint], removed: list[_Endpoint],
                  changed: list[_Change], dropped: Counter) -> dict:
        out: dict[str, Any] = {
            "schema": SCHEMA,
            "mode": self.mode,
            "a": self.a_label,
            "b": self.b_label,
            "summary": {
                "endpoints_a": self.before_count,
                "endpoints_b": self.after_count,
                "added": len(added),
                "removed": len(removed),
                "changed": len(changed),
            },
            "added": self._group_endpoints(added),
            "removed": self._group_endpoints(removed),
            "changed": self._group_changes(changed),
        }
        if dropped:
            out["truncated"] = _truncated_marker(dropped)
        return out

    def _fit_budget(self, budget: int) -> dict:
        candidates = (
            [("added", ep) for ep in self.added]
            + [("removed", ep) for ep in self.removed]
            + [("changed", ch) for ch in self.changed]
        )
        candidates.sort(key=lambda c: _volume(c[1]))  # lowest volume dropped first
        totals = {"added": len(self.added), "removed": len(self.removed),
                  "changed": len(self.changed)}

        def cost(c):
            section, item = c
            return estimate_tokens(self._change_dict(item) if section == "changed"
                                   else self._endpoint_dict(item))

        def assemble(kept):
            by_section = {"added": [], "removed": [], "changed": []}
            for section, item in kept:
                by_section[section].append(item)
            dropped: Counter = Counter()
            for section, total in totals.items():
                n = total - len(by_section[section])
                if n:
                    dropped[section] = n
            return self._assemble(by_section["added"], by_section["removed"],
                                  by_section["changed"], dropped)

        kept, _dropped = fit_budget(candidates, assemble, budget, cost=cost)
        return assemble(kept)

    # -- public renderers ---------------------------------------------------

    def to_dict(self, *, budget: Optional[int] = None) -> dict:
        """Return the diff as a JSON-serializable dict, optionally budget-trimmed."""
        effective = budget if budget is not None else self.budget
        if effective is not None:
            return self._fit_budget(effective)
        return self._assemble(self.added, self.removed, self.changed, Counter())

    def to_markdown(self, *, budget: Optional[int] = None) -> str:
        """Render the diff as Markdown (grouped by host, ref-based, budget-aware)."""
        return _render_markdown(self.to_dict(budget=budget))


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def _endpoint_line(row: dict) -> str:
    u = row["untrusted"]
    label = f"{u['method']} {u['host']}{u['path']}".strip()
    suffix = f"  (x{row['count']}, {row['ref']})" if row.get("ref") else f"  (x{row['count']})"
    return f"- `{label}`{suffix}"


def _change_lines(row: dict) -> list[str]:
    lines = [_endpoint_line(row)]
    for change in row.get("changes", []):
        field_name = change["field"]
        if "before" in change and "after" in change:
            lines.append(f"    - **{field_name}**: `{change['before']}` -> `{change['after']}`")
    return lines


def _group_section(title: str, groups: list[dict], change: bool) -> list[str]:
    if not groups:
        return []
    total = sum(len(g["endpoints"]) for g in groups)
    lines = [f"## {title} ({total})\n"]
    for group in groups:
        host = group["untrusted"]["host"]
        attribution = group.get("attribution")
        tag = ""
        if attribution:
            tag = " _(" + ", ".join(f"{k}={v}" for k, v in sorted(attribution.items())) + ")_"
        lines.append(f"### {host}{tag}\n")
        for row in group["endpoints"]:
            lines.extend(_change_lines(row) if change else [_endpoint_line(row)])
        lines.append("")
    return lines


def _render_markdown(diff: dict) -> str:
    s = diff["summary"]
    lines = ["# Capture Diff Report\n",
             f"**A:** `{diff['a']}`  ",
             f"**B:** `{diff['b']}`\n",
             "## Summary\n",
             "| Metric | Count |", "|--------|-------|",
             f"| Endpoints A | {s['endpoints_a']} |",
             f"| Endpoints B | {s['endpoints_b']} |",
             f"| Added | {s['added']} |",
             f"| Removed | {s['removed']} |",
             f"| Changed | {s['changed']} |", ""]
    lines += _group_section("Added Endpoints", diff["added"], change=False)
    lines += _group_section("Removed Endpoints", diff["removed"], change=False)
    lines += _group_section("Changed Endpoints", diff["changed"], change=True)
    if not (diff["added"] or diff["removed"] or diff["changed"]):
        lines.append("## No differences found.\n")
    if diff.get("truncated"):
        lines.append(f"_Truncated (budget): {diff['truncated']['dropped']}_")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def diff_taps(tap_a_path: str, tap_b_path: str, *,
              classify: Optional[ClassifyFn] = None,
              budget: Optional[int] = None,
              a_label: Optional[str] = None,
              b_label: Optional[str] = None) -> DiffResult:
    """Diff the endpoint sets of two ``.tap`` captures.

    Args:
        tap_a_path: baseline / "before" capture.
        tap_b_path: comparison / "after" capture.
        classify: optional ``host -> attribution dict`` callable; when given,
            each host group is annotated with its ``owner``/``category``/``party``.
        budget: optional soft token budget for :meth:`DiffResult.to_dict` /
            :meth:`DiffResult.to_markdown` (lowest-volume rows dropped first).
        a_label: optional label for side A (e.g. a capture session id);
            defaults to the basename of *tap_a_path*.
        b_label: optional label for side B; defaults to the basename of *tap_b_path*.

    Returns:
        A :class:`DiffResult` whose ``a``/``b`` are the two labels.
    """
    with TapReader(str(tap_a_path)) as reader_a:
        before = _collect_endpoints(reader_a.iter_flows())
    with TapReader(str(tap_b_path)) as reader_b:
        after = _collect_endpoints(reader_b.iter_flows())
    added, removed, changed = _diff_endpoints(before, after)
    # Report basenames only: the full resolved path would leak the server's
    # filesystem layout into results (every other tool returns tap.name).
    return DiffResult(mode="taps", a_label=a_label or Path(tap_a_path).name,
                      b_label=b_label or Path(tap_b_path).name,
                      added=added, removed=removed, changed=changed,
                      before_count=len(before), after_count=len(after),
                      classify=classify, budget=budget)


def diff_phases(tap_path: str, phases: list[dict], label_a: str, label_b: str, *,
                classify: Optional[ClassifyFn] = None) -> DiffResult:
    """Diff two phase windows *within* one capture.

    Flows are partitioned into phases by ``flow.started`` against the phase
    windows (see :func:`phase_label_for`), then phase ``label_a`` is diffed
    against phase ``label_b``.

    Args:
        tap_path: the capture to partition.
        phases: ``[{"t", "label"}, ...]`` as returned by :func:`load_phases`.
        label_a: baseline phase label.
        label_b: comparison phase label.
        classify: optional ``host -> attribution dict`` callable.

    Raises:
        ValueError: if ``label_a == label_b`` (every flow would fall into the
            first bucket, yielding a misleading "everything removed" diff).
    """
    if label_a == label_b:
        raise ValueError("label_a and label_b must differ")
    with TapReader(str(tap_path)) as reader:
        bucket_a, bucket_b = _partition_by_phase(reader.iter_flows(), phases, label_a, label_b)
        before = _collect_endpoints(bucket_a)
        after = _collect_endpoints(bucket_b)
    added, removed, changed = _diff_endpoints(before, after)
    return DiffResult(mode="phases", a_label=label_a, b_label=label_b,
                      added=added, removed=removed, changed=changed,
                      before_count=len(before), after_count=len(after),
                      classify=classify, budget=None)


__all__ = [
    "SCHEMA",
    "DiffResult",
    "diff_taps",
    "diff_phases",
    "load_phases",
    "phase_label_for",
    "phase_labels",
    "phases_sidecar_for",
    "load_sidecar_phases",
    "PHASES_SIDECAR",
    "host_counts_taps",
    "host_counts_phases",
]
