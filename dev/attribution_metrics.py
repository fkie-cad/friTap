#!/usr/bin/env python3
"""Measure how well friTap attributes Chromium-stack traffic to the originating SDK.

Dev-only measuring tool. It joins three inputs:

* a friTap ``.tap`` capture (read through friTap's own ``TapReader``),
* a ground-truth JSONL log written by the attribution fixture app
  (``adb logcat -v raw`` output; non-JSON noise lines are ignored),
* optionally an NSS keylog (``-k`` output) for key-coverage numbers,

and reports, per transport, per SDK and overall, how many ground-truth requests
were seen in plaintext, which wire protocol carried them, whether they were
attributed to an SDK, and whether that attribution was correct.

Usage::

    env/bin/python dev/attribution_metrics.py --tap X.tap --gt gt.jsonl \\
        [--keylog keys.log] [--run <id>] [--json out.json] \\
        [--sdk-map FritapAlpha=alpha --sdk-map FritapBeta=beta]

Exit status is 0 even with zero matches; 2 for unreadable inputs; 1 when any
flow claims a ``connection-fallback`` attribution with ``high`` confidence
(a fallback must never be high-confidence) or when any ground-truth request's
matched flow is attributed at ``high`` confidence to the WRONG SDK
(``wrong_high``).

When the ``.tap`` carries REC_REQUEST_CONTEXT records, the report also
measures request-context coverage: records are paired one-to-one with
ground-truth starts of the same normalized URL, in start-time order; ``ctx%``
counts starts that got a paired record and ``ctx_ok%`` those whose paired
record names the right SDK.

Everything except :func:`load_wire_flows` / :func:`main` is a pure function over
plain dataclasses, so the parsing/matching/aggregation logic is unit-testable
without a ``.tap`` file (see ``tests/unit/test_attribution_metrics.py``).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

if __name__ == "__main__":  # run as a script: make this checkout's friTap importable
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from friTap.flow.attribution import (  # noqa: E402  (after the script path bootstrap)
    CONFIDENCE_HIGH,
    SOURCE_CONNECTION_FALLBACK,
    flow_originator,
    flow_transport_kind,
)
from friTap.flow.request_context_join import normalize_request_key  # noqa: E402

DEFAULT_SDK_MAP = {"FritapAlpha": "alpha", "FritapBeta": "beta"}
DEFAULT_PORTS = {"https": 443, "http": 80}
CONTROL_METHODS = frozenset({"SETTINGS"})
ATTRIBUTION_FIELDS = ("sdk", "originator", "confidence", "source", "attribution")
FALLBACK_SOURCE = SOURCE_CONNECTION_FALLBACK
HIGH_CONFIDENCE = CONFIDENCE_HIGH
# Ground-truth transport -> the ``attribution.transport.kind`` friTap should report.
EXPECTED_TRANSPORT_KIND = {
    "cronet-embedded": "cronet", "cronet-shared": "cronet",
    "gms-cronet": "gms-cronet", "httpengine": "httpengine",
    "webview": "webview", "chrome": "chrome",
}
CLIENT_RANDOM_ATTR = "client_random"
TLS13_QUIC_LABELS = frozenset({
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0",
})
WIRE_PROTOCOL_LABELS = {
    "HTTP/1.0": "h1", "HTTP/1.1": "h1", "HTTP/2": "h2", "HTTP/3": "h3",
}

VERDICT_CACHE = "cache"
VERDICT_UNSEEN = "unseen"
VERDICT_UNATTRIBUTED = "unattributed"
VERDICT_CORRECT = "correct"
VERDICT_WRONG = "wrong"


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class GTRequest:
    """One ground-truth request, folded from its start/done/fail/skip events."""

    req_id: str
    sdk: str = ""
    transport: str = ""
    run: Any = None
    url: str = ""
    method: str = ""
    started: bool = False
    done: bool = False
    failed: bool = False
    skipped: bool = False
    skip_reason: str = ""
    status: Any = None
    protocol: str = ""
    cached: bool = False
    t_start_ms: Optional[float] = None


@dataclass
class GroundTruth:
    """Parsed ground-truth log: requests by id plus bookkeeping."""

    requests: dict[str, GTRequest] = field(default_factory=dict)
    runs: set = field(default_factory=set)
    skips_by_reason: Counter = field(default_factory=Counter)
    noise_lines: int = 0


@dataclass
class Attribution:
    """An SDK attribution as found on a flow, normalised across field shapes."""

    name: str = ""
    confidence: Any = None
    source: Any = None


@dataclass
class WireFlow:
    """The slice of a friTap ``Flow`` the metrics need (decoupled from friTap)."""

    flow_id: str = ""
    connection_id: str = ""
    transport: str = ""
    host: str = ""
    path: str = ""
    wire_protocol: str = ""
    decoded: bool = False
    client_random: Optional[str] = None
    attribution: Optional[Attribution] = None
    fields_present: frozenset = frozenset()
    transport_kind: str = ""
    bucket: str = ""
    mixed: bool = False
    has_caller_stack: bool = False


@dataclass
class MatchedRequest:
    """A ground-truth request together with the wire flows it matched."""

    gt: GTRequest
    flows: list[WireFlow]
    verdict: str
    attributed_names: list[str] = field(default_factory=list)
    context: Optional[dict] = None


# --------------------------------------------------------------------------- #
# Ground truth parsing
# --------------------------------------------------------------------------- #

def parse_gt_line(line: str) -> Optional[dict]:
    """Return the ground-truth event on *line*, or None for noise."""
    text = line.strip()
    brace = text.find("{")
    if brace < 0:
        return None
    try:
        event = json.loads(text[brace:])
    except ValueError:
        return None
    if not isinstance(event, dict) or event.get("v") != 1:
        return None
    return event if event.get("event") and event.get("req_id") else None


def _apply_identity(req: GTRequest, event: dict) -> None:
    for name in ("sdk", "transport", "run", "url", "method"):
        if event.get(name) not in (None, "") and getattr(req, name) in (None, ""):
            setattr(req, name, event[name])


def apply_gt_event(req: GTRequest, event: dict) -> None:
    """Fold one start/done/fail/skip event into *req*."""
    _apply_identity(req, event)
    kind = event["event"]
    if kind == "start":
        req.started = True
        if isinstance(event.get("t_ms"), (int, float)):
            req.t_start_ms = event["t_ms"]
    elif kind == "done":
        req.done = True
        req.status = event.get("status")
        req.protocol = event.get("protocol") or ""
        req.cached = event.get("cached") is True
    elif kind == "fail":
        req.failed = True
    elif kind == "skip":
        req.skipped = True
        req.skip_reason = str(event.get("reason") or "unknown")


def parse_ground_truth(lines: Iterable[str], run: Any = None) -> GroundTruth:
    """Parse ground-truth lines, optionally restricted to one *run* id."""
    gt = GroundTruth()
    for line in lines:
        event = parse_gt_line(line)
        if event is None:
            gt.noise_lines += bool(line.strip())
            continue
        gt.runs.add(event.get("run"))
        if run is not None and str(event.get("run")) != str(run):
            continue
        req = gt.requests.setdefault(event["req_id"], GTRequest(event["req_id"]))
        apply_gt_event(req, event)
    gt.skips_by_reason = Counter(
        r.skip_reason for r in gt.requests.values() if r.skipped)
    return gt


def measurable_requests(gt: GroundTruth) -> list[GTRequest]:
    """Requests that count toward ``gt_requests``: started and not skipped."""
    return [r for r in gt.requests.values() if r.started and not r.skipped]


# --------------------------------------------------------------------------- #
# URL normalisation
# --------------------------------------------------------------------------- #

def normalize_host(host: str, scheme: str = "https") -> str:
    """Lower-case *host* and drop the scheme's default port."""
    host = (host or "").strip().lower().rstrip(".")
    name, sep, port = host.rpartition(":")
    if sep and port.isdigit() and "]" not in port:
        if int(port) == DEFAULT_PORTS.get(scheme):
            return name
    return host


def normalize_path(path: str) -> str:
    """Strip query/fragment; an empty path is ``/``."""
    path = (path or "").split("#", 1)[0].split("?", 1)[0]
    return path or "/"


def normalize_url(url: str) -> tuple[str, str]:
    """Return the ``(host, path)`` match key of an absolute URL."""
    parts = urlsplit(url or "")
    scheme = (parts.scheme or "https").lower()
    return normalize_host(parts.netloc, scheme), normalize_path(parts.path)


def request_key(host: str, url: str) -> tuple[str, str]:
    """Match key for a decoded request whose *url* may be a path or absolute."""
    if "://" in (url or ""):
        return normalize_url(url)
    return normalize_host(host), normalize_path(url)


# --------------------------------------------------------------------------- #
# Flow adaptation (friTap Flow -> WireFlow)
# --------------------------------------------------------------------------- #

def _get(obj: Any, name: str) -> Any:
    """Read *name* from a dict or object without mutating either."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None) if obj is not None else None


def wire_protocol_label(protocol: str) -> str:
    """friTap's request protocol string as ``h1``/``h2``/``h3`` (else as-is)."""
    return WIRE_PROTOCOL_LABELS.get(protocol or "", (protocol or "").lower())


def _header(headers: dict, *names: str) -> str:
    lowered = {str(k).lower(): v for k, v in (headers or {}).items()}
    for name in names:
        if lowered.get(name):
            return str(lowered[name])
    return ""


def _layer_sni(flow: Any) -> str:
    layer_of = getattr(flow, "layer", None)
    for name in ("tls", "quic"):
        layer = layer_of(name) if callable(layer_of) else None
        if layer is not None and getattr(layer, "sni", ""):
            return layer.sni
    return ""


def flow_host(flow: Any) -> str:
    """Best available host for *flow*: request host, authority, then SNI."""
    request = getattr(flow, "request", None)
    headers = _get(request, "headers") or {}
    host = (_get(request, "host") or _header(headers, ":authority", "host")
            or _layer_sni(flow))
    return normalize_host(host)


def is_decoded_request(request: Any) -> bool:
    """True for a real (non-control) decoded L7 request with a URL."""
    if request is None or _get(request, "is_control_frame"):
        return False
    method = _get(request, "method") or ""
    return bool(method) and method not in CONTROL_METHODS and bool(_get(request, "url"))


def _first_present(sources: Iterable[Any], name: str) -> Any:
    for source in sources:
        value = _get(source, name)
        if value not in (None, ""):
            return value
    return None


def flow_client_random(flow: Any) -> Optional[str]:
    """The flow's normalized client_random, if any part of the flow carries a valid one."""
    from friTap.client_random import normalize_client_random

    layer_of = getattr(flow, "layer", None)
    layers = [layer_of(n) for n in ("tls", "quic")] if callable(layer_of) else []
    value = _first_present([flow, *layers], CLIENT_RANDOM_ATTR)
    return normalize_client_random(value) or None


def attribution_fields_present(flow: Any) -> frozenset:
    """Which attribution fields exist (non-empty) on *flow* today."""
    return frozenset(n for n in ATTRIBUTION_FIELDS if _get(flow, n) not in (None, ""))


def _sdk_name(container: Any) -> str:
    if isinstance(container, str):
        return container
    return str(_get(container, "sdk") or "")


def attribution_block(flow: Any) -> Any:
    """The flow's ``attribution`` block (absent/None on older taps)."""
    return _get(flow, "attribution")


def _attribution_holders(flow: Any) -> list:
    """Where attribution fields may live, most authoritative first."""
    block = attribution_block(flow)
    return [block, _get(block, "originator"),
            flow, _get(flow, "originator"), _get(flow, "sdk")]


def _sdk_containers(flow: Any) -> tuple:
    """SDK containers, most authoritative first: ``attribution.originator``,
    the legacy bare ``originator``, then ``sdk``."""
    originator = flow_originator(flow)  # attribution.originator, else flow.sdk
    sdk = _get(flow, "sdk")
    if originator is sdk:  # no attribution.originator: the legacy field outranks sdk
        originator = None
    return originator, _get(flow, "originator"), sdk


def attribution_name(flow: Any) -> str:
    """Attributed SDK name: ``attribution.originator.sdk``, then
    ``originator.sdk``, then ``sdk.sdk``."""
    for container in _sdk_containers(flow):
        name = _sdk_name(container)
        if name:
            return name
    return ""


def flow_attribution(flow: Any) -> Optional[Attribution]:
    """Normalised attribution of *flow*, or None when it carries none."""
    name = attribution_name(flow)
    if not name:
        return None
    holders = _attribution_holders(flow)
    return Attribution(name=name,
                       confidence=_first_present(holders, "confidence"),
                       source=_first_present(holders, "source"))


def transport_kind(flow: Any) -> str:
    """``attribution.transport.kind`` of *flow*, or ``""``."""
    return flow_transport_kind(flow) or ""


def to_wire_flow(flow: Any) -> WireFlow:
    """Adapt a friTap ``Flow`` into the metrics' :class:`WireFlow`."""
    request = getattr(flow, "request", None)
    decoded = is_decoded_request(request)
    host, path = flow_host(flow), ""
    if decoded:
        host, path = request_key(host, _get(request, "url"))
    return WireFlow(
        flow_id=getattr(flow, "flow_id", ""),
        connection_id=getattr(flow, "connection_id", "") or "",
        transport=getattr(flow, "transport", "") or "",
        host=host, path=path, decoded=decoded,
        wire_protocol=wire_protocol_label(_get(request, "protocol")),
        client_random=flow_client_random(flow),
        attribution=flow_attribution(flow),
        fields_present=attribution_fields_present(flow),
        transport_kind=transport_kind(flow),
        bucket=str(_get(attribution_block(flow), "bucket") or ""),
        mixed=_get(attribution_block(flow), "mixed") is True,
        has_caller_stack=bool(_get(flow, "caller_stack")),
    )


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #

def index_flows(flows: Iterable[WireFlow]) -> dict[tuple[str, str], list[WireFlow]]:
    """Decoded flows keyed by their ``(host, path)``."""
    index: dict[tuple[str, str], list[WireFlow]] = defaultdict(list)
    for flow in flows:
        if flow.decoded:
            index[(flow.host, flow.path)].append(flow)
    return index


class _LoweredSdkMap(dict):
    """An SDK map whose keys are already lower-cased (see :func:`lowercase_sdk_map`)."""


def lowercase_sdk_map(sdk_map: dict[str, str]) -> dict[str, str]:
    """*sdk_map* with lower-cased keys, built once per report; idempotent."""
    if isinstance(sdk_map, _LoweredSdkMap):
        return sdk_map
    return _LoweredSdkMap((k.lower(), v) for k, v in sdk_map.items())


def map_sdk(name: str, sdk_map: dict[str, str]) -> str:
    """Map an attributed SDK *name* to a ground-truth sdk id (case-insensitive)."""
    return lowercase_sdk_map(sdk_map).get(name.lower(), name)


def classify_request(gt: GTRequest, flows: list[WireFlow],
                     sdk_map: dict[str, str]) -> str:
    """Verdict for one ground-truth request given its matched flows."""
    if gt.cached:
        return VERDICT_CACHE
    if not flows:
        return VERDICT_UNSEEN
    mapped = [map_sdk(f.attribution.name, sdk_map) for f in flows if f.attribution]
    if not mapped:
        return VERDICT_UNATTRIBUTED
    if any(m != gt.sdk for m in mapped):
        return VERDICT_WRONG
    return VERDICT_CORRECT


def match_requests(requests: Iterable[GTRequest], flows: list[WireFlow],
                   sdk_map: dict[str, str]) -> list[MatchedRequest]:
    """Match each ground-truth request to the flows with the same host+path."""
    index = index_flows(flows)
    sdk_map = lowercase_sdk_map(sdk_map)
    matched = []
    for gt in requests:
        hits = [] if gt.cached else index.get(normalize_url(gt.url), [])
        names = [f.attribution.name for f in hits if f.attribution]
        matched.append(MatchedRequest(gt, hits, classify_request(gt, hits, sdk_map),
                                      names))
    return matched


def wire_leftovers(flows: list[WireFlow], matched: list[MatchedRequest]) -> dict:
    """Count flows not explained by any ground-truth request."""
    gt_hosts = {normalize_url(m.gt.url)[0] for m in matched}
    used = {id(f) for m in matched for f in m.flows}
    counts = Counter()
    for flow in flows:
        if id(flow) in used:
            continue
        if flow.host not in gt_hosts:
            counts["other_hosts"] += 1
        elif flow.decoded:
            counts["unmatched_wire"] += 1
        else:
            counts["undecoded_on_gt_hosts"] += 1
    return {k: counts.get(k, 0)
            for k in ("unmatched_wire", "undecoded_on_gt_hosts", "other_hosts")}


def _is_high(attribution: Optional[Attribution]) -> bool:
    return (attribution is not None
            and str(attribution.confidence or "").lower() == HIGH_CONFIDENCE)


def high_confidence_sdks(matched: MatchedRequest, sdk_map: dict[str, str]) -> list[str]:
    """GT sdk ids of the high-confidence attributions on *matched*'s flows."""
    return [map_sdk(f.attribution.name, sdk_map) for f in matched.flows
            if _is_high(f.attribution)]


def is_high_wrong(matched: MatchedRequest, sdk_map: dict[str, str]) -> bool:
    """Any matched flow attributed at high confidence to a wrong SDK (a defect)."""
    return any(s != matched.gt.sdk for s in high_confidence_sdks(matched, sdk_map))


def is_high_ok(matched: MatchedRequest, sdk_map: dict[str, str]) -> bool:
    """Attributed at high confidence to the right SDK, and never wrongly at high."""
    sdks = high_confidence_sdks(matched, sdk_map)
    return bool(sdks) and all(s == matched.gt.sdk for s in sdks)


# --------------------------------------------------------------------------- #
# Request-context coverage (REC_REQUEST_CONTEXT records)
# --------------------------------------------------------------------------- #

def context_url_key(url: Any) -> Optional[str]:
    """Method-agnostic normalized URL used to join GT requests and context records."""
    if not isinstance(url, str) or not url:
        return None
    key = normalize_request_key(url)
    return key[1] if key else None


def context_sdk(record: dict) -> str:
    """The SDK name a request-context record attributes, or ``""``."""
    return _sdk_name(record.get("originator") or "") if isinstance(record, dict) else ""


def _time_order(items: list, start_of: Any) -> list:
    """*items* by start time (missing times last), ties kept in input order."""
    def key(indexed: tuple) -> tuple:
        start = start_of(indexed[1])
        return (start is None, start if start is not None else 0, indexed[0])
    return [item for _, item in sorted(enumerate(items), key=key)]


def _record_start(record: dict) -> Optional[float]:
    start = record.get("t_start")
    return start if isinstance(start, (int, float)) else None


def attach_request_contexts(matched: list[MatchedRequest], records: list[dict]) -> int:
    """Pair records to GT requests one-to-one per URL key, both in time order (the clocks differ
    by an offset, only order matters). Returns the number of unpaired records."""
    records_by_url: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        key = context_url_key(record.get("url"))
        if key:
            records_by_url[key].append(record)
    requests_by_url: dict[str, list[MatchedRequest]] = defaultdict(list)
    for m in matched:
        m.context = None
        key = context_url_key(m.gt.url)
        if key:
            requests_by_url[key].append(m)
    paired = 0
    for key, requests in requests_by_url.items():
        ordered_records = _time_order(records_by_url.get(key, []), _record_start)
        ordered_requests = _time_order(requests, lambda m: m.gt.t_start_ms)
        for m, record in zip(ordered_requests, ordered_records):
            m.context = record
            paired += 1
    return len(records) - paired


def has_correct_context(matched: MatchedRequest, sdk_map: dict[str, str]) -> bool:
    """The record paired with the GT request names the GT request's SDK."""
    sdk = context_sdk(matched.context) if matched.context else ""
    return bool(sdk) and map_sdk(sdk, sdk_map) == matched.gt.sdk


def request_context_counts(records: list[dict], unmatched: int) -> dict:
    """Extras: record counts by source/confidence/stack_kind, cache bucket, unmatched."""
    return {
        "records": len(records),
        "by_source": _count(r.get("source") for r in records),
        "by_confidence": _count(r.get("confidence") for r in records),
        "by_stack_kind": _count(r.get("stack_kind") for r in records),
        "cache_bucket": sum(1 for r in records if r.get("bucket") == VERDICT_CACHE),
        "unmatched": unmatched,
    }


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #

def pct(part: int, whole: int) -> Optional[float]:
    """Percentage rounded to 1 decimal, or None when *whole* is zero."""
    return round(100.0 * part / whole, 1) if whole else None


def _client_random_stats(flows: list[WireFlow], field_exists: bool) -> Any:
    if not field_exists:
        return "field absent"
    return pct(sum(1 for f in flows if f.client_random), len(flows))


def _by_confidence(matched: list[MatchedRequest]) -> dict:
    table: dict[str, Counter] = defaultdict(Counter)
    for m in matched:
        for flow in m.flows:
            if flow.attribution and flow.attribution.confidence is not None:
                table[str(flow.attribution.confidence)][m.verdict] += 1
    return {k: dict(v) for k, v in sorted(table.items())}


def _transport_kind_stats(matched: list[MatchedRequest]) -> Optional[float]:
    """% of matched flows whose transport kind is the one expected for the GT
    transport; None when no matched flow has a mapped GT transport."""
    hits = total = 0
    for m in matched:
        expected = EXPECTED_TRANSPORT_KIND.get(m.gt.transport)
        if expected is None:
            continue
        total += len(m.flows)
        hits += sum(1 for f in m.flows if f.transport_kind == expected)
    return pct(hits, total)


def _high_and_context_metrics(matched: list[MatchedRequest], seen: int,
                              sdk_map: dict[str, str]) -> dict:
    """hi_ok / hi_wrong (over seen requests) and ctx / ctx_ok (over all GT starts)."""
    hi_ok = sum(1 for m in matched if is_high_ok(m, sdk_map))
    hi_wrong = sum(1 for m in matched if is_high_wrong(m, sdk_map))
    ctx = sum(1 for m in matched if m.context)
    ctx_ok = sum(1 for m in matched if has_correct_context(m, sdk_map))
    return {
        "hi_ok": hi_ok, "pct_hi_ok": pct(hi_ok, seen),
        "hi_wrong": hi_wrong, "pct_hi_wrong": pct(hi_wrong, seen),
        "ctx": ctx, "pct_ctx": pct(ctx, len(matched)),
        "ctx_ok": ctx_ok, "pct_ctx_ok": pct(ctx_ok, len(matched)),
    }


def compute_metrics(matched: list[MatchedRequest], client_random_field: bool,
                    sdk_map: Optional[dict[str, str]] = None) -> dict:
    """Metrics for one group of matched requests."""
    sdk_map = lowercase_sdk_map(sdk_map if sdk_map is not None else DEFAULT_SDK_MAP)
    verdicts = Counter(m.verdict for m in matched)
    seen = len(matched) - verdicts[VERDICT_CACHE] - verdicts[VERDICT_UNSEEN]
    attributed = verdicts[VERDICT_CORRECT] + verdicts[VERDICT_WRONG]
    flows = [f for m in matched for f in m.flows]
    metrics = {
        "gt_requests": len(matched),
        "cache": verdicts[VERDICT_CACHE],
        "failed": sum(1 for m in matched if m.gt.failed),
        "seen_plaintext": seen,
        "pct_plaintext": pct(seen, len(matched) - verdicts[VERDICT_CACHE]),
        "matched_flows": len(flows),
        "wire_protocol": dict(Counter(f.wire_protocol for f in flows)),
        "gt_protocol": dict(Counter(m.gt.protocol or "-" for m in matched if m.gt.done)),
        "has_client_random": _client_random_stats(flows, client_random_field),
        "pct_transport_kind": _transport_kind_stats(matched),
        "pct_caller_stack": pct(sum(1 for f in flows if f.has_caller_stack), len(flows)),
        "attributed": attributed,
        "pct_attributed": pct(attributed, seen),
        "correct": verdicts[VERDICT_CORRECT],
        "pct_correct": pct(verdicts[VERDICT_CORRECT], seen),
        "wrong": verdicts[VERDICT_WRONG],
        "pct_wrong": pct(verdicts[VERDICT_WRONG], seen),
    }
    metrics.update(_high_and_context_metrics(matched, seen, sdk_map))
    confidence = _by_confidence(matched)
    if confidence:
        metrics["by_confidence"] = confidence
    return metrics


def group_metrics(matched: list[MatchedRequest], key: str,
                  client_random_field: bool, sdk_map: Optional[dict[str, str]] = None) -> dict:
    """Metrics per value of GTRequest attribute *key* (e.g. ``sdk``)."""
    groups: dict[str, list[MatchedRequest]] = defaultdict(list)
    for m in matched:
        groups[str(getattr(m.gt, key) or "?")].append(m)
    return {name: compute_metrics(items, client_random_field, sdk_map)
            for name, items in sorted(groups.items())}


def _connection_summary(conn_id: str, items: list[MatchedRequest],
                        sdk_map: dict[str, str]) -> dict:
    flows = [f for m in items for f in m.flows if f.connection_id == conn_id]
    return {
        "connection_id": conn_id,
        "gt_sdks": sorted({m.gt.sdk for m in items}),
        "requests": len(items),
        "attributed_as": dict(Counter(
            map_sdk(f.attribution.name, sdk_map) if f.attribution else "(none)"
            for f in flows)),
        "verdicts": dict(Counter(m.verdict for m in items)),
    }


def mixed_connections(matched: list[MatchedRequest], sdk_map: dict[str, str]) -> dict:
    """Connections that carried matched requests of more than one SDK."""
    sdk_map = lowercase_sdk_map(sdk_map)
    by_conn: dict[str, list[MatchedRequest]] = defaultdict(list)
    for m in matched:
        for conn_id in {f.connection_id for f in m.flows if f.connection_id}:
            by_conn[conn_id].append(m)
    mixed = [_connection_summary(c, items, sdk_map)
             for c, items in sorted(by_conn.items())
             if len({m.gt.sdk for m in items}) > 1]
    return {"connections_with_matches": len(by_conn), "mixed": len(mixed),
            "details": mixed}


def is_fallback_high(flow: WireFlow) -> bool:
    """A connection-fallback attribution claiming high confidence (a defect)."""
    attribution = flow.attribution
    return (_is_high(attribution)
            and str(attribution.source or "").lower() == FALLBACK_SOURCE)


def has_attribution_data(flows: list[WireFlow]) -> bool:
    """True when any flow carries an attribution, transport kind or bucket."""
    return any(f.attribution or f.transport_kind or f.bucket for f in flows)


def _count(values: Iterable[Any]) -> dict:
    return dict(sorted(Counter(str(v) for v in values if v not in (None, "")).items()))


def attribution_counts(flows: list[WireFlow]) -> dict:
    """by_source / by_transport_kind / buckets (only when non-empty) plus the
    always-present ``fallback_high`` count."""
    counts = {
        "by_source": _count(f.attribution.source for f in flows if f.attribution),
        "by_transport_kind": _count(f.transport_kind for f in flows),
        "buckets": _count(f.bucket for f in flows),
    }
    report = {k: v for k, v in counts.items() if v}
    report["fallback_high"] = sum(1 for f in flows if is_fallback_high(f))
    return report


def fields_report(flows: list[WireFlow]) -> dict:
    """Which per-flow fields exist in this capture (detected, not assumed)."""
    report = {
        "flows": len(flows),
        "connection_id": sum(1 for f in flows if f.connection_id),
        CLIENT_RANDOM_ATTR: sum(1 for f in flows if f.client_random),
    }
    for name in ATTRIBUTION_FIELDS:
        report[name] = sum(1 for f in flows if name in f.fields_present)
    return report


# --------------------------------------------------------------------------- #
# Keylog
# --------------------------------------------------------------------------- #

def parse_keylog(lines: Iterable[str]) -> list[tuple[str, str]]:
    """``(label, client_random)`` pairs from NSS keylog lines.

    Uses friTap's strict NSS line parser: comments, malformed lines and
    placeholder client_randoms are skipped; client_randoms come back lowercased.
    """
    from friTap.offline.tls.keylog import parse_strict_nss_line

    entries = (parse_strict_nss_line(line) for line in lines)
    return [(entry.label, entry.client_random) for entry in entries if entry is not None]


def keylog_summary(entries: list[tuple[str, str]], flows: list[WireFlow],
                   client_random_field: bool) -> dict:
    """Key coverage: distinct client_randoms, labels, QUIC usability."""
    labels = Counter(label for label, _ in entries)
    randoms = {cr for _, cr in entries}
    summary = {
        "entries": len(entries),
        "distinct_client_randoms": len(randoms),
        "labels": dict(sorted(labels.items())),
        "tls13_quic_usable_labels": sorted(TLS13_QUIC_LABELS & set(labels)),
        "quic_prefixed_labels": sorted(lb for lb in labels if lb.startswith("QUIC")),
    }
    if not client_random_field:
        summary["matched_flows_with_key"] = "field absent"
    else:
        with_cr = [f for f in flows if f.client_random]
        summary["matched_flows_with_key"] = pct(
            sum(1 for f in with_cr if f.client_random in randoms), len(with_cr))
    return summary


# --------------------------------------------------------------------------- #
# Report assembly
# --------------------------------------------------------------------------- #

def build_report(gt: GroundTruth, flows: list[WireFlow], sdk_map: dict[str, str],
                 keylog_entries: Optional[list[tuple[str, str]]] = None,
                 request_contexts: Optional[list[dict]] = None) -> dict:
    """Assemble the full metrics report from parsed inputs."""
    matched = match_requests(measurable_requests(gt), flows, sdk_map)
    records = list(request_contexts or [])
    unmatched_records = attach_request_contexts(matched, records)
    fields = fields_report(flows)
    cr_field = fields[CLIENT_RANDOM_ATTR] > 0
    report = {
        "runs": sorted(str(r) for r in gt.runs),
        "skips_by_reason": dict(gt.skips_by_reason),
        "fields_present": fields,
        "overall": compute_metrics(matched, cr_field, sdk_map),
        "by_transport": group_metrics(matched, "transport", cr_field, sdk_map),
        "by_sdk": group_metrics(matched, "sdk", cr_field, sdk_map),
        "wire": wire_leftovers(flows, matched),
        "mixed_connections": mixed_connections(matched, sdk_map),
        "has_attribution_data": has_attribution_data(flows),
    }
    if not records:  # no request-context data: coverage is unknown, not 0%
        for metrics in (report["overall"], *report["by_transport"].values(),
                        *report["by_sdk"].values()):
            metrics["pct_ctx"] = metrics["pct_ctx_ok"] = None
    report.update(attribution_counts(flows))
    report["wrong_high"] = report["overall"]["hi_wrong"]
    report["request_contexts"] = request_context_counts(records, unmatched_records)
    if keylog_entries is not None:
        matched_flows = [f for m in matched for f in m.flows]
        report["keylog"] = keylog_summary(keylog_entries, matched_flows, cr_field)
    return report


def _fmt(value: Any) -> str:
    if value is None:
        return "-"
    if value == "field absent":
        return "absent"
    return f"{value:.1f}" if isinstance(value, float) else str(value)


def _protocol_cell(dist: dict) -> str:
    return " ".join(f"{k}:{v}" for k, v in sorted(dist.items())) or "-"


TABLE_COLUMNS = (
    ("gt", "gt_requests"), ("cache", "cache"), ("seen", "seen_plaintext"),
    ("%plain", "pct_plaintext"), ("%attr", "pct_attributed"),
    ("%ok", "pct_correct"), ("%wrong", "pct_wrong"),
    ("%hi_ok", "pct_hi_ok"), ("%hi_wr", "pct_hi_wrong"),
    ("ctx%", "pct_ctx"), ("ctx_ok%", "pct_ctx_ok"), ("cr%", "has_client_random"),
    ("tk%", "pct_transport_kind"), ("cs%", "pct_caller_stack"),
)
ATTRIBUTION_COUNT_KEYS = ("by_source", "by_transport_kind", "buckets")


def format_table(report: dict) -> list[str]:
    """Readable table rows: overall, then per transport, then per sdk."""
    header = f"{'group':<26}" + "".join(f"{c:>8}" for c, _ in TABLE_COLUMNS) + "  wire"
    rows = [("overall", report["overall"])]
    rows += [(f"transport:{k}", v) for k, v in report["by_transport"].items()]
    rows += [(f"sdk:{k}", v) for k, v in report["by_sdk"].items()]
    lines = [header, "-" * len(header)]
    for name, m in rows:
        cells = "".join(f"{_fmt(m.get(key))[:7]:>8}" for _, key in TABLE_COLUMNS)
        lines.append(f"{name:<26}{cells}  {_protocol_cell(m['wire_protocol'])}")
    return lines


def format_extras(report: dict) -> list[str]:
    """Wire leftovers, field presence, mixed connections, keylog."""
    mixed = report["mixed_connections"]
    lines = [
        "wire: " + ", ".join(f"{k}={v}" for k, v in report["wire"].items()),
        "fields present (flows with value): " + ", ".join(
            f"{k}={v}" for k, v in report["fields_present"].items()),
        f"mixed connections: {mixed['mixed']} of "
        f"{mixed['connections_with_matches']} connections with matches",
    ]
    lines += [f"  {d['connection_id']}: sdks={d['gt_sdks']} "
              f"attributed_as={d['attributed_as']}" for d in mixed["details"]]
    if "by_confidence" in report["overall"]:
        lines.append(f"by confidence: {report['overall']['by_confidence']}")
    lines += [f"{key.replace('_', ' ')}: {report[key]}"
              for key in ATTRIBUTION_COUNT_KEYS if report.get(key)]
    if report.get("has_attribution_data"):
        lines.append(f"fallback_high: {report.get('fallback_high', 0)}")
        lines.append(f"wrong_high: {report.get('wrong_high', 0)}")
    contexts = report.get("request_contexts") or {}
    if contexts.get("records"):
        lines.append("request contexts: " + json.dumps(contexts, sort_keys=True))
    if "keylog" in report:
        lines.append("keylog: " + json.dumps(report["keylog"], sort_keys=True))
    return lines


def format_header(tap: str, gt_path: str, report: dict) -> str:
    """One-line run header."""
    return (f"tap={tap} gt={gt_path} runs={','.join(report['runs']) or '-'} "
            f"skips={report['skips_by_reason'] or '-'}")


# --------------------------------------------------------------------------- #
# I/O + CLI
# --------------------------------------------------------------------------- #

def load_wire_flows(tap_path: str) -> list[WireFlow]:
    """Read every flow of *tap_path* through friTap's ``TapReader``."""
    from friTap.flow.tap_reader import TapReader

    with TapReader(tap_path) as reader:
        reader.open()
        return [to_wire_flow(flow) for flow in reader.read_all_flows()]


def load_request_contexts(tap_path: str) -> list[dict]:
    """Every REC_REQUEST_CONTEXT record of *tap_path*; ``[]`` when the path is
    not a file (:func:`load_wire_flows` already reports an unreadable capture)."""
    from friTap.flow.tap_reader import TapReader

    if not os.path.isfile(tap_path):
        return []
    with TapReader(tap_path) as reader:
        reader.open()
        return list(reader.iter_request_contexts())


def parse_sdk_map(pairs: Optional[list[str]]) -> dict[str, str]:
    """``NAME=sdk`` CLI pairs into a mapping (defaults when none given)."""
    if not pairs:
        return dict(DEFAULT_SDK_MAP)
    mapping = {}
    for pair in pairs:
        name, sep, sdk = pair.partition("=")
        if not sep or not name.strip() or not sdk.strip():
            raise ValueError(f"--sdk-map expects NAME=sdk, got {pair!r}")
        mapping[name.strip()] = sdk.strip()
    return mapping


def _read_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--tap", required=True, help="friTap .tap capture")
    parser.add_argument("--gt", required=True, help="ground-truth JSONL (logcat raw)")
    parser.add_argument("--keylog", help="NSS keylog file (-k output)")
    parser.add_argument("--run", help="only consider this ground-truth run id")
    parser.add_argument("--json", dest="json_out", help="write the report as JSON")
    parser.add_argument("--sdk-map", action="append", metavar="NAME=sdk",
                        help="attributed SDK name -> GT sdk (repeatable)")
    return parser


def _load_inputs(args: argparse.Namespace):
    sdk_map = parse_sdk_map(args.sdk_map)
    gt = parse_ground_truth(_read_lines(args.gt), run=args.run)
    flows = load_wire_flows(args.tap)
    contexts = load_request_contexts(args.tap)
    keylog = parse_keylog(_read_lines(args.keylog)) if args.keylog else None
    return sdk_map, gt, flows, keylog, contexts


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        sdk_map, gt, flows, keylog, contexts = _load_inputs(args)
    except Exception as exc:  # unreadable/invalid input is the only failure
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = build_report(gt, flows, sdk_map, keylog, contexts)
    print(format_header(args.tap, args.gt, report))
    print("\n".join(format_table(report) + format_extras(report)))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True, default=str)
    return exit_status(report)


def exit_status(report: dict) -> int:
    """1 when the report shows a high-confidence defect, else 0."""
    defects = report.get("fallback_high", 0) + report.get("wrong_high", 0)
    return 1 if defects > 0 else 0


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.exit(main())
