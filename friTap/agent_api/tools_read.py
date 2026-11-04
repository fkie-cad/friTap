"""
Read / discover / export tool registrations (.tap analysis, protocol catalog).

Each handler is ``handler(params, ctx) -> dict``: it resolves the capture
source, calls one service function and wraps the result in the envelope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from friTap.agent_api import envelope, protocol_catalog
from friTap.agent_api.context import ToolContext
from friTap.agent_api.registry import ToolSpec
from friTap.agent_api.schema import (
    COMPACT_PAGE_LIMIT,
    SHOW_VALUES,
    SLICE_PARAMS,
    TAP_SOURCE_KEYS,
    TAP_SOURCE_PARAMS,
    object_schema,
    page_params,
)
from friTap.agent_api.services import export as export_service
from friTap.agent_api.services import protocols as protocol_service
from friTap.agent_api.services import reading
from friTap.agent_api.services.sources import resolve_tap_source
from friTap.filter.protocols import known_protocol_names

if TYPE_CHECKING:
    from friTap.agent_api.registry import Registry

#: Endpoint/finding rows are token-heavy: page them compactly by default.
_COMPACT_PAGE = page_params(COMPACT_PAGE_LIMIT)

MAX_DIGEST_BUDGET = 8000
MAX_FLOW_BYTES = 16384
DEFAULT_FLOW_BYTES = 4096
SEVERITIES = ("critical", "high", "medium", "low", "info")
FINDING_CATEGORIES = ("network", "pii", "protocol", "secret", "uncategorized")

SCHEMA_CAPTURE_PROTOCOLS = "fritap.capture_protocols/1"
SCHEMA_PROTOCOLS = "fritap.protocols/1"
SCHEMA_DIGEST_MD = "fritap.digest_md/1"
SCHEMA_ENDPOINTS = "fritap.endpoints/1"
SCHEMA_FINDINGS = "fritap.findings/1"
SCHEMA_EXPORT = "fritap.export/1"


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

def _tap_schema(properties: dict[str, dict], required: tuple[str, ...] = ()) -> dict:
    """Object schema with exactly one of ``tap`` / ``session_id``."""
    return object_schema({**TAP_SOURCE_PARAMS, **properties}, required=required,
                         one_of_required=TAP_SOURCE_KEYS)


def _result(schema_name: str, properties: dict[str, Any]) -> dict:
    return {"type": "object", "properties": {"schema": {"const": schema_name}, **properties}}


_STR = {"type": "string"}
_INT = {"type": "integer"}
_COUNTS = {"type": "object", "additionalProperties": _INT}
_ROWS = {"type": "array", "items": {"type": "object"}}
_CURSOR = {"type": ["string", "null"]}
_SOURCE = {"type": "object", "properties": {"file": _STR, "flows_total": _INT,
                                            "flows_selected": _INT}}
_NOTICE = {"notice": _STR}


# ---------------------------------------------------------------------------
# list_supported_protocols
# ---------------------------------------------------------------------------

def _list_supported_protocols(params: dict, ctx: ToolContext) -> dict:
    del params, ctx
    return envelope.ok(SCHEMA_CAPTURE_PROTOCOLS, {
        "protocols": protocol_catalog.catalog(),
        "capture_modes": list(protocol_catalog.CAPTURE_MODES),
        "default": "omit protocols for auto (all protocols)",
    })


_SUPPORTED_SPEC = ToolSpec(
    name="list_supported_protocols",
    summary="List protocols friTap can capture, with platforms and capture options.",
    params_schema=object_schema({}),
    handler=_list_supported_protocols,
    kind="discover",
    result_schema=_result(SCHEMA_CAPTURE_PROTOCOLS, {
        "protocols": {"type": "array", "items": {"type": "object", "properties": {
            "name": _STR, "display_name": _STR, "description": _STR, "category": _STR,
            "platforms": {"type": "array", "items": _STR},
            "options": _ROWS, "capture_modes": {"type": "array", "items": _STR},
            "implies": {"type": "array", "items": _STR},
            "backends": {"type": "array", "items": _STR}}}},
        "capture_modes": {"type": "array", "items": _STR},
        "default": _STR,
    }),
)


# ---------------------------------------------------------------------------
# list_protocols
# ---------------------------------------------------------------------------

def _list_protocols(params: dict, ctx: ToolContext) -> dict:
    tap = resolve_tap_source(params, ctx)
    seen = protocol_service.protocols_in_tap(tap)
    return envelope.ok(SCHEMA_PROTOCOLS, {
        "source": {"file": tap.name, "flows_total": seen["flows_total"]},
        "protocols": seen["protocols"],
        "app_protocols": seen["app_protocols"],
        "known_protocols": known_protocol_names(),
    })


_PROTOCOLS_SPEC = ToolSpec(
    name="list_protocols",
    summary="Protocols and app protocols in a capture, with flow counts; valid slice names.",
    params_schema=_tap_schema({}),
    handler=_list_protocols,
    kind="read",
    result_schema=_result(SCHEMA_PROTOCOLS, {
        "source": _SOURCE, "protocols": _COUNTS, "app_protocols": _COUNTS,
        "known_protocols": {"type": "array", "items": _STR},
    }),
)


# ---------------------------------------------------------------------------
# get_digest
# ---------------------------------------------------------------------------

def _get_digest(params: dict, ctx: ToolContext) -> dict:
    doc = reading.digest(resolve_tap_source(params, ctx), params)
    if params["format"] == "md":
        return envelope.ok(SCHEMA_DIGEST_MD, {"markdown": reading.digest_markdown(doc)},
                           notice=True)
    return doc


def _digest_params() -> dict[str, dict]:
    from friTap.analysis.digest import DEFAULT_BUDGET_TOKENS, FOCUS_CHOICES

    return {
        **SLICE_PARAMS,
        "focus": {"type": "string", "enum": list(FOCUS_CHOICES), "default": "all",
                  "description": "Findings focus: all, privacy (pii) or security."},
        "budget": {"type": "integer", "minimum": 100, "maximum": MAX_DIGEST_BUDGET,
                   "default": DEFAULT_BUDGET_TOKENS,
                   "description": "Approximate token budget; low-volume rows drop first."},
        "format": {"type": "string", "enum": ["json", "md"], "default": "json",
                   "description": "json (structured) or md (compact Markdown)."},
        **SHOW_VALUES,
    }


_DIGEST_SPEC = ToolSpec(
    name="get_digest",
    summary="Start here: token-budgeted summary of hosts, endpoints, messages and findings.",
    params_schema=_tap_schema(_digest_params()),
    handler=_get_digest,
    kind="read",
    result_schema={"type": "object", "properties": {
        "schema": {"enum": ["fritap.digest/2", SCHEMA_DIGEST_MD]},
        "source": _SOURCE, "params": {"type": "object"}, **_NOTICE,
        "protocols": {"type": "object", "additionalProperties": {"type": "object"}},
        "findings": {"type": "object"}, "truncated": {}, "estimated_tokens": _INT,
        "markdown": _STR}},
)


# ---------------------------------------------------------------------------
# list_endpoints
# ---------------------------------------------------------------------------

def _page(rows: list, params: dict) -> dict[str, Any]:
    page, next_cursor = envelope.paginate(rows, params["limit"], params.get("cursor"))
    return {"total": len(rows), "rows": page, "next_cursor": next_cursor}


def _list_endpoints(params: dict, ctx: ToolContext) -> dict:
    source, rows = reading.endpoints(resolve_tap_source(params, ctx), params)
    return envelope.ok(SCHEMA_ENDPOINTS, {"source": source, **_page(rows, params)}, notice=True)


_ENDPOINTS_SPEC = ToolSpec(
    name="list_endpoints",
    summary="Paginated endpoint clusters (method, path template, key shapes), busiest first.",
    params_schema=_tap_schema({**SLICE_PARAMS, **_COMPACT_PAGE}),
    handler=_list_endpoints,
    kind="read",
    result_schema=_result(SCHEMA_ENDPOINTS, {
        "source": _SOURCE, "total": _INT, "next_cursor": _CURSOR, **_NOTICE,
        "rows": {"type": "array", "items": {"type": "object", "properties": {
            "protocol": _STR, "ref": _STR, "count": _INT, "bytes": _INT,
            "body_kind": _STR, "status": _COUNTS, "untrusted": {"type": "object"}}}},
    }),
)


# ---------------------------------------------------------------------------
# get_flow
# ---------------------------------------------------------------------------

def _get_flow(params: dict, ctx: ToolContext) -> dict:
    return reading.flow_detail(resolve_tap_source(params, ctx), params)


_FLOW_SPEC = ToolSpec(
    name="get_flow",
    summary="One flow by ref (f12 or f12#m3): metadata, request/response, messages.",
    params_schema=_tap_schema({
        "ref": {"type": "string", "minLength": 1, "maxLength": 256,
                "description": "Flow ref from get_digest/list_endpoints, e.g. f12 or f12#m3."},
        "max_bytes": {"type": "integer", "minimum": 64, "maximum": MAX_FLOW_BYTES,
                      "default": DEFAULT_FLOW_BYTES, "description": "Cap per body/message preview."},
        "fields": {"type": "array", "items": {"type": "string", "enum": list(reading.FLOW_FIELDS)},
                   "description": "Only these parts (default: all)."},
        **SHOW_VALUES,
    }, required=("ref",)),
    handler=_get_flow,
    kind="read",
    result_schema={"type": "object", "properties": {
        "schema": {"const": "fritap.flow/1"}, "source": {"type": "object"},
        "params": {"type": "object"}, **_NOTICE, "flow": {"type": "object"},
        "request": {"type": ["object", "null"]}, "response": {"type": ["object", "null"]},
        "messages": _ROWS, "messages_total": _INT}},
)


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

def _list_findings(params: dict, ctx: ToolContext) -> dict:
    source, summary, rows = reading.findings(resolve_tap_source(params, ctx), params)
    page = _page(rows, params)
    return envelope.ok(SCHEMA_FINDINGS, {"source": source, "summary": summary, **page},
                       notice=True)


_FINDINGS_SPEC = ToolSpec(
    name="list_findings",
    summary="Paginated analyzer findings (secrets, PII, IOCs), most severe first; values redacted.",
    params_schema=_tap_schema({
        **SLICE_PARAMS,
        "category": {"type": "string", "enum": list(FINDING_CATEGORIES),
                     "description": "Only this finding category."},
        "min_severity": {"type": "string", "enum": list(SEVERITIES),
                         "description": "Only findings at least this severe."},
        **_COMPACT_PAGE,
        **SHOW_VALUES,
    }),
    handler=_list_findings,
    kind="read",
    result_schema=_result(SCHEMA_FINDINGS, {
        "source": _SOURCE, "total": _INT, "next_cursor": _CURSOR, **_NOTICE,
        "summary": {"type": "object", "properties": {
            "total": _INT, "by_severity": _COUNTS, "by_category": _COUNTS}},
        "rows": {"type": "array", "items": {"type": "object", "properties": {
            "ref": _STR, "count": _INT, "severity": _STR, "category": _STR,
            "source": _STR, "untrusted": {"type": "object"}}}},
    }),
)


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

def _export(params: dict, ctx: ToolContext) -> dict:
    tap = resolve_tap_source(params, ctx)
    return envelope.ok(SCHEMA_EXPORT, export_service.export(tap, params, ctx))


_EXPORT_SPEC = ToolSpec(
    name="export",
    summary="Write a capture to a file as har, markdown or keylog; returns path and sha256.",
    params_schema=_tap_schema({
        "format": {"type": "string", "enum": list(export_service.EXPORT_FORMATS),
                   "description": "har (HTTP archive), markdown (report) or keylog (secrets)."},
        "out": {"type": "string", "minLength": 1,
                "description": "Output file path inside the sandbox root."},
        "overwrite": {"type": "boolean", "default": False,
                      "description": "Replace an existing output file."},
        "include_bodies": {"type": "boolean", "default": False,
                           "description": "har: embed request/response bodies."},
        "confirm_secrets": {"type": "boolean", "default": False,
                            "description": "keylog: confirm writing TLS key material (the "
                                           "server must also allow secrets)."},
        **SLICE_PARAMS,
        **SHOW_VALUES,
    }, required=("format", "out")),
    handler=_export,
    kind="export",
    mutating=True,
    result_schema=_result(SCHEMA_EXPORT, {
        "path": _STR, "bytes": _INT, "sha256": _STR, "format": _STR}),
)


TOOL_SPECS: tuple[ToolSpec, ...] = (
    _SUPPORTED_SPEC,
    _PROTOCOLS_SPEC,
    _DIGEST_SPEC,
    _ENDPOINTS_SPEC,
    _FLOW_SPEC,
    _FINDINGS_SPEC,
    _EXPORT_SPEC,
)


def register_all(registry: "Registry") -> None:
    """Register the read-side tools on ``registry``."""
    for spec in TOOL_SPECS:
        registry.register(spec)


__all__ = ["register_all", "TOOL_SPECS"]
