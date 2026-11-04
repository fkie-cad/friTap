"""
OpenAPI 3.1 description of the REST adapter, generated from the tool registry.

    python -m friTap.agent_api.adapters.openapi --out openapi.json --schemas docs/api/schemas

writes the OpenAPI document and one ``<tool>.params.json`` (plus
``<tool>.result.json`` when the tool declares a result schema) per tool.
Output is deterministic (sorted keys) so regenerated files diff cleanly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from friTap.agent_api.registry import Registry, ToolSpec

OPENAPI_VERSION = "3.1.0"
JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
TOOLS_PATH = "/v1/tools"
_REF = "#/components/schemas/"
_GENERIC_OBJECT = {"type": "object", "additionalProperties": True}

_ERROR_SCHEMA = {
    "type": "object",
    "required": ["error", "error_type", "exit_code"],
    "properties": {
        "error": {"type": "string"},
        "error_type": {"type": "string"},
        "hint": {"type": "string"},
        "exit_code": {"type": "integer"},
    },
    "additionalProperties": True,
}
_TOOL_DESCRIPTOR_SCHEMA = {
    "type": "object",
    "required": ["name", "summary", "kind", "mutating", "params_schema"],
    "properties": {
        "name": {"type": "string"},
        "summary": {"type": "string"},
        "kind": {"type": "string"},
        "mutating": {"type": "boolean"},
        "params_schema": {"type": "object"},
    },
}
_TOOL_LIST_SCHEMA = {
    "type": "object",
    "required": ["tools"],
    "properties": {"tools": {"type": "array", "items": {"$ref": _REF + "ToolDescriptor"}}},
}
_ERROR_STATUSES = {
    "400": "Invalid parameters or request body",
    "401": "Missing or wrong bearer token",
    "403": "Forbidden by server policy (sandbox root, capture, secrets)",
    "404": "Unknown tool or resource not found",
    "409": "Conflict (e.g. capture still running)",
    "413": "Request body too large",
    "500": "Tool runtime error",
}


def build_openapi(registry: Registry, *, version: str | None = None) -> dict[str, Any]:
    """Return the OpenAPI 3.1 document for every tool in ``registry``."""
    specs = registry.specs()
    paths = {**_static_paths(), **{f"{TOOLS_PATH}/{s.name}": {"post": _tool_operation(s)} for s in specs}}
    return {
        "openapi": OPENAPI_VERSION,
        "jsonSchemaDialect": JSON_SCHEMA_DIALECT,
        "info": {"title": "friTap agent API", "version": version or _fritap_version()},
        "paths": paths,
        "components": {
            "schemas": {**_shared_schemas(), **_tool_schemas(specs)},
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        },
    }


def _fritap_version() -> str:
    from friTap.about import __version__

    return __version__


def _shared_schemas() -> dict[str, Any]:
    return {
        "Error": _ERROR_SCHEMA,
        "ToolDescriptor": _TOOL_DESCRIPTOR_SCHEMA,
        "ToolList": _TOOL_LIST_SCHEMA,
        "GenericResult": _GENERIC_OBJECT,
    }


def _tool_schemas(specs: Sequence[ToolSpec]) -> dict[str, Any]:
    schemas: dict[str, Any] = {}
    for spec in specs:
        schemas[_params_name(spec)] = spec.params_schema
        if spec.result_schema is not None:
            schemas[_result_name(spec)] = spec.result_schema
    return schemas


def _params_name(spec: ToolSpec) -> str:
    return f"{spec.name}_params"


def _result_name(spec: ToolSpec) -> str:
    return f"{spec.name}_result" if spec.result_schema is not None else "GenericResult"


def _json_content(ref_name: str) -> dict[str, Any]:
    return {"application/json": {"schema": {"$ref": _REF + ref_name}}}


def _error_responses() -> dict[str, Any]:
    return {code: {"description": text, "content": _json_content("Error")}
            for code, text in _ERROR_STATUSES.items()}


def _get_operation(operation_id: str, summary: str, ref_name: str | None) -> dict[str, Any]:
    ok: dict[str, Any] = {"description": "OK"}
    if ref_name:
        ok["content"] = _json_content(ref_name)
    return {"get": {"operationId": operation_id, "summary": summary, "responses": {"200": ok}}}


def _static_paths() -> dict[str, Any]:
    return {
        TOOLS_PATH: _get_operation("list_tools", "List every tool with its parameter schema", "ToolList"),
        "/openapi.json": _get_operation("openapi", "This OpenAPI document", "GenericResult"),
        "/healthz": _get_operation("healthz", "Liveness probe", "GenericResult"),
    }


def _tool_operation(spec: ToolSpec) -> dict[str, Any]:
    return {
        "operationId": spec.name,
        "summary": spec.summary,
        "tags": [spec.kind],
        "x-fritap-mutating": spec.mutating,
        "requestBody": {"required": False, "content": _json_content(_params_name(spec))},
        "responses": {
            "200": {"description": "Tool result", "content": _json_content(_result_name(spec))},
            **_error_responses(),
        },
    }


def per_tool_schemas(registry: Registry) -> dict[str, dict[str, Any]]:
    """Map ``<tool>.params.json`` / ``<tool>.result.json`` file names to schemas."""
    files: dict[str, dict[str, Any]] = {}
    for spec in registry.specs():
        files[f"{spec.name}.params.json"] = _standalone(spec.params_schema, f"{spec.name} parameters")
        if spec.result_schema is not None:
            files[f"{spec.name}.result.json"] = _standalone(spec.result_schema, f"{spec.name} result")
    return files


def _standalone(schema: dict[str, Any], title: str) -> dict[str, Any]:
    return {"$schema": JSON_SCHEMA_DIALECT, "title": title, **schema}


def dump_json(doc: Any) -> str:
    """Deterministic pretty JSON with a trailing newline."""
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_outputs(registry: Registry, out: Path | None, schemas_dir: Path | None) -> None:
    """Write the OpenAPI document to ``out`` (stdout if None) and per-tool schemas."""
    text = dump_json(build_openapi(registry))
    if out is None:
        sys.stdout.write(text)
    else:
        out.write_text(text, encoding="utf-8")
    if schemas_dir is not None:
        schemas_dir.mkdir(parents=True, exist_ok=True)
        for name, schema in per_tool_schemas(registry).items():
            (schemas_dir / name).write_text(dump_json(schema), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m friTap.agent_api.adapters.openapi",
        description="Write the friTap agent API OpenAPI document and per-tool JSON schemas.",
    )
    parser.add_argument("--out", type=Path, help="OpenAPI output file (default: stdout).")
    parser.add_argument("--schemas", type=Path, metavar="DIR", help="Directory for per-tool schemas.")
    ns = parser.parse_args(argv)
    from friTap.agent_api.registry import registry

    write_outputs(registry, ns.out, ns.schemas)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["build_openapi", "per_tool_schemas", "write_outputs", "dump_json", "main"]
