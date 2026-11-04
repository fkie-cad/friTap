"""The committed agent API schemas in docs/api/schemas/ must match the registry.

If this fails after changing a tool, regenerate the files:

    env/bin/python -m friTap.agent_api.adapters.openapi \\
        --out docs/api/schemas/openapi.json --schemas docs/api/schemas
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from friTap.agent_api.adapters.openapi import build_openapi, dump_json, per_tool_schemas
from friTap.agent_api.registry import registry

SCHEMAS_DIR = Path(__file__).resolve().parents[3] / "docs" / "api" / "schemas"
OPENAPI_FILE = SCHEMAS_DIR / "openapi.json"
GENERATED_SUFFIXES = (".params.json", ".result.json")
REGENERATE_HINT = (
    "docs/api/schemas is out of date; run: env/bin/python -m friTap.agent_api.adapters.openapi "
    "--out docs/api/schemas/openapi.json --schemas docs/api/schemas"
)


def _committed_version() -> str:
    """The friTap version recorded in the committed document (not a drift signal)."""
    return json.loads(OPENAPI_FILE.read_text(encoding="utf-8"))["info"]["version"]


def _committed_tool_schema_files() -> set[str]:
    return {p.name for p in SCHEMAS_DIR.iterdir() if p.name.endswith(GENERATED_SUFFIXES)}


def test_openapi_document_in_sync():
    expected = dump_json(build_openapi(registry, version=_committed_version()))
    assert OPENAPI_FILE.read_text(encoding="utf-8") == expected, REGENERATE_HINT


def test_no_missing_or_stale_tool_schema_files():
    expected = set(per_tool_schemas(registry))
    assert _committed_tool_schema_files() == expected, REGENERATE_HINT


@pytest.mark.parametrize("name", sorted(per_tool_schemas(registry)))
def test_tool_schema_file_in_sync(name):
    expected = dump_json(per_tool_schemas(registry)[name])
    committed = SCHEMAS_DIR / name
    assert committed.is_file(), REGENERATE_HINT
    assert committed.read_text(encoding="utf-8") == expected, REGENERATE_HINT


def test_generator_writes_identical_files(tmp_path):
    """The CLI entry point produces exactly the committed files (version aside)."""
    from friTap.agent_api.adapters.openapi import main

    out = tmp_path / "openapi.json"
    assert main(["--out", str(out), "--schemas", str(tmp_path)]) == 0
    generated = {p.name for p in tmp_path.iterdir() if p.name.endswith(GENERATED_SUFFIXES)}
    assert generated == _committed_tool_schema_files()
    for name in generated:
        assert (tmp_path / name).read_text(encoding="utf-8") == (SCHEMAS_DIR / name).read_text(
            encoding="utf-8"), f"{name}: {REGENERATE_HINT}"
    regenerated = json.loads(out.read_text(encoding="utf-8"))
    regenerated["info"]["version"] = _committed_version()
    assert dump_json(regenerated) == OPENAPI_FILE.read_text(encoding="utf-8"), REGENERATE_HINT
