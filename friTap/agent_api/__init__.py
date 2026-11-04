"""
friTap agent API: one tool registry behind the CLI (``fritap q``), MCP and REST.

    from friTap.agent_api import call, list_tools, ToolContext
    call("get_digest", {"tap": "run.tap"}, context=ToolContext(root=Path(".")))

Every failure raises :class:`ToolError`; ``error.to_dict()`` is the JSON
error document all adapters return.
"""

from __future__ import annotations

from typing import Any

from friTap.agent_api.context import ToolContext
from friTap.agent_api.errors import ToolError
from friTap.agent_api.registry import ToolSpec, registry


def call(name: str, params: dict | None = None, *, context: ToolContext | None = None) -> dict:
    """Run tool ``name`` on the default registry (see :meth:`Registry.call`)."""
    return registry.call(name, params, context=context)


def list_tools() -> list[dict[str, Any]]:
    """Describe every registered tool as JSON-safe dicts, sorted by name."""
    return [spec.describe() for spec in registry.specs()]


__all__ = ["ToolSpec", "ToolError", "ToolContext", "call", "list_tools", "registry"]
