"""
Tool registry: the single source of truth for agent-facing tools.

A :class:`ToolSpec` names a tool, its JSON-Schema parameters and its handler
``handler(params: dict, ctx: ToolContext) -> dict``. The CLI (``fritap q``),
MCP and REST adapters are generated from :meth:`Registry.specs` and execute
tools through :meth:`Registry.call`, which validates parameters, runs the
handler, converts exceptions to :class:`ToolError` and caps the response.

The default registry loads :mod:`friTap.agent_api.tools` lazily on first use,
so importing this module stays cheap.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Callable

from friTap.agent_api.context import ToolContext
from friTap.agent_api.envelope import capped_json
from friTap.agent_api.errors import ToolError, wrap
from friTap.agent_api.schema import validate
from friTap.exit_codes import EXIT_RUNTIME_ERROR
from friTap.suggest import did_you_mean

TOOL_KINDS = frozenset({"read", "discover", "capture", "export"})
MAX_SUMMARY_LEN = 100

Handler = Callable[[dict, ToolContext], dict]


@dataclass(frozen=True)
class ToolSpec:
    """Declaration of one agent tool.

    Attributes:
        name: Unique snake_case tool name.
        summary: One-line description (<= 100 chars).
        params_schema: JSON-Schema object (see :func:`schema.object_schema`).
        handler: ``handler(params, ctx) -> dict`` (params already validated).
        kind: ``read`` | ``discover`` | ``capture`` | ``export``.
        mutating: True if the tool changes state (starts/stops captures, writes files).
        result_schema: Optional JSON-Schema of the result, used for docs.
    """

    name: str
    summary: str
    params_schema: dict[str, Any]
    handler: Handler
    kind: str
    mutating: bool = False
    result_schema: dict[str, Any] | None = None

    def describe(self, include_result: bool = False) -> dict[str, Any]:
        """JSON-safe description (everything but the handler) for tool listings.

        ``include_result`` adds ``result_schema`` when the tool declares one.
        """
        doc = {"name": self.name, "summary": self.summary, "kind": self.kind,
               "mutating": self.mutating, "params_schema": self.params_schema}
        if include_result and self.result_schema is not None:
            doc["result_schema"] = self.result_schema
        return doc

    def __post_init__(self) -> None:
        if self.kind not in TOOL_KINDS:
            raise ValueError(f"tool {self.name!r}: kind must be one of {sorted(TOOL_KINDS)}")
        if len(self.summary) > MAX_SUMMARY_LEN:
            raise ValueError(f"tool {self.name!r}: summary longer than {MAX_SUMMARY_LEN} chars")


class Registry:
    """Name -> :class:`ToolSpec` map; ``loader`` (a module name) is imported on first use.

    The loader module must expose ``register_all(registry)``.
    """

    def __init__(self, loader: str | None = None) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._loader = loader
        self._loaded = loader is None

    def register(self, spec: ToolSpec) -> ToolSpec:
        """Add ``spec``; a duplicate name raises ``ValueError``."""
        if spec.name in self._specs:
            raise ValueError(f"tool {spec.name!r} is already registered")
        self._specs[spec.name] = spec
        return spec

    def get(self, name: str) -> ToolSpec:
        """Return the spec for ``name`` or raise ``ToolError(unknown_tool)``."""
        self._ensure_loaded()
        spec = self._specs.get(name)
        if spec is None:
            raise ToolError(
                f"unknown tool {name!r}", "unknown_tool",
                hint=did_you_mean(name, sorted(self._specs), show_all=True),
            )
        return spec

    def names(self) -> list[str]:
        """Sorted tool names."""
        self._ensure_loaded()
        return sorted(self._specs)

    def specs(self) -> list[ToolSpec]:
        """Tool specs sorted by name."""
        return [self._specs[name] for name in self.names()]

    def call(
        self, name: str, params: dict | None = None, *, context: ToolContext | None = None
    ) -> dict[str, Any]:
        """Validate ``params``, run the tool and return its (size-capped) result.

        Raises:
            ToolError: for every failure (unknown tool, bad params, handler errors).
        """
        return self.call_json(name, params, context=context)[0]

    def call_json(
        self, name: str, params: dict | None = None, *, context: ToolContext | None = None
    ) -> tuple[dict[str, Any], str]:
        """Like :meth:`call`, also returning the result as compact JSON (encoded once).

        Raises:
            ToolError: for every failure (unknown tool, bad params, handler errors).
        """
        ctx = context if context is not None else ToolContext()
        try:
            spec = self.get(name)
            checked = validate(spec.params_schema, params)
            _check_values_allowed(checked, ctx)
            result = spec.handler(checked, ctx)
        except Exception as exc:  # noqa: BLE001 - every failure becomes a ToolError
            raise wrap(exc) from exc
        _check_result(name, result)
        return capped_json(result, ctx.max_response_bytes)

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True  # set first: the loader registers through this instance
        importlib.import_module(self._loader).register_all(self)


def _check_values_allowed(params: dict[str, Any], ctx: ToolContext) -> None:
    """Refuse ``show_values=true`` unless the context allows unredacted values."""
    if params.get("show_values") and not ctx.allow_values:
        raise ToolError("show_values is disabled on this server", "forbidden",
                        hint="start the server with --allow-values")


def _check_result(name: str, result: Any) -> None:
    if not isinstance(result, dict):
        raise ToolError(
            f"tool {name!r} returned {type(result).__name__}, expected a dict",
            "runtime_error", exit_code=EXIT_RUNTIME_ERROR,
        )


#: The process-wide registry used by the adapters.
registry = Registry(loader="friTap.agent_api.tools")


__all__ = ["ToolSpec", "Registry", "Handler", "TOOL_KINDS", "registry"]
