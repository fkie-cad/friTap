"""
Structured tool errors for the agent API.

Every failure that leaves a tool call is a :class:`ToolError`, so the CLI,
MCP and REST adapters can render one JSON shape
(``{"error", "error_type", "hint"?, "exit_code", ...}``) and map it to their
own status codes. :func:`wrap` converts arbitrary exceptions raised by the
services into that shape.
"""

from __future__ import annotations

from typing import Any

from friTap.exit_codes import EXIT_RUNTIME_ERROR, EXIT_USAGE_ERROR


class ToolError(Exception):
    """A tool call failure with a machine-readable ``error_type`` slug.

    Attributes:
        error: Human readable message.
        error_type: snake_case slug (``bad_param``, ``not_found``, ...).
        hint: Optional next step for the caller (did-you-mean, valid values).
        exit_code: Process exit code for the CLI adapter.
        extra: Additional JSON-safe fields merged into :meth:`to_dict`.
    """

    def __init__(
        self,
        error: str,
        error_type: str,
        hint: str | None = None,
        exit_code: int = EXIT_USAGE_ERROR,
        **extra: Any,
    ) -> None:
        super().__init__(error)
        self.error = error
        self.error_type = error_type
        self.hint = hint
        self.exit_code = exit_code
        self.extra: dict[str, Any] = dict(extra)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON error document."""
        doc: dict[str, Any] = {"error": self.error, "error_type": self.error_type}
        if self.hint:
            doc["hint"] = self.hint
        doc["exit_code"] = self.exit_code
        doc.update(self.extra)
        return doc


def wrap(exc: BaseException) -> ToolError:
    """Convert any exception raised by a tool into a :class:`ToolError`."""
    if isinstance(exc, ToolError):
        return exc
    for converter in (_filter_error, _flow_ref_error, _os_error):
        converted = converter(exc)
        if converted is not None:
            return converted
    return ToolError(
        f"{type(exc).__name__}: {exc}", "runtime_error", exit_code=EXIT_RUNTIME_ERROR
    )


def _filter_error(exc: BaseException) -> ToolError | None:
    from friTap.filter.errors import FilterSyntaxError, UnknownFieldError

    if not isinstance(exc, FilterSyntaxError):
        return None
    extra: dict[str, Any] = {}
    if exc.position >= 0:
        extra["position"] = exc.position
    if isinstance(exc, UnknownFieldError):
        hint = _unknown_field_hint(exc)
    else:
        hint = getattr(exc, "hint", None)
    return ToolError(str(exc), "bad_filter", hint=hint, **extra)


def _unknown_field_hint(exc: Any) -> str | None:
    parts = []
    if exc.did_you_mean:
        parts.append("did you mean: " + ", ".join(exc.did_you_mean))
    if exc.suggestions:
        parts.append("try: " + "; ".join(exc.suggestions))
    return " | ".join(parts) or None


def _flow_ref_error(exc: BaseException) -> ToolError | None:
    from friTap.analysis.digest_flow import FlowRefError

    if not isinstance(exc, FlowRefError):
        return None
    return ToolError(str(exc), "bad_ref", hint="use a ref like f12 or f12#m3 from get_digest")


def _os_error(exc: BaseException) -> ToolError | None:
    if isinstance(exc, FileNotFoundError):
        return ToolError(str(exc), "not_found")
    if isinstance(exc, PermissionError):
        return ToolError(str(exc), "forbidden")
    return None


__all__ = ["ToolError", "wrap"]
