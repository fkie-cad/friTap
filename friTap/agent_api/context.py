"""
Per-call policy for agent API tools.

Adapters build one :class:`ToolContext` from their command line (``--root``,
``--allow-capture``, ``--allow-target``, ``--allow-secrets``, ``--allow-values``)
and pass it to
every :func:`friTap.agent_api.call`. Handlers read policy from it instead of
from globals, so the same tool behaves per adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

DEFAULT_MAX_RESPONSE_BYTES = 65536


@dataclass(frozen=True)
class ToolContext:
    """Sandbox and permission settings for one tool call.

    Attributes:
        root: Sandbox root; tap paths and exports must resolve inside it.
        allow_capture: Whether capture tools may start processes.
        allow_targets: fnmatch patterns of allowed capture targets
            (empty = every target allowed).
        allow_secrets: Whether key material (keylog export) may be produced.
        allow_values: Whether ``show_values=true`` may return unredacted
            finding values. True in-process and for ``fritap q`` (the local
            user owns the data); MCP/REST servers default to False.
        max_response_bytes: Cap on the serialized JSON response size.
    """

    root: Path = field(default_factory=Path.cwd)
    allow_capture: bool = True
    allow_targets: tuple[str, ...] = ()
    allow_secrets: bool = False
    allow_values: bool = True
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES

    def target_allowed(self, target: str) -> bool:
        """True if ``target`` matches the allow-list (or the list is empty)."""
        if not self.allow_targets:
            return True
        return any(fnmatch(target, pattern) for pattern in self.allow_targets)


__all__ = ["ToolContext", "DEFAULT_MAX_RESPONSE_BYTES"]
