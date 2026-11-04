"""
Registers every built-in agent tool (loaded lazily by the default registry).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from friTap.agent_api import tools_capture, tools_read

if TYPE_CHECKING:
    from friTap.agent_api.registry import Registry


def register_all(registry: "Registry") -> None:
    """Register the read/discover/export and capture tools on ``registry``."""
    tools_read.register_all(registry)
    tools_capture.register_all(registry)


__all__ = ["register_all"]
