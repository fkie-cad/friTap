#!/usr/bin/env python3

"""Heap memory-scan secret formatter.

Each finding is a ``KeylogEvent(protocol="memscan")`` whose ``key_data`` is
already a complete NSS keylog line, so the base ``format`` is reused. Only
``protocol``, the header and the dedup key are specialised.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ..output.keylog_format import KeylogFormatter

if TYPE_CHECKING:
    from ..events import KeylogEvent


class MemoryScanKeylogFormatter(KeylogFormatter):
    """Formats heap-recovered NSS keylog lines (already Wireshark-loadable)."""

    @property
    def protocol(self) -> str:
        return "memscan"

    def header_comment(self) -> Optional[str]:
        return "# friTap heap memory-scan recovered TLS secrets (NSS keylog)"

    def dedup_key(self, event: "KeylogEvent") -> str:
        # The whole line is the identity; the agent also dedups upstream, so this
        # only guards against event-bus replay.
        return event.key_data
