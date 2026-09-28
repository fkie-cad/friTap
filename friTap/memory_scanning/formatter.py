#!/usr/bin/env python3

"""Heap memory-scan secret formatter.

Renders the NSS keylog lines recovered by the heap secret-scanner
(``--memory-scan`` / ``-ms``). The plugin forwards each finding as a
``KeylogEvent(protocol="memscan")`` whose ``key_data`` is already a complete
``LABEL <client_random> <secret>`` line, so this formatter follows the same
tagged-``KeylogEvent`` path the ``--scan-keys-region`` candidates use
(:class:`ScanCandidateKeylogFormatter`) and reuses the shared
:class:`~friTap.output.keylog_handler.KeylogOutputHandler` — no bespoke handler.

The base :meth:`KeylogFormatter.format` already returns ``[event.key_data]``,
which is exactly right here; only ``protocol``, a provenance header, and a cheap
dedup key are specialised.
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
