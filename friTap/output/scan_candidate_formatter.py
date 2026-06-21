#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic memory-scan candidate formatter.

Renders the ranked, anonymous key candidates emitted by the public memory-scan
engine (``agent/shared/scan/``) when the user passes ``--scan-keys-region``. The
agent tags those messages with ``classifier="scan_candidate"`` and the router
forwards them as ``KeylogEvent(protocol="scan_candidate")``; this formatter is
wired active whenever a scan region is configured (see
``friTap/output/factory.py``).

Protocol-agnostic by construction: each line is an anonymous candidate
(score / signals / region / offset / length / bytes) with no protocol identity
and no decrypted content. PUBLIC — not listed in ``private.txt``.
"""

from __future__ import annotations
from typing import List, Optional, TYPE_CHECKING

from .keylog_format import KeylogFormatter

if TYPE_CHECKING:
    from ..events import KeylogEvent


class ScanCandidateKeylogFormatter(KeylogFormatter):
    """Formats generic memory-scan key candidates into one comment line each."""

    @property
    def protocol(self) -> str:
        return "scan_candidate"

    def header_comment(self) -> Optional[str]:
        return (
            "# friTap memory-scan key candidates — "
            "score signals region offset length bytes"
        )

    def format(self, event: "KeylogEvent") -> List[str]:
        p = event.payload or {}
        signals = p.get("signals") or []
        if isinstance(signals, (list, tuple)):
            signals = ",".join(str(s) for s in signals)
        line = (
            f"# score={p.get('score', 0)} "
            f"signals={signals} "
            f"region={p.get('region', '')} "
            f"offset={p.get('offset', 0)} "
            f"length={p.get('length', 0)} "
            f"bytes={p.get('bytes', '')}"
        )
        return [line]

    def dedup_key(self, event: "KeylogEvent") -> str:
        p = event.payload or {}
        return f"{p.get('region', '')}|{p.get('offset', 0)}|{p.get('bytes', '')}"
