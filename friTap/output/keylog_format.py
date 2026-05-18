#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Per-protocol keylog line formatter abstraction.

Each :class:`~friTap.protocols.base.ProtocolHandler` may expose a
``keylog_formatter()`` that returns one of these. The generic
:class:`~friTap.output.keylog_handler.KeylogOutputHandler` then uses the
formatter to turn :class:`~friTap.events.KeylogEvent` instances into the
Wireshark-loadable lines for that specific protocol, without the output
layer needing protocol-specific branching.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from ..events import KeylogEvent


class KeylogFormatter(ABC):
    """Translates a :class:`KeylogEvent` into Wireshark-loadable keylog lines.

    Subclasses bind the formatter to exactly one protocol via the
    ``protocol`` property — the output handler uses that as an event-bus
    routing filter (``event.protocol == formatter.protocol``).
    """

    @property
    @abstractmethod
    def protocol(self) -> str:
        """Protocol identifier this formatter targets (e.g. ``"tls"``, ``"ssh"``)."""
        ...

    def header_comment(self) -> Optional[str]:
        """Optional comment written once when the keylog file is first opened.

        Wireshark dissectors ignore ``#``-prefixed lines, so this is a safe
        place to put human-readable provenance. Return ``None`` for no header.
        """
        return None

    def format(self, event: "KeylogEvent") -> List[str]:
        """Return zero or more keylog lines for *event* (no trailing newlines).

        The default returns ``event.key_data`` as a single line when present.
        This handles the common case where the agent already produced a
        protocol-correct line (NSS ``CLIENT_RANDOM …``, OpenSSH-style
        ``SSH_ENC_KEY_C2S …``, etc.); override for protocols that emit
        structured payloads (see :class:`SshKeylogFormatter`).
        """
        return [event.key_data] if event.key_data else []

    def dedup_key(self, event: "KeylogEvent") -> str:
        """Stable identity for the LRU deduplicator.

        The default joins the formatted lines — correct but calls
        :meth:`format` a second time. Subclasses on the keylog hot path
        should override with a cheaper identity (e.g. SSH
        ``cookie|shared_secret``) to avoid the double-format cost; the
        built-in TLS/SSH formatters do.
        """
        return "\n".join(self.format(event))
