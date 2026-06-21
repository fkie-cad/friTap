"""Registry of offline protocol decryptors (friTap-owned, non-tshark).

Some protocols carry their own end-to-end encryption *inside* the transport
that tshark already decrypts (or inside plain TCP): Signal (sealed-sender over
WebSocket-over-TLS) and MTProto (Telegram's obfuscated TCP) are decrypted by
friTap's OWN decryptors, keyed by a friTap-specific keylog, not by tshark.

This registry makes that set runtime-extensible, mirroring the proven
parser/analyzer model (:mod:`friTap.parsers.registry`,
:mod:`friTap.analysis.registry`): a protocol declares an
:class:`OfflineDecryptorEntry`, and :func:`~friTap.offline.pcap_to_tap.convert_pcap_to_tap`
iterates the registry instead of hardcoding ``if signal:``/``if mtproto:``
blocks. A new protocol (and any plugin discovered via
:mod:`friTap.offline.discovery`) then gets the offline pipeline, the CLI
``--<proto>-keylog`` flag, and the layered flow view for free.

An entry is pure metadata plus an *emitter* callable with a normalized
signature (see :data:`OfflineEmitter`); the built-in Signal/MTProto entries are
registered by :mod:`friTap.offline.pcap_to_tap` where their emitter functions
live (avoiding an import cycle).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Marker attribute an external module sets on a value it wants auto-discovered
# as an offline decryptor (mirrors ``is_fritap_parser`` / ``is_fritap_analyzer``).
OFFLINE_DECRYPTOR_MARKER_ATTR = "is_fritap_offline_decryptor"

# Entry-point group plugins publish offline decryptors under (see setup.py).
OFFLINE_DECRYPTOR_ENTRYPOINT_GROUP = "fritap.offline_decryptors"

# Environment variable to disable drop-in/entry-point discovery (test isolation).
OFFLINE_DECRYPTOR_DISCOVERY_DISABLE_ENV = "FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY"


# The emitter receives everything any built-in or plugin decryptor could need;
# each implementation uses the subset it cares about. It must emit DatalogEvents
# (and SessionEvents if it wants metadata layers) on *bus*, open the writer via
# ``state.ensure_open(...)``, and record its counters via
# ``result.record_protocol(...)``. It must never raise for a recoverable issue
# (missing dependency / unusable keylog) — log and return instead.
OfflineEmitter = Callable[..., None]


@dataclass(frozen=True)
class OfflineDecryptorEntry:
    """Describes one friTap-owned offline protocol decryptor.

    Attributes:
        protocol_name: Canonical protocol name (e.g. ``"signal"``). Used as the
            ``per_protocol`` counter key and to look up the protocol's keylog.
        cli_flag: The offline CLI flag that supplies this protocol's keylog
            (e.g. ``"--signal-keylog"``); built into the parser from the registry.
        cli_dest: argparse ``dest`` for *cli_flag* (e.g. ``"signal_keylog"``).
        requires_tls_strip: True when the protocol rides inside TLS and therefore
            consumes tshark's decrypted bytes (Signal) — it runs only under the
            keys-available branch and needs the TLS ``--keylog``. False for a
            self-contained transport (MTProto) that decrypts raw TCP independently.
        emitter: The normalized :data:`OfflineEmitter` doing the work.
        layer_cls: The flow layer class this protocol's messages land in
            (e.g. ``SignalLayer``) — used to wire the layer-registry decryptor hook.
        counter_prefix: Prefix for ``ConvertResult`` counters / ``per_protocol``
            key (usually equals *protocol_name*).
        cli_help: Help text for the generated CLI flag.
    """

    protocol_name: str
    cli_flag: str
    cli_dest: str
    requires_tls_strip: bool
    emitter: OfflineEmitter
    layer_cls: type
    counter_prefix: str
    cli_help: str = ""


class OfflineDecryptorRegistry:
    """Process-global, thread-safe registry of :class:`OfflineDecryptorEntry`."""

    def __init__(self) -> None:
        self._entries: Dict[str, OfflineDecryptorEntry] = {}
        self._lock = threading.RLock()

    def register(self, entry: OfflineDecryptorEntry, *, replace: bool = False) -> None:
        """Register *entry* keyed by ``protocol_name``.

        Re-registering the same name is idempotent when the entry is identical;
        a conflicting re-registration is rejected unless *replace* is True (so a
        plugin can deliberately override a built-in).
        """
        with self._lock:
            existing = self._entries.get(entry.protocol_name)
            if existing is not None and existing != entry and not replace:
                logger.warning(
                    "Offline decryptor %r already registered; ignoring conflicting "
                    "registration (pass replace=True to override)",
                    entry.protocol_name,
                )
                return
            self._entries[entry.protocol_name] = entry

    def get(self, protocol_name: str) -> Optional[OfflineDecryptorEntry]:
        """Return the entry for *protocol_name*, or ``None``."""
        with self._lock:
            return self._entries.get(protocol_name)

    def list(self) -> List[OfflineDecryptorEntry]:
        """Return all entries (registration order, stable for deterministic CLI)."""
        with self._lock:
            return list(self._entries.values())

    def names(self) -> List[str]:
        """Return all registered protocol names."""
        with self._lock:
            return list(self._entries.keys())


_REGISTRY = OfflineDecryptorRegistry()


def get_offline_decryptor_registry() -> OfflineDecryptorRegistry:
    """Return the process-global offline-decryptor registry."""
    return _REGISTRY


def register_offline_decryptor(entry: OfflineDecryptorEntry, *, replace: bool = False) -> None:
    """Register *entry* in the process-global registry (convenience wrapper)."""
    _REGISTRY.register(entry, replace=replace)


__all__ = [
    "OfflineDecryptorEntry",
    "OfflineDecryptorRegistry",
    "OfflineEmitter",
    "get_offline_decryptor_registry",
    "register_offline_decryptor",
    "OFFLINE_DECRYPTOR_MARKER_ATTR",
    "OFFLINE_DECRYPTOR_ENTRYPOINT_GROUP",
    "OFFLINE_DECRYPTOR_DISCOVERY_DISABLE_ENV",
]
