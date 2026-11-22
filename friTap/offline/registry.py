"""Registry of friTap-owned offline protocol decryptors (non-tshark).

Protocols with their own encryption inside TLS or plain TCP (Signal, MTProto,
RC4, Schannel, ...) declare an :class:`OfflineDecryptorEntry`. In-tree
subpackages self-register on import; plugins arrive via
:mod:`friTap.offline.discovery`. :mod:`friTap.offline.pcap_to_tap` iterates the
registry, so each entry gets the offline pipeline, its ``--<proto>-keylog`` CLI
flag and the layered flow view without protocol-specific code.
"""
from __future__ import annotations

import importlib
import logging
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Set

logger = logging.getLogger(__name__)

# Set on a value an external module wants auto-discovered as an offline decryptor.
OFFLINE_DECRYPTOR_MARKER_ATTR = "is_fritap_offline_decryptor"

OFFLINE_DECRYPTOR_ENTRYPOINT_GROUP = "fritap.offline_decryptors"

# Disables drop-in/entry-point discovery (test isolation).
OFFLINE_DECRYPTOR_DISCOVERY_DISABLE_ENV = "FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY"


# Emitter contract: receives every kwarg any decryptor could need and uses a
# subset. Emits DatalogEvents (plus SessionEvents for metadata layers) on *bus*,
# opens the writer via ``state.ensure_open(...)``, records counters via
# ``result.record_protocol(prefix, **counters)``, and keeps per-conversion state
# in a ``pipeline_api.register_protocol_state`` namespace. Must not raise on a
# recoverable issue (missing dependency, unusable keylog); log and return.
OfflineEmitter = Callable[..., None]

# Post-collection hook: gets the collector's live flows and the writer state,
# runs after every emitter and before the final flush, and returns the ids of
# flows it fully absorbed (not written), or None.
OfflineAttach = Callable[[list, object], Optional[Set[str]]]

# Mid-stream span hook: called as ``(state, bound_keys, proto_keylogs,
# present_entries, *, bus, result)`` once the mid-stream TLS stage bound a
# connection; decodes from ``state.tls_spans``. Must not raise.
OfflineMidstreamSpans = Callable[..., None]


@dataclass(frozen=True)
class OfflineDecryptorEntry:
    """One friTap-owned offline protocol decryptor.

    Attributes:
        protocol_name: Canonical name (``"signal"``); the ``per_protocol``
            counter key and keylog lookup key.
        cli_flag / cli_dest: Keylog CLI flag (``"--signal-keylog"``) and its
            argparse dest, both generated from the registry.
        requires_tls_strip: True when the protocol rides inside TLS and consumes
            tshark's decrypted bytes (Signal); False for raw TCP (MTProto).
        emitter: The normalized :data:`OfflineEmitter`.
        layer_cls: Flow layer class for the protocol's messages.
        counter_prefix: Prefix for ``ConvertResult`` counters (usually
            *protocol_name*).
        cli_help: Help text for the generated flag.
        picker_group: Empty lists the protocol on its own in the TUI keylog
            picker; otherwise the picker entry it is offered through.
        accepts_keylog: For grouped entries, whether a keylog path supplied
            under *picker_group* belongs here. ``None`` means never.
        decoder_family: Entries sharing a non-empty family run one decoder once
            per capture with merged keylogs (``mtproto``, ``telegram``). A family
            emitter receiving several keylogs must accept ``extra_keylogs``.
        nests_in_tls: True when the protocol can ride inside decrypted TLS
            (RC4-in-TLS); its flows and the TLS flows are held back until the
            nested attach, which may absorb a TLS flow.
        attach: Optional :data:`OfflineAttach` hook; runs on every conversion.
            A decoder family declares it on one member only.
        attach_order: Sort key among all attach hooks (ties keep registration
            order).
        messaging: True when the CLI/TUI summarize its counters via
            ``messaging_buckets``.
        resync_default: Default mid-stream resync depth in the decryptor's own
            unit, or ``None`` without mid-stream recovery. The first non-``None``
            value is the public default.
        resync_param: Emitter keyword receiving ``resync_search_depth``, or
            ``None``. Forwarded only if the emitter accepts it (or ``**kwargs``).
        midstream_spans: Optional :data:`OfflineMidstreamSpans` hook.
    """

    protocol_name: str
    cli_flag: str
    cli_dest: str
    requires_tls_strip: bool
    emitter: OfflineEmitter
    layer_cls: type
    counter_prefix: str
    cli_help: str = ""
    picker_group: str = ""
    accepts_keylog: Optional[Callable[[str], bool]] = None
    decoder_family: str = ""
    nests_in_tls: bool = False
    attach: Optional[OfflineAttach] = None
    attach_order: int = 0
    messaging: bool = False
    resync_default: Optional[int] = None
    resync_param: Optional[str] = None
    midstream_spans: Optional[OfflineMidstreamSpans] = None


class OfflineDecryptorRegistry:
    """Process-global, thread-safe registry of :class:`OfflineDecryptorEntry`."""

    def __init__(self) -> None:
        self._entries: Dict[str, OfflineDecryptorEntry] = {}
        self._lock = threading.RLock()

    def register(self, entry: OfflineDecryptorEntry, *, replace: bool = False) -> None:
        """Register *entry* by ``protocol_name``; a conflicting entry needs *replace*."""
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
        """All entries in registration order."""
        with self._lock:
            return list(self._entries.values())

    def names(self) -> List[str]:
        """Return all registered protocol names."""
        with self._lock:
            return list(self._entries.keys())


_REGISTRY = OfflineDecryptorRegistry()


def entry_family(entry: OfflineDecryptorEntry) -> str:
    """Decoder family of *entry* (its own protocol name if unset)."""
    return getattr(entry, "decoder_family", "") or entry.protocol_name


def attach_hooks(entries: List[OfflineDecryptorEntry]) -> List[OfflineAttach]:
    """The entries' attach hooks, stably sorted by ``attach_order``."""
    ordered = sorted(entries, key=lambda e: e.attach_order)
    return [entry.attach for entry in ordered if entry.attach is not None]


def messaging_protocol_names(entries: List[OfflineDecryptorEntry]) -> tuple:
    """Names of the ``messaging`` entries, in *entries* (registration) order."""
    return tuple(e.protocol_name for e in entries if getattr(e, "messaging", False))


def default_resync_search_depth(entries: List[OfflineDecryptorEntry], fallback: int = 0) -> int:
    """The first entry's non-``None`` ``resync_default``, else *fallback*."""
    for entry in entries:
        value = getattr(entry, "resync_default", None)
        if value is not None:
            return value
    return fallback


def get_offline_decryptor_registry() -> OfflineDecryptorRegistry:
    """Return the process-global offline-decryptor registry."""
    return _REGISTRY


def register_offline_decryptor(entry: OfflineDecryptorEntry, *, replace: bool = False) -> None:
    """Register *entry* in the process-global registry (convenience wrapper)."""
    _REGISTRY.register(entry, replace=replace)


def register_offline_decryptors_safely(
    package: str, builder_names: Sequence[str], skip_message: str,
) -> None:
    """Register the entries built by ``<package>.offline_decryptor``, never raising.

    A failure is logged at debug as *skip_message* and skips the rest.
    """
    try:
        module = importlib.import_module(f"{package}.offline_decryptor")
        for builder_name in builder_names:
            register_offline_decryptor(getattr(module, builder_name)())
    except Exception:  # noqa: BLE001 - registration must never break import
        logging.getLogger(package).debug(skip_message, exc_info=True)


__all__ = [
    "OfflineDecryptorEntry",
    "OfflineDecryptorRegistry",
    "attach_hooks",
    "default_resync_search_depth",
    "entry_family",
    "messaging_protocol_names",
    "OfflineEmitter",
    "OfflineAttach",
    "OfflineMidstreamSpans",
    "get_offline_decryptor_registry",
    "register_offline_decryptor",
    "register_offline_decryptors_safely",
    "OFFLINE_DECRYPTOR_MARKER_ATTR",
    "OFFLINE_DECRYPTOR_ENTRYPOINT_GROUP",
    "OFFLINE_DECRYPTOR_DISCOVERY_DISABLE_ENV",
]
