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
signature (see :data:`OfflineEmitter`); the built-in entries (Signal, MTProto /
Telegram, RC4, Schannel, ...) are self-registered by their own in-tree
subpackages (e.g. :mod:`friTap.offline.mtproto`, :mod:`friTap.offline.signal`),
which register their entries when imported. The offline driver
(:mod:`friTap.offline.pcap_to_tap`) imports every in-tree subpackage at load
time without naming any protocol.
"""

from __future__ import annotations

import importlib
import logging
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Set

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
# ``result.record_protocol(prefix, **counters)`` (generic per-type merge into
# ``per_protocol[prefix]``). Per-conversion protocol bookkeeping belongs in a
# namespace registered with ``pipeline_api.register_protocol_state`` and reached
# via ``protocol_state_of(state, name)``. It must never raise for a recoverable
# issue (missing dependency / unusable keylog) — log and return instead.
OfflineEmitter = Callable[..., None]

# A post-collection attach hook receives the collector's LIVE flows and the
# conversion's writer state, runs after every emitter and before the final
# flush, and returns the ids of flows it fully absorbed (not written), or None.
OfflineAttach = Callable[[list, object], Optional[Set[str]]]

# A mid-stream span hook receives ``(state, bound_keys, proto_keylogs,
# present_entries, *, bus, result)`` once the mid-stream TLS stage bound at least
# one connection, and decodes the protocol directly from the recovered TLS
# plaintext in ``state.tls_spans``. It must guard its own decode (never raise).
OfflineMidstreamSpans = Callable[..., None]


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
        picker_group: Empty for a protocol listed on its own in the TUI keylog
            picker. Non-empty (e.g. ``"tls"``) means the protocol is NOT listed
            on its own but offered through the named picker entry instead (a
            Schannel sidecar supplied under ``tls`` is routed to ``schannel``).
        accepts_keylog: Optional predicate telling whether a keylog path supplied
            under the entry's *picker_group* belongs to this decryptor (e.g. the
            Schannel entry recognizes a ``.schannel.unpaired`` sidecar). Only
            consulted for grouped entries; ``None`` means "never routed here".
        decoder_family: Entries sharing a non-empty family run the SAME decoder
            (e.g. ``mtproto`` and ``telegram`` both run the Telegram decoder).
            The conversion runs a family once per capture (merging distinct
            keylogs) instead of once per entry. Empty means the entry is its
            own family (keyed by *protocol_name*). An emitter of a family that
            can receive several keylogs must accept an ``extra_keylogs`` kwarg.
        nests_in_tls: True for an independent decryptor whose protocol can ride
            INSIDE the decrypted TLS plaintext (RC4-in-TLS). Its flows and the
            TLS flows of the capture are held back until the post-collection
            nested attach, which may absorb a TLS flow it fully consumed.
        attach: Optional post-collection :data:`OfflineAttach` hook folding the
            protocol's accumulated metadata onto the LIVE flows before the final
            flush. Runs on every conversion, whether or not the protocol was
            selected (the hook itself is a no-op when its protocol recorded
            nothing); entries sharing a decoder family declare it on ONE member.
        attach_order: Sort key of *attach* among all entries' hooks (ties keep
            registration order).
        messaging: True for a messaging protocol whose counters the CLI/TUI
            summarize via ``messaging_buckets`` (MTProto, Telegram, Signal).
        resync_default: Default mid-stream resync search depth this decryptor
            supports (in its own unit), or ``None`` when it has no mid-stream
            recovery. The first non-``None`` value is the public default.
        resync_param: Name of the emitter keyword that receives the generic
            ``resync_search_depth`` (e.g. ``"obf_max_blocks"``), or ``None`` when
            the emitter takes no resync depth. The conversion forwards an explicit
            depth only under this name and only when the emitter declares it (or
            a ``**kwargs`` catch-all); an entry without it is never handed one.
        midstream_spans: Optional :data:`OfflineMidstreamSpans` hook decoding the
            protocol from TLS plaintext recovered by the mid-stream TLS stage
            (flows captured with no ClientHello). ``None`` for most entries.
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


def entry_family(entry: OfflineDecryptorEntry) -> str:
    """Decoder family of *entry* (its own protocol name if unset)."""
    return getattr(entry, "decoder_family", "") or entry.protocol_name


def attach_hooks(entries: List[OfflineDecryptorEntry]) -> List[OfflineAttach]:
    """Return the entries' attach hooks in run order.

    Sorted by ``attach_order`` (a stable sort, so ties keep *entries* order).
    """
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
    """Self-register a protocol package's entries, never raising.

    Imports ``<package>.offline_decryptor`` lazily and registers the entry built
    by each of its *builder_names*, in order. Any failure (a missing dependency,
    an import cycle) is logged at debug on *package*'s logger as *skip_message*
    and skips the rest. Re-registration of an identical entry is idempotent.
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
