"""Flow metadata stamping for :class:`FlowCollector`.

The host class owns the state; methods run under its lock unless noted.
Collector constants are read through ``_collector()`` at call time so patches take effect.
"""

import re
from typing import Optional

from .attribution import (
    CHROMIUM_FAMILY_KINDS,
    SOURCE_NATIVE_STACK,
    merge_attribution,
    module_basename,
    transport_attribution,
)
from .collector_state import _merge_session_meta, _Publication
from .collector_state import collector_module as _collector
from .layer_pipeline import MESSAGE_TRANSPORTS
from .models import Flow, FlowEventType


class FlowMetadataMixin:
    """Library, module path, transport attribution, capture target and handshake metadata stamped onto flows."""

    def on_library_detected(self, event) -> None:
        """EventBus subscriber for LibraryDetectedEvent.

        Records the library per protocol tag as a fallback for data events that do
        not name their module (``_stamp_detected_library`` prefers the event's own ``library``).
        """
        library = getattr(event, 'library', '') or ''
        publication = self._record_module_path(event)
        if library:
            protocol = getattr(event, 'protocol', 'tls') or 'tls'
            with self._lock:
                self._detected_libraries[protocol] = library
        self._publish(publication)

    def _record_module_path(self, event) -> '_Publication':
        """Remember the event's load path under its module basename and ``library`` name (case-insensitive),
        dropping the oldest past :data:`MAX_MODULE_PATHS`, then re-classify those modules' present flows
        (UPDATED events returned for :meth:`_publish`). Takes the lock."""
        path = str(getattr(event, 'path', '') or '')
        if not path:
            return _Publication([])
        names = (str(getattr(event, 'module', '') or '') or path,
                 str(getattr(event, 'library', '') or ''))
        keys = {self._module_key(name) for name in names} - {""}
        if not keys:
            return _Publication([])
        with self._lock:
            for key in keys:
                self._module_paths.pop(key, None)
                self._module_paths[key] = path
            while len(self._module_paths) > _collector().MAX_MODULE_PATHS:
                self._module_paths.popitem(last=False)
            pending: list = []
            self._reclassify_transports(keys, pending)
            return self._stage_publication(pending)

    @staticmethod
    def _module_key(module: str) -> str:
        """The ``_module_paths`` key of *module*: its lower-cased basename."""
        return module_basename(module).lower()

    def _module_path_for(self, library: str) -> str:
        """The recorded load path of *library*, else ``""``. Under lock."""
        return self._module_paths.get(self._module_key(library), '')

    def _reclassify_transports(self, modules: Optional[set], pending: list) -> None:
        """Re-classify present flows' ``attribution.transport`` with the current module paths and capture target.

        Limited to flows whose module key is in *modules* (all when ``None``). Only the
        transport is replaced; a ``native-stack`` claim's confidence is recomputed from
        the new kind. Queues one UPDATED per changed flow. Under lock.
        """
        for flow in self._flows.values():
            old = (flow.attribution or {}).get("transport")
            if not isinstance(old, dict):
                continue
            if modules is not None and self._module_key(old.get("module", "")) not in modules:
                continue
            layer = flow.layer(flow.transport)
            library = getattr(layer, 'library', '') if layer is not None else ''
            new = transport_attribution(library, self._module_path_for(library),
                                        self._process_name, self._package_name)
            if not new or new.get("kind") == old.get("kind"):
                continue
            attribution = dict(flow.attribution)
            attribution["transport"] = new
            self._note_transport(new)
            if attribution.get("source") == SOURCE_NATIVE_STACK and attribution.get("originator"):
                attribution["confidence"] = _collector().direct_attribution(
                    attribution["originator"], new.get("kind", ""))["confidence"]
            flow.attribution = attribution
            pending.append((FlowEventType.UPDATED, flow))

    def set_capture_target(self, target: str, process_name: Optional[str] = None) -> None:
        """Record the capture target and derive process/package names.

        ``process_name`` defaults to *target* and doubles as ``package_name`` only
        when it has Android-package shape. Already-stamped flows are re-classified.
        """
        target = target or ""
        name = process_name or target
        looks_like_package = self._looks_like_android_package(name)
        pending: list = []
        with self._lock:
            self._capture_target = target
            self._process_name = name
            self._package_name = name if looks_like_package else ""
            self._reclassify_transports(None, pending)
            publication = self._stage_publication(pending)
        self._publish(publication)

    # Dot-separated identifier segments starting with a letter ("com.example.app");
    # single-segment process names and IPv4 literals cannot match.
    _ANDROID_PACKAGE_RE = re.compile(
        r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$"
    )

    # Extensions a real package name never ends in.
    _NON_PACKAGE_EXTENSIONS = (
        ".so", ".exe", ".bin", ".apk", ".dll", ".dylib",
        ".jar", ".dex", ".out", ".elf",
    )

    @classmethod
    def _looks_like_android_package(cls, target: str) -> bool:
        """True only for Android package-id shapes (not a path, IP, PID or binary name)."""
        if not target or any(c.isspace() for c in target):
            return False
        if "/" in target or "\\" in target:  # paths like /proc/1/exe
            return False
        lowered = target.lower()
        if lowered.endswith(cls._NON_PACKAGE_EXTENSIONS):
            return False
        if not cls._ANDROID_PACKAGE_RE.match(target):
            return False
        return True

    @staticmethod
    def _apply_session_metadata(flow: Flow, meta: dict) -> bool:
        """Fill empty fields of the flow's transport layer (``quic`` or ``tls``) from cached session metadata; True if changed."""
        changed = False
        if getattr(flow, "transport", "tls") == "quic":
            layer = flow.quic
            qv = meta.get("quic_version", "")
            if qv and not layer.version:
                layer.version = qv
                changed = True
            if meta.get("sni") and not layer.sni:
                layer.sni = meta["sni"]
                changed = True
            if meta.get("alpn") and not layer.alpn:
                layer.alpn = meta["alpn"]
                changed = True
            if meta.get("cipher") and not layer.cipher:
                layer.cipher = meta["cipher"]
                changed = True
        else:
            layer = flow.tls
            if meta.get("version") and not layer.version:
                layer.version = meta["version"]
                changed = True
            if meta.get("sni") and not layer.sni:
                layer.sni = meta["sni"]
                changed = True
            if meta.get("alpn") and not layer.alpn:
                layer.alpn = meta["alpn"]
                changed = True
            if meta.get("cipher") and not layer.cipher:
                layer.cipher = meta["cipher"]
                changed = True
        if meta.get("client_random") and not layer.client_random:
            layer.client_random = meta["client_random"]
            changed = True
        return changed

    def _stamp_tls_metadata(self, event) -> None:
        """Stamp handshake metadata from a SessionEvent onto matching flows.

        Cached by ``connection_id`` so later flows are backfilled by :meth:`_stamp_metadata`.
        Only the offline pcap->tap producer emits it. Updated flows are notified after the lock.
        """
        conn_id = getattr(event, 'connection_id', '')
        if not conn_id:
            return

        meta = {
            "version": getattr(event, 'protocol_version', '') or '',
            "sni": getattr(event, 'server_name', '') or '',
            "alpn": getattr(event, 'alpn', '') or '',
            "cipher": (getattr(event, 'cipher', '')
                       or getattr(event, 'cipher_suite', '') or ''),
            "quic_version": getattr(event, 'quic_version', '') or '',
            "client_random": getattr(event, 'client_random', '') or '',
        }
        if not any(meta.values()):
            return

        pending = []
        with self._lock:
            conn_id = self._lifecycle_conn_id(event, conn_id)
            # Merge so a partial RESUMED event never blanks fields a prior STARTED set.
            _merge_session_meta(self._session_tls.setdefault(conn_id, {}), meta)

            # Index lookup, not a scan of every flow (O(streams x flows) offline).
            for flow in self._connection_flows(conn_id):
                if self._apply_session_metadata(flow, meta):
                    pending.append((FlowEventType.UPDATED, flow))
            publication = self._stage_publication(pending)

        self._publish(publication)

    # Transports whose layer carries a ``library`` field (TlsLayer/QuicLayer).
    _LIBRARY_TRANSPORTS = ("tls", "quic")

    def _stamp_detected_library(self, flow: Flow, event) -> None:
        """Stamp the producing library onto the flow's TLS/QUIC layer.

        Prefers the record's own ``library``, else the last one announced for the
        transport. Other transports are skipped: attribute access auto-creates the
        layer, which would make them match the "tls"/"quic" filter.
        """
        if flow.transport not in self._LIBRARY_TRANSPORTS:
            return
        library = (getattr(event, 'library', '') or ''
                   or self._detected_libraries.get(flow.transport, ''))
        if not library:
            return
        layer = getattr(flow, flow.transport)
        if not layer.library:
            layer.library = library

    def _stamp_transport_attribution(self, flow: Flow) -> None:
        """Stamp ``attribution.transport`` from the flow's TLS/QUIC library, its recorded load path and the target's names.

        No-op for other transports or a flow without a library. Does not create the layer. Under lock.
        """
        if flow.transport not in self._LIBRARY_TRANSPORTS:
            return
        layer = flow.layer(flow.transport)
        library = getattr(layer, 'library', '') if layer is not None else ''
        if not library:
            return
        transport = transport_attribution(
            library, self._module_path_for(library),
            self._process_name, self._package_name)
        if transport:
            self._note_transport(transport)
            flow.attribution = merge_attribution(flow.attribution, {"transport": transport})

    def _note_transport(self, transport: dict) -> None:
        if transport.get("kind") in CHROMIUM_FAMILY_KINDS:
            self._chromium_transport_seen = True

    def _stamp_metadata(self, flow: Flow, event) -> None:
        """Stamp cheaply-available metadata onto a freshly-created Flow. Under lock."""
        # Set first: it decides TlsLayer vs QuicLayer below.
        flow.transport = getattr(event, 'protocol', 'tls') or 'tls'
        self._stamp_detected_library(flow, event)
        self._stamp_transport_attribution(flow)
        self._stamp_client_random(flow, event)
        # Backfill handshake metadata cached before this flow existed.
        cached_meta = self._session_tls.get(flow.connection_id)
        if cached_meta:
            self._apply_session_metadata(flow, cached_meta)
        self._stamp_caller_attribution(flow)
        flow.process_name = self._process_name
        flow.package_name = self._package_name
        # Hook origin: prefer the first chunk's function, fall back to event.
        hook = ""
        if flow.chunks:
            hook = flow.chunks[0].function
        if not hook:
            hook = getattr(event, 'function', '') or ''
        flow.hook_function = hook
        (flow.local_addr, flow.local_port,
         flow.remote_addr, flow.remote_port) = self._local_remote_endpoints(flow, event)

    def _local_remote_endpoints(self, flow: Flow, event) -> tuple:
        """``(local_addr, local_port, remote_addr, remote_port)`` for *flow*.

        Message-transport flows keep the packet's real src/dst, so a received (read)
        packet travels remote -> local. Other flows are already local -> remote.
        """
        if flow.transport in MESSAGE_TRANSPORTS and self._event_direction(event) == "read":
            return (flow.dst_addr, flow.dst_port, flow.src_addr, flow.src_port)
        return (flow.src_addr, flow.src_port, flow.dst_addr, flow.dst_port)

    def _event_direction(self, event) -> str:
        """The event's direction, falling back to the hook-function heuristic."""
        return (getattr(event, 'direction', '')
                or self._get_direction(getattr(event, 'function', '') or ''))
