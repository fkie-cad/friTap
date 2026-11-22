#!/usr/bin/env python3

"""Reconstruct a friTap ``.tap`` from a tshark-decrypted capture.

A thin adapter over friTap's parsers: tshark recovers plaintext (TLS/TCP
payloads, ``quic.stream_data``) as ``-T ek`` rows, which become DatalogEvents fed
through :class:`~friTap.flow.collector.FlowCollector` and
:class:`~friTap.flow.tap_writer.TapWriter`. No protocol parsing is duplicated.
"""

from __future__ import annotations

import contextlib
import importlib
import inspect
import logging
import os
from dataclasses import dataclass, field
from typing import Callable, Iterator, Tuple

from friTap.events import DatalogEvent, EventBus, SessionEvent
from friTap.flow.collector import FlowCollector
from friTap.flow.layer_pipeline import MESSAGE_TRANSPORTS
from friTap.flow.layers import SshLayer
from friTap.flow.tap_writer import TapWriter

from .pipeline_api import (
    ConvertResult,
    StreamDirectionTracker,
    TlsSinglePass,
    WriterState,
    coerce_float,
    coerce_int,
    ek_as_list,
    ek_field,
    ek_first,
    extract_addrs,
    tls_packet_to_events,
    unique_keylog_paths,
)
from .plaintext_events import (  # noqa: F401 - _is_encrypted_record re-exported for tests
    _is_encrypted_record,
    _plaintext_packet_to_events,
)
from .quic_events import (  # noqa: F401 - private helpers re-exported for tests
    _align_payloads,
    _emit_quic_session_event,
    _fold_metadata_row,
    _quic_frame_layout,
    _quic_packet_to_events,
    _QuicCombinedSink,
)
from .quic_reassembly import (
    _QuicStreamReassembler,  # noqa: F401 - re-exported for tests
)
from .transport_layers import (
    _attach_transport_metadata_layers,
    _tls_riding_protocol_names,
)
from .tshark import (
    SshConnectionAccumulator,
    build_combined_command,
    build_plaintext_command,
    build_quic_detection_command,
    capture_has_dsb,
    extract_ssh_connections,
    find_tshark,
    has_plaintext_payload,
    is_ssh_row,
    stream_packets,
    tls_app_data_marker,
    tshark_version,
    warn_if_outdated,
)

logger = logging.getLogger(__name__)

# Aliases of friTap.offline.pipeline_api names used by this module and tests.
_StreamDirectionTracker = StreamDirectionTracker
_WriterState = WriterState
_field = ek_field
_as_list = ek_as_list
_first = ek_first
_coerce_int = coerce_int
_coerce_float = coerce_float
_extract_addrs = extract_addrs
_tls_packet_to_events = tls_packet_to_events


@contextlib.contextmanager
def _closing_packets(packets):
    """Yield *packets* and close it afterwards if it can be closed.

    Closing the ``stream_packets`` generator terminates and reaps tshark, so an
    early exit never leaves it running. Test fakes may return a plain list.
"""
    try:
        yield packets
    finally:
        close = getattr(packets, "close", None)
        if callable(close):
            close()


# Cleartext server ports anchoring flow direction for an already-plaintext capture (no handshake to infer it from); --tls-port / --quic-port values are added at the call site.
_PLAINTEXT_SERVER_PORTS = (80, 8080, 8000)


def messaging_buckets(result) -> Iterator[Tuple[str, dict]]:
    """Yield ``(prefix, counters)`` per messaging prefix in fixed order.

    *counters* is ``result.per_protocol[prefix]`` or ``{}``; any object with or without ``per_protocol`` works.
"""
    per_protocol = getattr(result, "per_protocol", None) or {}
    for prefix in MESSAGING_PREFIXES:
        yield prefix, per_protocol.get(prefix) or {}


def _detect_encrypted_quic_streams(
    tshark_bin: str,
    pcap_path: str,
    *,
    quic_ports: tuple[int, ...],
    extra_decode_as: tuple[str, ...],
    heuristic: bool,
) -> frozenset[str]:
    """``udp:<stream>`` keys of genuinely encrypted QUIC in a keyless capture.

    Header protection hides the first byte, so without keys real QUIC cannot be told
    from decrypted HTTP/3 by header fields. The key-free signal is a captured QUIC
    handshake (:func:`~friTap.offline.tshark.build_quic_detection_command`). The
    plaintext pass skips these streams. A detection failure returns an empty set.
"""
    cmd = build_quic_detection_command(
        pcap_path, quic_ports=quic_ports,
        extra_decode_as=extra_decode_as, heuristic=heuristic)
    cmd[0] = tshark_bin
    streams: set[str] = set()
    try:
        with _closing_packets(stream_packets(cmd)) as packets:
            for pkt in packets:
                layers = pkt.get("layers") or {}
                stream_id = _first(_field(layers, "udp.stream"))
                if stream_id is not None and str(stream_id) != "":
                    streams.add(f"udp:{stream_id}")
    except Exception:
        logger.debug("QUIC encrypted-stream detection failed; "
                     "treating capture as fully plaintext", exc_info=True)
        return frozenset()
    return frozenset(streams)


def _emit_plaintext_streams_singlepass(
    tshark_bin: str,
    pcap_path: str,
    *,
    extra_decode_as: tuple[str, ...],
    heuristic: bool,
    bus: EventBus,
    state: _WriterState,
    result: ConvertResult,
    tracker: _StreamDirectionTracker,
    encrypted_quic_streams: frozenset[str] = frozenset(),
    ssh_accumulator: SshConnectionAccumulator | None = None,
) -> None:
    """Export raw transport payload via ONE ``-T ek`` pass and emit events.

    The keyless counterpart of :func:`_run_keyed_combined_pass`. Encrypted streams
    are skipped (:func:`_plaintext_packet_to_events`) and counted on *result* for the
    ``--keylog`` hint. With *ssh_accumulator* the pass also folds SSH metadata rows.
"""
    include_ssh = ssh_accumulator is not None
    cmd = build_plaintext_command(
        pcap_path, extra_decode_as=extra_decode_as, heuristic=heuristic,
        include_ssh=include_ssh)
    cmd[0] = tshark_bin  # replace the literal "tshark" with the resolved path

    encrypted_streams: set[str] = set()
    with _closing_packets(stream_packets(cmd)) as packets:
        for pkt in packets:
            if include_ssh:
                layers = pkt.get("layers") or {}
                if is_ssh_row(layers):
                    _fold_metadata_row(ssh_accumulator, layers, "SSH")
                if not has_plaintext_payload(layers):
                    continue
            try:
                events = _plaintext_packet_to_events(
                    pkt, tracker, encrypted_streams, encrypted_quic_streams)
            except Exception:
                result.dropped_packet_count += 1
                logger.debug("Skipping unparseable plaintext packet", exc_info=True)
                continue
            if not events:
                continue

            state.ensure_open()
            for ev in events:
                result.decrypted_packet_count += 1
                bus.emit(ev)

    # Only cleartext packets reach the tracker, so its stream_count is the distinct-cleartext count; encrypted streams are tallied separately.
    result.stream_count += tracker.stream_count
    result.encrypted_streams_skipped += len(encrypted_streams)


class NoDecryptionKeysError(ValueError):
    """Raised when a capture cannot be decrypted: no keylog and no embedded DSB."""


def _require_decryptable(pcap_path: str, keylog_path: str | None) -> None:
    """Fail loud when *pcap_path* has no path to decryption.

    Without keys tshark silently emits no plaintext, giving an empty ``.tap`` that
    looks like success. Needs an explicit keylog or a pcapng with a Decryption Secrets Block.
"""
    has_keylog = bool(keylog_path) and os.path.isfile(keylog_path)
    if has_keylog or capture_has_dsb(pcap_path):
        return
    if keylog_path:
        detail = f"keylog file not found: {keylog_path}"
    else:
        detail = "no --keylog given and the capture has no embedded DSB"
    raise NoDecryptionKeysError(
        f"Cannot decrypt {pcap_path}: {detail}. "
        "Pass --keylog <SSLKEYLOGFILE>, or use a pcapng with an embedded "
        "Decryption Secrets Block (DSB)."
    )


def _emit_ssh_connections(
    tshark_bin: str,
    pcap_path: str,
    *,
    heuristic: bool,
    collector: FlowCollector,
    state: _WriterState,
) -> None:
    """Add a metadata-only synthetic flow per SSH connection in *pcap*.

    SSH banners and KEXINIT are plaintext. Purely additive: extraction failures are logged and swallowed.
"""
    try:
        connections = extract_ssh_connections(
            tshark_bin, pcap_path, heuristic=heuristic)
    except Exception:
        logger.warning("SSH metadata extraction failed; continuing without "
                       "SSH flows", exc_info=True)
        return
    _add_ssh_synthetic_flows(connections, collector, state)


def _add_ssh_synthetic_flows(connections: list[dict], collector: FlowCollector,
                             state: _WriterState) -> None:
    """Add one metadata-only synthetic flow (an :class:`SshLayer`) per SSH connection."""
    for conn in connections:
        layer = SshLayer(
            client_version=conn.get("client_version", ""),
            server_version=conn.get("server_version", ""),
            kex=conn.get("kex", ""),
            cipher=conn.get("cipher", ""),
            mac=conn.get("mac", ""),
        )
        collector.add_synthetic_flow(
            src_addr=conn.get("src_addr", ""),
            src_port=conn.get("src_port", 0),
            dst_addr=conn.get("dst_addr", ""),
            dst_port=conn.get("dst_port", 0),
            layer=layer,
            detected_protocol="SSH",
            transport="tcp",
            protocol="ssh",
        )
        state.ensure_open()


# convert_pcap_to_tap iterates the registry so plugin protocols join automatically. In-tree decryptors self-register via _discover_offline_decryptor_extensions in sorted name order: mtproto, telegram, rc4, schannel, signal.

def _discover_offline_decryptor_extensions() -> None:
    """Import in-tree offline-decryptor subpackages so they self-register.

    Mirrors ``friTap.protocols.registry._discover_protocol_extensions``: imports every
    non-underscore subpackage; those with the discovery marker register their entry,
    others (``net``, ``tls``) import harmlessly. Idempotent; a broken subpackage is
    logged at debug and skipped.
"""
    import pkgutil

    try:
        from friTap import offline as _offline_pkg
    except Exception:  # pragma: no cover - the package we live in must import
        return
    for info in pkgutil.iter_modules(_offline_pkg.__path__):
        if not info.ispkg or info.name.startswith("_"):
            continue
        try:
            importlib.import_module(f"{_offline_pkg.__name__}.{info.name}")
        except Exception as exc:  # a broken/optional subpackage must not break core
            logger.debug("skipping offline-decryptor subpackage %r: %s", info.name, exc)


# mtproto sorts first, so its entries stay ahead of the TLS-riding / nested decryptors. Tests call the alias.
_register_builtin_offline_decryptors = _discover_offline_decryptor_extensions


_register_builtin_offline_decryptors()


# Messaging protocols friTap decrypts itself, in registration order; counters live in ``ConvertResult.per_protocol``. The flat ``mtproto_*`` names are read-only properties over it (``result_schema.V1_FLAT_COUNTERS``, frozen v1 JSON).
from friTap.offline.registry import attach_hooks as _attach_hooks  # noqa: E402
from friTap.offline.registry import (  # noqa: E402
    default_resync_search_depth as _default_resync_search_depth,
)
from friTap.offline.registry import entry_family as _entry_family  # noqa: E402
from friTap.offline.registry import (  # noqa: E402
    get_offline_decryptor_registry as _get_offline_decryptor_registry,
)
from friTap.offline.registry import (  # noqa: E402
    messaging_protocol_names as _messaging_protocol_names,
)

MESSAGING_PREFIXES = _messaging_protocol_names(_get_offline_decryptor_registry().list())

# MTProto's default resync depth (display only); ``resync_search_depth`` defaults to ``None`` so each decryptor applies its own.
DEFAULT_RESYNC_SEARCH_DEPTH = _default_resync_search_depth(
    _get_offline_decryptor_registry().list())


def _tls_nested_protocol_names() -> set:
    """Names of registered decryptors with ``nests_in_tls`` (today ``{"rc4"}``)."""
    return {
        e.protocol_name
        for e in _get_offline_decryptor_registry().list()
        if e.nests_in_tls
    }


def _post_attach_transports() -> frozenset:
    """Transports whose flows get metadata folded on AFTER collection.

    TLS-riding, TLS-nesting and message transports; the writer defers them on
    "completed" until the ``_attach_*`` passes ran.
"""
    return frozenset(_tls_riding_protocol_names() | _tls_nested_protocol_names()
                     | MESSAGE_TRANSPORTS)


def _tls_holdback_transports(present_entries) -> frozenset:
    """``{"tls"}`` while a TLS-nesting decryptor runs, else empty.

    Its TLS flows are written only after the nested attach, which may absorb them.
"""
    if any(getattr(e, "nests_in_tls", False) for e in present_entries):
        return frozenset({"tls"})
    return frozenset()


def _run_registered_attaches(collector, state) -> set:
    """Run every entry's post-collection attach hook in order; returns the union of absorbed flow ids.

    Hooks get the LIVE flows and run whether or not their protocol was selected
    (a no-op without their own state).
"""
    absorbed: set = set()
    for hook in _attach_hooks(_get_offline_decryptor_registry().list()):
        absorbed |= hook(collector.live_flows(), state) or set()
    return absorbed


def _run_midstream_tls_stage(
    pcap_path: str,
    sidecar_path: str | None,
    *,
    bus: EventBus,
    state: _WriterState,
    result: ConvertResult,
    tls_ports: tuple[int, ...],
) -> set:
    """Bind mid-stream TLS secret bundles and emit their plaintext; returns bound keys.

    No-op (empty set) without a sidecar or when it is absent (warned) or empty.
    Seeded with the capture's first-packet time so events order after the
    handshake-anchored flows. Never aborts the conversion.
"""
    if not sidecar_path:
        return set()
    if not os.path.isfile(sidecar_path):
        logger.warning("TLS mid-stream secret-bundle sidecar %s not found; "
                       "skipping mid-stream TLS decryption", sidecar_path)
        return set()
    try:
        from friTap.offline.tls_midstream.pipeline import run_midstream_tls_stage

        server_ports = tls_ports or (443,)
        return run_midstream_tls_stage(
            pcap_path, sidecar_path,
            bus=bus, state=state, result=result,
            base_ts=_first_packet_time(pcap_path),
            server_ports=tuple(server_ports),
        )
    except Exception:  # noqa: BLE001 - the mid-stream stage is additive
        logger.warning("Mid-stream TLS stage failed; continuing without it",
                       exc_info=True)
        return set()


def _possible_raw_tcp_consumers(midstream_sidecar: str | None,
                                independent_plan: list) -> int:
    """Upper bound on raw-TCP reassemblies one conversion may run.

    Over-counting only keeps the shared parse cached, so no per-protocol knowledge is needed.
"""
    midstream = 1 if midstream_sidecar and os.path.isfile(midstream_sidecar) else 0
    return midstream + len(independent_plan)


def _bridge_bound_midstream_spans(
    state: _WriterState,
    bound_keys: set,
    proto_keylogs: dict,
    present_entries: list,
    *,
    bus: EventBus,
    result: ConvertResult,
) -> None:
    """Hand mid-stream-recovered TLS plaintext to every entry's ``midstream_spans`` hook.

    Only an import failure of the hook's lazy component is guarded: an absent
    component (filtered build) is a silent no-op, other import errors are surfaced
    without aborting. Decode failures propagate. No-op when nothing bound.
"""
    if not bound_keys:
        return
    for entry in _get_offline_decryptor_registry().list():
        hook = entry.midstream_spans
        if hook is None:
            continue
        try:
            hook(state, bound_keys, proto_keylogs, present_entries,
                 bus=bus, result=result)
        except ImportError as exc:  # the bridge is additive; never break convert
            if not _is_absent_hook_component(exc, hook):
                logger.warning("Mid-stream span bridge unavailable; continuing without it",
                               exc_info=True)


def _is_absent_hook_component(exc: ImportError, hook) -> bool:
    """True when *exc* is a missing module of *hook*'s own package (filtered build)."""
    package = getattr(hook, "__module__", "").rpartition(".")[0]
    return bool(package) and isinstance(exc, ModuleNotFoundError) and (
        exc.name or "").startswith(package)


def _relabel_midstream_flows(flows, bound_keys: set) -> None:
    """Stamp ``TLS(midstream)`` on flows bound only via a mid-stream secret.

    Flows already carrying a ``detected_protocol`` keep it (a richer inner decoder wins). Mutates live flows.
"""
    if not bound_keys:
        return
    from friTap.connection_index import canonical_4tuple
    from friTap.offline.tls_midstream.pipeline import MIDSTREAM_PROTOCOL_LABEL

    for flow in flows:
        key = canonical_4tuple(
            flow.src_addr, flow.src_port, flow.dst_addr, flow.dst_port)
        if key in bound_keys and not getattr(flow, "detected_protocol", ""):
            flow.detected_protocol = MIDSTREAM_PROTOCOL_LABEL


def _family_representative(members: list, family: str):
    """Pick the entry that runs a family: the one named after it, else the first."""
    for entry in members:
        if entry.protocol_name == family:
            return entry
    return members[0]


def _dedupe_independent_entries(entries, proto_keylogs: dict) -> list:
    """Collapse entries that would run the same decoder twice.

    Grouped by :func:`_entry_family`; each family runs ONCE via the entry named after
    it. Returns ``(entry, keylogs)`` with the family's distinct keylog paths (by real
    path); several paths mean the pass must load their union. Order follows first appearance.
"""
    families: dict = {}
    for entry in entries:
        families.setdefault(_entry_family(entry), []).append(entry)
    plan = []
    for family, members in families.items():
        chosen = _family_representative(members, family)
        paths = unique_keylog_paths(
            proto_keylogs[chosen.protocol_name],
            [proto_keylogs[m.protocol_name] for m in members],
        )
        for dropped in (m for m in members if m is not chosen):
            logger.debug(
                "offline decryptor %r shares decoder family %r with %r; "
                "running it once", dropped.protocol_name, family,
                chosen.protocol_name,
            )
        plan.append((chosen, paths))
    return plan


def _emitter_accepts(emitter, name: str) -> bool:
    """True if *emitter* declares keyword *name* or ``**kwargs``; fails open on introspection errors.

    Keeps a plugin emitter with a fixed signature from receiving an argument it cannot take.
"""
    try:
        params = inspect.signature(emitter).parameters.values()
    except (TypeError, ValueError):
        return True
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params):
        return True
    return any(p.name == name for p in params)


def _resync_kwargs(entry, depth: int | None) -> dict:
    """Map the generic resync *depth* onto *entry*'s emitter keyword.

    ``{}`` when *depth* is ``None``, the entry has no ``resync_param``, or its emitter
    does not accept it. An explicit ``0`` is forwarded.
"""
    param = getattr(entry, "resync_param", None)
    if depth is None or not param or not _emitter_accepts(entry.emitter, param):
        return {}
    return {param: depth}


def _run_independent_entry(entry, keylogs: list, **emitter_kwargs) -> None:
    """Run one self-contained offline entry; ``extra_keylogs`` is passed only when a family brought several files."""
    if len(keylogs) > 1:
        emitter_kwargs["extra_keylogs"] = tuple(keylogs[1:])
    entry.emitter(proto_keylog=keylogs[0], **emitter_kwargs)


def _emit_progress(progress: "Callable[[str], None] | None", message: str) -> None:
    """Report a coarse milestone to *progress*; a raising or missing callback never breaks the conversion."""
    if progress is None:
        return
    try:
        progress(message)
    except Exception:  # noqa: BLE001 - progress reporting is best-effort
        logger.debug("progress callback raised", exc_info=True)


@dataclass
class _ConversionContext:
    """Everything one :func:`convert_pcap_to_tap` run threads through its stages.

    Filled in three steps: inputs, the plan (:func:`_prepare_conversion`), then the
    pipeline (:func:`_wire_pipeline`); cross-stage fields carry results between stages.
"""

    # Inputs (the caller's arguments).
    pcap_path: str
    keylog_path: str | None
    tap_path: str
    tls_ports: tuple[int, ...]
    quic_ports: tuple[int, ...]
    extra_decode_as: tuple[str, ...]
    heuristic: bool
    capture_target: str
    resync_search_depth: int | None
    tls_midstream_secrets: str | None
    progress: "Callable[[str], None] | None"
    request_contexts: str | None = None
    # Derived plan.
    has_keys: bool = False
    proto_keylogs: dict = field(default_factory=dict)
    present_entries: list = field(default_factory=list)
    tls_strip_entries: list = field(default_factory=list)
    independent_entries: list = field(default_factory=list)
    independent_plan: list = field(default_factory=list)
    tshark_bin: str = ""
    tshark_release: tuple = ()
    target: str = ""
    # Event pipeline.
    bus: EventBus | None = None
    collector: FlowCollector | None = None
    writer: TapWriter | None = None
    post_attach_transports: frozenset = frozenset()
    tracker: StreamDirectionTracker | None = None
    tls_tracker: StreamDirectionTracker | None = None
    result: ConvertResult | None = None
    state: WriterState | None = None
    # Cross-stage results.
    midstream_bound_keys: set = field(default_factory=set)
    absorbed_flow_ids: set = field(default_factory=set)


def _fold_protocol_keylogs(protocol_keylogs: dict | None,
                           legacy_protocol_keylogs: dict) -> dict:
    """Merge ``<protocol>_keylog`` kwargs into the generic keylog map; returns a new dict.

    The protocol is the token before ``_keylog``. Existing *protocol_keylogs* entries win; empty values are ignored.
"""
    proto_keylogs: dict[str, str] = dict(protocol_keylogs or {})
    for kwarg_name, kwarg_value in legacy_protocol_keylogs.items():
        if kwarg_value and kwarg_name.endswith("_keylog"):
            proto_keylogs.setdefault(kwarg_name[: -len("_keylog")], kwarg_value)
    return proto_keylogs


def _present_offline_entries(proto_keylogs: dict) -> list:
    """Registered offline entries whose keylog was supplied and exists (a missing one is logged and skipped)."""
    present = []
    for entry in _get_offline_decryptor_registry().list():
        keylog = proto_keylogs.get(entry.protocol_name)
        if not keylog:
            continue
        if not os.path.isfile(keylog):
            logger.warning(
                "%s keylog %s not found; skipping %s decryption",
                entry.protocol_name, keylog, entry.protocol_name,
            )
            continue
        present.append(entry)
    return present


def _prepare_conversion(ctx: _ConversionContext, protocol_keylogs: dict | None,
                        legacy_protocol_keylogs: dict, tshark_path: str | None) -> None:
    """Fill *ctx*'s derived plan: keys, offline entries, tshark binary, target.

    Decryption needs an explicit keylog or a pcapng DSB; with neither the capture is
    ingested as plaintext, but a given-and-missing ``--keylog`` fails loud
    (:class:`NoDecryptionKeysError`). Entries split into TLS-riding (run only with
    keys) and independent ones (raw TCP), the latter one pass per decoder family.
"""
    keylog_path = ctx.keylog_path
    keylog_present = bool(keylog_path) and os.path.isfile(keylog_path)
    ctx.has_keys = keylog_present or capture_has_dsb(ctx.pcap_path)
    if keylog_path and not ctx.has_keys:
        _require_decryptable(ctx.pcap_path, keylog_path)  # raises NoDecryptionKeysError

    ctx.proto_keylogs = _fold_protocol_keylogs(protocol_keylogs, legacy_protocol_keylogs)
    ctx.present_entries = _present_offline_entries(ctx.proto_keylogs)
    ctx.tls_strip_entries = [e for e in ctx.present_entries if e.requires_tls_strip]
    ctx.independent_entries = [e for e in ctx.present_entries if not e.requires_tls_strip]
    ctx.independent_plan = _dedupe_independent_entries(
        ctx.independent_entries, ctx.proto_keylogs)

    ctx.tshark_bin = find_tshark(tshark_path)
    ctx.tshark_release = tshark_version(ctx.tshark_bin) or ()
    warn_if_outdated(ctx.tshark_release)
    ctx.target = ctx.capture_target or os.path.basename(ctx.pcap_path)


def _wire_pipeline(ctx: _ConversionContext) -> None:
    """Build the bus -> collector -> writer pipeline and direction trackers.

    Offline events carry capture times, so idle time is measured by them. Post-attach
    transports are written once after the attach. Trackers are seeded with their
    protocol's server ports (TLS on ``tcp.stream``, QUIC on ``udp.stream``). The
    ``.tap`` opens lazily on the first event.
"""
    ctx.bus = EventBus()
    ctx.collector = FlowCollector(event_bus=ctx.bus)
    ctx.collector.use_event_clock(True)
    post_attach = (_post_attach_transports()
                   | _tls_holdback_transports(ctx.present_entries))
    ctx.post_attach_transports = post_attach
    ctx.writer = TapWriter(
        defer_flow=lambda flow: getattr(flow, "transport", "") in post_attach,
    )
    ctx.collector.set_capture_target(ctx.target)
    ctx.bus.subscribe(DatalogEvent, ctx.collector.on_data)
    ctx.bus.subscribe(SessionEvent, ctx.collector.on_session_event)
    ctx.collector.subscribe(ctx.writer.on_flow_event)

    ctx.tracker = _StreamDirectionTracker(server_ports=ctx.quic_ports)
    ctx.tls_tracker = _StreamDirectionTracker(server_ports=ctx.tls_ports)
    ctx.result = ConvertResult(tap_path=ctx.tap_path)
    ctx.state = _WriterState(ctx.writer, ctx.tap_path, ctx.target, ctx.keylog_path)


def _run_request_context_stage(ctx: _ConversionContext) -> None:
    """Replay the ``--attribute-sdk`` request-context sidecar into the collector before any traffic.

    The ``.tap`` opens first because the writer drops request-context records while closed.
"""
    from .request_contexts import load_request_contexts, replay_request_contexts

    events = load_request_contexts(ctx.request_contexts)
    if not events:
        return
    ctx.state.ensure_open()
    ctx.collector.set_request_context_sink(ctx.writer.write_request_context)
    # The sidecar read is size-capped, so holding every context is bounded.
    ctx.collector.reserve_request_contexts(len({event.req_id for event in events}))
    delivered = replay_request_contexts(events, ctx.collector.on_request_context)
    logger.info("Replayed %d request context event(s) from %s",
                delivered, ctx.request_contexts)
    evicted = ctx.collector.evicted_request_contexts
    if evicted:
        logger.warning("%d replayed request context(s) were evicted before "
                       "their flows; their flows stay unattributed", evicted)


def _run_midstream_stage(ctx: _ConversionContext) -> None:
    """Bind mid-stream TLS secret bundles, then bridge their plaintext.

    Flows captured without a ClientHello never surface in the tshark passes, so
    their plaintext is recovered first for span-consuming decoders. Runs regardless
    of ``has_keys``; both steps are no-ops without bindings.
"""
    ctx.midstream_bound_keys = _run_midstream_tls_stage(
        ctx.pcap_path, ctx.tls_midstream_secrets,
        bus=ctx.bus, state=ctx.state, result=ctx.result, tls_ports=ctx.tls_ports,
    )
    _bridge_bound_midstream_spans(
        ctx.state, ctx.midstream_bound_keys, ctx.proto_keylogs, ctx.present_entries,
        bus=ctx.bus, result=ctx.result,
    )


def _run_tshark_stage(ctx: _ConversionContext) -> None:
    """Run the tshark passes over the capture.

    With keys: ONE combined ``-T ek`` pass (:func:`_run_keyed_combined_pass`). Without
    keys and without an independent decryptor (its obfuscated bytes are not
    plaintext), the capture is ingested as plaintext (:func:`_run_keyless_passes`).
    Otherwise only the SSH metadata pass runs. SSH adds synthetic flows last and
    never aborts the conversion.
"""
    if ctx.has_keys:
        _emit_progress(ctx.progress, "Decrypting TLS/QUIC streams…")
        ssh_connections = _run_keyed_combined_pass(ctx)
    elif not ctx.independent_entries:
        ssh_connections = _run_keyless_passes(ctx)
    else:
        _emit_ssh_connections(ctx.tshark_bin, ctx.pcap_path, heuristic=ctx.heuristic,
                              collector=ctx.collector, state=ctx.state)
        return
    _add_ssh_synthetic_flows(ssh_connections, ctx.collector, ctx.state)


def _run_keyed_combined_pass(ctx: _ConversionContext) -> list[dict]:
    """Decrypt TLS and QUIC and read every metadata with ONE tshark run.

    Rows go to their consumers via the :mod:`friTap.offline.tshark` predicates: TLS
    rows to :class:`TlsSinglePass`, QUIC to :class:`_QuicCombinedSink`, SSH to the
    accumulator. Event order matches the former separate passes (see
    ``tests/fixtures/combined_pass/``): TLS events stream live, then QUIC
    SessionEvents, QUIC data and reassembly leftovers (buffered). Metadata failures
    are non-fatal. Returns the SSH connections.
"""
    marker = tls_app_data_marker(ctx.tshark_release)
    cmd = build_combined_command(
        ctx.pcap_path, ctx.keylog_path,
        tls_ports=ctx.tls_ports, quic_ports=ctx.quic_ports,
        extra_decode_as=ctx.extra_decode_as, heuristic=ctx.heuristic,
        app_data_marker=marker)
    cmd[0] = ctx.tshark_bin  # replace the literal "tshark" with the resolved path

    tls = TlsSinglePass(bus=ctx.bus, state=ctx.state, result=ctx.result,
                        tracker=ctx.tls_tracker, app_data_marker=marker,
                        packet_to_events=_tls_packet_to_events)
    quic = _QuicCombinedSink(ctx.bus, ctx.state, ctx.result, ctx.tracker)
    ssh = SshConnectionAccumulator()
    with _closing_packets(stream_packets(cmd)) as packets:
        for pkt in packets:
            tls.feed(pkt)
            layers = pkt.get("layers") or {}
            quic.feed(pkt, layers)
            if is_ssh_row(layers):
                _fold_metadata_row(ssh, layers, "SSH")
    tls.finish()
    quic.flush()
    return ssh.result()


def _capture_may_carry_udp(pcap_path: str) -> bool:
    """Conservatively tell whether *pcap_path* may hold UDP (lazy import: pulls in scapy's pcap reader)."""
    from friTap.offline.net.pcap_fast import capture_may_carry_udp

    return capture_may_carry_udp(pcap_path)


def _run_keyless_passes(ctx: _ConversionContext) -> list[dict]:
    """Ingest an already-plaintext capture; returns its SSH connections.

    QUIC handshake detection stays its own pass because the plaintext pass must not
    get the ``udp.port==443,quic`` Decode-As (it would skip friTap's decrypted
    HTTP/3); it is skipped when the capture has no UDP.
"""
    common = dict(extra_decode_as=ctx.extra_decode_as, heuristic=ctx.heuristic)
    encrypted_quic_streams: frozenset[str] = frozenset()
    if _capture_may_carry_udp(ctx.pcap_path):
        encrypted_quic_streams = _detect_encrypted_quic_streams(
            ctx.tshark_bin, ctx.pcap_path, quic_ports=ctx.quic_ports, **common)
    plaintext_tracker = _StreamDirectionTracker(
        server_ports=(*_PLAINTEXT_SERVER_PORTS, *ctx.tls_ports, *ctx.quic_ports))
    ssh = SshConnectionAccumulator()
    _emit_plaintext_streams_singlepass(
        ctx.tshark_bin, ctx.pcap_path, **common,
        bus=ctx.bus, state=ctx.state, result=ctx.result, tracker=plaintext_tracker,
        encrypted_quic_streams=encrypted_quic_streams, ssh_accumulator=ssh,
    )
    return ssh.result()


def _run_tls_riding_decryptors(ctx: _ConversionContext) -> None:
    """Run each present TLS-riding entry (e.g. Signal) over tshark's plaintext (keys only)."""
    if not ctx.has_keys:
        return
    for entry in ctx.tls_strip_entries:
        entry.emitter(
            pcap_path=ctx.pcap_path,
            proto_keylog=ctx.proto_keylogs[entry.protocol_name],
            tls_keylog_path=ctx.keylog_path,
            tshark_bin=ctx.tshark_bin,
            tls_ports=ctx.tls_ports,
            bus=ctx.bus, state=ctx.state, result=ctx.result,
            **_resync_kwargs(entry, ctx.resync_search_depth),
        )


def _entry_display_name(entry) -> str:
    """The protocol name an offline-decryptor *entry* is shown under in progress text."""
    return getattr(entry, "protocol_name", "") or "protocol"


def _run_independent_decryptors(ctx: _ConversionContext) -> None:
    """Run each self-contained decoder family (e.g. MTProto, RC4) over raw TCP, with or without keys."""
    for entry, entry_keylogs in ctx.independent_plan:
        _emit_progress(
            ctx.progress,
            f"Decrypting {_entry_display_name(entry)}…",
        )
        _run_independent_entry(
            entry, entry_keylogs,
            pcap_path=ctx.pcap_path,
            tls_keylog_path=ctx.keylog_path,
            tshark_bin=ctx.tshark_bin,
            tls_ports=ctx.tls_ports,
            bus=ctx.bus, state=ctx.state, result=ctx.result,
            **_resync_kwargs(entry, ctx.resync_search_depth),
        )


def _finalize_conversion(ctx: _ConversionContext) -> None:
    """Fold post-collection metadata onto the live flows, then write every flow.

    The ``.tap`` header starts at the capture's FIRST packet. Everything here
    mutates LIVE flows and so runs before ``flush()``: transport metadata layers,
    the ``TLS(midstream)`` relabel and the attach hooks, whose fully absorbed TLS
    flows are not written.
"""
    ctx.state.ensure_open()
    ctx.state.note_capture_time(_first_packet_time(ctx.pcap_path))
    _attach_transport_metadata_layers(ctx.collector.live_flows(), ctx.state.inner_meta)
    _relabel_midstream_flows(ctx.collector.live_flows(), ctx.midstream_bound_keys)
    ctx.absorbed_flow_ids = _run_registered_attaches(ctx.collector, ctx.state)
    _write_remaining_flows(ctx)
    _emit_progress(ctx.progress, "Writing .tap…")


def _write_remaining_flows(ctx: _ConversionContext) -> None:
    """Flush the collector and write every flow the writer has not persisted.

    ``TapWriter.on_flow_event`` writes only on "completed", so ``flush()`` completes
    the active flows first. Deferred post-attach flows are written here once; a
    rewrite of an early-written flow wins (the index keeps the LAST record per flow_id).
"""
    ctx.collector.flush(end_at_last_activity=True)
    flows = [f for f in ctx.collector.get_flows()
             if f.flow_id not in ctx.absorbed_flow_ids]
    for flow in flows:
        transport = getattr(flow, "transport", "")
        if (not ctx.writer.has_written(flow.flow_id)
                or transport in ctx.post_attach_transports):
            ctx.writer.write_flow(flow)
    ctx.result.flow_count = len(flows)


def _report_conversion(result: ConvertResult) -> None:
    """Log the one-line conversion summary."""
    logger.info(
        "Offline conversion: %d flows, %d decrypted packets, %d streams, "
        "%d dropped TLS stream(s), %d dropped QUIC packet(s)",
        result.flow_count, result.decrypted_packet_count,
        result.stream_count, result.dropped_stream_count,
        result.dropped_packet_count,
    )


def convert_pcap_to_tap(
    pcap_path: str,
    keylog_path: str | None = None,
    tap_path: str | None = None,
    *,
    tls_ports: tuple[int, ...] = (),
    quic_ports: tuple[int, ...] = (),
    extra_decode_as: tuple[str, ...] = (),
    heuristic: bool = False,
    run_scan: bool = False,
    capture_target: str = "",
    tshark_path: str | None = None,
    protocol_keylogs: dict[str, str] | None = None,
    resync_search_depth: int | None = None,
    tls_midstream_secrets: str | None = None,
    progress: "Callable[[str], None] | None" = None,
    request_contexts: str | None = None,
    **legacy_protocol_keylogs: str | None,
) -> ConvertResult:
    """Decrypt *pcap_path* with tshark and reconstruct a friTap ``.tap`` file.

    Args:
        pcap_path: Encrypted capture (pcap/pcapng).
        keylog_path: NSS SSLKEYLOGFILE, or None for a DSB-embedded pcapng.
        tap_path: Output path; defaults to ``<pcap stem>.tap``.
        tls_ports / quic_ports: Custom server ports to Decode-As TLS / QUIC.
        extra_decode_as: Raw tshark ``-d`` rules passed through.
        heuristic: Enable tshark TLS-over-TCP heuristic dissection.
        run_scan: Run the analysis registry over the produced .tap afterward.
        capture_target: Target label stored in the .tap (defaults to basename).
        tshark_path: Explicit tshark binary path/command (else auto-discovered).
        protocol_keylogs: ``{protocol_name: keylog_path}`` for registered offline
            decryptors (including plugins); wins over *legacy_protocol_keylogs*.
        resync_search_depth: Search depth when re-aligning a mid-stream flow to a
            recovered key, forwarded only to emitters naming a ``resync_param``.
            ``None`` forwards nothing (each emitter keeps its default); an explicit
            value, including ``0`` (no lag search), is always forwarded.
        tls_midstream_secrets: JSONL sidecar of TLS 1.3 secret bundles for flows
            without a ClientHello; the mid-stream stage trial-binds each bundle to
            the raw TLS streams and relabels bound flows ``TLS(midstream)``.
        request_contexts: ``--attribute-sdk`` JSONL sidecar of Java request
            contexts, joined onto the flows and written as request-context records.
        legacy_protocol_keylogs: ``<protocol>_keylog`` kwargs (``mtproto_keylog=``),
            folded into ``protocol_keylogs``; explicit entries win.

    Returns:
        A :class:`ConvertResult` summarizing the conversion.
"""
    if tap_path is None:
        tap_path = os.path.splitext(pcap_path)[0] + ".tap"
    ctx = _ConversionContext(
        pcap_path=pcap_path, keylog_path=keylog_path, tap_path=tap_path,
        tls_ports=tls_ports, quic_ports=quic_ports, extra_decode_as=extra_decode_as,
        heuristic=heuristic, capture_target=capture_target,
        resync_search_depth=resync_search_depth,
        tls_midstream_secrets=tls_midstream_secrets, progress=progress,
        request_contexts=request_contexts,
    )
    _prepare_conversion(ctx, protocol_keylogs, legacy_protocol_keylogs, tshark_path)
    _wire_pipeline(ctx)
    _run_request_context_stage(ctx)

    from friTap.offline.net.capture_cache import capture_cache_scope

    # Every raw-TCP reassembly below shares ONE parse of the capture; with fewer than two possible consumers nothing is cached.
    raw_tcp_consumers = _possible_raw_tcp_consumers(
        ctx.tls_midstream_secrets, ctx.independent_plan)
    try:
        with capture_cache_scope(ctx.pcap_path, expected_consumers=raw_tcp_consumers):
            _run_midstream_stage(ctx)
            _run_tshark_stage(ctx)
            _run_tls_riding_decryptors(ctx)
            _run_independent_decryptors(ctx)
        _finalize_conversion(ctx)
    finally:
        if ctx.state.opened:
            ctx.writer.close()

    if run_scan:
        _emit_progress(progress, "Running analysis…")
        ctx.result.findings_count = _run_scan(tap_path)
    _report_conversion(ctx.result)
    return ctx.result


def _first_packet_time(pcap_path: str) -> float:
    """Capture time (epoch seconds) of the first packet, read via :func:`friTap.offline.net.pcap_fast.first_packet_time`.

    ``0.0`` ("unknown") for an empty or unreadable capture.
"""
    # scapy warns about an embedded DSB it cannot use; irrelevant here.
    scapy_log = logging.getLogger("scapy.runtime")
    previous_level = scapy_log.level
    scapy_log.setLevel(logging.ERROR)
    try:
        from friTap.offline.net.pcap_fast import first_packet_time

        return float(first_packet_time(pcap_path))
    except Exception:
        logger.debug("Could not read first packet time of %s", pcap_path,
                     exc_info=True)
    finally:
        scapy_log.setLevel(previous_level)
    return 0.0


def _run_scan(tap_path: str) -> int:
    """Run all registered analyzers over *tap_path*; return the finding count."""
    from friTap.analysis import analyze_tap_multi
    from friTap.analysis.registry import resolve_analyzers

    findings = analyze_tap_multi(resolve_analyzers("all"), tap_path)
    return len(findings)


def _merge_memory_scan_sidecars_into(
    ms_map: dict,
    pcap_path: str,
    keylog: str | None,
    protocol_keylogs: dict[str, str],
    legacy_keylogs: dict[str, str | None],
) -> str | None:
    """Union memory-scan sidecars into the effective keylog of each protocol.

    The effective keylog is what convert_pcap_to_tap will use: a ``protocol_keylogs``
    entry, then the ``<proto>_keylog`` kwarg. Merged paths are written back into BOTH
    maps in place; TLS stays on the base ``keylog_path``. Returns the updated base *keylog*.
"""
    def _current(proto: str) -> str | None:
        if proto == "tls":
            return keylog
        return protocol_keylogs.get(proto) or legacy_keylogs.get(f"{proto}_keylog")

    from .keylog_picker import merge_memory_scan_sidecars

    merged_sidecars = merge_memory_scan_sidecars(
        ms_map, _current,
        out_dir=os.path.dirname(os.path.abspath(pcap_path)) or None)
    keylog = merged_sidecars.pop("tls", keylog)
    for proto, merged_path in merged_sidecars.items():
        protocol_keylogs[proto] = merged_path
        legacy_keylogs[f"{proto}_keylog"] = merged_path
    return keylog


def _with_manifest_protocol_keylogs(
    protocol_keylogs: dict[str, str] | None,
    explicit_legacy_keylogs: dict[str, str | None],
    manifest: dict,
) -> dict[str, str] | None:
    """*protocol_keylogs* plus the manifest's keylog for every protocol not given.

    Given means passed in *protocol_keylogs* or as a ``<protocol>_keylog`` kwarg
    (*explicit_legacy_keylogs*). Returns a new dict only if the manifest adds anything.
"""
    from .cli import manifest_protocol_keylogs

    merged = dict(protocol_keylogs or {})
    for proto, path in manifest_protocol_keylogs(manifest).items():
        if not merged.get(proto) and not explicit_legacy_keylogs.get(f"{proto}_keylog"):
            merged[proto] = path
    return merged if merged != (protocol_keylogs or {}) else protocol_keylogs


def pcap_to_tap(
    pcap_path: str,
    *,
    keylog_path: str | None = None,
    tap_path: str | None = None,
    tls_ports: tuple[int, ...] = (),
    quic_ports: tuple[int, ...] = (),
    extra_decode_as: tuple[str, ...] = (),
    heuristic: bool = False,
    run_scan: bool = False,
    capture_target: str = "",
    tshark_path: str | None = None,
    protocol_keylogs: dict[str, str] | None = None,
    resync_search_depth: int | None = None,
    tls_midstream_secrets: str | None = None,
    use_manifest: bool = True,
    progress: "Callable[[str], None] | None" = None,
    request_contexts: str | None = None,
    **legacy_protocol_keylogs: str | None,
) -> ConvertResult:
    """Convert a captured pcap/pcapng to a friTap ``.tap``, manifest-aware.

    Presentation-agnostic wrapper of :func:`convert_pcap_to_tap` for external tools.
    With *use_manifest* and a ``<pcap>.fritap.json`` sidecar, values the caller did
    not pass (``keylog_path``/``tls_ports``/``quic_ports``) are filled from it, as in
    ``fritap --from-pcap``; explicit arguments win. Exposed as
    :func:`friTap.pcap_to_tap`; it lives here so it does not shadow the
    ``friTap.offline.pcap_to_tap`` module attribute.

    Raises :class:`NoDecryptionKeysError` when the capture is encrypted and no keys
    are available; other tshark/IO failures propagate.
"""
    keylog = keylog_path
    tls = tuple(tls_ports)
    quic = tuple(quic_ports)
    midstream_secrets = tls_midstream_secrets
    contexts_sidecar = request_contexts
    # ``<protocol>_keylog`` kwargs are carried generically: matching manifest keys fill any not passed.
    legacy_keylogs: dict[str, str | None] = dict(legacy_protocol_keylogs)
    if use_manifest:
        # Lazy import avoids a cli <-> pcap_to_tap cycle.
        from .cli import (
            load_manifest,
            manifest_ports,
            resolve_manifest_keylog_paths,
            resolve_manifest_path,
        )

        # Manifest keylog paths resolve against the manifest's directory then the CWD, as in the CLI; unsafe targets are dropped (cli.resolve_manifest_path).
        manifest = resolve_manifest_keylog_paths(pcap_path, load_manifest(pcap_path))
        if manifest:
            keylog = keylog or manifest.get("keylog") or None
            tls = tls or tuple(manifest_ports(manifest, "tls_ports"))
            quic = quic or tuple(manifest_ports(manifest, "quic_ports"))
            # Mid-stream TLS 1.3 secret-bundle sidecar, resolved like the CLI.
            midstream_secrets = midstream_secrets or resolve_manifest_path(
                pcap_path, manifest.get("tls_midstream_secrets") or None)
            # Already resolved above (one of the CLI's _MANIFEST_SIDECAR_KEYS).
            contexts_sidecar = contexts_sidecar or manifest.get("request_contexts") or None
            # Pull any ``<protocol>_keylog`` manifest keys the caller did not pass.
            for man_key, man_value in manifest.items():
                if (
                    man_key.endswith("_keylog")
                    and man_value
                    and not legacy_keylogs.get(man_key)
                ):
                    legacy_keylogs[man_key] = man_value
            # The per-protocol ``keylogs`` map fills every protocol not passed, as in the CLI's merge_manifest.
            protocol_keylogs = _with_manifest_protocol_keylogs(
                protocol_keylogs, legacy_protocol_keylogs, manifest)
            # Memory-scan sidecars carry keys the hook keylog lacks (e.g. MTProto OBF + auth keys). Merge them into the protocol_keylogs map (its entries win over ``<proto>_keylog``; mirrors cli.merge_manifest).
            ms_map = manifest.get("memory_scan_keylogs") or {}
            if ms_map:
                protocol_keylogs = dict(protocol_keylogs or {})
                keylog = _merge_memory_scan_sidecars_into(
                    ms_map, pcap_path, keylog, protocol_keylogs, legacy_keylogs)

    return convert_pcap_to_tap(
        pcap_path,
        keylog_path=keylog,
        tap_path=tap_path,
        tls_ports=tls,
        quic_ports=quic,
        extra_decode_as=tuple(extra_decode_as),
        heuristic=heuristic,
        run_scan=run_scan,
        capture_target=capture_target,
        tshark_path=tshark_path,
        protocol_keylogs=protocol_keylogs,
        resync_search_depth=resync_search_depth,
        tls_midstream_secrets=midstream_secrets,
        progress=progress,
        request_contexts=contexts_sidecar,
        **{k: v for k, v in legacy_keylogs.items() if v},
    )
