"""Bind mid-stream TLS 1.3 secret bundles to a pcap's raw TLS streams and emit
the recovered plaintext into the offline conversion pipeline.

Phase 2.3 (binding) + the emit side of 2.4 (classification): the BoringSSL
memscan engine writes a leak-safe JSONL sidecar of TLS 1.3 secret bundles for
flows whose ClientHello was never captured (see
:meth:`friTap.memory_scanning.engine.MemoryScanEngine.tls_midstream_manifest_entry`).
This module loads that sidecar, enumerates the pcap's raw TLS streams
(:func:`~friTap.offline.tls_midstream.transport.midstream_tls_streams`), and
trial-binds each bundle against each stream using the AEAD tag as a
zero-false-accept oracle (:func:`~friTap.offline.tls.stream.pick_binding`):
``CLIENT_TRAFFIC_SECRET_0`` on the client->server (``"write"``) direction,
``SERVER_TRAFFIC_SECRET_0`` on the server->client (``"read"``) direction. A
bundle that decrypts a direction binds to the stream AND fixes that direction's
cipher suite and starting record sequence number in one step.

Each bound direction's application_data is decrypted
(:func:`~friTap.offline.tls.stream.decrypt_stream_from`), turned into a
:class:`~friTap.events.DatalogEvent` identical in shape to the tshark single-pass
path (:func:`friTap.offline.pcap_to_tap._tls_packet_to_events`), and emitted
through the same ``EventBus`` while its plaintext is recorded as a
:class:`~friTap.offline.tls_spans.TlsPlaintextSpan`
(:func:`~friTap.offline.tls_spans.record_tls_span`). Every downstream consumer
(the collector, the ``.tap`` writer, a TLS-riding decoder) therefore sees it
exactly as if tshark had decrypted a handshake-anchored flow. Ahead of a bound
stream's DatalogEvents, one SessionEvent
(:func:`~friTap.offline.pipeline_api.emit_tls_session_event`) records the facts
the binding proves -- TLS 1.3 and the bound cipher suite; SNI/ALPN stay empty.

All cryptographic / transport primitives are IMPORTED READ-ONLY; this module
only wires them into the offline conversion.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from friTap.connection_index import canonical_4tuple
from friTap.events import DatalogEvent
from friTap.offline.pipeline_api import emit_tls_session_event
from friTap.offline.tls.stream import (
    DEFAULT_BIND_RECORDS,
    DEFAULT_MAX_SEQ,
    app_data_records,
    decrypt_stream_from,
    pick_binding,
    seq_windows,
)
from friTap.offline.tls.tls13 import VERSION_LABEL, inner_app_content
from friTap.offline.tls_spans import record_tls_span

from .transport import READ, WRITE, MidstreamTlsStream, midstream_tls_streams

logger = logging.getLogger(__name__)

# The display protocol stamped onto a flow that bound only via a mid-stream
# secret (no captured handshake). Surfaces through Flow.display_protocol when no
# richer inner protocol (e.g. Signal) was parsed on top of the plaintext.
MIDSTREAM_PROTOCOL_LABEL = "TLS(midstream)"

# TLS 1.3 handshake outer content-type. A reassembled stream that BEGINS with a
# handshake record carries its own ClientHello/ServerHello, so tshark can follow
# and decrypt it from the NSS keylog — it is not a mid-stream flow and we leave
# it to the normal single-pass path (avoids a duplicate flow).
_HANDSHAKE_CONTENT_TYPE = 0x16

# ``ConvertResult.per_protocol`` prefix for this stage's honest-diagnostics
# counters (recorded only when something was skipped or a stream was partial).
STATS_PREFIX = "tls_midstream"

# Binding passes, by how many leading application_data records each may try. The
# cheap first-record pass places every bundle whose session starts cleanly; only
# bundles still unplaced pay for the deeper retry (each extra record is another
# full seq sweep per wrong stream).
_BIND_PASSES = (1, DEFAULT_BIND_RECORDS)

# The bundle secret tried on each direction, in binding order (write, then read).
_DIRECTION_SECRETS = ((WRITE, "client_traffic_secret_0"),
                      (READ, "server_traffic_secret_0"))


def _bind_windows():
    """Yield ``(first_record, max_records)`` per pass in :data:`_BIND_PASSES`.

    A pass only reaches bundle/stream pairs whose earlier passes failed on BOTH
    directions, so it starts after the records those passes already tried.
    """
    first_record = 0
    for max_records in _BIND_PASSES:
        yield first_record, max_records
        first_record = max_records


@dataclass(frozen=True)
class _DirectionBinding:
    """One direction's recovered decryption parameters.

    ``start_seq`` is the seq of the application_data record at ``record_index``
    (the binding point); earlier app-data records were not decryptable.
    """

    secret_hex: str
    suite: str
    start_seq: int
    record_index: int = 0


@dataclass
class _StageStats:
    """Per-run diagnostics: decrypted / undecryptable records, partial streams."""

    messages: int = 0
    undecryptable: int = 0
    partial: int = 0

    def report(self, result) -> None:
        """Record the counters on *result* when anything was lost or partial."""
        if not (self.undecryptable or self.partial):
            return
        result.record_protocol(
            STATS_PREFIX,
            messages=self.messages,
            undecryptable=self.undecryptable,
            partial=self.partial,
        )


@dataclass(frozen=True)
class StreamBinding:
    """A secret bundle bound to a mid-stream TLS stream (one or both directions)."""

    stream: MidstreamTlsStream
    write: Optional[_DirectionBinding] = None
    read: Optional[_DirectionBinding] = None


def _valid_bundle(obj) -> bool:
    """True when *obj* is a secret bundle carrying at least one traffic secret."""
    return isinstance(obj, dict) and bool(
        obj.get("client_traffic_secret_0") or obj.get("server_traffic_secret_0")
    )


def load_secret_bundles(path: str) -> List[dict]:
    """Load the JSONL secret-bundle sidecar at *path* (``[]`` on any error).

    Each non-empty line is one bundle object (see the engine sidecar schema).
    Malformed lines and bundles missing both traffic secrets are skipped; a bad
    or absent file yields an empty list so the stage is simply a no-op.
    """
    bundles: List[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if _valid_bundle(obj):
                    bundles.append(obj)
    except OSError:
        return []
    return bundles


def _has_leading_handshake(records: List[Tuple[int, bytes, bytes]]) -> bool:
    """True when the stream's first record is a TLS handshake (captured ClientHello)."""
    return bool(records) and records[0][0] == _HANDSHAKE_CONTENT_TYPE


def _starts_with_handshake(stream: MidstreamTlsStream) -> bool:
    """True when either direction of *stream* begins with a captured handshake."""
    return any(_has_leading_handshake(stream.records.get(direction) or [])
               for direction in (WRITE, READ))


def _directions(bundle: dict, stream: MidstreamTlsStream) -> list:
    """``[(secret_hex, records)]`` for the write, then the read direction."""
    return [(bundle.get(key, ""), stream.records.get(direction) or [])
            for direction, key in _DIRECTION_SECRETS]


def _direction_binding(binding: StreamBinding,
                       index: int) -> Optional[_DirectionBinding]:
    """The write (``index`` 0) or read (``index`` 1) binding of *binding*."""
    return binding.write if index == 0 else binding.read


def _bind_direction(
    secret_hex: str,
    records: List[Tuple[int, bytes, bytes]],
    max_seq: int = DEFAULT_MAX_SEQ,
    max_records: int = DEFAULT_BIND_RECORDS,
    first_record: int = 0,
    suites: Optional[List[str]] = None,
    min_seq: int = 0,
) -> Optional[_DirectionBinding]:
    """Trial-bind *secret_hex* to one direction's *records*, or ``None``.

    The AEAD tag is a zero-false-accept oracle: a wrong secret never recovers a
    suite/seq, so a returned binding is a genuine match. ``min_seq..max_seq``
    bounds the starting-sequence search for a mid-stream (no-handshake) capture;
    the application_data records from ``first_record`` up to ``max_records`` are
    tried, with *suites* (default: every suite matching the secret's length).
    """
    if not secret_hex or not records:
        return None
    picked = pick_binding(secret_hex, records, suites=suites, max_seq=max_seq,
                          max_records=max_records, first_record=first_record,
                          min_seq=min_seq)
    if picked is None:
        return None
    return _DirectionBinding(secret_hex, picked.suite, picked.seq, picked.record_index)


def _bind_bundle_to_stream(
    bundle: dict, stream: MidstreamTlsStream,
    max_seq: int = DEFAULT_MAX_SEQ,
    max_records: int = 1,
    first_record: int = 0,
) -> Optional[StreamBinding]:
    """Try to bind one secret *bundle* to one *stream* (both directions), or ``None``.

    ``client_traffic_secret_0`` is tried on the ``"write"`` (client->server)
    direction and ``server_traffic_secret_0`` on the ``"read"`` (server->client)
    direction. A stream that begins with a captured handshake is skipped (the
    normal tshark single pass already decrypts it). The AEAD tag is a
    zero-false-accept oracle, so a returned binding is a genuine match.

    Each direction is tried on its first ``max_records`` application_data
    records. Once one direction binds, the stream is known to be the bundle's
    session, so the other direction always gets the full
    :data:`DEFAULT_BIND_RECORDS` retry (its first record may simply have failed).

    ``first_record`` > 0 means the caller already tried the earlier records of
    both directions and they failed, so they are skipped. The deep retry skips
    every record already tried and uses only the bound direction's suite (both
    TLS 1.3 directions share the negotiated suite), so it yields exactly what a
    full retry would.
    """
    if _starts_with_handshake(stream):
        return None
    directions = _directions(bundle, stream)
    binds = [_bind_direction(secret, records, max_seq, max_records, first_record)
             for secret, records in directions]
    return _finish(stream, directions, binds, max_seq, max_records)


def _finish(stream: MidstreamTlsStream, directions: list, binds: Sequence,
            max_seq: int, max_records: int,
            retry_from: int = 0) -> Optional[StreamBinding]:
    """Turn a stream's first-stage direction *binds* into a StreamBinding, or ``None``.

    ``None`` when no direction bound. Otherwise the stream is known to be the
    bundle's session, so each unbound direction gets the partner deep retry: the
    records after the first ``max_records`` up to :data:`DEFAULT_BIND_RECORDS`,
    with the bound direction's suite, at seqs ``retry_from..max_seq``
    (``retry_from`` > 0 only when the lower seqs were already retried).
    """
    bound = next((bind for bind in binds if bind), None)
    if bound is None:
        return None
    deep = max(max_records, DEFAULT_BIND_RECORDS)
    binds = [bind or _bind_direction(secret, records, max_seq, deep, max_records,
                                     suites=[bound.suite], min_seq=retry_from)
             for bind, (secret, records) in zip(binds, directions)]
    return StreamBinding(stream, binds[0], binds[1])


def _open_directions(bundle: dict, stream: MidstreamTlsStream,
                     binding: Optional[StreamBinding] = None) -> list:
    """``[(index, secret_hex, records)]`` of the directions still worth searching.

    A direction qualifies when *bundle* carries its secret and *binding* (when
    given) has not bound it; *stream* supplies the records.
    """
    open_dirs = []
    for index, (direction, key) in enumerate(_DIRECTION_SECRETS):
        secret = bundle.get(key)
        if secret and (binding is None or _direction_binding(binding, index) is None):
            open_dirs.append((index, secret, stream.records.get(direction) or []))
    return open_dirs


def _ciphertexts(stream: MidstreamTlsStream) -> Set[bytes]:
    """Every application_data fragment carried by *stream*, both directions."""
    return {frag for records in stream.records.values()
            for _ctype, _hdr, frag in app_data_records(records)}


def _shares_ciphertext(first: MidstreamTlsStream, second: MidstreamTlsStream) -> bool:
    """True when two streams carry an identical ciphertext record (a copy stream)."""
    return not _ciphertexts(first).isdisjoint(_ciphertexts(second))


def _any_shared_ciphertext(streams: Iterable[MidstreamTlsStream]) -> bool:
    """True when any two of *streams* carry an identical ciphertext record."""
    owner: dict = {}
    for index, stream in enumerate(streams):
        for frag in _ciphertexts(stream):
            if owner.setdefault(frag, index) != index:
                return True
    return False


class _BundleSearch:
    """Place one secret bundle by an exact iterative-deepening seq search.

    The original search (:func:`_bind_bundle_to_stream` with the full
    ``max_seq``, applied to the unclaimed streams in order, first binding stream
    wins) sweeps ``0..max_seq`` for every wrong stream. This search visits the
    seq windows of :func:`~friTap.offline.tls.stream.seq_windows` in increasing
    order instead, every candidate stream per window, and returns the SAME
    stream and the SAME :class:`StreamBinding` under the one-stream assumption
    below. Why it is exact:

    * The AEAD tag never false-accepts, so a record authenticates at most at one
      ``(suite, seq)``, and only the session's suite authenticates at all: the
      suite loop order cannot change a direction's result.
    * Within one direction, the records under one secret consume consecutive
      sequence numbers, so their seq never decreases with the record index. The
      lowest binding record (what the original returns) therefore binds at the
      lowest seq, i.e. in the earliest window holding any binding seq, where the
      in-order record loop meets it first. Searching each direction window by
      window yields the original direction result.
    * ASSUMPTION (one stream per session): a secret belongs to exactly one
      session, and that session is carried by one stream or by copies of it
      that share at least one identical ciphertext record (a copy stream,
      :func:`_shares_ciphertext`). So a stream can only bind through a secret
      that bound another stream when the two share a ciphertext record.

    So when the first hit is stream ``p`` in window ``L``: every stream after
    ``p`` is irrelevant (the original stops at the first binding stream), and
    the streams before ``p`` failed windows ``0..L`` in both directions. Their
    only way to bind is in a later window, through a secret the winner did not
    bind (a mis-paired bundle), or through any secret when they share
    ciphertext with the winner. :meth:`settle` finishes the winner over the
    later windows, re-checks the earlier streams in order with exactly those
    directions, and lets the first earlier hit win (completed in full).

    The first window runs through :func:`_bind_bundle_to_stream` with ``max_seq``
    clipped to that window, so its partner deep retry already covered the
    window's seqs; a later finish only retries the seqs above it.

    Where the assumption fails: ONE session seen under two 4-tuples whose
    records do not overlap (e.g. a NAT'd connection captured on both sides at
    different times and merged into one pcap). An earlier stream holding the
    other part of the winner's session at a later window is not re-checked
    through the winner's secrets, so the later-ordered stream wins where the
    full-range search would pick the earlier one. There is no cheap exact test
    for this: telling such a stream apart costs the full-range AEAD sweep the
    ladder exists to avoid. Both streams are still the bundle's session, and
    the AEAD oracle still never binds a wrong stream.
    """

    def __init__(self, bundle: dict, max_seq: int, max_records: int,
                 first_record: int):
        self.bundle = bundle
        self.max_seq = max_seq
        self.max_records = max_records
        self.first_record = first_record
        self.windows = list(seq_windows(max_seq))

    def find(self, unclaimed: list) -> Optional[Tuple[int, StreamBinding]]:
        """``(index into unclaimed, binding)`` for the stream the bundle binds."""
        for level, window in enumerate(self.windows):
            for position, stream in enumerate(unclaimed):
                partial = self.probe(stream, window)
                if partial is not None:
                    return self.settle(unclaimed, position, partial, level)
        return None

    def probe(self, stream: MidstreamTlsStream,
              window: Tuple[int, int]) -> Optional[StreamBinding]:
        """Bind *stream* within one seq *window*; ``None`` when nothing binds."""
        low, high = window
        if low == 0:
            return _bind_bundle_to_stream(self.bundle, stream, max_seq=high,
                                          max_records=self.max_records,
                                          first_record=self.first_record)
        open_dirs = _open_directions(self.bundle, stream)
        if not open_dirs or _starts_with_handshake(stream):
            return None
        return self.partial(stream, self.sweep(open_dirs, (None, None), [window]))

    def settle(self, unclaimed: list, position: int, partial: StreamBinding,
               level: int) -> Tuple[int, StreamBinding]:
        """Finish the first hit, then let an earlier stream that binds win."""
        later = self.windows[level + 1:]
        retry_from = self.windows[0][1] + 1 if level == 0 else 0
        winner = self.complete(unclaimed[position], partial, later, retry_from)
        for index, stream in enumerate(unclaimed[:position]):
            binding = self.recheck(stream, winner, later)
            if binding is not None:
                return index, binding
        return position, winner

    def recheck(self, stream: MidstreamTlsStream, winner: StreamBinding,
                windows: list) -> Optional[StreamBinding]:
        """Bind an earlier *stream* in *windows* the way the original search could."""
        open_dirs = _open_directions(self.bundle, stream)
        if not open_dirs or _starts_with_handshake(stream):
            return None
        if not _shares_ciphertext(stream, winner.stream):
            open_dirs = _open_directions(self.bundle, stream, winner)
        partial = self.partial(stream, self.sweep(open_dirs, (None, None), windows))
        return partial and self.complete(stream, partial, windows)

    def complete(self, stream: MidstreamTlsStream, partial: StreamBinding,
                 windows: list, retry_from: int = 0) -> StreamBinding:
        """Search *partial*'s unbound directions over *windows*, then finish it."""
        open_dirs = _open_directions(self.bundle, stream, partial)
        if not open_dirs:
            return partial
        binds = self.sweep(open_dirs, (partial.write, partial.read), windows)
        return _finish(stream, _directions(self.bundle, stream), binds,
                       self.max_seq, self.max_records, retry_from)

    def sweep(self, open_dirs: list, binds: Sequence, windows: list) -> list:
        """Fill each unbound direction's first-stage binding, window by window."""
        binds = list(binds)
        for low, high in windows:
            for index, secret, records in open_dirs:
                if binds[index] is None:
                    binds[index] = _bind_direction(
                        secret, records, high, self.max_records,
                        self.first_record, min_seq=low)
        return binds

    @staticmethod
    def partial(stream: MidstreamTlsStream, binds: list) -> Optional[StreamBinding]:
        """A first-stage StreamBinding of *binds*, or ``None`` when none bound."""
        return StreamBinding(stream, binds[0], binds[1]) if any(binds) else None


def _find_binding(bundle: dict, unclaimed: list, max_records: int,
                  first_record: int = 0,
                  max_seq: int = DEFAULT_MAX_SEQ) -> Optional[Tuple[int, StreamBinding]]:
    """``(index, binding)`` of the first unclaimed stream *bundle* binds, or ``None``.

    Exactly what walking *unclaimed* in order with :func:`_bind_bundle_to_stream`
    returns, found by the iterative-deepening seq search of :class:`_BundleSearch`.
    """
    return _BundleSearch(bundle, max_seq, max_records, first_record).find(unclaimed)


@dataclass
class _Placements:
    """Secrets proven by earlier placements, to skip duplicate bundles.

    A secret that bound a claimed stream belongs to that stream's session, so,
    under the one-stream-per-session assumption of :class:`_BundleSearch`, it
    cannot bind an unclaimed stream unless two streams carry identical
    ciphertext. A bundle whose every secret is proven (a duplicate of a fully
    bound bundle) therefore binds nothing; it is skipped without a single AEAD
    trial unless the capture holds copy streams.

    Only a placement that bound BOTH directions proves its secrets: a stream
    with one direction bound may hold just part of its session (a one-sided
    bundle, or a session whose other part sits under another 4-tuple), so a
    duplicate of it is still searched like any other bundle.
    """

    streams: list
    proven: Set[str] = field(default_factory=set)
    copies: Optional[bool] = None

    def record(self, bundle: dict, binding: StreamBinding) -> None:
        """Remember the secrets of *bundle* when *binding* bound both directions."""
        secrets = [bundle.get(key) for _direction, key in _DIRECTION_SECRETS]
        if all(secrets) and binding.write is not None and binding.read is not None:
            self.proven.update(secrets)

    def is_duplicate(self, bundle: dict) -> bool:
        """True when every secret of *bundle* is proven and no copy streams exist."""
        secrets = {bundle.get(key) for _direction, key in _DIRECTION_SECRETS}
        secrets.discard(None)
        secrets.discard("")
        if not secrets or not secrets <= self.proven:
            return False
        if self.copies is None:
            self.copies = _any_shared_ciphertext(self.streams)
        return not self.copies


def bind_stream(
    stream: MidstreamTlsStream, bundles: List[dict],
    max_seq: int = DEFAULT_MAX_SEQ,
) -> Optional[StreamBinding]:
    """Bind the first *bundle* that decrypts a direction of *stream*, or ``None``.

    Thin wrapper over :func:`_bind_bundle_to_stream` preserving the stream-centric
    API (first matching bundle wins). ``run_midstream_tls_stage`` itself drives a
    key-centric loop for efficiency; this remains for direct/stream-at-a-time use.
    Like the stage, a first-record pass over every bundle runs before the
    deeper :data:`DEFAULT_BIND_RECORDS` retry.
    """
    for first_record, max_records in _bind_windows():
        for bundle in bundles:
            binding = _bind_bundle_to_stream(bundle, stream, max_seq, max_records,
                                             first_record)
            if binding is not None:
                return binding
    return None


def _decrypt_direction(
    binding: _DirectionBinding, records: List[Tuple[int, bytes, bytes]]
) -> Tuple[bytes, int, int]:
    """Decrypt one direction: ``(joined app content, decrypted, undecryptable)``.

    ``undecryptable`` counts every application_data record that yielded no
    plaintext, including those skipped before the binding point.
    """
    app_records = app_data_records(records)
    plaintexts = decrypt_stream_from(
        binding.secret_hex, binding.suite, app_records, binding.start_seq,
        start_index=binding.record_index,
    )
    parts = [content for content in map(inner_app_content, plaintexts) if content]
    return b"".join(parts), len(plaintexts), len(app_records) - len(plaintexts)


def _direction_plaintext(
    binding: _DirectionBinding, records: List[Tuple[int, bytes, bytes]]
) -> bytes:
    """Decrypt one direction and join its application_data content in order."""
    return _decrypt_direction(binding, records)[0]


def _make_event(
    stream: MidstreamTlsStream, direction: str, data: bytes, base_ts: float
) -> DatalogEvent:
    """Build a DatalogEvent shaped exactly like the tshark single-pass TLS path."""
    if direction == WRITE:
        (src_addr, src_port), (dst_addr, dst_port) = (
            stream.client_addr,
            stream.server_addr,
        )
    else:
        (src_addr, src_port), (dst_addr, dst_port) = (
            stream.server_addr,
            stream.client_addr,
        )
    return DatalogEvent(
        timestamp=base_ts,
        data=data,
        function="tls_midstream",
        direction=direction,
        src_addr=src_addr,
        src_port=src_port,
        dst_addr=dst_addr,
        dst_port=dst_port,
        ss_family=stream.ss_family,
        ssl_session_id="",
        transport="tcp",
        stream_id=None,
        protocol="tls",
    )


def _note_stream_quality(stream: MidstreamTlsStream, direction: str) -> bool:
    """Log a bound direction's start gap / resync; True when it has a later gap."""
    start_gap = stream.start_gap.get(direction, False)
    if start_gap or stream.resynced.get(direction, False):
        logger.info(
            "Mid-stream TLS %s<->%s %s: %s; decrypting from the first record "
            "boundary found.", stream.client_addr, stream.server_addr, direction,
            "a start gap swallowed the opening bytes" if start_gap
            else "the capture started inside a record",
        )
    return stream.degraded.get(direction, False) and not start_gap


def _decrypt_binding(binding: StreamBinding,
                     stats: _StageStats) -> List[Tuple[str, bytes]]:
    """Decrypt each bound direction: ``[(direction, plaintext)]``, non-empty only.

    Decrypted / undecryptable records, partial (later-gap) streams and resyncs
    are tallied in *stats* whether or not any plaintext came out.
    """
    plaintexts: List[Tuple[str, bytes]] = []
    partial = False
    for direction, dbind in ((WRITE, binding.write), (READ, binding.read)):
        if dbind is None:
            continue
        records = binding.stream.records.get(direction) or []
        data, decrypted, undecryptable = _decrypt_direction(dbind, records)
        stats.messages += decrypted
        stats.undecryptable += undecryptable
        partial |= _note_stream_quality(binding.stream, direction)
        if data:
            plaintexts.append((direction, data))
    stats.partial += int(partial)
    return plaintexts


def _bound_suite(binding: StreamBinding) -> str:
    """The cipher suite the AEAD binding proved (both TLS 1.3 directions share it)."""
    dbind = binding.write or binding.read
    return dbind.suite if dbind is not None else ""


def _emit_session_metadata(binding: StreamBinding, bus) -> None:
    """Emit the TLS session metadata the AEAD binding proves for *binding*.

    Only the protocol version and the bound cipher suite are known; SNI and
    ALPN live in the uncaptured handshake, so they stay empty. Must precede the
    stream's DatalogEvents so the collector backfills the TLS layer as the
    flow's outermost layer (``[tls, http2]``, not ``[http2, tls]``).
    """
    stream = binding.stream
    endpoints = (stream.client_addr[0], stream.client_addr[1],
                 stream.server_addr[0], stream.server_addr[1])
    emit_tls_session_event(
        bus, endpoints, {"version": VERSION_LABEL, "cipher": _bound_suite(binding)})


def _emit_binding(binding: StreamBinding, *, bus, state, result, base_ts: float,
                  stats: Optional[_StageStats] = None) -> bool:
    """Emit a bound stream: one session event, then a span + DatalogEvent per direction.

    Both directions are decrypted first; when any plaintext came out, the TLS
    session metadata is emitted once, before the data. Returns True when at
    least one non-empty direction was emitted.
    """
    stats = stats if stats is not None else _StageStats()
    plaintexts = _decrypt_binding(binding, stats)
    if not plaintexts:
        return False
    _emit_session_metadata(binding, bus)
    for direction, data in plaintexts:
        event = _make_event(binding.stream, direction, data, base_ts)
        record_tls_span(state.tls_spans, {}, event)
        bus.emit(event)
        result.decrypted_packet_count += 1
    return True


def run_midstream_tls_stage(
    pcap_path: str,
    sidecar_path: str,
    *,
    bus,
    state,
    result,
    base_ts: float = 0.0,
    server_ports: Tuple[int, ...] = (443,),
    max_seq: int = DEFAULT_MAX_SEQ,
) -> Set[str]:
    """Bind the sidecar's secret bundles to *pcap_path*'s mid-stream TLS streams.

    Loads the secret bundles, enumerates the raw TLS streams, and for each stream
    that a bundle binds, emits the recovered plaintext through *bus* (recording a
    span in ``state.tls_spans``). Returns the set of :func:`canonical_4tuple`
    keys of the bound flows so the caller can relabel them ``TLS(midstream)``.
    A missing/empty sidecar (or an enumeration failure) is a no-op returning an
    empty set — the stage never aborts the surrounding conversion. ``max_seq``
    bounds the starting-sequence search (see :data:`DEFAULT_MAX_SEQ`).
    """
    bundles = load_secret_bundles(sidecar_path)
    if not bundles:
        return set()
    try:
        streams = list(midstream_tls_streams(pcap_path, server_ports=server_ports))
    except Exception:  # noqa: BLE001 - a reassembly failure must not break convert
        logger.debug(
            "mid-stream TLS enumeration failed for %r", pcap_path, exc_info=True
        )
        return set()

    # Key-centric binding: each secret bundle maps to exactly ONE TLS session, so
    # we place each bundle in turn -- scanning the not-yet-claimed streams until it
    # binds, then claiming that stream and moving on to the next bundle. A matched
    # bundle is never retried, a claimed stream is never re-tested, and the loop
    # ends as soon as the last bundle is placed, so unrelated no-handshake streams
    # are never trial-decrypted once every secret has found its home. (The AEAD tag
    # is a zero-false-accept oracle, and one secret binds one session, so this
    # yields the same set of bindings the stream-centric scan did.)
    # Binding runs in two passes (see _BIND_PASSES): first-record-only, then a
    # deeper retry for the bundles the first pass could not place. Within a pass
    # each bundle's seq search deepens window by window (see _BundleSearch), so a
    # wrong stream costs a few dozen AEAD trials instead of a full max_seq sweep.
    bound_keys: Set[str] = set()
    stats = _StageStats()
    unclaimed = list(streams)
    unplaced = list(bundles)
    placements = _Placements(streams)
    for first_record, max_records in _bind_windows():
        unplaced = [
            bundle for bundle in unplaced
            if not _place_bundle(bundle, unclaimed, max_records, first_record,
                                 bus=bus, state=state,
                                 result=result, base_ts=base_ts, stats=stats,
                                 bound_keys=bound_keys, max_seq=max_seq,
                                 placements=placements)
        ]
        if not unplaced or not unclaimed:
            break
    stats.report(result)
    return bound_keys


def _place_bundle(bundle: dict, unclaimed: list, max_records: int,
                  first_record: int = 0, *, bus, state, result, base_ts: float,
                  stats: _StageStats, bound_keys: Set[str],
                  max_seq: int = DEFAULT_MAX_SEQ,
                  placements: Optional[_Placements] = None) -> bool:
    """Bind *bundle* to the first unclaimed stream it decrypts; emit and claim it.

    Returns True when the bundle was placed (the stream is removed from
    *unclaimed*). A duplicate of an already fully bound bundle is skipped (see
    :class:`_Placements`).
    """
    if placements is not None and placements.is_duplicate(bundle):
        return False
    found = _find_binding(bundle, unclaimed, max_records, first_record, max_seq)
    if found is None:
        return False
    idx, binding = found
    stream = unclaimed[idx]
    state.ensure_open()
    if _emit_binding(binding, bus=bus, state=state, result=result,
                     base_ts=base_ts, stats=stats):
        bound_keys.add(
            canonical_4tuple(
                stream.client_addr[0],
                stream.client_addr[1],
                stream.server_addr[0],
                stream.server_addr[1],
            )
        )
        result.stream_count += 1
    if placements is not None:
        placements.record(bundle, binding)
    del unclaimed[idx]
    return True
