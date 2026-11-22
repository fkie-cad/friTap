"""Top-level orchestrator: pcap -> decrypted MTProto messages.

Ties together TCP reassembly (:mod:`.reassembly`), transport de-obfuscation
(:mod:`.transport`), and record decryption (:mod:`.crypto`). Streams that are not
MTProto-obfuscated are silently skipped (false-positive guard); unsupported
transports (padded-intermediate, full, Fake-TLS) and degraded streams are counted
and logged with an actionable hint, mirroring friTap's keyless-skip logging.

The crypto backend is imported lazily; a :class:`MtprotoDependencyError` is
re-raised so the parent offline driver can catch it and skip MTProto cleanly.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from ...protocols.mtproto_keylog_spec import MtprotoAuthKey, MtprotoObfKey
from ..net.endpoints import normalize_endpoint, stream_endpoint
from ..net.tcp_reassembly import TcpStreamReassembler
from . import MtprotoCryptoError, MtprotoDependencyError
from .packet_meta import PLAUSIBLE_MSG_EPOCH_RANGE, msg_id_seconds
from .reassembly import (
    INIT_BLOCK_LEN,
    StreamPair,
    reassemble_pcap,
)
from .records import DecryptedMessage, MtprotoStats
from .transport import (
    _MIN_RECORD_LEN,
    CLIENT_TO_SERVER,
    DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS,
    DEFAULT_OBF_MAX_BLOCKS,
    SERVER_TO_CLIENT,
    ObfAlignment,
    ObfuscationCipher,
    detect_transport,
    iter_frames_with_offsets,
    recover_obf_alignment,
)

logger = logging.getLogger(__name__)

# The shortest run worth attempting mid-stream obfuscation recovery on: a run must
# at least be able to hold one outer record (auth_key_id + msg_key + one AES block).
_MIN_RECOVERABLE_RUN = _MIN_RECORD_LEN

# msg_id carries unix seconds in its upper 32 bits; anything below this is not a
# plausible wall-clock time (2001-09-09) and is treated as "unknown".
_MIN_PLAUSIBLE_EPOCH = PLAUSIBLE_MSG_EPOCH_RANGE[0]

TimestampLookup = Callable[[int], float]


def _msg_id_seconds(msg_id: int) -> float:
    """Unix seconds encoded in an MTProto ``msg_id`` (upper 32 bits), or 0.0."""
    seconds = msg_id_seconds(msg_id or 0)
    return float(seconds) if seconds > _MIN_PLAUSIBLE_EPOCH else 0.0


def _offset_ts_lookup(reasm: TcpStreamReassembler, base: int) -> TimestampLookup:
    """Map a payload offset to its capture time; the payload starts at run offset *base*.

    AES-CTR de-obfuscation is length- and position-preserving, so payload byte
    ``i`` is exactly contiguous-run byte ``base + i``.
    """
    return lambda offset: reasm.timestamp_at(base + offset)


def _message_timestamp(
    ts_of: Optional[TimestampLookup], frame_end: int, msg_id: int
) -> float:
    """Capture time of the frame's LAST byte, else the msg_id clock, else 0.0."""
    ts = ts_of(frame_end - 1) if ts_of is not None else 0.0
    return ts if ts > 0 else _msg_id_seconds(msg_id)


# Telegram's published data-center IP ranges (the blocks the apps hardcode as DC
# endpoints). Offline there is no way to probe reachability, so "the peer is a
# known Telegram DC" is the strongest available evidence that an init-less stream
# is MTProto and not foreign TLS or plain TCP captured mid-connection.
_TELEGRAM_DC_NETS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "149.154.160.0/20",
        "91.108.4.0/22",
        "91.108.8.0/22",
        "91.108.12.0/22",
        "91.108.16.0/22",
        "91.108.56.0/22",
        "91.105.192.0/23",
        "95.161.64.0/20",
        "2001:b28:f23d::/48",
        "2001:b28:f23f::/48",
        "2001:b28:f242::/48",
        "2001:67c:4e8::/48",
    )
)


def _is_telegram_dc(addr: str) -> bool:
    """True if *addr* falls inside a published Telegram DC range (IPv4 or IPv6)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in _TELEGRAM_DC_NETS)


def _has_mtproto_evidence(pair: StreamPair) -> bool:
    """True if either endpoint of an init-less *pair* is a known Telegram DC.

    Only such streams count toward ``streams_degraded``; the rest go to
    ``streams_degraded_non_mtproto`` so foreign/empty streams do not inflate it.
    """
    return _is_telegram_dc(pair.server_addr[0]) or _is_telegram_dc(pair.client_addr[0])


def iter_decrypted_messages(
    pcap_path: str,
    keymap: Dict[bytes, MtprotoAuthKey],
    *,
    server_ports: Tuple[int, ...] = (443, 80, 5222),
    stats: Optional[MtprotoStats] = None,
    obf_keys: Optional[Sequence[MtprotoObfKey]] = None,
    obf_max_blocks: int = DEFAULT_OBF_MAX_BLOCKS,
) -> Iterator[DecryptedMessage]:
    """Yield every decryptable MTProto message from ``pcap_path``.

    Per conversation: de-obfuscate the 64-byte client init block and detect the
    transport tag (``None`` = not MTProto, skipped silently), CTR-decrypt both
    directions, split into outer records and decrypt each with the auth_key
    looked up by ``outer[0:8]``.

    Failed records count as ``records_undecryptable``, split into
    ``records_malformed`` / ``records_unknown_key`` / ``records_crypto_failed``;
    unknown auth_key_ids are collected in ``stats.unknown_key_ids`` for a key hunt.
    Undecryptable streams are bucketed by reason (``streams_degraded``,
    ``streams_short``, ``streams_unsupported_framing``) and logged.
    :class:`MtprotoDependencyError` is re-raised.

    With ``obf_keys`` (memory-recovered ``MTPROTO_OBF_KEY`` entries), an init-less
    conversation is re-attempted from the recovered live CTR state (see
    :func:`_process_recovered_stream`). ``obf_max_blocks`` bounds how far behind the
    live CTR counter each direction is searched; raise it when the obfuscation key
    was captured long after the pcap.
    """
    # Lazy backend check: surface a missing crypto dep to the parent immediately.
    from . import MTPROTO_DEPENDENCY_HINT, crypto

    if not crypto.backend_available():
        raise MtprotoDependencyError(MTPROTO_DEPENDENCY_HINT)

    if stats is None:
        stats = MtprotoStats()
    if obf_keys:
        stats.set_obf_keys_loaded(len(obf_keys))

    streams = reassemble_pcap(pcap_path, server_ports=server_ports)
    for pair in streams.values():
        stats.add_stream()
        yield from _process_stream(
            pair, keymap, stats, obf_keys, obf_max_blocks=obf_max_blocks
        )


def _process_stream(
    pair: StreamPair,
    keymap: Dict[bytes, MtprotoAuthKey],
    stats: MtprotoStats,
    obf_keys: Optional[Sequence[MtprotoObfKey]] = None,
    *,
    obf_max_blocks: int = DEFAULT_OBF_MAX_BLOCKS,
) -> Iterator[DecryptedMessage]:
    client = pair.client
    client_bytes = client.contiguous_bytes()

    # A client run shorter than the 64-byte init block cannot be de-obfuscated.
    # It counts as MTProto only with positive evidence (a Telegram DC endpoint).
    if len(client_bytes) < INIT_BLOCK_LEN:
        # A download-heavy / idle-client mid-stream flow can still be recovered
        # from its server run alone. Only a server run that can hold an outer
        # record is worth the search, so short non-MTProto streams stay cheap.
        if obf_keys and len(pair.server.contiguous_bytes()) >= _MIN_RECOVERABLE_RUN:
            recovered = _try_obf_recovery(
                pair, obf_keys, keymap, stats, obf_max_blocks=obf_max_blocks
            )
            if recovered is not None:
                yield from recovered
                return
        # Classify why the init is missing, only for an accurate hint.
        if not client.saw_syn:
            reason = "capture started mid-flow (no client SYN observed)"
        elif client.has_start_gap:
            reason = "a gap swallowed the opening obfuscation bytes"
        else:
            reason = "the connection carried too little client data to de-obfuscate"
        if _has_mtproto_evidence(pair):
            # A short/lossy stream, not one captured mid-flow.
            stats.add_short_stream()
            logger.info(
                "Skipping MTProto stream %s<->%s: %s (need the first %d client "
                "bytes). Re-capture from connection start to decrypt this stream.",
                pair.client_addr,
                pair.server_addr,
                reason,
                INIT_BLOCK_LEN,
            )
        else:
            # No Telegram-DC endpoint: almost certainly not MTProto.
            stats.add_degraded_non_mtproto()
            logger.debug(
                "Ignoring init-less non-MTProto stream %s<->%s (%s).",
                pair.client_addr,
                pair.server_addr,
                reason,
            )
        return

    cipher = ObfuscationCipher(client_bytes[:INIT_BLOCK_LEN])

    decrypted_init = cipher.decrypt_out(client_bytes[:INIT_BLOCK_LEN])
    transport_type = detect_transport(decrypted_init)
    if transport_type is None:
        # A None tag normally means "not MTProto". Without the client SYN the first
        # contiguous bytes need not be the real init block, so this may be a
        # mid-stream Telegram session: try the recovered obfuscation keys first,
        # then classify it as degraded when there is DC evidence.
        if obf_keys:
            recovered = _try_obf_recovery(
                pair, obf_keys, keymap, stats, obf_max_blocks=obf_max_blocks
            )
            if recovered is not None:
                yield from recovered
                return
            # Recovery was attempted but no key aligned. Returning here keeps
            # degraded_unrecovered mutually exclusive with add_degraded() below.
            stats.add_degraded_unrecovered()
            logger.info(
                "MTProto stream %s<->%s looks mid-stream, but no supplied "
                "obfuscation key aligned to it (searched up to %d CTR blocks). "
                "Counted degraded (unrecovered); raise --resync-search-depth if "
                "the key was captured long after the pcap.",
                pair.client_addr,
                pair.server_addr,
                obf_max_blocks,
            )
            return
        if not client.saw_syn and _has_mtproto_evidence(pair):
            # Mid-stream with no obf keys: only a re-capture can recover it.
            stats.add_degraded()
            logger.info(
                "MTProto stream %s<->%s looks mid-stream (no SYN, init not "
                "recoverable). Counted degraded; re-capture from connection start.",
                pair.client_addr,
                pair.server_addr,
            )
        return  # SYN-anchored + no tag -> genuinely not MTProto, skip silently

    # A gap after a valid init block keeps the stream: ``contiguous_bytes()`` stops
    # at the first gap, so the pre-gap prefix decrypts and the stream counts partial.
    truncated = client.degraded or pair.server.degraded

    client_payload = cipher.decrypt_out(client_bytes[INIT_BLOCK_LEN:])
    server_payload = cipher.decrypt_in(pair.server.contiguous_bytes())

    try:
        yield from _decrypt_direction(
            transport_type, client_payload, "write", pair, keymap, stats,
            ts_of=_offset_ts_lookup(pair.client, INIT_BLOCK_LEN),
        )
        yield from _decrypt_direction(
            transport_type, server_payload, "read", pair, keymap, stats,
            ts_of=_offset_ts_lookup(pair.server, 0),
        )
    except NotImplementedError:
        # The start was captured; only the framing (padded-intermediate / full /
        # Fake-TLS) is not decodable, so this is not a degraded stream.
        stats.add_unsupported_framing()
        logger.info(
            "Skipping MTProto stream %s<->%s: %r transport framing is not yet "
            "supported (only abridged/intermediate are). Counted, not decrypted.",
            pair.client_addr,
            pair.server_addr,
            transport_type,
        )
        return

    if truncated:
        stats.add_partial()
        logger.info(
            "MTProto stream %s<->%s had a gap after a valid init block: decrypted "
            "the contiguous records before the gap only (partial). Re-capture "
            "without loss to recover the rest.",
            pair.client_addr,
            pair.server_addr,
        )


def _try_obf_recovery(
    pair: StreamPair,
    obf_keys: Sequence[MtprotoObfKey],
    keymap: Dict[bytes, MtprotoAuthKey],
    stats: MtprotoStats,
    *,
    obf_max_blocks: int,
) -> Optional[List[DecryptedMessage]]:
    """Mid-stream recovery with its success bookkeeping; ``None`` on a miss.

    On success the stream is counted recovered and logged; a miss leaves every
    stream bucket untouched so the caller keeps its own classification.
    """
    recovered = _process_recovered_stream(
        pair, obf_keys, keymap, stats, obf_max_blocks=obf_max_blocks
    )
    if recovered is None:
        return None
    stats.add_recovered_stream()
    logger.info(
        "Recovered mid-stream MTProto conversation %s<->%s from "
        "memory-scanned obfuscation keys (%d message(s)).",
        pair.client_addr,
        pair.server_addr,
        len(recovered),
    )
    return recovered


def _pair_endpoints(pair: StreamPair) -> Set[str]:
    """Canonical ``ip:port`` forms of both stream ends (unknown ones omitted)."""
    ends = {stream_endpoint(pair.client_addr), stream_endpoint(pair.server_addr)}
    ends.discard(None)
    return ends


def _key_endpoint_in(key: MtprotoObfKey, endpoints: Set[str]) -> bool:
    """Whether *key*'s endpoint hint names one of *endpoints* (``-`` never does)."""
    endpoint = normalize_endpoint(key.endpoint)
    return endpoint is not None and endpoint in endpoints


def _ordered_obf_keys(
    obf_keys: Sequence[MtprotoObfKey], pair: StreamPair
) -> List[MtprotoObfKey]:
    """Endpoint-matched keys first, then the rest.

    The endpoint hint is advisory (may be ``-``), so this only orders trials; every
    key is still tried.
    """
    endpoints = _pair_endpoints(pair)
    matched = [k for k in obf_keys if _key_endpoint_in(k, endpoints)]
    others = [k for k in obf_keys if not _key_endpoint_in(k, endpoints)]
    return matched + others


def _align_direction(
    run: bytes,
    key: bytes,
    live_counter: bytes,
    num: int,
    keymap: Dict[bytes, MtprotoAuthKey],
    *,
    max_blocks: int,
    direction: str,
    transport_hint: Optional[str] = None,
) -> Optional[ObfAlignment]:
    """Align one *direction* (``"write"``/``"read"``) at a fixed depth of ``max_blocks``.

    Returns the :class:`ObfAlignment`, or ``None`` when the run cannot hold one
    outer record or nothing aligns. Depth escalation is the caller's job.
    *direction* disambiguates the server's quick-ack header.
    """
    if len(run) < _MIN_RECOVERABLE_RUN:
        return None
    return recover_obf_alignment(
        key, live_counter, num, run, keymap,
        transport_hint=transport_hint, max_blocks=max_blocks, direction=direction,
    )


_DIRECTIONS = (CLIENT_TO_SERVER, SERVER_TO_CLIENT)


def _key_half(key: MtprotoObfKey, direction: str) -> Tuple[bytes, bytes, int]:
    """``(aes_key, live_counter, num)`` of *key* for one direction."""
    if direction == CLIENT_TO_SERVER:
        return key.key_out, key.iv_out, key.num_out
    return key.key_in, key.iv_in, key.num_in


class _ObfAlignmentSearch:
    """Align each direction of one stream pair independently over the candidate keys.

    Memscan keylogs hold several snapshots of the same connection (same key
    material, different live counters), and the snapshot that best reaches the
    client tail need not be the one that reaches the server tail. The search runs:

    1. every key at the base depth, stopping at the first key that aligns either
       direction (the "primary");
    2. only if nothing aligned: endpoint-matched keys at the wide depth, again
       stopping at the first hit;
    3. for each direction still unaligned: the primary and the remaining keys at
       the base depth (primary, then same key material, then same endpoint, then
       the rest), then the wide depth only for endpoint-matched keys with the same
       key material as the primary. Widening unrelated same-endpoint keys caused
       a 10+ min hang.

    Every ``(direction, key, depth)`` search runs at most once, so an aligned
    direction is never re-searched, and each key actually tried is counted exactly
    once by :meth:`record_trials` (aligned if it aligned any direction).
    """

    def __init__(
        self,
        pair: StreamPair,
        obf_keys: Sequence[MtprotoObfKey],
        keymap: Dict[bytes, MtprotoAuthKey],
        obf_max_blocks: int,
    ) -> None:
        self._runs = {
            CLIENT_TO_SERVER: pair.client.contiguous_bytes(),
            SERVER_TO_CLIENT: pair.server.contiguous_bytes(),
        }
        self._keys = _ordered_obf_keys(obf_keys, pair)
        self._endpoints = _pair_endpoints(pair)
        self._keymap = keymap
        self._base = obf_max_blocks
        self._wide = max(obf_max_blocks, DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS)
        self._tried: set = set()  # (direction, key index, depth)
        self._outcome: Dict[int, bool] = {}  # key index -> aligned any direction
        self.primary: Optional[MtprotoObfKey] = None
        self.aligned: Dict[str, Tuple[MtprotoObfKey, ObfAlignment]] = {}

    def run(self) -> None:
        primary = self._first_aligning_key(range(len(self._keys)), self._base)
        if primary is None:
            eligible = [i for i in range(len(self._keys)) if self._eligible_for_wide(i)]
            primary = self._first_aligning_key(eligible, self._wide)
        if primary is None:
            return
        self.primary = self._keys[primary]
        for direction in _DIRECTIONS:
            if direction not in self.aligned:
                self._fill_direction(direction, primary)

    def record_trials(self, stats: MtprotoStats) -> None:
        for index in sorted(self._outcome):
            stats.add_obf_trial(aligned=self._outcome[index])

    def _endpoint_matched(self, index: int) -> bool:
        return _key_endpoint_in(self._keys[index], self._endpoints)

    def _eligible_for_wide(self, index: int) -> bool:
        # Only an endpoint-matched key earns the deep search, and only when the
        # wide ceiling actually exceeds the base depth.
        return self._endpoint_matched(index) and self._wide > self._base

    def _first_aligning_key(self, indices, depth: int) -> Optional[int]:
        for index in indices:
            if self._try_key(index, depth):
                return index
        return None

    def _try_key(self, index: int, depth: int) -> bool:
        # Client first so its resolved framing can hint the server search.
        hits = [self._try(index, direction, depth) for direction in _DIRECTIONS]
        return any(hits)

    def _fill_direction(self, direction: str, primary: int) -> None:
        material = _key_half(self._keys[primary], direction)[0]

        def same_material(index: int) -> bool:
            return _key_half(self._keys[index], direction)[0] == material

        order = sorted(
            range(len(self._keys)),
            key=lambda i: (i != primary, not same_material(i),
                           not self._endpoint_matched(i), i),
        )
        for index in order:
            if self._try(index, direction, self._base):
                return
        for index in order:
            if (self._eligible_for_wide(index) and same_material(index)
                    and self._try(index, direction, self._wide)):
                return

    def _try(self, index: int, direction: str, depth: int) -> bool:
        run = self._runs[direction]
        attempt = (direction, index, depth)
        if (direction in self.aligned or attempt in self._tried
                or len(run) < _MIN_RECOVERABLE_RUN):
            return False
        self._tried.add(attempt)
        self._outcome.setdefault(index, False)
        key = self._keys[index]
        aes_key, live_counter, num = _key_half(key, direction)
        alignment = _align_direction(
            run, aes_key, live_counter, num, self._keymap,
            max_blocks=depth, direction=direction,
            transport_hint=self._transport_hint(),
        )
        if alignment is None:
            return False
        self.aligned[direction] = (key, alignment)
        self._outcome[index] = True
        return True

    def _transport_hint(self) -> Optional[str]:
        # The framing already resolved for the other direction, if any.
        for _key, alignment in self.aligned.values():
            return alignment.transport_type
        return None


def _process_recovered_stream(
    pair: StreamPair,
    obf_keys: Sequence[MtprotoObfKey],
    keymap: Dict[bytes, MtprotoAuthKey],
    stats: MtprotoStats,
    *,
    obf_max_blocks: int = DEFAULT_OBF_MAX_BLOCKS,
) -> Optional[List[DecryptedMessage]]:
    """Re-derive an init-less stream from recovered live CTR state, or ``None``.

    The obfuscation key gives the AES-256 key and live CTR counter per direction,
    not where the captured tail sits in the keystream. :func:`recover_obf_alignment`
    finds that using the auth_key_ids in ``keymap`` as known plaintext, so recovery
    needs both keys. Each direction aligns independently, possibly via a different
    key snapshot (see :class:`_ObfAlignmentSearch`); one aligned direction is enough.
    ``obf_max_blocks`` bounds the CTR back-search; endpoint-matched keys auto-widen
    it on a miss. Returns the decrypted messages, or ``None`` if nothing aligned.
    """
    if not keymap:
        # No auth_key means no alignment oracle.
        return None
    client_run = pair.client.contiguous_bytes()
    server_run = pair.server.contiguous_bytes()
    if (len(client_run) < _MIN_RECOVERABLE_RUN
            and len(server_run) < _MIN_RECOVERABLE_RUN):
        # Neither direction carries enough contiguous data to hold one outer record.
        return None

    search = _ObfAlignmentSearch(pair, obf_keys, keymap, obf_max_blocks)
    search.run()
    search.record_trials(stats)
    if search.primary is None:
        return None
    return _decrypt_recovered(search, client_run, server_run, pair, keymap, stats)


def _decrypt_recovered(
    search: _ObfAlignmentSearch,
    client_run: bytes,
    server_run: bytes,
    pair: StreamPair,
    keymap: Dict[bytes, MtprotoAuthKey],
    stats: MtprotoStats,
) -> List[DecryptedMessage]:
    """De-obfuscate and decrypt every direction *search* aligned.

    Each cipher half is seeded from its own direction's key and resolved counter;
    an unaligned direction gets the primary key's raw IV and is not decrypted.
    """
    out = search.aligned.get(CLIENT_TO_SERVER)
    inn = search.aligned.get(SERVER_TO_CLIENT)
    out_key = out[0] if out else search.primary
    in_key = inn[0] if inn else search.primary
    cipher = ObfuscationCipher.from_recovered(
        out_key.key_out,
        out[1].counter_block if out else out_key.iv_out,
        in_key.key_in,
        inn[1].counter_block if inn else in_key.iv_in,
    )
    transport_type = (out or inn)[1].transport_type
    messages: List[DecryptedMessage] = []
    if out is not None:
        messages.extend(_decrypt_aligned(
            cipher.decrypt_out, out[1], client_run, transport_type, CLIENT_TO_SERVER,
            pair, keymap, stats,
        ))
    if inn is not None:
        messages.extend(_decrypt_aligned(
            cipher.decrypt_in, inn[1], server_run, transport_type, SERVER_TO_CLIENT,
            pair, keymap, stats,
        ))
    return messages


def _decrypt_aligned(
    decrypt: Callable[[bytes], bytes],
    align: ObfAlignment,
    run: bytes,
    transport_type: str,
    direction: str,
    pair: StreamPair,
    keymap: Dict[bytes, MtprotoAuthKey],
    stats: MtprotoStats,
) -> List[DecryptedMessage]:
    """De-obfuscate one direction's *run* from its resolved alignment and decrypt it.

    *decrypt* is that direction's stateful cipher half; the run is phase-padded so
    the keystream lines up, and the framed payload starts at ``frame_offset``.
    """
    plain = decrypt(b"\x00" * align.phase + run)
    payload = plain[align.phase + align.frame_offset :]
    side = pair.client if direction == "write" else pair.server
    return list(_decrypt_direction(
        transport_type, payload, direction, pair, keymap, stats,
        ts_of=_offset_ts_lookup(side, align.frame_offset),
    ))


def _decrypt_direction(
    transport_type: str,
    payload: bytes,
    direction: str,
    pair: StreamPair,
    keymap: Dict[bytes, MtprotoAuthKey],
    stats: MtprotoStats,
    ts_of: Optional[TimestampLookup] = None,
) -> Iterator[DecryptedMessage]:
    """Split *payload* into records and decrypt each one.

    ``ts_of`` maps an offset in *payload* to its capture time; each message is
    stamped with the time of its frame's last byte (the moment it was complete),
    falling back to the ``msg_id`` clock when no capture time is known.
    """
    from . import crypto

    if direction == "write":
        src_addr, src_port = pair.client_addr
        dst_addr, dst_port = pair.server_addr
    else:
        src_addr, src_port = pair.server_addr
        dst_addr, dst_port = pair.client_addr

    for _frame_start, frame_end, frame in iter_frames_with_offsets(
        transport_type, payload, keymap, direction
    ):
        # Three ways a record fails to open, and they are not the same failure.
        # All three bump ``records_undecryptable``; only the middle one is worth
        # reporting to the user, so each gets its own counter. See MtprotoStats.
        if len(frame) < 8 or len(frame) > crypto.MAX_RECORD_LEN:
            # Too short to even hold an auth_key_id (nothing to report, nothing
            # to recover), or a forged length header naming an oversized frame
            # that must not be AES-decrypted at all.
            stats.add_malformed_record()
            continue
        auth_key_id = frame[0:8]
        entry = keymap.get(auth_key_id)
        if entry is None:
            # The id is in the clear in the first 8 bytes, so record it: it is
            # the exact search term for a follow-up key hunt over the app's heap.
            stats.add_unknown_key(auth_key_id.hex())
            continue
        try:
            record = crypto.decrypt_record(entry.auth_key, frame, direction)
        except MtprotoCryptoError:
            # The key is held but did not verify; a key hunt for this id would
            # only find the same key, so it stays out of ``unknown_key_ids``.
            stats.add_crypto_failure()
            continue
        stats.add_message()
        yield DecryptedMessage(
            src_addr=src_addr,
            src_port=src_port,
            dst_addr=dst_addr,
            dst_port=dst_port,
            ss_family=pair.ss_family,
            direction=direction,
            message=record.envelope.message,
            dc_id=entry.dc_id,
            transport=transport_type,
            obfuscated=True,
            auth_key_id_hex=auth_key_id.hex(),
            timestamp=_message_timestamp(ts_of, frame_end, record.envelope.msg_id),
            **_envelope_kwargs(record, frame),
        )


def _envelope_kwargs(record, frame: bytes) -> dict:
    """:class:`DecryptedMessage` keyword args taken from a record's envelope.

    Carries every :class:`~.crypto.MtprotoEnvelope` field except the TL
    ``message`` itself (passed separately), plus the outer frame length.
    """
    envelope = record.envelope
    return {
        "msg_id": envelope.msg_id,
        "salt": bytes(envelope.salt),
        "session_id": bytes(envelope.session_id),
        "seq_no": envelope.seq_no,
        "msg_len": envelope.msg_len,
        "padding_len": len(envelope.padding or b""),
        "frame_len": len(frame),
    }
