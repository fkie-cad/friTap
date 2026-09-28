"""MTProto obfuscated-transport de-obfuscation and frame extraction.

Reimplemented from the *algorithm* described by ``tomer8007/mtproto-dissector``
(``mtproto/mtproto.lua``) and the Telegram MTProto transport docs — no GPL text
is copied.

Obfuscated transport prepends a 64-byte init block to the client->server stream.
The whole stream (init block included) is AES-256-CTR encrypted; the keystream is
position-dependent, so each direction is driven by ONE stateful CTR cipher that
must be fed bytes strictly in order. The init block is keyed as follows:

  * ``key_out = init[8:40]``,  ``iv_out = init[40:56]``           (client->server)
  * ``rev = init[8:56][::-1]`` (48 bytes); ``key_in = rev[0:32]``,
    ``iv_in = rev[32:48]``                                        (server->client)

After CTR-decrypting the first 64 client bytes, ``init[56:60]`` carries a 4-byte
transport tag. Byte 64 onward is the framed record stream.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple

# Transport tags found at decrypted init[56:60].
ABRIDGED = "abridged"
INTERMEDIATE = "intermediate"
PADDED_INTERMEDIATE = "padded_intermediate"

_TAG_ABRIDGED = b"\xef\xef\xef\xef"
_TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
_TAG_PADDED_INTERMEDIATE = b"\xdd\xdd\xdd\xdd"

_INIT_LEN = 64

_QUICK_ACK_BIT = 0x80  # high bit of the abridged length byte; masked off
# Bit 31 of the little-endian intermediate length word: the same quick-ack flag.
_INTERMEDIATE_QUICK_ACK_BIT = 0x80000000
# A standalone quick-ack TOKEN (the server's answer to an ack request) is 4 bytes.
_QUICK_ACK_TOKEN_LEN = 4

# Stream directions, spelled like the decryptor's ``direction`` argument. Only the
# client sets the quick-ack REQUEST flag on a data frame; only the server sends
# quick-ack TOKENS. ``None`` means the direction is unknown to the caller.
CLIENT_TO_SERVER = "write"
SERVER_TO_CLIENT = "read"


def _ctr_cipher(key: bytes, iv: bytes):
    """Create a stateful AES-256-CTR encryptor (CTR is symmetric: enc == dec).

    AES-CTR comes from ``cryptography`` only (``tgcrypto`` cannot do the stateful,
    position-continuous CTR this needs). Missing it surfaces as a clean
    :class:`MtprotoDependencyError` rather than a raw ImportError.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        from . import MTPROTO_DEPENDENCY_HINT, MtprotoDependencyError

        raise MtprotoDependencyError(MTPROTO_DEPENDENCY_HINT) from exc

    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def derive_obfuscation_keys(init: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Derive ``(key_out, iv_out, key_in, iv_in)`` from the raw 64-byte init block.

    ``init`` is the *encrypted* client->server prefix as seen on the wire.
    """
    if len(init) < 56:
        raise ValueError("init block too short to derive obfuscation keys")
    key_out = init[8:40]
    iv_out = init[40:56]
    rev = init[8:56][::-1]
    key_in = rev[0:32]
    iv_in = rev[32:48]
    return key_out, iv_out, key_in, iv_in


_COUNTER_LEN = 16  # AES block / CTR counter width in bytes


def counter_add(counter_block: bytes, delta_blocks: int) -> bytes:
    """Return the 16-byte CTR counter *delta_blocks* ahead of *counter_block*.

    Big-endian 128-bit add, mod 2^128 (matching how AES-CTR increments its
    counter). ``delta_blocks`` may be negative to walk the counter backwards, which
    is how :func:`recover_obf_alignment` searches the blocks captured *behind* the
    live counter.
    """
    if len(counter_block) != _COUNTER_LEN:
        raise ValueError("counter block must be 16 bytes")
    value = (int.from_bytes(counter_block, "big") + delta_blocks) % (1 << 128)
    return value.to_bytes(_COUNTER_LEN, "big")


def deobfuscate_at(key: bytes, counter_block: bytes, data: bytes) -> bytes:
    """One-shot, seekable AES-256-CTR of *data* with *counter_block* as the IV.

    CTR is position-independent given the right counter, so the caller can jump to
    any block boundary by advancing the counter (see :func:`counter_add`) and
    de-obfuscate a slice in isolation — the seekable counterpart to the stateful
    :class:`ObfuscationCipher`. A sub-block byte-phase is handled by prepending that
    many padding bytes and discarding them from the result.
    """
    return _ctr_cipher(key, counter_block).update(data)


class ObfuscationCipher:
    """Stateful de-obfuscation for one MTProto conversation.

    Holds two CTR ciphers — ``out`` (client->server) and ``in`` (server->client)
    — each seeded from the client init block. Bytes must be fed in stream order
    because CTR advances its counter across calls.
    """

    def __init__(self, init: bytes):
        key_out, iv_out, key_in, iv_in = derive_obfuscation_keys(init)
        self._out = _ctr_cipher(key_out, iv_out)
        self._in = _ctr_cipher(key_in, iv_in)

    @classmethod
    def from_recovered(
        cls,
        key_out: bytes,
        iv_out: bytes,
        key_in: bytes,
        iv_in: bytes,
    ) -> "ObfuscationCipher":
        """Build a cipher directly from memory-recovered per-direction key/IV pairs.

        Unlike :meth:`__init__` (which derives the keys from the 64-byte client init
        block), this seeds each direction's CTR cipher straight from the recovered
        ``key``/``iv`` — used for a connection whose init block was never captured
        (mid-stream). ``iv_out``/``iv_in`` are the 16-byte CTR counter blocks the
        caller has resolved for each direction (via :func:`recover_obf_alignment`),
        so feeding the (phase-padded) payload de-obfuscates it in place. The
        init-bytes ``__init__`` path is left untouched.
        """
        self = cls.__new__(cls)
        self._out = _ctr_cipher(key_out, iv_out)
        self._in = _ctr_cipher(key_in, iv_in)
        return self

    def decrypt_out(self, data: bytes) -> bytes:
        """De-obfuscate the next chunk of the client->server stream."""
        return self._out.update(data)

    def decrypt_in(self, data: bytes) -> bytes:
        """De-obfuscate the next chunk of the server->client stream."""
        return self._in.update(data)


def detect_transport(decrypted_init: bytes) -> Optional[str]:
    """Identify the transport from the *decrypted* 64-byte init block.

    Returns one of ``ABRIDGED``/``INTERMEDIATE``/``PADDED_INTERMEDIATE`` or
    ``None`` when no known tag matches (the false-positive guard: the stream is
    not MTProto-obfuscated).
    """
    if len(decrypted_init) < 60:
        return None
    tag = decrypted_init[56:60]
    if tag == _TAG_ABRIDGED:
        return ABRIDGED
    if tag == _TAG_INTERMEDIATE:
        return INTERMEDIATE
    if tag == _TAG_PADDED_INTERMEDIATE:
        return PADDED_INTERMEDIATE
    return None


def iter_frames(transport_type: str, stream_bytes: bytes) -> Iterator[bytes]:
    """Yield each outer MTProto record from a *de-obfuscated* payload stream.

    ``stream_bytes`` starts at decrypted byte 64 (after the init block). A partial
    trailing frame is dropped cleanly (the stream may have been cut mid-record).

    ``padded_intermediate`` and ``full`` are not supported here and raise
    :class:`NotImplementedError`; the caller degrades gracefully.
    """
    for _start, _end, payload in iter_frames_with_offsets(transport_type, stream_bytes):
        yield payload


FrameSpan = Tuple[int, int, bytes]  # (frame start incl. header, frame end, payload)


def iter_frames_with_offsets(
    transport_type: str, buf: bytes,
    keymap: Optional[Dict[bytes, object]] = None,
    direction: Optional[str] = None,
) -> Iterator[FrameSpan]:
    """Like :func:`iter_frames` but yield ``(start, end, payload)`` per record.

    ``start`` is the offset of the frame's length header within *buf* and ``end``
    the offset one past its last payload byte, so ``buf[end - 1]`` is the byte
    whose arrival completed the record (used to timestamp it).

    *direction* (:data:`CLIENT_TO_SERVER` / :data:`SERVER_TO_CLIENT`) and *keymap*
    (the auth-key-id table) tell a quick-ack request flag from a quick-ack token;
    see :func:`_parse_frame_header`.
    """
    if transport_type == ABRIDGED:
        yield from _iter_abridged_offsets(buf, keymap, direction)
    elif transport_type == INTERMEDIATE:
        yield from _iter_intermediate_offsets(buf, keymap, direction)
    elif transport_type == PADDED_INTERMEDIATE:
        raise NotImplementedError("padded_intermediate framing is not supported")
    else:
        raise NotImplementedError(f"unsupported transport type: {transport_type!r}")


def _iter_abridged(buf: bytes) -> Iterator[bytes]:
    for _start, _end, payload in _iter_abridged_offsets(buf):
        yield payload


def _iter_intermediate(buf: bytes) -> Iterator[bytes]:
    for _start, _end, payload in _iter_intermediate_offsets(buf):
        yield payload


def _iter_abridged_offsets(
    buf: bytes, keymap: Optional[Dict[bytes, object]] = None,
    direction: Optional[str] = None,
) -> Iterator[FrameSpan]:
    return _iter_framed_offsets(ABRIDGED, buf, keymap, direction)


def _iter_intermediate_offsets(
    buf: bytes, keymap: Optional[Dict[bytes, object]] = None,
    direction: Optional[str] = None,
) -> Iterator[FrameSpan]:
    return _iter_framed_offsets(INTERMEDIATE, buf, keymap, direction)


def _iter_framed_offsets(
    transport_type: str, buf: bytes,
    keymap: Optional[Dict[bytes, object]] = None,
    direction: Optional[str] = None,
) -> Iterator[FrameSpan]:
    """Walk *buf* frame by frame using the shared :func:`_parse_frame_header`.

    Stops cleanly at a truncated length header or a partial trailing frame.
    """
    pos = 0
    n = len(buf)
    while True:
        header = _parse_frame_header(transport_type, buf, pos, keymap, direction)
        if header is None:
            return  # end of buffer or partial length header
        header_end, payload_len = header
        end = header_end + payload_len
        if end > n:
            return  # partial trailing frame
        yield pos, end, buf[header_end:end]
        pos = end


# --------------------------------------------------------------------------- #
# Mid-stream obfuscation-key recovery (init block never captured)
# --------------------------------------------------------------------------- #

# A well-formed outer record is auth_key_id(8) + msg_key(16) + >= one AES block(16).
_MIN_RECORD_LEN = 40
# How much of each candidate we de-obfuscate to test the known-plaintext anchor.
_ANCHOR_TEST_WINDOW = 2048
# The frame boundary sits within roughly one max control frame of the tail start.
_ANCHOR_MAX_START = 1024
# Default: how many AES blocks behind the live counter to search (capture lag).
DEFAULT_OBF_MAX_BLOCKS = 4096
# An endpoint-matched key is confidently the flow's, so search far further before
# giving up (auto-widen): the ~500x deeper ceiling only ever runs for a key whose
# endpoint hint ties it to this exact flow, keeping the expensive search off every
# un-attributed key.
DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS = 2_000_000
# Consecutive in-keymap frames required to beat a ~2^-64 false accept.
_ANCHOR_FRAMES = 2


@dataclass(frozen=True)
class ObfAlignment:
    """A resolved mid-stream de-obfuscation alignment for one direction.

    Feed ``(b"\\x00" * phase) + run`` into a CTR cipher seeded at ``counter_block``
    and drop the first ``phase`` bytes to recover the plaintext stream; the framed
    record payload begins at ``frame_offset`` within it. ``transport_type`` is the
    framing the anchor matched (abridged/intermediate).
    """

    counter_block: bytes
    phase: int
    frame_offset: int
    transport_type: str


def _abridged_length_header(buf: bytes, pos: int, length_byte: int, n: int) -> Optional[tuple[int, int]]:
    """``(header_end, payload_len)`` for a NORMAL abridged length header.

    *length_byte* is the (already quick-ack-bit-masked) first byte: < ``0x7f`` is a
    1-byte header, ``0x7f`` escapes to a 3-byte little-endian length.
    """
    if length_byte < 0x7F:
        return pos + 1, length_byte * 4
    if pos + 4 > n:
        return None
    return pos + 4, int.from_bytes(buf[pos + 1 : pos + 4], "little") * 4


def _header_names_known_key(
    buf: bytes, header: Optional[tuple[int, int]], keymap: Dict[bytes, object]
) -> bool:
    """True if *header* opens a real record: a full-length frame whose leading 8
    bytes are an ``auth_key_id`` we hold. The known-plaintext oracle used to tell a
    quick-ack-REQUEST data frame from a standalone quick-ack TOKEN (see
    :func:`_parse_frame_header`, which only calls it when a *keymap* is supplied).
    """
    if header is None:
        return False
    header_end, payload_len = header
    if payload_len < _MIN_RECORD_LEN or header_end + 8 > len(buf):
        return False
    return bytes(buf[header_end : header_end + 8]) in keymap


def _parse_frame_header(
    transport_type: str, buf: bytes, pos: int,
    keymap: Optional[Dict[bytes, object]] = None,
    direction: Optional[str] = None,
) -> Optional[tuple[int, int]]:
    """Return ``(header_end, payload_len)`` for the frame at *pos*, or ``None``.

    The single length-header parser shared by the frame iterators and the
    recovery anchor, so both always agree on frame boundaries. ``None`` means the
    header is truncated within *buf* (or *pos* is at its end).

    The quick-ack flag (``0x80`` on the abridged first byte, bit 31 of the
    intermediate length word) is ambiguous: the CLIENT sets it on a data frame's
    length to request an ack (mask it off and read a normal frame), while the
    SERVER's ack response is a standalone 4-byte token carrying no record
    (returned as ``(pos + 4, 0)``). See :func:`_resolve_quick_ack` for how the
    *direction* and the *keymap* oracle pick between the two.
    """
    n = len(buf)
    if transport_type == ABRIDGED:
        if pos >= n:
            return None
        first = buf[pos]
        if not first & _QUICK_ACK_BIT:
            return _abridged_length_header(buf, pos, first, n)
        masked = _abridged_length_header(buf, pos, first & ~_QUICK_ACK_BIT, n)
    elif transport_type == INTERMEDIATE:
        if pos + 4 > n:
            return None
        length = int.from_bytes(buf[pos : pos + 4], "little")
        if not length & _INTERMEDIATE_QUICK_ACK_BIT:
            return pos + 4, length
        masked = (pos + 4, length & ~_INTERMEDIATE_QUICK_ACK_BIT)
    else:
        return None
    return _resolve_quick_ack(transport_type, buf, pos, masked, keymap, direction)


def _quick_ack_token(buf: bytes, pos: int) -> Optional[tuple[int, int]]:
    """``(header_end, 0)`` for a 4-byte quick-ack token at *pos*, ``None`` if cut."""
    if pos + _QUICK_ACK_TOKEN_LEN > len(buf):
        return None
    return pos + _QUICK_ACK_TOKEN_LEN, 0


def _resolve_quick_ack(
    transport_type: str,
    buf: bytes,
    pos: int,
    masked: Optional[tuple[int, int]],
    keymap: Optional[Dict[bytes, object]],
    direction: Optional[str],
) -> Optional[tuple[int, int]]:
    """Resolve a quick-ack-flagged header to a data frame (*masked*) or a token.

    Decided by DIRECTION first, since each side only ever emits one of the two:

    * client->server: always an ack-REQUEST flag on a data frame -> *masked*, so a
      flagged frame under an unknown auth_key_id still frames (and gets reported);
    * server->client (or unknown): a token unless :func:`_flagged_is_data_frame`
      says the masked reading is a real record; with no oracle at all the server
      side defaults to a token and the unknown side keeps the historical masked
      reading.
    """
    if direction == CLIENT_TO_SERVER:
        return masked
    if keymap is None:
        return masked if direction is None else _quick_ack_token(buf, pos)
    if _flagged_is_data_frame(transport_type, buf, pos, masked, keymap):
        return masked
    return _quick_ack_token(buf, pos)


def _flagged_is_data_frame(
    transport_type: str,
    buf: bytes,
    pos: int,
    masked: Optional[tuple[int, int]],
    keymap: Dict[bytes, object],
) -> bool:
    """Heuristic for a flagged header whose sender may have been the server.

    A data frame if the masked frame names a known auth_key_id. Otherwise it is a
    token when the frame right after a 4-byte token names a known key; failing
    both, a sane masked frame (a full record that fits in *buf* and ends at the
    buffer's end or at a known-key frame) is still read as data, so its unknown
    auth_key_id is reported instead of the stream losing frame sync.
    """
    if _header_names_known_key(buf, masked, keymap):
        return True
    if _frame_at_names_known_key(transport_type, buf, pos + _QUICK_ACK_TOKEN_LEN, keymap):
        return False
    if masked is None:
        return False
    header_end, payload_len = masked
    frame_end = header_end + payload_len
    if payload_len < _MIN_RECORD_LEN or frame_end > len(buf):
        return False
    return frame_end == len(buf) or _frame_at_names_known_key(
        transport_type, buf, frame_end, keymap
    )


def _frame_at_names_known_key(
    transport_type: str, buf: bytes, pos: int, keymap: Dict[bytes, object]
) -> bool:
    """True if a frame read at *pos* (flag masked, no lookahead) opens a known key."""
    header = _parse_frame_header(transport_type, buf, pos, None, CLIENT_TO_SERVER)
    return _header_names_known_key(buf, header, keymap)


def _count_anchor_frames(
    buf: bytes,
    start: int,
    transport_type: str,
    auth_keymap: Dict[bytes, object],
    need: int,
    direction: Optional[str] = None,
) -> bool:
    """True if *need* consecutive frames from *start* each name a known auth_key_id.

    The known-plaintext oracle: at a real frame boundary the length header is
    plausible and the 8 bytes following it are an ``auth_key_id`` carried in the
    clear, which we can test against ``auth_keymap``. Requiring several consecutive
    hits drives the false-accept probability far below ~2^-64. A quick-ack token
    between two records (the server interleaves them with its replies) is stepped
    over without counting, so it does not break the run; the anchor frame itself
    must always be a real record.
    """
    pos = start
    hits = 0
    while hits < need:
        header = _parse_frame_header(transport_type, buf, pos, auth_keymap, direction)
        if header is None:
            return False
        header_end, payload_len = header
        if hits and header == (pos + _QUICK_ACK_TOKEN_LEN, 0):
            pos = header_end  # a quick-ack token between two anchor records
            continue
        if payload_len < _MIN_RECORD_LEN:
            return False
        if header_end + 8 > len(buf):
            return False
        if bytes(buf[header_end : header_end + 8]) not in auth_keymap:
            return False
        hits += 1
        pos = header_end + payload_len
    return True


# Header length(s) that can precede the auth_key_id, per framing: abridged uses
# a 1-byte or a 4-byte (0x7f-escaped) header, intermediate a 4-byte one.
_HEADER_LENGTHS = {ABRIDGED: (1, 4), INTERMEDIATE: (4,)}
_AUTH_KEY_ID_LEN = 8


def _anchor_candidates(
    buf: bytes, transport_type: str, auth_keymap: Dict[bytes, object], limit: int
) -> list[int]:
    """Sorted frame starts ``< limit`` whose header could end at a known auth_key_id.

    A frame passes :func:`_count_anchor_frames` only if a known auth_key_id sits
    right after its length header, so locating the ids first (``bytes.find``)
    and stepping back by each possible header length yields every start that can
    possibly hit — the expensive per-offset check then runs only there.
    """
    header_lengths = _HEADER_LENGTHS.get(transport_type, ())
    search_end = limit + max(header_lengths, default=0) + _AUTH_KEY_ID_LEN
    starts = set()
    for kid in auth_keymap:
        if not isinstance(kid, bytes) or len(kid) != _AUTH_KEY_ID_LEN:
            continue  # can never equal an 8-byte slice of the stream
        idx = buf.find(kid, 0, search_end)
        while idx != -1:
            starts.update(idx - h for h in header_lengths if 0 <= idx - h < limit)
            idx = buf.find(kid, idx + 1, search_end)
    return sorted(starts)


def _find_frame_anchor(
    buf: bytes,
    transport_type: str,
    auth_keymap: Dict[bytes, object],
    need: int,
    direction: Optional[str] = None,
) -> Optional[int]:
    """First byte offset in *buf* where the known-plaintext anchor holds, else ``None``."""
    limit = min(len(buf), _ANCHOR_MAX_START)
    for start in _anchor_candidates(buf, transport_type, auth_keymap, limit):
        if _count_anchor_frames(buf, start, transport_type, auth_keymap, need, direction):
            return start
    return None


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """Bytewise XOR of two equal-length byte strings."""
    return (int.from_bytes(a, "little") ^ int.from_bytes(b, "little")).to_bytes(
        len(a), "little"
    )


def _anchor_id_positions(window: bytes, transports: Tuple[str, ...]) -> List[int]:
    """Window offsets at which a known auth_key_id could open an anchor frame.

    Mirrors :func:`_anchor_candidates`: the id must follow a length header whose
    start lies inside :data:`_ANCHOR_MAX_START` (clipped to the window).
    """
    limit = min(len(window), _ANCHOR_MAX_START)
    header_lengths = {h for t in transports for h in _HEADER_LENGTHS.get(t, ())}
    last = len(window) - _AUTH_KEY_ID_LEN
    return [
        j for j in range(0, last + 1)
        if any(0 <= j - h < limit for h in header_lengths)
    ]


def _keystream_targets(
    window: bytes, positions: List[int], auth_keymap: Dict[bytes, object]
) -> Dict[bytes, List[int]]:
    """``{8 keystream bytes: [window offsets]}`` that would decrypt to a known id.

    Plaintext ``window[j:j+8] ^ ks[o+j:o+j+8]`` equals auth_key_id ``kid`` exactly
    when the keystream there is ``window[j:j+8] ^ kid``; so every (offset, id) pair
    reduces to ONE 8-byte keystream pattern, independent of the unknown lag ``o``.
    """
    kids = [k for k in auth_keymap if isinstance(k, bytes) and len(k) == _AUTH_KEY_ID_LEN]
    targets: Dict[bytes, List[int]] = {}
    for j in positions:
        chunk = window[j : j + _AUTH_KEY_ID_LEN]
        for kid in kids:
            targets.setdefault(_xor_bytes(chunk, kid), []).append(j)
    return targets


def _keystream_hits(keystream: bytes, targets: Dict[bytes, List[int]]) -> set:
    """Target patterns occurring ANYWHERE (any byte offset) in *keystream*.

    One C-level pass per 8-byte residue class: the keystream is viewed as native
    uint64 words starting at byte ``r`` and intersected with the target set, so
    every byte offset is covered without a Python-level loop over the offsets.
    """
    wanted = {int.from_bytes(t, sys.byteorder): t for t in targets}
    wanted_words = set(wanted)
    view = memoryview(keystream)
    found: set = set()
    # The auth_key_id is 8 bytes: scan it as one native uint64 word per offset.
    for r in range(_AUTH_KEY_ID_LEN):
        words = (len(keystream) - r) // _AUTH_KEY_ID_LEN
        if words <= 0:
            continue
        lane = view[r : r + words * _AUTH_KEY_ID_LEN].cast("Q")
        # set.intersection(iterable) probes each word against the small target
        # set in C, never materialising a set of the (huge) keystream itself.
        found.update(wanted[w] for w in wanted_words.intersection(lane))
    return found


def _lag_offsets(
    keystream: bytes,
    targets: Dict[bytes, List[int]],
    max_offset: int,
) -> set:
    """Keystream start offsets ``o`` in ``0..max_offset`` where some target lands."""
    offsets = set()
    for pattern in _keystream_hits(keystream, targets):
        idx = keystream.find(pattern)
        while idx != -1:
            offsets.update(
                idx - j for j in targets[pattern] if 0 <= idx - j <= max_offset
            )
            idx = keystream.find(pattern, idx + 1)
    return offsets


def recover_obf_alignment(
    key: bytes,
    live_counter: bytes,
    num: int,
    run_bytes: bytes,
    auth_keymap: Dict[bytes, object],
    *,
    transport_hint: Optional[str] = None,
    max_blocks: int = DEFAULT_OBF_MAX_BLOCKS,
    direction: Optional[str] = None,
) -> Optional[ObfAlignment]:
    """Recover the CTR alignment that de-obfuscates a mid-stream *run_bytes* tail.

    For a connection captured after it was already open, the 64-byte init block is
    gone, so :func:`detect_transport` cannot key the stream. Instead we hold (from
    live memory) the raw obfuscation ``key`` for one direction plus that
    direction's LIVE CTR state — the 16-byte ``live_counter`` and the byte-phase
    ``num`` — captured while the connection was alive.

    The unknown is the capture LAG: how many bytes separate the tail's last byte
    from the live position. It is searched BYTE-granular (the capture lag is not a
    whole number of AES blocks in general) over ``-16 * max_blocks ..
    16 * max_blocks`` bytes — the negative side covers a pcap that runs PAST the
    snapshot (the counter model is symmetric, so the cap is the same depth). One
    keystream is generated over that whole span and every byte offset of it is
    tested at once for a known auth_key_id right after a plausible length header
    (see :func:`_keystream_hits`); only the few offsets that hit get the full
    two-consecutive-frames anchor check. Candidates are tried smallest ``|lag|``
    first, so a tail ending exactly at the live position wins.

    ``transport_hint`` (the framing already resolved for the other direction)
    constrains the search to that one framing; ``direction`` resolves quick-ack
    flags (see :func:`_parse_frame_header`). Returns an :class:`ObfAlignment` or
    ``None`` when nothing aligns (e.g. the wrong key).
    """
    run_len = len(run_bytes)
    if run_len < _MIN_RECORD_LEN or not auth_keymap or max_blocks < 0:
        return None
    if transport_hint in (ABRIDGED, INTERMEDIATE):
        transports: tuple[str, ...] = (transport_hint,)
    else:
        transports = (ABRIDGED, INTERMEDIATE)

    window = bytes(run_bytes[:_ANCHOR_TEST_WINDOW])
    targets = _keystream_targets(
        window, _anchor_id_positions(window, transports), auth_keymap
    )
    if not targets:
        return None
    max_lag = max_blocks * _COUNTER_LEN
    # Byte position of the tail's first byte relative to the live counter block,
    # at the largest lag (earliest keystream) searched: ``rel(lag) = rel0 - lag``.
    rel0 = num - run_len
    first_block = (rel0 - max_lag) // _COUNTER_LEN
    ks_origin = first_block * _COUNTER_LEN  # rel of keystream byte 0
    max_offset = 2 * max_lag + (rel0 - max_lag - ks_origin)
    span = -(-(max_offset + len(window)) // _COUNTER_LEN) * _COUNTER_LEN
    keystream = deobfuscate_at(key, counter_add(live_counter, first_block), bytes(span))

    offsets = _lag_offsets(keystream, targets, max_offset)
    for offset in sorted(offsets, key=lambda o: (abs(rel0 - ks_origin - o), o)):
        plain = _xor_bytes(window, keystream[offset : offset + len(window)])
        for transport_type in transports:
            start = _find_frame_anchor(
                plain, transport_type, auth_keymap, _ANCHOR_FRAMES, direction
            )
            if start is not None:
                rel = ks_origin + offset
                return ObfAlignment(
                    counter_block=counter_add(live_counter, rel // _COUNTER_LEN),
                    phase=rel % _COUNTER_LEN,
                    frame_offset=start,
                    transport_type=transport_type,
                )
    return None
