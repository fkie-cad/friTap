"""RC4 trial-decryption, candidate extraction, and the offline orchestrator.

Two layers:

  * The **pure trial-decrypt engine** — a byte-for-byte port of the scoring,
    candidate-extraction, and trial-decryption logic in
    ``research/memory_scan_lsass/tools/rc4_trial_decrypt.py``. Output that "looks
    like plaintext" (printable fraction + token bonuses) proves the key. This is
    how a key is recovered from candidate BYTES when none is supplied.

  * The **friTap offline orchestrator** :func:`iter_decrypted_messages` — decides
    NESTED (RC4-in-TLS) vs STANDALONE (RC4-over-raw-TCP) from whether a TLS keylog
    is present, obtains the per-direction RC4 ciphertext via :mod:`.transport`,
    and yields one :class:`DecryptedRc4Message` per recovered direction. Mirrors
    the shape of the Signal/MTProto ``iter_decrypted_messages`` orchestrators.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .crypto import INNER_APPLICATION_DATA, rc4, rc4_prga

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Plaintext scoring — the trial-decrypt validator (port of scorePlaintext/TOKENS
# in agent/rc4_decrypt.js / rc4_trial_decrypt.py: output that looks like
# plaintext proves the key).
# --------------------------------------------------------------------------- #

TOKENS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"HTTP", b"Host:",
          b"User-Agent", b"{", b"</", b": ")


def score_plaintext(data: bytes) -> Tuple[float, float, str]:
    """Return (printable_fraction, score, ascii). score = fraction + token bonus."""
    if not data:
        return 0.0, 0.0, ""
    printable = sum(1 for c in data if c in (9, 10, 13) or 0x20 <= c <= 0x7E)
    frac = printable / len(data)
    ascii_ = "".join(chr(c) if 0x20 <= c <= 0x7E else "." for c in data)
    bonus = sum(0.15 for t in TOKENS if t in data)
    return frac, frac + bonus, ascii_


# --------------------------------------------------------------------------- #
# Candidate-key extraction from a byte blob (offline analogue of the agent's
# scanChunk/runToTrials: ASCII and UTF-16LE printable runs become candidate keys).
# --------------------------------------------------------------------------- #

_ASCII_RUN = re.compile(rb"[\x20-\x7e]+")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00)+")


def _run_to_candidates(run: bytes, min_len: int, max_len: int,
                       max_window_run: int) -> Iterator[bytes]:
    """Yield candidate keys from one printable run.

    Whole run when it is short enough to be a key on its own (the isolated
    allocation case). A longer run is windowed so a key embedded inside a bigger
    printable blob is still found, but ONLY up to ``max_window_run``: a giant blob
    is skipped rather than windowed, so it cannot dominate the candidate set.
    """
    length = len(run)
    if length < min_len:
        return
    if length <= max_len:
        yield run
        return
    if length > max_window_run:
        return  # too long to be (or usefully window for) a key; budget guard
    for start in range(length):
        here = min(max_len, length - start)
        for keylen in range(min_len, here + 1):
            yield run[start:start + keylen]


def extract_candidates(blob: bytes, min_len: int = 5, max_len: int = 64,
                       max_window_run: int = 256) -> Iterator[bytes]:
    """Every candidate key in a blob: ASCII runs and UTF-16LE runs (even printable
    byte, zero odd byte -> decoded to its ASCII bytes)."""
    for m in _ASCII_RUN.finditer(blob):
        yield from _run_to_candidates(m.group(), min_len, max_len, max_window_run)
    for m in _UTF16_RUN.finditer(blob):
        yield from _run_to_candidates(m.group()[::2], min_len, max_len, max_window_run)


@dataclass(frozen=True)
class Rc4Candidate:
    """A recovered RC4 secret to trial-decrypt with.

    ``material`` is either a KEY (fed through the KSA) or, when ``is_sbox`` is
    True, a 256-byte post-KSA S-box PERMUTATION used directly as keystream state
    (i=j=0), skipping the KSA. This lets the recovered S-box artifact
    (``memscan-sbox``) be consumed offline instead of being wrongly KSA'd as a key.
    """

    source: str
    material: bytes
    is_sbox: bool = False

    # Backward-compat: behave like the legacy ``(source, material)`` 2-tuple so
    # existing callers/tests that unpack or index a candidate keep working, while
    # the S-box flag rides along as an attribute.
    def __iter__(self):
        return iter((self.source, self.material))

    def __len__(self) -> int:
        return 2

    def __getitem__(self, idx):
        return (self.source, self.material)[idx]


def _as_candidate(item) -> Rc4Candidate:
    """Normalize a candidate, accepting either an :class:`Rc4Candidate` or a legacy
    ``(source, material)`` 2-tuple (treated as a key, ``is_sbox=False``).

    Keeps every existing caller and test that passes bare 2-tuples working.
    """
    if isinstance(item, Rc4Candidate):
        return item
    source, material = item
    return Rc4Candidate(source=source, material=material, is_sbox=False)


def _apply(cand: Rc4Candidate, data: bytes) -> bytes:
    """Decrypt ``data`` with a candidate: keystream from its S-box directly when it
    is an S-box (skip KSA, i=j=0 — correct for the reset-per-message/framed case),
    else run the full KSA over the key bytes."""
    if cand.is_sbox:
        return rc4_prga(list(cand.material), data)
    return rc4(cand.material, data)


def materialize_candidates(candidates: Iterable[Tuple[str, bytes]]
                           ) -> List[Tuple[str, bytes]]:
    """De-duplicate a candidate stream into a reusable list (each secret tried once).

    Accepts legacy ``(source, key)`` 2-tuples or :class:`Rc4Candidate` objects;
    returns :class:`Rc4Candidate` objects. The dedup key is ``(is_sbox, material)``
    so a 256-byte S-box and a hypothetical 256-byte key never collide.
    """
    seen: set = set()
    out: List[Rc4Candidate] = []
    for item in candidates:
        cand = _as_candidate(item)
        if not cand.material:
            continue
        dedup = (cand.is_sbox, cand.material)
        if dedup not in seen:
            seen.add(dedup)
            out.append(cand)
    return out


# --------------------------------------------------------------------------- #
# Trial decryption
# --------------------------------------------------------------------------- #

def _best_by_prefix_score(ciphertext: bytes, cands: List[Rc4Candidate],
                          prefix: int) -> Optional[Rc4Candidate]:
    """The candidate whose decryption of the first ``prefix`` bytes scores highest."""
    prefix_ct = ciphertext[:prefix] if prefix else ciphertext
    best_cand: Optional[Rc4Candidate] = None
    best_score = 0.0
    for cand in cands:
        _frac, sc, _ = score_plaintext(_apply(cand, prefix_ct))
        if best_cand is None or sc > best_score:
            best_cand, best_score = cand, sc
    return best_cand


def _best_containing(ciphertext: bytes, cands: List[Rc4Candidate],
                     known_plaintext: bytes) -> Optional[Rc4Candidate]:
    """The best-scoring candidate whose FULL decryption contains ``known_plaintext``.

    known_plaintext is exact evidence, so it must drive the choice: a wrong key
    whose prefix happens to look more printable must never shadow the proven one.
    """
    best_cand: Optional[Rc4Candidate] = None
    best_score = 0.0
    for cand in cands:
        full = _apply(cand, ciphertext)
        if known_plaintext not in full:
            continue
        _frac, sc, _ = score_plaintext(full)
        if best_cand is None or sc > best_score:
            best_cand, best_score = cand, sc
    return best_cand


def _key_ascii(cand: Rc4Candidate) -> Optional[str]:
    """ASCII form of a key candidate; None for an S-box or non-ASCII key."""
    if cand.is_sbox:
        return None  # An S-box permutation has no meaningful ASCII key form.
    try:
        return cand.material.decode("ascii")
    except UnicodeDecodeError:
        return None


def _decrypt_result(cand: Rc4Candidate, ciphertext: bytes, accept: float,
                    known_plaintext: Optional[bytes]) -> dict:
    """Run ``cand`` over the whole ciphertext and build the result dict.

    Acceptance = EXACT evidence when available, else the strict combined score.
    known_plaintext is exact proof (RC4 keystream reproduces known bytes), so it
    overrides the fuzzy printability score; without it, require frac + token-bonus
    >= accept (NOT the old "printable OR has any token byte" clause, which let
    ~random output containing a single token byte like b"{" pass as plaintext).
    """
    full = _apply(cand, ciphertext)
    frac, sc, ascii_ = score_plaintext(full)
    accepted = (known_plaintext in full) if known_plaintext else (sc >= accept)
    return {
        "key": cand.material,
        "source": cand.source,
        "score": sc,
        "printable_fraction": frac,
        "is_sbox": cand.is_sbox,
        "key_hex": cand.material.hex(),
        "key_ascii": _key_ascii(cand),
        "plaintext": full,
        "plaintext_hex": full.hex(),
        "plaintext_ascii": ascii_,
        "accepted": accepted,
    }


def trial_decrypt(ciphertext: bytes, candidates: Iterable[Tuple[str, bytes]],
                  prefix: int = 64, accept: float = 0.85,
                  known_plaintext: Optional[bytes] = None) -> Optional[dict]:
    """Trial-decrypt ``ciphertext`` against (source, key) candidates; keep the best.

    With ``known_plaintext``, the winner is the best-scoring candidate whose full
    decryption CONTAINS it; only when no candidate does, the ranking falls back to
    the prefix score (and the result is then reported as not accepted). Without it,
    each key decrypts the first ``prefix`` bytes and the highest score wins.
    Returns a result dict (with an ``accepted`` flag) or None when there were no
    candidates.
    """
    cands = materialize_candidates(candidates)
    best_cand = None
    if known_plaintext:
        best_cand = _best_containing(ciphertext, cands, known_plaintext)
    if best_cand is None:
        best_cand = _best_by_prefix_score(ciphertext, cands, prefix)
    if best_cand is None:
        return None
    return _decrypt_result(best_cand, ciphertext, accept, known_plaintext)


# --------------------------------------------------------------------------- #
# Framed RC4 (length-prefixed, re-keyed per frame).
#
# A continuous RC4 stream (one keystream per direction from byte 0) is the common
# case that :func:`trial_decrypt` on the whole direction handles. But some protocols
# frame each message as ``[length][RC4(message)]`` and RE-KEY RC4 per frame (a fresh
# key schedule each message). Then the concatenated direction is NOT one keystream, so
# a whole-blob decrypt fails; each frame must be located by its length prefix and
# decrypted independently. friTap's own RC4-in-TLS fixture (tls13_rc4_chat.ps1) does
# exactly this, and the live agent recovers it frame-by-frame — this is the offline
# counterpart. Auto-detected: the caller tries the continuous path first and only falls
# back here, so real continuous RC4 is unaffected.
# --------------------------------------------------------------------------- #

# A frame length header wider than this is treated as "not a frame boundary" — guards
# against misreading random bytes as a huge length on a non-framed (continuous) stream.
_MAX_FRAME_LEN = 1 << 20  # 1 MiB


@dataclass(frozen=True)
class FrameSpan:
    """One ``[length][payload]`` frame located in its direction's blob.

    ``offset`` is where the frame's length HEADER starts; the payload starts at
    ``offset + header_len``.
    """

    offset: int
    header_len: int
    payload: bytes


def parse_length_prefixed_frame_spans(blob: bytes, *, length_size: int = 4,
                                      big_endian: bool = True,
                                      max_frame_len: int = _MAX_FRAME_LEN
                                      ) -> Optional[List[FrameSpan]]:
    """Parse ``blob`` as consecutive ``[length][payload]`` frames, with offsets.

    Returns one :class:`FrameSpan` per frame when the blob parses cleanly into
    whole frames (no trailing garbage, every length in range), else ``None`` — so
    a continuous (non-framed) stream is rejected rather than mis-split.
    """
    order = "big" if big_endian else "little"
    spans: List[FrameSpan] = []
    i, n = 0, len(blob)
    while i < n:
        if i + length_size > n:
            return None  # dangling partial header -> not cleanly framed
        length = int.from_bytes(blob[i:i + length_size], order)
        start = i
        i += length_size
        if length <= 0 or length > max_frame_len or i + length > n:
            return None
        spans.append(FrameSpan(start, length_size, blob[i:i + length]))
        i += length
    return spans or None


def parse_length_prefixed_frames(blob: bytes, *, length_size: int = 4,
                                 big_endian: bool = True,
                                 max_frame_len: int = _MAX_FRAME_LEN) -> Optional[list]:
    """Parse ``blob`` as consecutive ``[length][payload]`` frames.

    Returns the list of payload ``bytes`` when the blob parses cleanly into whole
    frames (no trailing garbage, every length in range), else ``None`` — so a
    continuous (non-framed) stream is rejected rather than mis-split. Thin view
    over :func:`parse_length_prefixed_frame_spans`.
    """
    spans = parse_length_prefixed_frame_spans(
        blob, length_size=length_size, big_endian=big_endian,
        max_frame_len=max_frame_len)
    return [span.payload for span in spans] if spans else None


def _tag_frame(result: dict, offset: int, header_len: int) -> dict:
    """Record where ``result``'s ciphertext sits in its direction's blob:
    ``frame_offset`` (start of the length header) and ``frame_header_len``."""
    result["frame_offset"] = offset
    result["frame_header_len"] = header_len
    return result


def _proven_frame_key(frames: list, cands: List[Rc4Candidate],
                      known_plaintext: bytes) -> Optional[Rc4Candidate]:
    """The best candidate proven by ``known_plaintext`` across the framed direction.

    A candidate is proven when the marker occurs in one of its per-frame
    decryptions OR in their concatenation (a marker spanning a frame boundary).
    Among proven candidates the highest total plaintext score wins.
    """
    best_cand: Optional[Rc4Candidate] = None
    best_score = 0.0
    for cand in cands:
        plains = [_apply(cand, fr) for fr in frames]
        if known_plaintext not in b"".join(plains):
            continue
        total = sum(score_plaintext(p)[1] for p in plains)
        if best_cand is None or total > best_score:
            best_cand, best_score = cand, total
    return best_cand


def _decrypt_frames_with_known_plaintext(frames: list, cands: List[Rc4Candidate],
                                         accept: float,
                                         known_plaintext: bytes,
                                         frame_spans: Optional[List[FrameSpan]] = None
                                         ) -> list:
    """Decrypt every frame with the key proven by ``known_plaintext``.

    The frame(s) carrying the marker are accepted on that exact evidence (a marker
    spanning frames accepts the frames it touches); every other frame decrypted
    with the proven key must still pass the normal score gate. With
    ``frame_spans`` (parallel to ``frames``) each result carries its frame's
    ``frame_offset``/``frame_header_len``; without, both are 0.
    """
    key = _proven_frame_key(frames, cands, known_plaintext)
    if key is None:
        return []
    results = [_decrypt_result(key, fr, accept, None) for fr in frames]
    for idx, res in enumerate(results):
        span = frame_spans[idx] if frame_spans else None
        _tag_frame(res, span.offset if span else 0, span.header_len if span else 0)
    for idx in _frames_touching_marker([r["plaintext"] for r in results],
                                       known_plaintext):
        results[idx]["accepted"] = True
    return [r for r in results if r["accepted"]]


def _frames_touching_marker(plains: list, marker: bytes) -> set:
    """Indices of the frames that hold any byte of an occurrence of ``marker`` in
    the concatenation of ``plains``."""
    joined = b"".join(plains)
    bounds, pos = [], 0
    for p in plains:
        bounds.append((pos, pos + len(p)))
        pos += len(p)
    touched: set = set()
    hit = joined.find(marker)
    while hit != -1:
        end = hit + len(marker)
        touched.update(i for i, (lo, hi) in enumerate(bounds) if lo < end and hi > hit)
        hit = joined.find(marker, hit + 1)
    return touched


def decrypt_framed(ciphertext: bytes, candidates: Iterable[Tuple[str, bytes]],
                   prefix: int = 64, accept: float = 0.85,
                   known_plaintext: Optional[bytes] = None) -> list:
    """Decrypt a length-prefixed, per-frame-re-keyed RC4 direction.

    Parses ``[4-byte big-endian length][RC4 frame]`` records and trial-decrypts each
    frame independently. Returns a list of per-frame result dicts (same shape as
    :func:`trial_decrypt`) for the ACCEPTED frames, or ``[]`` when the blob is not
    cleanly framed or nothing decrypts (so the caller keeps the continuous result).

    ``known_plaintext`` semantics: it selects the KEY, not the frames. The key is
    the candidate whose frame decryptions contain the marker (inside one frame, or
    across a frame boundary); the frames holding the marker are accepted on that
    exact proof, and every other frame is decrypted with the same key and accepted
    by the normal score gate. No candidate containing the marker -> ``[]``.
    """
    cand_list = materialize_candidates(candidates)
    if not cand_list:
        return []
    spans = parse_length_prefixed_frame_spans(ciphertext)
    if not spans:
        return []
    frames = [span.payload for span in spans]
    if known_plaintext:
        return _decrypt_frames_with_known_plaintext(frames, cand_list, accept,
                                                    known_plaintext, spans)
    results = []
    for span in spans:
        r = trial_decrypt(span.payload, cand_list, prefix=prefix, accept=accept)
        if r is not None and r["accepted"]:
            results.append(_tag_frame(r, span.offset, span.header_len))
    return results


# --------------------------------------------------------------------------- #
# Nested TLS 1.3 record path (pure Python, no tshark) — used by the record-level
# tests and by a caller that supplies a raw traffic secret rather than a keylog.
# --------------------------------------------------------------------------- #

def rc4_cts_from_inners(inners: Iterable[bytes]) -> List[bytes]:
    """TLS 1.3 inner plaintexts -> the application_data record bodies (RC4 ct).

    Each inner plaintext is content || content_type || zeros; strip the zeros,
    then the 1-byte type, and keep only application_data (0x17) bodies.
    """
    out: List[bytes] = []
    for inner in inners:
        stripped = inner.rstrip(b"\x00")
        if not stripped:
            continue
        if stripped[-1] == INNER_APPLICATION_DATA and len(stripped) > 1:
            out.append(stripped[:-1])
    return out


def decrypt_records_with_candidates(records, suite: str, secret_hex: str,
                                    candidates: List[Tuple[str, bytes]],
                                    prefix: int = 64, accept: float = 0.85,
                                    known_plaintext: Optional[bytes] = None):
    """Peel TLS 1.3 off one direction's ``records`` with the traffic ``secret_hex``,
    then RC4 trial-decrypt each application_data body. Returns [(ct, result), ...]."""
    from . import crypto

    inners = crypto.decrypt_stream(secret_hex, records, suite)
    results = []
    for ct in rc4_cts_from_inners(inners):
        r = trial_decrypt(ct, candidates, prefix, accept,
                          known_plaintext=known_plaintext)
        if r is not None:
            results.append((ct, r))
    return results


# --------------------------------------------------------------------------- #
# friTap offline orchestrator
# --------------------------------------------------------------------------- #

@dataclass
class DecryptedRc4Message:
    """One RC4-decrypted directional payload (fed to the flow as a chunk)."""

    src_addr: str
    src_port: int
    dst_addr: str
    dst_port: int
    ss_family: str          # "AF_INET" | "AF_INET6"
    direction: str          # "read" (server->client) | "write" (client->server)
    message: bytes          # the recovered plaintext bytes
    key: bytes              # the RC4 key that recovered it
    source: str             # candidate source / keylog hook that supplied the key
    nested: bool            # True when peeled out of TLS first
    # Provenance (defaults when the stream carries no TLS spans):
    timestamp: float = 0.0  # pcap time of the last TLS frame the message used
    tls_frames: tuple = ()  # TLS frame numbers holding its prefix + ciphertext
    cipher_offset: int = 0  # ciphertext start in the directional TLS plaintext
    cipher_len: int = 0     # ciphertext length (== len(message), RC4 is 1:1)
    frame_header_len: int = 0  # length-prefix bytes before the ciphertext


def _provenance(stream, direction: str, result: dict) -> dict:
    """Provenance fields of one decrypt ``result`` from ``stream``'s TLS spans.

    The covered range is the frame's header plus its ciphertext; a continuous
    (unframed) result has offset 0 and header 0. Returns ``{}`` (dataclass
    defaults) when the stream has no spans for ``direction``.
    """
    from ..tls_spans import spans_covering

    spans = (getattr(stream, "spans", None) or {}).get(direction)
    if not spans:
        return {}
    offset = result.get("frame_offset", 0)
    header_len = result.get("frame_header_len", 0)
    cipher_len = len(result["plaintext"])
    covering = spans_covering(spans, offset, offset + header_len + cipher_len)
    frames = tuple(dict.fromkeys(span.frame_no for span in covering))
    return {
        "timestamp": covering[-1].ts if covering else 0.0,
        "tls_frames": frames,
        "cipher_offset": offset + header_len,
        "cipher_len": cipher_len,
        "frame_header_len": header_len,
    }


@dataclass
class Rc4Stats:
    """Counters for one :func:`iter_decrypted_messages` run."""

    streams: int = 0
    messages: int = 0
    streams_degraded: int = 0
    directions_undecryptable: int = 0

    def add_stream(self) -> None:
        self.streams += 1

    def add_message(self) -> None:
        self.messages += 1

    def add_degraded(self) -> None:
        self.streams_degraded += 1

    def add_undecryptable(self) -> None:
        self.directions_undecryptable += 1

    @property
    def records_undecryptable(self) -> int:  # naming parity with the other stats
        return self.directions_undecryptable


def iter_decrypted_messages(
    pcap_path: str,
    candidates: List[Tuple[str, bytes]],
    *,
    tls_keylog_path: Optional[str] = None,
    tshark_bin: Optional[str] = None,
    tls_ports: Tuple[int, ...] = (),
    server_ports: Tuple[int, ...] = (443, 80),
    accept: float = 0.85,
    known_plaintext: Optional[bytes] = None,
    stats: Optional[Rc4Stats] = None,
    streams: Optional[Iterable] = None,
) -> Iterator[DecryptedRc4Message]:
    """Yield every RC4-decryptable directional payload from ``pcap_path``.

    Dual-mode, decided purely by ``tls_keylog_path``:

      * **nested** (a TLS keylog is present): tshark strips the outer TLS 1.3
        layer first (via :func:`.transport.nested_rc4_streams`, which reuses the
        SAME ``list_tls_streams``/``follow_tls_stream`` helpers the Signal emitter
        uses); the decrypted TLS plaintext IS the RC4 ciphertext, from which RC4
        is stripped.
      * **standalone** (no TLS keylog): RC4 is the outer cipher over raw TCP;
        :func:`.transport.standalone_rc4_streams` reassembles each TCP direction
        and RC4 is stripped directly.

    For each direction the best-scoring candidate key wins (:func:`trial_decrypt`);
    an accepted decrypt becomes one :class:`DecryptedRc4Message`.

    ``streams`` (e.g. :func:`.transport.rc4_streams_from_spans` over the TLS
    single pass's span store) replaces the tshark/reassembly source entirely and
    is treated as nested; streams carrying spans fill each message's provenance
    (timestamp, TLS frames, cipher offset/length).
    """
    from .transport import nested_rc4_streams, standalone_rc4_streams

    if stats is None:
        stats = Rc4Stats()

    nested = bool(tls_keylog_path) or streams is not None
    if streams is not None:
        stream_iter = iter(streams)
    elif nested:
        stream_iter = nested_rc4_streams(
            pcap_path, tls_keylog_path, tshark_bin=tshark_bin, tls_ports=tls_ports,
        )
    else:
        stream_iter = standalone_rc4_streams(pcap_path, server_ports=server_ports)

    for stream in stream_iter:
        stats.add_stream()
        # Candidate keys can be enriched from the ciphertext bytes themselves when
        # no explicit key was supplied (a key sometimes travels in-band); the
        # keylog keys always take priority in trial ordering.
        for direction, ciphertext in stream.directions.items():
            if not ciphertext:
                continue
            cands = candidates
            if not cands:
                cands = materialize_candidates(
                    ("candidate-bytes", k) for k in extract_candidates(ciphertext)
                )
            # Try the CONTINUOUS-stream interpretation first (one keystream per
            # direction — the common case). If that does not decrypt, fall back to
            # the FRAMED interpretation ([len][RC4 frame], re-keyed per frame), which
            # yields one message per frame. Auto-detected, so real continuous RC4 is
            # unaffected and a framed protocol (the RC4-in-TLS fixture) still decrypts.
            per_direction: list = []
            result = trial_decrypt(ciphertext, cands, accept=accept,
                                   known_plaintext=known_plaintext)
            if result is not None and result["accepted"]:
                per_direction = [_tag_frame(result, 0, 0)]
            else:
                per_direction = decrypt_framed(ciphertext, cands, accept=accept,
                                               known_plaintext=known_plaintext)
            if not per_direction:
                stats.add_undecryptable()
                continue
            if direction == "write":
                src_addr, src_port = stream.client_addr
                dst_addr, dst_port = stream.server_addr
            else:
                src_addr, src_port = stream.server_addr
                dst_addr, dst_port = stream.client_addr
            for result in per_direction:
                stats.add_message()
                yield DecryptedRc4Message(
                    src_addr=src_addr,
                    src_port=src_port,
                    dst_addr=dst_addr,
                    dst_port=dst_port,
                    ss_family=stream.ss_family,
                    direction=direction,
                    message=result["plaintext"],
                    key=result["key"],
                    source=result["source"],
                    nested=nested,
                    **_provenance(stream, direction, result),
                )
