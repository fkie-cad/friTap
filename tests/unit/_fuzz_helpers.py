"""Stdlib-only seeded mutation fuzzing helpers for the parser fuzz suite.

Everything is deterministic: a ``random.Random`` seeded with a string (which
CPython hashes with SHA-512, independent of ``PYTHONHASHSEED``) drives every
mutation, so a failing case reproduces exactly from its pytest id.

A *transcript* is a list of :class:`Feed` objects: the chunks one parser
instance receives in order (direction label, optional QUIC stream id, bytes,
and optional hints where length fields live so the length-inflation mutator
can aim at them).
"""

from __future__ import annotations

import contextlib
import random
import signal
import struct
import time
import traceback
import tracemalloc
from dataclasses import dataclass, field, replace
from typing import Callable, Iterable, Optional

import pytest

MIB = 1024 * 1024
MAX_CASE_SECONDS = 2.0
MAX_CASE_PEAK_BYTES = 64 * MIB
# Hard wall-clock guard that turns a hang into a test failure instead of a
# stuck suite. Above the per-case 2 s budget (asserted separately with
# perf_counter) so a merely slow input reports its real duration.
HANG_GUARD_SECONDS = 5.0
# tracemalloc slows Python down several times; trace every Nth input only.
TRACE_EVERY = 5
# Hang-guard stretch for the memory-only traced run: tracemalloc's slowdown
# (~3.6x measured for allocation-heavy TL decoding on CPython 3.11) must not
# turn a merely traced run into a reported hang.
TRACED_HANG_FACTOR = 3.0

INTERESTING_BYTES = (0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF)


@dataclass(frozen=True)
class Feed:
    """One ``parser.feed`` call."""

    direction: str
    data: bytes
    stream_id: Optional[int] = None
    length_offsets: tuple[int, ...] = field(default=(), compare=False)


def make_rng(target: str, seed: int) -> random.Random:
    """Deterministic RNG for (*target*, *seed*)."""
    return random.Random(f"fritap-fuzz:{target}:{seed}")


# --------------------------------------------------------------------------- #
# Byte-level mutators: (rng, data, hints, other) -> bytes
# --------------------------------------------------------------------------- #

def bit_flip(rng: random.Random, data: bytes, _hints=(), _other=b"") -> bytes:
    if not data:
        return data
    buf = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        pos = rng.randrange(len(buf))
        buf[pos] ^= 1 << rng.randrange(8)
    return bytes(buf)


def byte_replace(rng: random.Random, data: bytes, _hints=(), _other=b"") -> bytes:
    if not data:
        return data
    buf = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        pos = rng.randrange(len(buf))
        buf[pos] = rng.choice(INTERESTING_BYTES) if rng.random() < 0.5 else rng.randrange(256)
    return bytes(buf)


def truncate(rng: random.Random, data: bytes, _hints=(), _other=b"") -> bytes:
    return data[:rng.randrange(len(data) + 1)]


def insert_random(rng: random.Random, data: bytes, _hints=(), _other=b"") -> bytes:
    pos = rng.randrange(len(data) + 1)
    blob = bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
    return data[:pos] + blob + data[pos:]


def inflate_length(rng: random.Random, data: bytes, hints=(), _other=b"") -> bytes:
    """Overwrite 1..8 bytes at a (hinted) length-field offset with a big value."""
    if not data:
        return data
    pos = rng.choice(hints) if hints and rng.random() < 0.8 else rng.randrange(len(data))
    pos = min(pos, len(data) - 1)
    width = rng.randint(1, 8)
    big = rng.choice((
        b"\xff" * width,
        b"\x7f" + b"\xff" * (width - 1),
        (1 << 30).to_bytes(8, "big")[-width:],
        struct.pack(">Q", rng.getrandbits(64))[:width],
    ))
    return data[:pos] + big + data[pos + len(big):]


def splice(rng: random.Random, data: bytes, _hints=(), other=b"") -> bytes:
    if not other:
        return data
    return data[:rng.randrange(len(data) + 1)] + other[rng.randrange(len(other) + 1):]


def repeat_slice(rng: random.Random, data: bytes, _hints=(), _other=b"") -> bytes:
    """Duplicate a slice many times (frame floods, repeated headers)."""
    if not data:
        return data
    start = rng.randrange(len(data))
    end = min(len(data), start + rng.randint(1, 64))
    return data[:end] + data[start:end] * rng.randint(2, 200) + data[end:]


BYTE_MUTATORS: tuple[Callable, ...] = (
    bit_flip, byte_replace, truncate, insert_random, inflate_length, splice, repeat_slice,
)


def mutate_bytes(rng: random.Random, data: bytes, hints: Iterable[int] = (),
                 other: bytes = b"", rounds: Optional[int] = None) -> bytes:
    """Apply 1..3 random byte mutators to *data*."""
    hints = tuple(hints)
    for _ in range(rounds or rng.randint(1, 3)):
        data = rng.choice(BYTE_MUTATORS)(rng, data, hints, other)
    return data


# --------------------------------------------------------------------------- #
# Transcript-level mutators
# --------------------------------------------------------------------------- #

def chunk_split(rng: random.Random, feeds: list[Feed], max_chunk: int = 64) -> list[Feed]:
    """Re-split every feed into random 1..max_chunk byte chunks (reassembly)."""
    out: list[Feed] = []
    for feed in feeds:
        pos = 0
        if not feed.data:
            out.append(feed)
        while pos < len(feed.data):
            size = rng.randint(1, max_chunk)
            out.append(replace(feed, data=feed.data[pos:pos + size], length_offsets=()))
            pos += size
    return out


def swap_directions(_rng: random.Random, feeds: list[Feed]) -> list[Feed]:
    flip = {"read": "write", "write": "read"}
    return [replace(f, direction=flip.get(f.direction, f.direction)) for f in feeds]


def mutate_one_feed(rng: random.Random, feeds: list[Feed], other: bytes = b"") -> list[Feed]:
    if not feeds:
        return feeds
    idx = rng.randrange(len(feeds))
    feed = feeds[idx]
    data = mutate_bytes(rng, feed.data, feed.length_offsets, other)
    return feeds[:idx] + [replace(feed, data=data)] + feeds[idx + 1:]


def splice_transcripts(rng: random.Random, feeds: list[Feed], other: list[Feed]) -> list[Feed]:
    if not other:
        return feeds
    return feeds[:rng.randrange(len(feeds) + 1)] + other[rng.randrange(len(other) + 1):]


def drop_or_duplicate(rng: random.Random, feeds: list[Feed]) -> list[Feed]:
    if not feeds:
        return feeds
    idx = rng.randrange(len(feeds))
    if rng.random() < 0.5:
        return feeds[:idx] + feeds[idx + 1:]
    return feeds[:idx + 1] + [feeds[idx]] * rng.randint(1, 20) + feeds[idx + 1:]


def mutate_transcript(rng: random.Random, feeds: list[Feed], pool: list[list[Feed]],
                      allow_swap: bool = True) -> list[Feed]:
    """Apply 1..3 transcript mutations; byte-level mutation is the most likely."""
    feeds = list(feeds)
    other = rng.choice(pool) if pool else []
    other_bytes = rng.choice(other).data if other else b""
    for _ in range(rng.randint(1, 3)):
        op = rng.random()
        if op < 0.55:
            feeds = mutate_one_feed(rng, feeds, other_bytes)
        elif op < 0.70:
            feeds = chunk_split(rng, feeds, rng.choice((1, 3, 16, 64, 512)))
        elif op < 0.80 and allow_swap:
            feeds = swap_directions(rng, feeds)
        elif op < 0.90:
            feeds = splice_transcripts(rng, feeds, other)
        else:
            feeds = drop_or_duplicate(rng, feeds)
    return feeds


def describe_transcript(feeds: list[Feed]) -> str:
    """Reproducer text: one ``direction sid hex`` line per feed."""
    return "\n".join(
        f"  ({f.direction!r}, {f.stream_id!r}, bytes.fromhex({f.data.hex()!r})),"
        for f in feeds
    )


# --------------------------------------------------------------------------- #
# Contract enforcement
# --------------------------------------------------------------------------- #

class HangGuardTimeout(Exception):
    """Raised by the SIGALRM hang guard."""


@contextlib.contextmanager
def hang_guard(seconds: float = HANG_GUARD_SECONDS):
    """Raise :class:`HangGuardTimeout` after *seconds* (POSIX main thread only)."""
    if not hasattr(signal, "setitimer"):
        yield
        return

    def _on_alarm(_signum, _frame):
        raise HangGuardTimeout(f"input did not finish within {seconds} s")

    try:
        previous = signal.signal(signal.SIGALRM, _on_alarm)
    except ValueError:  # not the main thread
        yield
        return
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def run_contract(label: str, action: Callable[[], object], reproducer: str,
                 allowed: tuple[type[BaseException], ...] = (),
                 trace_memory: bool = False,
                 hang_seconds: float = HANG_GUARD_SECONDS) -> None:
    """Run *action* and enforce exception, time and memory contracts.

    The time budget is asserted on an untraced run. With *trace_memory* the
    (deterministic) action runs a second time under ``tracemalloc`` for the
    memory budget only: tracemalloc's per-allocation hook slows
    allocation-heavy parsers ~1.4-3.6x depending on the CPython version, so a
    traced wall-clock measures the profiler rather than the parser.
    """
    elapsed = _timed_run(label, action, reproducer, allowed, hang_seconds)
    assert elapsed < MAX_CASE_SECONDS, (
        f"{label}: took {elapsed:.2f} s (> {MAX_CASE_SECONDS} s)\nreproducer:\n{reproducer}")
    if not trace_memory:
        return
    peak = _traced_peak(label, action, reproducer, allowed, hang_seconds * TRACED_HANG_FACTOR)
    assert peak < MAX_CASE_PEAK_BYTES, (
        f"{label}: tracemalloc peak {peak / MIB:.1f} MiB\nreproducer:\n{reproducer}")


def _run_guarded(label: str, action: Callable[[], object], reproducer: str,
                 allowed: tuple[type[BaseException], ...], hang_seconds: float) -> None:
    """Run *action* under the hang guard; fail on any exception not in *allowed*."""
    try:
        with hang_guard(hang_seconds):
            action()
    except allowed:
        pass
    except Exception as exc:  # noqa: BLE001 - this IS the contract check
        pytest.fail(
            f"{label}: uncaught {type(exc).__name__}: {exc}\n"
            f"reproducer:\n{reproducer}\n{traceback.format_exc()}",
            pytrace=False,
        )


def _timed_run(label: str, action: Callable[[], object], reproducer: str,
               allowed: tuple[type[BaseException], ...], hang_seconds: float) -> float:
    """Wall-clock seconds of one untraced, guarded run of *action*."""
    start = time.perf_counter()
    _run_guarded(label, action, reproducer, allowed, hang_seconds)
    return time.perf_counter() - start


def _traced_peak(label: str, action: Callable[[], object], reproducer: str,
                 allowed: tuple[type[BaseException], ...], hang_seconds: float) -> int:
    """``tracemalloc`` peak bytes of one guarded run of *action*."""
    tracemalloc.start()
    try:
        _run_guarded(label, action, reproducer, allowed, hang_seconds)
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def drive_parser(parser, feeds: list[Feed]) -> None:
    """Feed every chunk, then flush; results must be lists."""
    for feed in feeds:
        if feed.stream_id is None:
            results = parser.feed(feed.data, feed.direction)
        else:
            results = parser.feed(feed.data, feed.direction, stream_id=feed.stream_id)
        assert isinstance(results, list), f"feed returned {type(results).__name__}"
    assert isinstance(parser.flush(), list)


def fuzz_parser_transcripts(target: str, seed: int, parser_factory: Callable,
                            pool: list[list[Feed]], mutants: int,
                            allow_swap: bool = True) -> None:
    """Run *mutants* mutated transcripts directly and via SafeParserAdapter."""
    from friTap.parsers.base import SafeParserAdapter

    rng = make_rng(target, seed)
    base = pool[seed % len(pool)]
    for index in range(mutants):
        feeds = mutate_transcript(rng, base, pool, allow_swap)
        repro = describe_transcript(feeds)
        trace = index % TRACE_EVERY == 0
        label = f"{target}[seed={seed},mutant={index}]"
        run_contract(label + " direct", lambda: drive_parser(parser_factory(), feeds),
                     repro, trace_memory=trace)
        run_contract(label + " adapter",
                     lambda: drive_parser(SafeParserAdapter(parser_factory()), feeds), repro)


def fuzz_bytes_function(target: str, seed: int, seeds: list[bytes],
                        action: Callable[[bytes, random.Random], object],
                        allowed: tuple[type[BaseException], ...], mutants: int,
                        hints: Callable[[bytes], Iterable[int]] = lambda _d: ()) -> None:
    """Run *mutants* mutated byte inputs through *action* under the contract."""
    rng = make_rng(target, seed)
    base = seeds[seed % len(seeds)]
    for index in range(mutants):
        data = mutate_bytes(rng, base, hints(base), rng.choice(seeds))
        label = f"{target}[seed={seed},mutant={index}]"
        call_seed = rng.getrandbits(32)  # fresh RNG per run: timed and traced runs match
        run_contract(label, lambda: action(data, random.Random(call_seed)),
                     f"  bytes.fromhex({data.hex()!r})", allowed,
                     trace_memory=index % TRACE_EVERY == 0)
