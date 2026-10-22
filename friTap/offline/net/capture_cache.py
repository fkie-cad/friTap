"""Share one scapy parse of a capture across the decryptors of one conversion.

Several offline stages reassemble the same pcap's TCP conversations (mid-stream
TLS binding, MTProto, standalone RC4), each through
:func:`friTap.offline.net.tcp_reassembly.reassemble_pcap`. Inside a
:func:`capture_cache_scope` for that file, the first of them parses it with
:func:`~friTap.offline.net.tcp_reassembly.parse_pcap` and the rest reuse the
:class:`~friTap.offline.net.tcp_reassembly.ParsedCapture` (each still gets its own
pairs, oriented for its own server ports).

The scope lives in a :class:`~contextvars.ContextVar`, so it is visible only to
code running inside it (and is restored on exit, nested scopes included). The
cache is keyed on ``(realpath, size, mtime_ns)``: another file, or this file once
modified, bypasses it. Captures larger than ``FRITAP_PCAP_CACHE_MAX_MB``
(default 256; ``0`` disables caching; non-numeric or non-finite values fall back
to the default) are never held, and a parse that raises is never memoized, so the
next caller retries it. A scope told that fewer than two reassemblies will run
inside it caches nothing, so a lone consumer never pays the retained memory.
"""

from __future__ import annotations

import logging
import math
import os
import time
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional, Tuple

from . import tcp_reassembly

logger = logging.getLogger(__name__)

MAX_MB_ENV = "FRITAP_PCAP_CACHE_MAX_MB"
DEFAULT_MAX_MB = 256

CaptureKey = Tuple[str, int, int]  # (realpath, st_size, st_mtime_ns)


def capture_key(path: str) -> Optional[CaptureKey]:
    """``(realpath, size, mtime_ns)`` of *path*, or None when it cannot be stat'ed."""
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return (os.path.realpath(path), stat.st_size, stat.st_mtime_ns)


def max_cache_bytes() -> int:
    """The size limit from ``FRITAP_PCAP_CACHE_MAX_MB`` (0 = caching disabled)."""
    raw = os.environ.get(MAX_MB_ENV, "").strip()
    try:
        megabytes = float(raw) if raw else DEFAULT_MAX_MB
    except ValueError:
        megabytes = None
    if megabytes is None or not math.isfinite(megabytes):
        # "inf"/"nan"/"1e400" parse as floats but cannot become a byte count.
        logger.debug("Ignoring invalid %s=%r", MAX_MB_ENV, raw)
        megabytes = DEFAULT_MAX_MB
    try:
        return max(0, int(megabytes * 1024 * 1024))
    except (OverflowError, ValueError):  # defensive: finite yet unrepresentable
        logger.debug("Ignoring invalid %s=%r", MAX_MB_ENV, raw)
        return DEFAULT_MAX_MB * 1024 * 1024


class CaptureCache:
    """Holds at most one parse: the scope's capture, while it is unchanged."""

    def __init__(self, path: str, max_bytes: int) -> None:
        self.key = capture_key(path)
        self.max_bytes = max_bytes
        self.parse_count = 0
        self._parsed: Optional[tcp_reassembly.ParsedCapture] = None

    def lookup(self, path: str) -> Optional[tcp_reassembly.ParsedCapture]:
        """The shared parse of *path*, parsing it on first use; None to bypass."""
        key = capture_key(path)
        if key is None or key != self.key:
            logger.debug("Capture cache bypassed for %s (not the scope's capture "
                         "or modified since the scope opened)", path)
            return None
        if key[1] > self.max_bytes:
            logger.debug("Capture cache bypassed for %s (%d bytes > limit %d)",
                         path, key[1], self.max_bytes)
            return None
        if self._parsed is None:
            self._parsed = self._parse(path)
        return self._parsed

    def _parse(self, path: str) -> tcp_reassembly.ParsedCapture:
        start = time.perf_counter()
        # Looked up on the module so a test (or the bench) can wrap parse_pcap.
        parsed = tcp_reassembly.parse_pcap(path)  # an error propagates, unmemoized
        self.parse_count += 1
        logger.debug("Capture cache parsed %s: %d TCP conversation(s) in %.2fs",
                     path, len(parsed), time.perf_counter() - start)
        return parsed


_ACTIVE_CACHE: ContextVar[Optional[CaptureCache]] = ContextVar(
    "fritap_capture_cache", default=None)


def active_parsed_capture(path: str) -> Optional[tcp_reassembly.ParsedCapture]:
    """The active scope's shared parse of *path*, or None (caller parses itself)."""
    cache = _ACTIVE_CACHE.get()
    return cache.lookup(path) if cache is not None else None


@contextmanager
def capture_cache_scope(
    path: str, expected_consumers: Optional[int] = None,
) -> Iterator[Optional[CaptureCache]]:
    """Share one parse of *path* among the reassemblies run inside this block.

    Yields the :class:`CaptureCache` (``parse_count`` tells how often it parsed),
    or None when caching is disabled (``FRITAP_PCAP_CACHE_MAX_MB=0``), in which
    case any enclosing scope is hidden too. The previous scope is restored on exit
    and the parse is released with the scope.

    *expected_consumers* is the caller's upper bound on how many reassemblies will
    run inside the block. Below two there is nothing to share, so caching is
    disabled (as above) rather than holding the parse in memory for the whole
    block; None (the default) means unknown and always caches.
    """
    max_bytes = max_cache_bytes()
    worth_sharing = expected_consumers is None or expected_consumers >= 2
    cache = CaptureCache(path, max_bytes) if max_bytes > 0 and worth_sharing else None
    token = _ACTIVE_CACHE.set(cache)
    try:
        yield cache
    finally:
        _ACTIVE_CACHE.reset(token)
