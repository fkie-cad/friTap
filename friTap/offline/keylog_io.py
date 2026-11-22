"""The shared read loop behind the line-oriented offline keylog loaders.

Protocol-neutral: each loader supplies ``parse_line`` (``None`` for comments,
blanks, malformed or foreign lines) and optionally a join key. Every reader goes
through :func:`iter_bounded_lines`, so a file with no newlines (binary junk or a
hostile manifest-named file) never becomes one giant in-memory line.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, Hashable, Iterator, List, Optional, TypeVar, Union

from friTap.output.keylog_format import MAX_KEYLOG_LINE_LENGTH

logger = logging.getLogger(__name__)

T = TypeVar("T")
AnyStr = TypeVar("AnyStr", str, bytes)

# Longest line (excluding its newline) a keylog reader accepts; longer lines are
# skipped. Matches the longest line a keylog writer ever emits.
_MAX_LINE_CHARS = MAX_KEYLOG_LINE_LENGTH
# Chunk size used to drain (discard) the rest of an over-long line.
_DRAIN_CHUNK_CHARS = 64 * 1024


def _newline_for(chunk: AnyStr) -> AnyStr:
    """The newline of *chunk*'s type: ``b"\\n"`` for bytes, ``"\\n"`` for text."""
    return b"\n" if isinstance(chunk, bytes) else "\n"


def _drain_line(fh, newline: AnyStr) -> None:
    """Discard the rest of the current line of *fh* in bounded chunks."""
    while True:
        chunk = fh.readline(_DRAIN_CHUNK_CHARS)
        if not chunk or chunk.endswith(newline):
            return


def _source_name(fh, source: Optional[str]) -> str:
    """Name of the file behind *fh* for log messages."""
    return source or str(getattr(fh, "name", "") or "<stream>")


def iter_bounded_lines(
    fh, max_chars: int = _MAX_LINE_CHARS, source: Optional[str] = None,
) -> Iterator[AnyStr]:
    """Yield the lines of *fh* (text or binary) like ``for line in fh``, skipping over-long ones.

    A line over *max_chars* is drained in bounded chunks so memory stays bounded.
    Skipped lines are reported in ONE warning per file (naming *source* or ``fh.name``).
"""
    skipped = 0
    try:
        while True:
            line = fh.readline(max_chars + 1)
            if not line:
                return
            newline = _newline_for(line)
            if len(line) > max_chars and not line.endswith(newline):
                skipped += 1
                _drain_line(fh, newline)
                continue
            yield line
    finally:
        if skipped:
            logger.warning(
                "Skipped %d over-long line(s) (> %d chars) in %s",
                skipped, max_chars, _source_name(fh, source))


def load_keylog_lines(
    path: str,
    parse_line: Callable[[str], Optional[T]],
    key: Optional[Callable[[T], Hashable]] = None,
) -> Union[List[T], Dict[Hashable, T]]:
    """Parse each line of the keylog at *path* with *parse_line*, skipping ``None``.

    Read as UTF-8 with replacement; a missing or unreadable file raises :class:`OSError`.
    Without *key* returns a list in file order; with *key* ``{key(entry): entry}``, last duplicate wins.
"""
    entries: List[T] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in iter_bounded_lines(fh):
            entry = parse_line(line)
            if entry is not None:
                entries.append(entry)
    if key is None:
        return entries
    return {key(entry): entry for entry in entries}


__all__ = ["iter_bounded_lines", "load_keylog_lines"]
