"""The shared read loop behind the line-oriented offline keylog loaders.

Protocol-neutral: each loader supplies its own ``parse_line`` (which returns
``None`` for comments, blanks and malformed or foreign lines) and, optionally,
the join key its entries are looked up by.
"""

from __future__ import annotations

from typing import Callable, Dict, Hashable, List, Optional, TypeVar, Union

T = TypeVar("T")


def load_keylog_lines(
    path: str,
    parse_line: Callable[[str], Optional[T]],
    key: Optional[Callable[[T], Hashable]] = None,
) -> Union[List[T], Dict[Hashable, T]]:
    """Parse each line of the keylog at *path* with *parse_line*, skipping ``None``.

    The file is read as UTF-8 with undecodable bytes replaced, line by line
    (each line keeps its trailing newline); a missing or unreadable file raises
    :class:`OSError`. Without *key* the entries are returned as a list in file
    order; with *key* they are returned as ``{key(entry): entry}``, where the
    last entry for a duplicate key wins.
    """
    entries: List[T] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = parse_line(line)
            if entry is not None:
                entries.append(entry)
    if key is None:
        return entries
    return {key(entry): entry for entry in entries}


__all__ = ["load_keylog_lines"]
