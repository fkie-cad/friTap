"""Read a friTap RC4 keylog into trial-decrypt candidate keys.

ALL line-format knowledge is delegated to
:mod:`friTap.protocols.rc4_keylog_spec` (the single source of truth shared with
the live ``Rc4KeylogFormatter``) via its :func:`parse_line`, so this reader can
never drift from the writer. Each ``RC4_KEY`` line becomes one
``(source, key_bytes)`` candidate tuple in the shape :func:`trial_decrypt`
consumes; the ``source`` carries the recovering hook + direction hint for
provenance. Duplicate keys are preserved here (de-duplication happens once in
:func:`~friTap.offline.rc4.decrypt.materialize_candidates`).
"""

from __future__ import annotations

import logging
from typing import List, Tuple

from ...protocols.rc4_keylog_spec import parse_line
from .decrypt import Rc4Candidate

logger = logging.getLogger(__name__)


def candidates_from_rc4_keylog_text(text: str) -> List[Rc4Candidate]:
    """Parse keylog *text* into :class:`Rc4Candidate` objects (pure, no I/O).

    An entry flagged ``is_sbox`` (source ``memscan-sbox``, 256 bytes) carries a
    post-KSA S-box permutation, which the decryptor uses as keystream directly
    (skipping the KSA) instead of KSA'ing it as a 256-byte key.
    """
    out: List[Rc4Candidate] = []
    for line in text.splitlines():
        entry = parse_line(line)
        if entry is None:
            continue
        source = f"rc4-keylog:{entry.source}/{entry.direction}"
        out.append(Rc4Candidate(source=source, material=entry.key,
                                is_sbox=entry.is_sbox))
    return out


def load_rc4_keylog(path: str) -> List[Rc4Candidate]:
    """Read an RC4 keylog file into ``(source, key)`` candidate tuples.

    Returns an empty list (never raises) when the file is missing/unreadable, so
    the offline driver can log-and-skip gracefully.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        logger.warning("Could not read RC4 keylog %s: %s", path, exc)
        return []
    return candidates_from_rc4_keylog_text(text)
