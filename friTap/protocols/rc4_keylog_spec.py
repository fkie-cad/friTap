"""Canonical friTap RC4 keylog format.

Shared by the live writer (``Rc4KeylogFormatter``) and the offline RC4 decrypt.
One record per line, single-space-separated, lowercase hex::

    RC4_KEY <key_hex> <key_len> <source> <direction> <assoc>

  * ``key_hex``    raw RC4 key (1..256 bytes).
  * ``key_len``    key length in bytes; redundant, so a truncated line is detectable.
  * ``source``     whitespace-free hook name, e.g. ``RC4_set_key``,
                   ``BCryptGenerateSymmetricKey``, ``mbedtls_arc4_setup``.
  * ``direction``  ``out`` (client->server), ``in`` or ``unknown`` (key setup
                   usually predates any direction).
  * ``assoc``      agent thread id, or ``-``; groups RC4-in-TLS keys with the
                   record stream captured on the same thread.

:func:`parse_line` skips ``#`` and blank lines. Example::

    RC4_KEY 6672697461702d7263342d64656d6f2d6b6579 19 RC4_set_key unknown 4711
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

VERSION = 1
LABEL = "RC4_KEY"

# RC4 keys are 1..256 bytes.
MIN_KEY_LEN = 1
MAX_KEY_LEN = 256

# A recovered post-KSA S-box uses the same line shape, but ``key_hex`` is the
# 256-byte permutation (state i=j=0), not a key. Identified by (source, key_len);
# decrypt with rc4_prga(sbox, data) directly, skipping the KSA.
SBOX_SOURCE = "memscan-sbox"
SBOX_LEN = 256

DIR_OUT = "out"
DIR_IN = "in"
DIR_UNKNOWN = "unknown"
_VALID_DIRECTIONS = (DIR_OUT, DIR_IN, DIR_UNKNOWN)

HEADER_COMMENT = (
    f"# friTap RC4 keylog v{VERSION} — format:\n"
    f"#   {LABEL} <key_hex> <key_len> <source> <direction> <assoc>"
)


@dataclass(frozen=True)
class Rc4Key:
    """One parsed RC4 keylog entry."""

    key: bytes
    source: str
    direction: str
    assoc: str

    @property
    def key_len(self) -> int:
        return len(self.key)

    @property
    def is_sbox(self) -> bool:
        """True for a post-KSA S-box; both conditions guard against a real 256-byte key."""
        return self.source == SBOX_SOURCE and self.key_len == SBOX_LEN


def _norm_hex(value: str) -> str:
    return (value or "").strip().lower()


def _valid_hex(value: str) -> bool:
    # Not int(value, 16): it accepts "0x" and "_" that bytes.fromhex rejects,
    # which would abort the whole keylog conversion on one malformed line.
    if not value or (len(value) % 2) != 0:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _sanitize_token(value: str, default: str) -> str:
    """Whitespace-free token (runs of whitespace become ``_``); empty gives *default*."""
    token = "_".join((value or "").split())
    return token or default


def format_line(
    *,
    key: str,
    key_len: Optional[int] = None,
    source: str = "",
    direction: str = DIR_UNKNOWN,
    assoc: str = "-",
) -> Optional[str]:
    """Render an ``RC4_KEY`` line from the agent payload, or ``None`` if malformed.

    Returns ``None`` instead of raising so one bad event does not abort the keylog.
    """
    key_hex = _norm_hex(key)
    if not _valid_hex(key_hex):
        return None
    actual_len = len(key_hex) // 2
    if actual_len < MIN_KEY_LEN or actual_len > MAX_KEY_LEN:
        return None
    # A supplied key_len must agree with the hex (guards against truncation).
    if key_len is not None:
        try:
            if int(key_len) != actual_len:
                return None
        except (TypeError, ValueError):
            return None

    dir_norm = (direction or DIR_UNKNOWN).strip().lower()
    if dir_norm not in _VALID_DIRECTIONS:
        dir_norm = DIR_UNKNOWN
    source_tok = _sanitize_token(source, "unknown")
    assoc_tok = _sanitize_token(assoc, "-")
    return f"{LABEL} {key_hex} {actual_len} {source_tok} {dir_norm} {assoc_tok}"


def parse_line(line: str) -> Optional[Rc4Key]:
    """Parse one ``RC4_KEY`` line into an :class:`Rc4Key`, or ``None``.

    Skips blank lines and ``#`` comments. Requires the ``RC4_KEY`` label and the
    six-token layout; a ``key_len`` that disagrees with the hex is rejected.
    """
    s = (line or "").strip()
    if not s or s.startswith("#"):
        return None
    parts = s.split()
    if len(parts) != 6 or parts[0] != LABEL:
        return None
    _, key_hex, key_len_s, source, direction, assoc = parts
    key_hex = key_hex.lower()
    if not _valid_hex(key_hex):
        return None
    actual_len = len(key_hex) // 2
    if actual_len < MIN_KEY_LEN or actual_len > MAX_KEY_LEN:
        return None
    try:
        if int(key_len_s) != actual_len:
            return None
    except ValueError:
        return None
    direction = direction.lower()
    if direction not in _VALID_DIRECTIONS:
        direction = DIR_UNKNOWN
    return Rc4Key(
        key=bytes.fromhex(key_hex),
        source=source,
        direction=direction,
        assoc=assoc,
    )


def matches_line(line: str) -> bool:
    """True when *line* is a valid RC4 keylog record (keylog sniffing)."""
    return parse_line(line) is not None
