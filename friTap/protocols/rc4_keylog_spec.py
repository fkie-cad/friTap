"""Canonical friTap RC4 keylog format — the single source of truth.

Imported by BOTH the live writer (``Rc4KeylogFormatter`` in
``friTap.protocols.rc4_handler``) and a later offline RC4 decrypt workstream, so
the two never drift.

Unlike keylogs whose layout is dictated by an external Wireshark dissector
(e.g. the TLS ``SSLKEYLOGFILE`` format), the RC4 keylog is a **friTap-owned, label-prefixed** format, like the
MTProto keylog. One record per line, single-space-separated, lowercase-hex key::

    RC4_KEY <key_hex> <key_len> <source> <direction> <assoc>

Fields:
  * ``RC4_KEY``    — the constant line label (:data:`LABEL`).
  * ``key_hex``    — the raw RC4 key, lowercase hex, no separator (1..256 bytes).
  * ``key_len``    — the key length in **bytes** (decimal). Redundant with
                     ``key_hex`` but explicit, so a truncated line is detectable.
  * ``source``     — the hook that recovered the key (a whitespace-free token,
                     e.g. ``RC4_set_key``, ``BCryptGenerateSymmetricKey``,
                     ``mbedtls_arc4_setup``, ``nettle_arcfour_set_key``,
                     ``CryptEncrypt/RC4(CryptExportKey)``).
  * ``direction``  — ``out`` (client→server), ``in`` (server→client), or
                     ``unknown`` (RC4 key SETUP usually predates any direction).
  * ``assoc``      — association hint for the nested (RC4-in-TLS) case: the agent
                     thread id at capture, or ``-`` when unavailable. A downstream
                     RC4 decryptor uses it to group keys captured on the same
                     thread as the RC4 record stream that TLS-stripping produced.

Comment lines (``#``) and blank lines are skipped by :func:`parse_line`, so a
provenance ``HEADER_COMMENT`` may be written into a friTap RC4 keylog file.

Example (the fixture key ``fritap-rc4-demo-key``)::

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

# A recovered post-KSA S-box is emitted on the SAME RC4_KEY line shape, but its
# `key_hex` is the 256-byte PERMUTATION (running keystream state, i=j=0), NOT a key
# to feed through the KSA. It is disambiguated by (source, key_len): the offline
# decryptor must decrypt with rc4_prga(sbox, data) directly, skipping the KSA.
SBOX_SOURCE = "memscan-sbox"
SBOX_LEN = 256

DIR_OUT = "out"
DIR_IN = "in"
DIR_UNKNOWN = "unknown"
_VALID_DIRECTIONS = (DIR_OUT, DIR_IN, DIR_UNKNOWN)

# friTap-internal provenance; safe to write (parse_line skips ``#``).
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
        """True when this entry carries a post-KSA S-box permutation, not a key.

        Both conditions are required so a genuine 256-byte KEY from some other hook
        is never misread as an S-box.
        """
        return self.source == SBOX_SOURCE and self.key_len == SBOX_LEN


def _norm_hex(value: str) -> str:
    return (value or "").strip().lower()


def _valid_hex(value: str) -> bool:
    # Gate on bytes.fromhex (not int(value, 16)): the latter accepts a "0x"
    # prefix and "_" digit separators that bytes.fromhex — used by parse_line
    # to materialise the key — rejects, which would otherwise raise an uncaught
    # ValueError and abort the whole keylog conversion on one malformed line.
    if not value or (len(value) % 2) != 0:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _sanitize_token(value: str, default: str) -> str:
    """Collapse a field to a single whitespace-free token (never empty).

    Whitespace would break the single-space split, so any run of it becomes an
    underscore; an empty field falls back to *default*.
    """
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

    Returning ``None`` (rather than raising) lets the formatter drop a bad event
    without aborting the whole keylog, matching friTap's other formatters.
    """
    key_hex = _norm_hex(key)
    if not _valid_hex(key_hex):
        return None
    actual_len = len(key_hex) // 2
    if actual_len < MIN_KEY_LEN or actual_len > MAX_KEY_LEN:
        return None
    # If the agent supplied key_len, it must agree with the hex (guards against a
    # truncated/garbled key field).
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
