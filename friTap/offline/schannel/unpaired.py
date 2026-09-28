"""Parser for the Schannel mem-scan ``.schannel.unpaired`` sidecar (PUBLIC).

The read-only Schannel memory-scan engine cannot read the ClientHello random out
of lsass (it is a transient parameter to ncrypt!Ssl*MasterKey, gone by scan time),
so every recovered secret is written UNPAIRED to a sidecar next to the mem-scan
keylog (``<memscan-keylog-stem>.schannel.unpaired``), one record per line:

    <kind> <secret_hex> <session_id|-> <ssl_version>

where

  * ``kind`` is ``schannel_tls12_master`` or ``schannel_tls13_secret``,
  * ``secret_hex`` is the 48-byte master (TLS 1.2) or 32/48-byte secret (TLS 1.3),
  * ``session_id`` is a hex session id or ``-`` (Schannel keeps no memory-resident
    client_random, so it is effectively always ``-`` on this build), and
  * ``ssl_version`` is ``771`` (TLS 1.2) or ``772`` (TLS 1.3).

Blank lines and ``#`` comment/header lines are skipped. This module is PURE and
has no third-party dependency — it only turns text into records; the correlation
that joins each secret to its client_random lives in :mod:`.correlate`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

# The two kinds the scanner emits, and the TLS versions they map to.
KIND_TLS12_MASTER = "schannel_tls12_master"
KIND_TLS13_SECRET = "schannel_tls13_secret"

SIDECAR_KINDS = (KIND_TLS12_MASTER, KIND_TLS13_SECRET)

# Filename suffix of the sidecar written next to the mem-scan keylog.
SIDECAR_SUFFIX = ".schannel.unpaired"

SSL_VERSION_TLS12 = 771  # 0x0303
SSL_VERSION_TLS13 = 772  # 0x0304

_HEX = re.compile(r"^[0-9a-fA-F]+$")
# TLS 1.2 master is 48 bytes; TLS 1.3 secrets are 32 (SHA-256) or 48 (SHA-384).
_TLS12_HEXLEN = 96
_TLS13_HEXLENS = frozenset({64, 96})
# Bounded read used when sniffing whether a file is a sidecar.
_SNIFF_BYTES = 64 * 1024


@dataclass(frozen=True)
class UnpairedRecord:
    """One parsed line of the ``.schannel.unpaired`` sidecar.

    Attributes:
        kind: ``schannel_tls12_master`` or ``schannel_tls13_secret``.
        secret: lower-cased hex secret (master or TLS 1.3 secret).
        session_id: lower-cased hex session id, or ``None`` when the field was ``-``.
        ssl_version: 771 (TLS 1.2) or 772 (TLS 1.3), or ``None`` when unparseable.
    """

    kind: str
    secret: str
    session_id: str | None
    ssl_version: int | None

    @property
    def is_tls13(self) -> bool:
        """True when this record is a TLS 1.3 secret (by kind or ssl_version)."""
        return self.kind == KIND_TLS13_SECRET or self.ssl_version == SSL_VERSION_TLS13

    @property
    def is_tls12(self) -> bool:
        """True when this record is a TLS 1.2 master (by kind or ssl_version)."""
        return self.kind == KIND_TLS12_MASTER or self.ssl_version == SSL_VERSION_TLS12


def _parse_session_id(token: str) -> str | None:
    """Return a lower-cased hex session id, or ``None`` for ``-``/empty/non-hex."""
    token = token.strip()
    if not token or token == "-":
        return None
    return token.lower() if _HEX.match(token) else None


def _parse_ssl_version(token: str) -> int | None:
    """Return the integer TLS version code, or ``None`` when absent/unparseable."""
    token = token.strip()
    if not token or token == "-":
        return None
    try:
        return int(token, 0)
    except ValueError:
        return None


def parse_unpaired(text: str) -> List[UnpairedRecord]:
    """Parse the ``.schannel.unpaired`` sidecar text into records.

    Skips blank lines and ``#`` comments/headers. A line must carry at least a
    kind token and a hex secret of a valid length (48-byte master, or 32/48-byte
    TLS 1.3 secret); anything else is ignored. ``session_id`` and ``ssl_version``
    columns are optional and default to ``None`` when missing or ``-``. Records
    are de-duplicated on (kind, secret), order preserved.
    """
    records: List[UnpairedRecord] = []
    seen: set[tuple[str, str]] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        kind = parts[0]
        secret = parts[1].lower()
        if not _HEX.match(secret):
            continue
        is_tls13_kind = kind == KIND_TLS13_SECRET
        valid_len = secret_len_ok(secret, tls13=is_tls13_kind)
        if not valid_len:
            continue
        session_id = _parse_session_id(parts[2]) if len(parts) >= 3 else None
        ssl_version = _parse_ssl_version(parts[3]) if len(parts) >= 4 else None
        key = (kind, secret)
        if key in seen:
            continue
        seen.add(key)
        records.append(UnpairedRecord(kind, secret, session_id, ssl_version))
    return records


def _first_record_line(path: str) -> str:
    """First non-blank, non-comment line within the first bytes of *path*."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(_SNIFF_BYTES)
    for line in head.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped
    return ""


def looks_like_unpaired(path: str) -> bool:
    """True when *path* looks like a ``.schannel.unpaired`` sidecar.

    Matches by :data:`SIDECAR_SUFFIX` (even if the file does not exist yet) or
    by content: the first record line (within a bounded read) starts with one of
    :data:`SIDECAR_KINDS`. Unreadable files yield ``False``, never an exception.
    """
    if not path:
        return False
    if path.endswith(SIDECAR_SUFFIX):
        return True
    try:
        return _first_record_line(path).startswith(SIDECAR_KINDS)
    except (OSError, ValueError):
        return False


def secret_len_ok(secret: str, *, tls13: bool) -> bool:
    """Length gate for a secret hex: 48-byte master (TLS 1.2) or 32/48-byte (1.3)."""
    if tls13:
        return len(secret) in _TLS13_HEXLENS
    return len(secret) == _TLS12_HEXLEN


def tls12_masters(records: List[UnpairedRecord]) -> List[str]:
    """The distinct 48-byte TLS 1.2 master hexes, order preserved."""
    out: List[str] = []
    seen: set[str] = set()
    for r in records:
        if r.is_tls12 and r.secret not in seen and secret_len_ok(r.secret, tls13=False):
            seen.add(r.secret)
            out.append(r.secret)
    return out


def tls13_secrets(records: List[UnpairedRecord]) -> List[str]:
    """The distinct TLS 1.3 secret hexes (32/48-byte), order preserved."""
    out: List[str] = []
    seen: set[str] = set()
    for r in records:
        if r.is_tls13 and r.secret not in seen and secret_len_ok(r.secret, tls13=True):
            seen.add(r.secret)
            out.append(r.secret)
    return out


def session_map(records: List[UnpairedRecord]) -> dict[str, str]:
    """session_id(hex) -> master(hex) for TLS 1.2 records that carry a real id.

    Records whose session_id is ``-`` (the norm on this build) contribute nothing;
    a session id, when present, lets the correlator join on it instead of trial
    decrypting (Wireshark also ingests ``RSA Session-ID:<sid> Master-Key:<m>``).
    """
    mapping: dict[str, str] = {}
    for r in records:
        if r.is_tls12 and r.session_id and secret_len_ok(r.secret, tls13=False):
            mapping.setdefault(r.session_id, r.secret)
    return mapping


__all__ = [
    "UnpairedRecord",
    "parse_unpaired",
    "looks_like_unpaired",
    "secret_len_ok",
    "tls12_masters",
    "tls13_secrets",
    "session_map",
    "KIND_TLS12_MASTER",
    "KIND_TLS13_SECRET",
    "SIDECAR_KINDS",
    "SIDECAR_SUFFIX",
    "SSL_VERSION_TLS12",
    "SSL_VERSION_TLS13",
]
