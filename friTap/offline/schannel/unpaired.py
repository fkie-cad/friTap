"""Parser for the Schannel mem-scan ``.schannel.unpaired`` sidecar (PUBLIC).

The Schannel memory scan cannot read the ClientHello random out of lsass (a
transient ncrypt parameter), so every recovered secret goes to
``<memscan-keylog-stem>.schannel.unpaired``, one record per line:

    <kind> <secret_hex> <session_id|-> <ssl_version>

``kind`` is ``schannel_tls12_master`` or ``schannel_tls13_secret``; ``secret_hex``
a 48-byte master (1.2) or 32/48-byte secret (1.3); ``session_id`` hex or ``-``
(effectively always ``-``); ``ssl_version`` 771 (TLS 1.2) or 772 (TLS 1.3).
Blank and ``#`` lines are skipped. This module only parses; the join to
client_random lives in :mod:`.correlate`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

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
        secret: lower-cased hex secret.
        session_id: lower-cased hex session id, ``None`` when ``-``.
        ssl_version: 771 or 772, ``None`` when unparseable.
        group: optional connection-group id (5th column, ``group=<id>`` or bare)
            tying sibling secrets so an unlabeled EXPORTER_SECRET can be placed by
            elimination; ``None`` when absent.
"""

    kind: str
    secret: str
    session_id: str | None
    ssl_version: int | None
    group: str | None = None

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


def _parse_group(token: str) -> str | None:
    """Return the group id from a ``group=<id>`` or bare token, or ``None``."""
    token = token.strip()
    if token.startswith("group="):
        token = token[len("group="):]
    if not token or token == "-":
        return None
    return token


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
    """Parse the sidecar text into records.

    Skips blank and ``#`` lines. A line needs a kind token and a hex secret of valid
    length; ``session_id`` / ``ssl_version`` are optional (``None`` when missing or
    ``-``). De-duplicated on (kind, secret), ordered.
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
        group = _parse_group(parts[4]) if len(parts) >= 5 else None
        key = (kind, secret)
        if key in seen:
            continue
        seen.add(key)
        records.append(UnpairedRecord(kind, secret, session_id, ssl_version, group))
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
    """True when *path* looks like a sidecar: :data:`SIDECAR_SUFFIX` (even if absent) or its first record line (bounded read) starts with a :data:`SIDECAR_KINDS` token. Never raises."""
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


def tls13_groups(records: List[UnpairedRecord]) -> dict[str, str]:
    """secret(hex) -> group id for TLS 1.3 records with a 5th-column group (lets the correlator place an unlabeled EXPORTER_SECRET)."""
    mapping: dict[str, str] = {}
    for r in records:
        if r.is_tls13 and r.group and secret_len_ok(r.secret, tls13=True):
            mapping.setdefault(r.secret, r.group)
    return mapping


def session_map(records: List[UnpairedRecord]) -> dict[str, str]:
    """session_id(hex) -> master(hex) for TLS 1.2 records with a real id (``-`` contributes nothing); lets the correlator join instead of trial decrypting."""
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
    "tls13_groups",
    "session_map",
    "KIND_TLS12_MASTER",
    "KIND_TLS13_SECRET",
    "SIDECAR_KINDS",
    "SIDECAR_SUFFIX",
    "SSL_VERSION_TLS12",
    "SSL_VERSION_TLS13",
]
