"""The one NSS SSLKEYLOGFILE line parser shared by the offline readers.

An NSS keylog line is ``LABEL CLIENT_RANDOM SECRET``: exactly three
whitespace-separated tokens. :func:`parse_strict_nss_line` is the one
validation policy every reader uses: ``#`` comments are skipped (leading
whitespace before ``#`` still makes a comment), the client random must be 32
bytes of hex and the secret 32 or 48 bytes of hex (any case). Two keyword
options cover the remaining per-caller differences:

  * ``label_ok`` -- an optional predicate the label must satisfy.
  * ``allow_unknown_client_random`` -- also accept the literal ``???`` client
    random, which the live ncrypt/lsass hook writes when it cannot correlate
    the ClientHello.random; it bypasses the client-random checks.

Duplicate handling and the shape of the result stay with each caller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

_HEX = re.compile(r"^[0-9a-fA-F]+$")
UNKNOWN_CLIENT_RANDOM = "???"
NSS_CLIENT_RANDOM_HEX_LEN = 64  # 32 bytes
NSS_SECRET_HEX_LENS = (64, 96)  # 32/48 bytes: TLS 1.3 secrets, TLS 1.2 master secret

# TLS 1.3 NSS keylog labels. Every secret of one connection shares that
# connection's ONE client_random. EXPORTER_SECRET protects no records.
TLS13_LABELS = (
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
)
# The TLS 1.3 labels whose secret protects records, so trial decryption can
# confirm them; the server handshake secret (the anchor) first.
TLS13_TRIAL_LABELS = (
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_TRAFFIC_SECRET_0",
    "CLIENT_TRAFFIC_SECRET_0",
)


@dataclass(frozen=True)
class NssEntry:
    """One parsed NSS keylog line; client random and secret are lowercased."""

    label: str
    client_random: str
    secret: str


def parse_strict_nss_line(
    line: str,
    *,
    label_ok: Optional[Callable[[str], bool]] = None,
    allow_unknown_client_random: bool = False,
) -> Optional[NssEntry]:
    """Parse *line* under the shared strict policy (see the module docstring)."""
    if line.strip().startswith("#"):
        return None
    parts = line.split()
    if len(parts) != 3:
        return None
    label, client_random, secret = parts
    if label_ok is not None and not label_ok(label):
        return None
    unknown = allow_unknown_client_random and client_random == UNKNOWN_CLIENT_RANDOM
    if not unknown and not _is_hex_of_len(client_random, (NSS_CLIENT_RANDOM_HEX_LEN,)):
        return None
    if not _is_hex_of_len(secret, NSS_SECRET_HEX_LENS):
        return None
    return NssEntry(label, client_random.lower(), secret.lower())


def _is_hex_of_len(token: str, lengths: tuple) -> bool:
    """True when *token* is hex and its raw length is one of *lengths*."""
    return len(token) in lengths and bool(_HEX.match(token))


__all__ = [
    "NSS_CLIENT_RANDOM_HEX_LEN",
    "NSS_SECRET_HEX_LENS",
    "NssEntry",
    "TLS13_LABELS",
    "TLS13_TRIAL_LABELS",
    "UNKNOWN_CLIENT_RANDOM",
    "parse_strict_nss_line",
]
