"""Split a reassembled TLS byte stream into records and read hello fields.

Pure parsing (no crypto, no third-party dependency); unit-testable via
:func:`parse_records`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

# TLS record content types (RFC 8446 sec 5.1 / RFC 5246 sec 6.2.1).
CT_CHANGE_CIPHER_SPEC = 0x14
CT_ALERT = 0x15
CT_HANDSHAKE = 0x16
CT_APPLICATION_DATA = 0x17

# Plausible TLS record header fields (RFC 8446 sec 5.1): content types
# change_cipher_spec (0x14) .. heartbeat (0x18); legacy record versions
# 0x0301..0x0303 (0x0301 appears on an initial ClientHello); a fragment of at
# most 2^14 + 256 bytes (the TLS 1.3 TLSCiphertext limit) and never empty.
_VALID_CONTENT_TYPES = range(0x14, 0x19)
_VALID_VERSION_MINORS = (0x01, 0x02, 0x03)
MAX_RECORD_FRAGMENT_LEN = 2 ** 14 + 256
RECORD_HEADER_LEN = 5


def plausible_record_header(stream: bytes, i: int) -> bool:
    """True when the 5 bytes at ``stream[i]`` look like a TLS record header."""
    if i < 0 or i + RECORD_HEADER_LEN > len(stream):
        return False
    length = int.from_bytes(stream[i + 3:i + 5], "big")
    return (
        stream[i] in _VALID_CONTENT_TYPES
        and stream[i + 1] == 0x03
        and stream[i + 2] in _VALID_VERSION_MINORS
        and 0 < length <= MAX_RECORD_FRAGMENT_LEN
    )


def _starts_record_chain(stream: bytes, i: int) -> bool:
    """True when a plausible header at *i* is followed by another (or the end)."""
    if not plausible_record_header(stream, i):
        return False
    following = i + RECORD_HEADER_LEN + int.from_bytes(stream[i + 3:i + 5], "big")
    if following > len(stream):
        return False
    return len(stream) - following < RECORD_HEADER_LEN or plausible_record_header(
        stream, following
    )


def find_record_boundary(stream: bytes, start: int = 0) -> Optional[int]:
    """Offset of the first plausible TLS record boundary at/after *start*, or None.

    Resyncs a byte run that begins INSIDE a record (a capture that started
    mid-record, or a TCP start gap). A candidate must be a plausible header whose
    record is followed by another plausible header (or ends the run), so random
    ciphertext bytes rarely pass. Any real boundary lies within one maximum-size
    record of *start*, which bounds the search.
    """
    last = min(len(stream) - RECORD_HEADER_LEN,
               start + RECORD_HEADER_LEN + MAX_RECORD_FRAGMENT_LEN)
    for i in range(start, last + 1):
        if _starts_record_chain(stream, i):
            return i
    return None


def parse_records(
    stream: bytes, validate: bool = False
) -> List[Tuple[int, bytes, bytes]]:
    """Split a reassembled TLS byte stream into (content_type, header5, fragment).

    With ``validate`` the split stops at the first implausible header (see
    :func:`plausible_record_header`) instead of emitting a garbage record; the
    default keeps the historical length-only framing.
    """
    out, i, n = [], 0, len(stream)
    while i + 5 <= n:
        if validate and not plausible_record_header(stream, i):
            break
        ctype = stream[i]
        length = int.from_bytes(stream[i + 3:i + 5], "big")
        if i + 5 + length > n:
            break
        out.append((ctype, stream[i:i + 5], stream[i + 5:i + 5 + length]))
        i += 5 + length
    return out


def client_random_from_clienthello(frag: bytes) -> Optional[str]:
    """ClientHello handshake fragment -> 32-byte random (hex), or None."""
    if len(frag) >= 38 and frag[0] == 0x01:
        return frag[6:38].hex()
    return None


# --------------------------------------------------------------------------- #
# Handshake message walking and ServerHello details
# --------------------------------------------------------------------------- #

# RFC 8446 sec 4.1.3: a HelloRetryRequest is a ServerHello whose random is
# SHA-256("HelloRetryRequest").
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

# Extension type of supported_versions (RFC 8446 sec 4.2.1).
EXT_SUPPORTED_VERSIONS = 0x002B
# Extension type of early_data (RFC 8446 sec 4.2.10).
EXT_EARLY_DATA = 0x002A
# Extension type of encrypt_then_mac (RFC 7366): when a TLS 1.2 ServerHello echoes
# it, that connection's CBC records are Encrypt-then-MAC rather than MAC-then-encrypt.
EXT_ENCRYPT_THEN_MAC = 0x0016

_HANDSHAKE_HEADER_LEN = 4


def iter_handshake_messages(data: bytes) -> List[Tuple[int, bytes]]:
    """Split concatenated handshake bytes into ``(msg_type, body)`` pairs.

    Stops at the first message whose declared length runs past the end (a
    message split across records the caller did not join).
    """
    out: List[Tuple[int, bytes]] = []
    i, n = 0, len(data)
    while i + _HANDSHAKE_HEADER_LEN <= n:
        length = int.from_bytes(data[i + 1:i + 4], "big")
        end = i + _HANDSHAKE_HEADER_LEN + length
        if end > n:
            break
        out.append((data[i], data[i + _HANDSHAKE_HEADER_LEN:end]))
        i = end
    return out


def _iter_extensions(body: bytes, off: int) -> List[Tuple[int, bytes]]:
    """``(type, data)`` pairs of the extensions block starting at ``body[off]``."""
    if off + 2 > len(body):
        return []
    end = min(len(body), off + 2 + int.from_bytes(body[off:off + 2], "big"))
    off += 2
    out: List[Tuple[int, bytes]] = []
    while off + 4 <= end:
        ext_type = int.from_bytes(body[off:off + 2], "big")
        ext_len = int.from_bytes(body[off + 2:off + 4], "big")
        if off + 4 + ext_len > end:
            break
        out.append((ext_type, body[off + 4:off + 4 + ext_len]))
        off += 4 + ext_len
    return out


@dataclass(frozen=True)
class ServerHelloInfo:
    """The ServerHello fields the offline oracles need.

    ``version`` is the negotiated protocol version: the supported_versions
    ``selected_version`` when present (TLS 1.3), else ``legacy_version``.
    """

    random: bytes
    cipher_suite: int
    legacy_version: int
    selected_version: Optional[int]
    is_hrr: bool
    uses_etm: bool = False

    @property
    def version(self) -> int:
        return self.selected_version or self.legacy_version


def server_hello_info(frag: bytes) -> Optional[ServerHelloInfo]:
    """Parse the ServerHello at the start of a handshake fragment, or ``None``.

    Respects the message length, so a TLS 1.2 ServerHello coalesced with the
    Certificate / ServerHelloDone in one record parses correctly.
    """
    messages = iter_handshake_messages(frag)
    if not messages or messages[0][0] != 0x02:
        return None
    body = messages[0][1]
    if len(body) < 2 + 32 + 1:
        return None
    legacy_version = int.from_bytes(body[0:2], "big")
    random = body[2:34]
    off = 34 + 1 + body[34]              # session id
    if off + 3 > len(body):
        return None
    suite = int.from_bytes(body[off:off + 2], "big")
    off += 3                             # suite + compression method
    selected = None
    uses_etm = False
    for ext_type, ext_data in _iter_extensions(body, off):
        if ext_type == EXT_SUPPORTED_VERSIONS and len(ext_data) == 2:
            selected = int.from_bytes(ext_data, "big")
        elif ext_type == EXT_ENCRYPT_THEN_MAC:
            uses_etm = True
    return ServerHelloInfo(random, suite, legacy_version, selected,
                           random == HRR_RANDOM, uses_etm)


def client_hello_extensions(frag: bytes) -> Optional[List[int]]:
    """Extension types of the ClientHello at the start of a fragment, or ``None``."""
    messages = iter_handshake_messages(frag)
    if not messages or messages[0][0] != 0x01:
        return None
    body = messages[0][1]
    off = 34                                            # version + random
    if off >= len(body):
        return None
    off += 1 + body[off]                                # session id
    if off + 2 > len(body):
        return None
    off += 2 + int.from_bytes(body[off:off + 2], "big")  # cipher suites
    if off >= len(body):
        return None
    off += 1 + body[off]                                # compression methods
    return [ext_type for ext_type, _ in _iter_extensions(body, off)]
