"""Decoder for the AppLovin MAX ``/1.0/mediate`` app-layer cipher.

Based on the published (unverified) description (Buchodi, May 2026)::

    envelope   = base64( "2:" + protocol_id + ":" + sdk_key[32:] + ":" + binary )
    protocol_id = SHA-1(salt).hex()            # salt: 32-byte constant
    dk          = SHA-256(salt || sdk_key[:32])
    binary      = masked_counter (8 B LE) || ciphertext
    counter     = masked_counter XOR uint64(dk[0:8])   # = currentTimeMillis
    pt[i]       = ct[i] ^ byte(mix64(block_input), i % 8) ^ dk[i % 32]

The plaintext is gzip-compressed JSON. The spec leaves two details open
(the byte order of ``dk[0:8]`` and the keystream block input); they are
modelled as :class:`CipherVariant` and every variant is tried, accepting
only output that is a valid gzip stream.

Pure functions only: no I/O, no TUI/analysis imports.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, replace
from typing import Any, Literal
from urllib.parse import parse_qsl

from friTap.parsers.decompress import MAX_AUTO_DECOMPRESS, decompress_body

MASK64 = (1 << 64) - 1
COUNTER_SIZE = 8
DERIVED_KEY_SIZE = 32
SDK_KEY_PREFIX_LEN = 32
GZIP_MAGIC = b"\x1f\x8b\x08"
ENVELOPE_FIELD_COUNT = 4
PAYLOAD_PARAM = "p"

_MIX_MUL_1 = 0xC2B2AE3D27D4EB4F
_MIX_MUL_2 = 0x85EBCA77C2B2AE63
_URLSAFE_TO_STD = str.maketrans("-_", "+/")
_ENVELOPE_HEAD = re.compile(rb"^\d+:[0-9a-fA-F]{40}:")

REASON_TRUNCATED = "ciphertext shorter than the 8-byte masked counter"
REASON_PROTOCOL_ID_MISMATCH = "protocol_id does not match SHA-1(salt)"
REASON_NO_VARIANT = "no cipher variant produced a valid gzip plaintext"

MEDIATE_HOST_SUFFIX = "applovin.com"
MEDIATE_PATH_PREFIX = "/1.0/mediate"


def is_mediate_request(host: str, path: str) -> bool:
    """True for ``*.applovin.com/1.0/mediate...`` requests.

    *host* must already be lower-cased with any ``:port`` stripped; the check
    is a plain suffix/prefix match (case-sensitive, ``applovin.com`` itself
    included).
    """
    return host.endswith(MEDIATE_HOST_SUFFIX) and path.startswith(MEDIATE_PATH_PREFIX)


@dataclass(frozen=True)
class MediateEnvelope:
    """The colon-separated envelope after base64 decoding."""

    version: str
    protocol_id: str
    sdk_key_suffix: str
    ciphertext: bytes  # masked counter (8 B) followed by the encrypted body


@dataclass(frozen=True)
class CipherVariant:
    """One interpretation of the spec's unstated details.

    dk_endianness: byte order used to read ``dk[0:8]`` as the counter mask.
    block_input:   ``counter_plus_i``     -> mix64(counter + i - i % 8)
                   ``counter_plus_block`` -> mix64(counter + i // 8)
    """

    dk_endianness: Literal["little", "big"]
    block_input: Literal["counter_plus_i", "counter_plus_block"]


ALL_VARIANTS: tuple[CipherVariant, ...] = tuple(
    CipherVariant(endianness, block_input)
    for endianness in ("little", "big")
    for block_input in ("counter_plus_i", "counter_plus_block")
)


@dataclass(frozen=True)
class DecryptResult:
    """A successful decryption."""

    variant: CipherVariant
    timestamp_ms: int
    plaintext: bytes  # gunzipped bytes
    json: Any | None  # parsed JSON, or None when the plaintext is not JSON
    sdk_key_matches_suffix: bool


# --------------------------------------------------------------------------
# Envelope extraction and parsing
# --------------------------------------------------------------------------

def extract_envelope_payload(body: bytes, query: str | None) -> bytes | None:
    """Return the base64-decoded envelope from a request, or None.

    Looks, in order, at ``p=`` in the URL *query*, ``p=`` in a
    form-encoded *body*, and finally the raw *body* as base64.
    """
    candidates = [_form_param(query or "", PAYLOAD_PARAM)]
    text_body = _ascii_or_none(body)
    if text_body is not None:
        candidates += [_form_param(text_body, PAYLOAD_PARAM), text_body]
    for candidate in candidates:
        decoded = _decode_base64_lenient(candidate) if candidate else None
        if decoded is not None and looks_like_envelope(decoded):
            return decoded
    return None


def looks_like_envelope(raw: bytes) -> bool:
    """True when *raw* starts with ``<version>:<40 hex>:``."""
    return _ENVELOPE_HEAD.match(raw) is not None


def parse_envelope(raw: bytes) -> MediateEnvelope:
    """Split ``version:protocol_id:sdk_key_suffix:binary`` on the first 3 colons.

    Raises ValueError when the envelope is malformed.
    """
    parts = raw.split(b":", ENVELOPE_FIELD_COUNT - 1)
    if len(parts) != ENVELOPE_FIELD_COUNT or not looks_like_envelope(raw):
        raise ValueError("not an AppLovin mediate envelope")
    version, protocol_id, suffix, ciphertext = parts
    return MediateEnvelope(
        version=version.decode("ascii"),
        protocol_id=protocol_id.decode("ascii").lower(),
        sdk_key_suffix=suffix.decode("ascii", errors="replace"),
        ciphertext=ciphertext,
    )


def _ascii_or_none(data: bytes) -> str | None:
    try:
        return data.decode("ascii").strip()
    except UnicodeDecodeError:
        return None


def _form_param(encoded: str, name: str) -> str | None:
    """Value of *name* in a URL-encoded string; '+'-as-space is undone."""
    if "=" not in encoded:
        return None
    for key, value in parse_qsl(encoded.lstrip("?"), keep_blank_values=True):
        if key == name:
            return value.replace(" ", "+")  # base64 never contains spaces
    return None


def _decode_base64_lenient(text: str) -> bytes | None:
    """Decode standard or URL-safe base64, tolerating missing padding."""
    compact = "".join(text.split())
    padded = compact + "=" * (-len(compact) % 4)
    for alphabet in (padded, padded.translate(_URLSAFE_TO_STD)):
        try:
            return base64.b64decode(alphabet.encode("ascii"), validate=True)
        except (binascii.Error, ValueError):
            continue
    return None


# --------------------------------------------------------------------------
# Key schedule and keystream
# --------------------------------------------------------------------------

def protocol_id_for_salt(salt: bytes) -> str:
    """``SHA-1(salt)`` as lowercase hex (the envelope's protocol_id)."""
    return hashlib.sha1(salt).hexdigest()


def derive_key(salt: bytes, sdk_key: str) -> bytes:
    """``dk = SHA-256(salt || sdk_key[:32])``."""
    return hashlib.sha256(salt + sdk_key[:SDK_KEY_PREFIX_LEN].encode("ascii")).digest()


def mix64(x: int) -> int:
    """AppLovin's 64-bit finaliser (NOT standard SplitMix64)."""
    x &= MASK64
    x = ((x ^ (x >> 33)) * _MIX_MUL_1) & MASK64
    x = ((x ^ (x >> 29)) * _MIX_MUL_2) & MASK64
    return x ^ (x >> 32)


def counter_mask(dk: bytes, variant: CipherVariant) -> int:
    """``dk[0:8]`` read as uint64 in the variant's byte order."""
    return int.from_bytes(dk[:COUNTER_SIZE], variant.dk_endianness)


def block_input(counter: int, index: int, variant: CipherVariant) -> int:
    """The mix64 input for byte *index* under *variant*."""
    if variant.block_input == "counter_plus_block":
        return (counter + index // 8) & MASK64
    return (counter + index - index % 8) & MASK64


def keystream_byte(counter: int, index: int, dk: bytes, variant: CipherVariant) -> int:
    """The byte XORed onto ciphertext byte *index* (mixer byte ^ dk byte)."""
    return _xor_byte(mix64(block_input(counter, index, variant)), index, dk)


def _xor_byte(mixed: int, index: int, dk: bytes) -> int:
    return ((mixed >> ((index % 8) * 8)) & 0xFF) ^ dk[index % DERIVED_KEY_SIZE]


def apply_keystream(data: bytes, counter: int, dk: bytes, variant: CipherVariant) -> bytes:
    """XOR *data* with the keystream (encryption and decryption are identical)."""
    out = bytearray(len(data))
    mixed = 0
    for index, value in enumerate(data):
        if index % 8 == 0:
            mixed = mix64(block_input(counter, index, variant))
        out[index] = value ^ _xor_byte(mixed, index, dk)
    return bytes(out)


def unmask_counter(masked: bytes, dk: bytes, variant: CipherVariant) -> int:
    """Recover ``currentTimeMillis`` from the 8-byte little-endian masked counter."""
    return int.from_bytes(masked[:COUNTER_SIZE], "little") ^ counter_mask(dk, variant)


# --------------------------------------------------------------------------
# Decryption
# --------------------------------------------------------------------------

def sdk_key_matches_suffix(sdk_key: str, envelope: MediateEnvelope) -> bool:
    """True when *sdk_key* ends with the suffix carried in the envelope."""
    return bool(envelope.sdk_key_suffix) and sdk_key.endswith(envelope.sdk_key_suffix)


def decrypt(envelope: MediateEnvelope, sdk_key: str, salt: bytes) -> DecryptResult | None:
    """Decrypt *envelope*; None when it fails (see :func:`decrypt_with_reason`)."""
    return decrypt_with_reason(envelope, sdk_key, salt)[0]


def decrypt_with_reason(
    envelope: MediateEnvelope, sdk_key: str, salt: bytes,
) -> tuple[DecryptResult | None, str]:
    """Decrypt *envelope*, returning ``(result, "")`` or ``(None, reason)``."""
    if len(envelope.ciphertext) < COUNTER_SIZE:
        return None, REASON_TRUNCATED
    if protocol_id_for_salt(salt) != envelope.protocol_id:
        return None, REASON_PROTOCOL_ID_MISMATCH
    dk = derive_key(salt, sdk_key)
    for variant in ALL_VARIANTS:
        result = _try_variant(envelope, dk, variant)
        if result is not None:
            matches = sdk_key_matches_suffix(sdk_key, envelope)
            return replace(result, sdk_key_matches_suffix=matches), ""
    return None, REASON_NO_VARIANT


def _try_variant(
    envelope: MediateEnvelope, dk: bytes, variant: CipherVariant,
) -> DecryptResult | None:
    counter = unmask_counter(envelope.ciphertext, dk, variant)
    body = envelope.ciphertext[COUNTER_SIZE:]
    head = apply_keystream(body[:len(GZIP_MAGIC)], counter, dk, variant)
    if head != GZIP_MAGIC:
        return None
    plaintext = gunzip_or_none(apply_keystream(body, counter, dk, variant))
    if plaintext is None:
        return None
    return DecryptResult(variant, counter, plaintext, parse_json_or_none(plaintext), False)


def gunzip_or_none(data: bytes) -> bytes | None:
    """Bounded gunzip via the shared decompressor; None on any failure."""
    if not data.startswith(GZIP_MAGIC):
        return None
    out, error = decompress_body(data, "gzip", MAX_AUTO_DECOMPRESS)
    return None if error else out


def parse_json_or_none(data: bytes) -> Any | None:
    """Parse UTF-8 JSON; None when *data* is not JSON."""
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
