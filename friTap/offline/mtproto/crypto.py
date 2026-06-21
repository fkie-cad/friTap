"""MTProto 2.0 cryptography primitives.

Pinned against the official spec (core.telegram.org/mtproto/description) and the
``tomer8007/mtproto-dissector`` reference (reimplemented from the algorithm, not
copied). Covers cloud-chat (client<->server transport) encryption:

  * ``auth_key_id``  = low 64 bits of SHA1(auth_key)  — the ONLY SHA1 use.
  * KDF              = SHA256-based (MTProto 2.0; the legacy SHA1 KDF is 1.0).
  * record cipher    = AES-256 in IGE mode.
  * integrity        = msg_key == SHA256(auth_key[88+x:120+x] + plaintext)[8:24].

Direction parameter ``x``: 0 for client->server ("write"), 8 for server->client
("read").

The AES primitive comes from an optional backend (``tgcrypto`` fast path, else
``cryptography`` + a pure-Python IGE built on AES-ECB). Importing this module
never requires the backend; :func:`_aes_ecb` resolves it lazily and raises
:class:`MtprotoDependencyError` if absent.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import NamedTuple, Optional

from . import MTPROTO_DEPENDENCY_HINT, MtprotoCryptoError, MtprotoDependencyError

AES_BLOCK = 16
AUTH_KEY_LEN = 256
AUTH_KEY_ID_LEN = 8
MSG_KEY_LEN = 16
OUTER_HEADER_LEN = AUTH_KEY_ID_LEN + MSG_KEY_LEN  # 24: auth_key_id(8) + msg_key(16)

# Envelope field offsets inside the decrypted plaintext.
_ENVELOPE_PREFIX = 32  # salt(8)+session_id(8)+msg_id(8)+seq_no(4)+msg_len(4)
_MIN_PADDING = 12


# --------------------------------------------------------------------------- #
# AES backend (optional dependency, resolved lazily)
# --------------------------------------------------------------------------- #

_ECB_ENCRYPT = None  # type: ignore[var-annotated]
_ECB_DECRYPT = None  # type: ignore[var-annotated]
_TGCRYPTO = None  # type: ignore[var-annotated]
_BACKEND_RESOLVED = False


def _resolve_backend() -> None:
    """Resolve the AES backend once.

    ``cryptography`` is the FLOOR: it provides AES-CTR (the transport
    de-obfuscation in :mod:`.transport`) and AES-ECB (the pure-Python IGE
    fallback here). ``tgcrypto``, when ALSO installed, only accelerates AES-IGE —
    it cannot do the transport CTR and therefore cannot substitute for
    ``cryptography``.
    """
    global _ECB_ENCRYPT, _ECB_DECRYPT, _TGCRYPTO, _BACKEND_RESOLVED
    if _BACKEND_RESOLVED:
        return

    try:  # optional fast path
        import tgcrypto  # type: ignore

        _TGCRYPTO = tgcrypto
    except ImportError:
        _TGCRYPTO = None

    try:
        from cryptography.hazmat.primitives.ciphers import (  # type: ignore
            Cipher,
            algorithms,
            modes,
        )

        def _ecb_encrypt(key: bytes, data: bytes) -> bytes:
            enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            return enc.update(data) + enc.finalize()

        def _ecb_decrypt(key: bytes, data: bytes) -> bytes:
            dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
            return dec.update(data) + dec.finalize()

        _ECB_ENCRYPT = _ecb_encrypt
        _ECB_DECRYPT = _ecb_decrypt
    except ImportError:
        _ECB_ENCRYPT = None
        _ECB_DECRYPT = None

    _BACKEND_RESOLVED = True


def _require_backend() -> None:
    """Ensure the AES backend the MTProto pipeline needs is importable.

    Gates on ``cryptography`` (the floor — covers both CTR and the IGE fallback).
    ``tgcrypto`` alone is NOT sufficient because the transport layer needs CTR.
    """
    _resolve_backend()
    if _ECB_ENCRYPT is None:
        raise MtprotoDependencyError(MTPROTO_DEPENDENCY_HINT)


def backend_available() -> bool:
    """True if the AES backend the MTProto pipeline needs (``cryptography``) is importable.

    Deliberately gates on ``cryptography`` (not ``tgcrypto``): tgcrypto cannot
    perform the transport AES-CTR de-obfuscation, so a tgcrypto-only environment
    cannot run the pipeline. Gates on the base-install ``cryptography`` backend.
    """
    _resolve_backend()
    return _ECB_ENCRYPT is not None


# --------------------------------------------------------------------------- #
# AES-256-IGE
# --------------------------------------------------------------------------- #


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def aes_ige_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-256 IGE decrypt. ``iv`` is 32 bytes (iv1||iv2); ``data`` len % 16 == 0."""
    if len(iv) != 32:
        raise MtprotoCryptoError("IGE IV must be 32 bytes")
    if len(data) % AES_BLOCK != 0:
        raise MtprotoCryptoError("IGE data length must be a multiple of 16")
    _require_backend()

    if _TGCRYPTO is not None:
        return _TGCRYPTO.ige256_decrypt(data, key, iv)

    iv1, iv2 = iv[:AES_BLOCK], iv[AES_BLOCK:]
    out = bytearray()
    for i in range(0, len(data), AES_BLOCK):
        c = data[i : i + AES_BLOCK]
        d = _ECB_DECRYPT(key, _xor(c, iv2))  # type: ignore[misc]
        p = _xor(d, iv1)
        out += p
        iv1, iv2 = c, p
    return bytes(out)


def aes_ige_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-256 IGE encrypt — the inverse of :func:`aes_ige_decrypt`.

    Used to build golden test vectors (and never on a real capture path).
    """
    if len(iv) != 32:
        raise MtprotoCryptoError("IGE IV must be 32 bytes")
    if len(data) % AES_BLOCK != 0:
        raise MtprotoCryptoError("IGE data length must be a multiple of 16")
    _require_backend()

    if _TGCRYPTO is not None:
        return _TGCRYPTO.ige256_encrypt(data, key, iv)

    iv1, iv2 = iv[:AES_BLOCK], iv[AES_BLOCK:]
    out = bytearray()
    for i in range(0, len(data), AES_BLOCK):
        p = data[i : i + AES_BLOCK]
        c = _xor(_ECB_ENCRYPT(key, _xor(p, iv1)), iv2)  # type: ignore[misc]
        out += c
        iv1, iv2 = c, p
    return bytes(out)


# --------------------------------------------------------------------------- #
# Key derivation / identity
# --------------------------------------------------------------------------- #


def compute_auth_key_id(auth_key: bytes) -> bytes:
    """auth_key_id = low 64 bits of SHA1(auth_key) (the last 8 bytes)."""
    if len(auth_key) != AUTH_KEY_LEN:
        raise MtprotoCryptoError(f"auth_key must be {AUTH_KEY_LEN} bytes")
    return hashlib.sha1(auth_key).digest()[-AUTH_KEY_ID_LEN:]


def _direction_x(direction: str) -> int:
    """0 for client->server ("write"), 8 for server->client ("read")."""
    if direction == "write":
        return 0
    if direction == "read":
        return 8
    raise MtprotoCryptoError(f"direction must be 'read' or 'write', got {direction!r}")


def derive_aes_key_iv(auth_key: bytes, msg_key: bytes, direction: str) -> tuple[bytes, bytes]:
    """MTProto 2.0 SHA256 KDF → (aes_key[32], aes_iv[32])."""
    x = _direction_x(direction)
    sha256_a = hashlib.sha256(msg_key + auth_key[x : x + 36]).digest()
    sha256_b = hashlib.sha256(auth_key[40 + x : 40 + x + 36] + msg_key).digest()
    aes_key = sha256_a[0:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[0:8] + sha256_a[8:24] + sha256_b[24:32]
    return aes_key, aes_iv


def compute_msg_key(auth_key: bytes, plaintext: bytes, direction: str) -> bytes:
    """msg_key = SHA256(auth_key[88+x:120+x] + plaintext)[8:24] (incl. padding)."""
    x = _direction_x(direction)
    msg_key_large = hashlib.sha256(auth_key[88 + x : 88 + x + 32] + plaintext).digest()
    return msg_key_large[8:24]


# --------------------------------------------------------------------------- #
# Record-level decrypt / parse
# --------------------------------------------------------------------------- #


class MtprotoEnvelope(NamedTuple):
    salt: bytes
    session_id: bytes
    msg_id: int
    seq_no: int
    msg_len: int
    message: bytes  # the TL-serialized payload — left to the user's parser
    padding: bytes


def parse_envelope(plaintext: bytes) -> MtprotoEnvelope:
    """Split a decrypted plaintext envelope into its fields.

    Layout: salt(8) session_id(8) msg_id(8) seq_no(4) msg_len(4) message padding.
    """
    if len(plaintext) < _ENVELOPE_PREFIX:
        raise MtprotoCryptoError("plaintext too short for MTProto envelope")
    salt = plaintext[0:8]
    session_id = plaintext[8:16]
    (msg_id,) = struct.unpack_from("<Q", plaintext, 16)
    (seq_no,) = struct.unpack_from("<I", plaintext, 24)
    (msg_len,) = struct.unpack_from("<I", plaintext, 28)
    end = _ENVELOPE_PREFIX + msg_len
    if end > len(plaintext):
        raise MtprotoCryptoError("declared msg_len exceeds plaintext")
    message = plaintext[_ENVELOPE_PREFIX:end]
    padding = plaintext[end:]
    return MtprotoEnvelope(salt, session_id, msg_id, seq_no, msg_len, message, padding)


@dataclass
class DecryptedRecord:
    direction: str
    auth_key_id: bytes
    envelope: MtprotoEnvelope


def decrypt_record(
    auth_key: bytes,
    outer: bytes,
    direction: str,
    *,
    verify: bool = True,
) -> DecryptedRecord:
    """Decrypt one outer MTProto record: auth_key_id(8) + msg_key(16) + enc_data.

    Raises :class:`MtprotoCryptoError` on a length/verification failure.
    """
    if len(outer) < OUTER_HEADER_LEN + AES_BLOCK:
        raise MtprotoCryptoError("record too short")
    auth_key_id = outer[0:AUTH_KEY_ID_LEN]
    msg_key = outer[AUTH_KEY_ID_LEN:OUTER_HEADER_LEN]
    enc = outer[OUTER_HEADER_LEN:]
    if len(enc) % AES_BLOCK != 0:
        raise MtprotoCryptoError("encrypted body not block-aligned")

    aes_key, aes_iv = derive_aes_key_iv(auth_key, msg_key, direction)
    plaintext = aes_ige_decrypt(aes_key, aes_iv, enc)

    if verify:
        expected = compute_msg_key(auth_key, plaintext, direction)
        if expected != msg_key:
            raise MtprotoCryptoError("msg_key verification failed (wrong key or corruption)")

    return DecryptedRecord(direction, auth_key_id, parse_envelope(plaintext))


# --------------------------------------------------------------------------- #
# Test/diagnostic helper: build a valid encrypted record (the encrypt direction)
# --------------------------------------------------------------------------- #


def build_encrypted_record(
    auth_key: bytes,
    message: bytes,
    direction: str,
    *,
    salt: bytes = b"\x00" * 8,
    session_id: bytes = b"\x00" * 8,
    msg_id: int = 0,
    seq_no: int = 0,
    padding: Optional[bytes] = None,
) -> bytes:
    """Produce a valid ``auth_key_id + msg_key + enc_data`` record.

    The inverse of :func:`decrypt_record`; used by tests and the Phase 0.1
    kill-switch experiment to validate the crypto without real traffic.
    """
    if padding is None:
        body_len = _ENVELOPE_PREFIX + len(message)
        pad_len = (-(body_len + _MIN_PADDING)) % AES_BLOCK + _MIN_PADDING
        padding = bytes(pad_len)
    plaintext = (
        salt
        + session_id
        + struct.pack("<Q", msg_id)
        + struct.pack("<I", seq_no)
        + struct.pack("<I", len(message))
        + message
        + padding
    )
    if len(plaintext) % AES_BLOCK != 0:
        raise MtprotoCryptoError("constructed plaintext not block-aligned (bad padding)")

    msg_key = compute_msg_key(auth_key, plaintext, direction)
    aes_key, aes_iv = derive_aes_key_iv(auth_key, msg_key, direction)
    enc = aes_ige_encrypt(aes_key, aes_iv, plaintext)
    return compute_auth_key_id(auth_key) + msg_key + enc


# --------------------------------------------------------------------------- #
# Secret-chat (end-to-end) decrypt / parse
# --------------------------------------------------------------------------- #
#
# Secret chats ride INSIDE the cloud-chat transport: a decrypted transport
# message carries a TL-serialized E2E blob whose own AES-IGE layer is keyed by
# the per-chat 256-byte shared key (NOT the transport auth_key). The crypto is
# the same MTProto 2.0 KDF/IGE as above, only the key and the wire framing
# differ — so everything here reuses the primitives above.

SECRET_CHAT_KEY_LEN = 256
E2E_FINGERPRINT_LEN = 8
E2E_HEADER_LEN = E2E_FINGERPRINT_LEN + MSG_KEY_LEN  # 24: fingerprint(8) + msg_key(16)


def compute_secret_chat_fingerprint(shared_key: bytes) -> bytes:
    """key_fingerprint = low 64 bits of SHA1(shared_key) (the last 8 bytes).

    Identical algorithm to :func:`compute_auth_key_id`; aliased so the secret-chat
    code reads in its own terms while sharing the single SHA1 implementation.
    """
    assert len(shared_key) == SECRET_CHAT_KEY_LEN, (
        f"shared_key must be {SECRET_CHAT_KEY_LEN} bytes"
    )
    return compute_auth_key_id(shared_key)


def decrypt_secret_chat_blob(
    shared_key: bytes,
    blob: bytes,
    *,
    verify: bool = True,
    direction: Optional[str] = None,
) -> bytes:
    """Decrypt one secret-chat E2E blob: key_fingerprint(8) + msg_key(16) + enc.

    The ``x`` direction offset (0 when the sender is the chat creator, 8
    otherwise) is NOT carried on the wire. With ``verify=True`` (default) both
    directions are tried and the one whose recomputed msg_key matches is accepted
    — msg_key verification is cryptographically strong, so a false accept is
    infeasible. Returns the RAW plaintext (4-byte LE length prefix + TL payload +
    random padding).

    ``verify=False`` skips that verification, so the direction can no longer be
    inferred from the blob; an explicit ``direction`` ('write' = sender is the
    chat creator, 'read' = the other party) is then REQUIRED — otherwise this
    raises :class:`ValueError`. (Previously ``verify=False`` silently returned the
    ``write`` decryption for every blob, yielding garbage for non-creator-sent
    messages.)

    Raises :class:`MtprotoCryptoError` on a length/verification failure.
    """
    if direction not in (None, "write", "read"):
        raise ValueError(f"direction must be 'write', 'read', or None: {direction!r}")
    if not verify and direction is None:
        raise ValueError(
            "decrypt_secret_chat_blob(verify=False) requires an explicit "
            "direction ('write' or 'read'): the E2E sender direction is not on "
            "the wire and can only be resolved by msg_key verification"
        )
    if len(blob) < E2E_HEADER_LEN + AES_BLOCK:
        raise MtprotoCryptoError("secret-chat blob too short")
    if (len(blob) - E2E_HEADER_LEN) % AES_BLOCK != 0:
        raise MtprotoCryptoError("secret-chat encrypted body not block-aligned")
    msg_key = blob[E2E_FINGERPRINT_LEN:E2E_HEADER_LEN]
    enc = blob[E2E_HEADER_LEN:]

    directions = (direction,) if direction is not None else ("write", "read")
    for d in directions:
        aes_key, aes_iv = derive_aes_key_iv(shared_key, msg_key, d)
        plaintext = aes_ige_decrypt(aes_key, aes_iv, enc)
        if not verify:
            return plaintext
        if compute_msg_key(shared_key, plaintext, d) == msg_key:
            return plaintext
    raise MtprotoCryptoError("secret-chat msg_key verification failed")


def parse_secret_chat_plaintext(plaintext: bytes) -> bytes:
    """Strip the secret-chat plaintext framing, returning the TL payload bytes.

    Layout: length(4 bytes LE) + TL_payload(length bytes) + random_padding.
    Raises :class:`MtprotoCryptoError` if the declared length exceeds bounds.
    """
    if len(plaintext) < 4:
        raise MtprotoCryptoError("secret-chat plaintext too short for length prefix")
    (length,) = struct.unpack_from("<I", plaintext, 0)
    end = 4 + length
    if end > len(plaintext):
        raise MtprotoCryptoError("declared secret-chat payload length exceeds plaintext")
    return plaintext[4:end]


def build_secret_chat_blob(
    shared_key: bytes,
    payload: bytes,
    *,
    sender_is_creator: bool,
    padding: Optional[bytes] = None,
) -> bytes:
    """Produce a valid ``key_fingerprint + msg_key + enc`` secret-chat blob.

    The inverse of :func:`decrypt_secret_chat_blob`; used by tests to validate
    the secret-chat crypto without real traffic. ``sender_is_creator`` selects
    the direction (``"write"`` / x=0 for the creator, ``"read"`` / x=8 otherwise).
    """
    direction = "write" if sender_is_creator else "read"
    head = struct.pack("<I", len(payload)) + payload
    if padding is None:
        pad_len = (-(len(head) + _MIN_PADDING)) % AES_BLOCK + _MIN_PADDING
        padding = bytes(pad_len)
    plaintext = head + padding
    if len(plaintext) % AES_BLOCK != 0:
        raise MtprotoCryptoError("constructed plaintext not block-aligned (bad padding)")

    msg_key = compute_msg_key(shared_key, plaintext, direction)
    aes_key, aes_iv = derive_aes_key_iv(shared_key, msg_key, direction)
    enc = aes_ige_encrypt(aes_key, aes_iv, plaintext)
    return compute_secret_chat_fingerprint(shared_key) + msg_key + enc
