"""MTProto obfuscated-transport de-obfuscation and frame extraction.

Reimplemented from the *algorithm* described by ``tomer8007/mtproto-dissector``
(``mtproto/mtproto.lua``) and the Telegram MTProto transport docs — no GPL text
is copied.

Obfuscated transport prepends a 64-byte init block to the client->server stream.
The whole stream (init block included) is AES-256-CTR encrypted; the keystream is
position-dependent, so each direction is driven by ONE stateful CTR cipher that
must be fed bytes strictly in order. The init block is keyed as follows:

  * ``key_out = init[8:40]``,  ``iv_out = init[40:56]``           (client->server)
  * ``rev = init[8:56][::-1]`` (48 bytes); ``key_in = rev[0:32]``,
    ``iv_in = rev[32:48]``                                        (server->client)

After CTR-decrypting the first 64 client bytes, ``init[56:60]`` carries a 4-byte
transport tag. Byte 64 onward is the framed record stream.
"""

from __future__ import annotations

from typing import Iterator, Optional

# Transport tags found at decrypted init[56:60].
ABRIDGED = "abridged"
INTERMEDIATE = "intermediate"
PADDED_INTERMEDIATE = "padded_intermediate"

_TAG_ABRIDGED = b"\xef\xef\xef\xef"
_TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
_TAG_PADDED_INTERMEDIATE = b"\xdd\xdd\xdd\xdd"

_INIT_LEN = 64

_QUICK_ACK_BIT = 0x80  # high bit of the abridged length byte; masked off


def _ctr_cipher(key: bytes, iv: bytes):
    """Create a stateful AES-256-CTR encryptor (CTR is symmetric: enc == dec).

    AES-CTR comes from ``cryptography`` only (``tgcrypto`` cannot do the stateful,
    position-continuous CTR this needs). Missing it surfaces as a clean
    :class:`MtprotoDependencyError` rather than a raw ImportError.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        from . import MTPROTO_DEPENDENCY_HINT, MtprotoDependencyError

        raise MtprotoDependencyError(MTPROTO_DEPENDENCY_HINT) from exc

    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def derive_obfuscation_keys(init: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Derive ``(key_out, iv_out, key_in, iv_in)`` from the raw 64-byte init block.

    ``init`` is the *encrypted* client->server prefix as seen on the wire.
    """
    if len(init) < 56:
        raise ValueError("init block too short to derive obfuscation keys")
    key_out = init[8:40]
    iv_out = init[40:56]
    rev = init[8:56][::-1]
    key_in = rev[0:32]
    iv_in = rev[32:48]
    return key_out, iv_out, key_in, iv_in


class ObfuscationCipher:
    """Stateful de-obfuscation for one MTProto conversation.

    Holds two CTR ciphers — ``out`` (client->server) and ``in`` (server->client)
    — each seeded from the client init block. Bytes must be fed in stream order
    because CTR advances its counter across calls.
    """

    def __init__(self, init: bytes):
        key_out, iv_out, key_in, iv_in = derive_obfuscation_keys(init)
        self._out = _ctr_cipher(key_out, iv_out)
        self._in = _ctr_cipher(key_in, iv_in)

    def decrypt_out(self, data: bytes) -> bytes:
        """De-obfuscate the next chunk of the client->server stream."""
        return self._out.update(data)

    def decrypt_in(self, data: bytes) -> bytes:
        """De-obfuscate the next chunk of the server->client stream."""
        return self._in.update(data)


def detect_transport(decrypted_init: bytes) -> Optional[str]:
    """Identify the transport from the *decrypted* 64-byte init block.

    Returns one of ``ABRIDGED``/``INTERMEDIATE``/``PADDED_INTERMEDIATE`` or
    ``None`` when no known tag matches (the false-positive guard: the stream is
    not MTProto-obfuscated).
    """
    if len(decrypted_init) < 60:
        return None
    tag = decrypted_init[56:60]
    if tag == _TAG_ABRIDGED:
        return ABRIDGED
    if tag == _TAG_INTERMEDIATE:
        return INTERMEDIATE
    if tag == _TAG_PADDED_INTERMEDIATE:
        return PADDED_INTERMEDIATE
    return None


def iter_frames(transport_type: str, stream_bytes: bytes) -> Iterator[bytes]:
    """Yield each outer MTProto record from a *de-obfuscated* payload stream.

    ``stream_bytes`` starts at decrypted byte 64 (after the init block). A partial
    trailing frame is dropped cleanly (the stream may have been cut mid-record).

    ``padded_intermediate`` and ``full`` are not supported here and raise
    :class:`NotImplementedError`; the caller degrades gracefully.
    """
    if transport_type == ABRIDGED:
        yield from _iter_abridged(stream_bytes)
    elif transport_type == INTERMEDIATE:
        yield from _iter_intermediate(stream_bytes)
    elif transport_type == PADDED_INTERMEDIATE:
        raise NotImplementedError("padded_intermediate framing is not supported")
    else:
        raise NotImplementedError(f"unsupported transport type: {transport_type!r}")


def _iter_abridged(buf: bytes) -> Iterator[bytes]:
    pos = 0
    n = len(buf)
    while pos < n:
        first = buf[pos] & ~_QUICK_ACK_BIT  # mask off the quick-ack high bit
        if first < 0x7F:
            payload_len = first * 4
            header_end = pos + 1
        else:
            if pos + 4 > n:
                return  # partial 3-byte length
            payload_len = int.from_bytes(buf[pos + 1 : pos + 4], "little") * 4
            header_end = pos + 4
        end = header_end + payload_len
        if end > n:
            return  # partial trailing frame
        yield buf[header_end:end]
        pos = end


def _iter_intermediate(buf: bytes) -> Iterator[bytes]:
    pos = 0
    n = len(buf)
    while pos + 4 <= n:
        payload_len = int.from_bytes(buf[pos : pos + 4], "little")
        start = pos + 4
        end = start + payload_len
        if end > n:
            return  # partial trailing frame
        yield buf[start:end]
        pos = end
