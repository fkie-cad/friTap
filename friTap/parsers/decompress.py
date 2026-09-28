"""Shared HTTP content decompression."""

import zlib

try:
    import brotli
    _brotli = True
except ImportError:
    _brotli = False

try:
    import zstandard
    _zstd = True
except ImportError:
    _zstd = False


# Alternative spellings of an encoding (the body-processing modal's option ids
# and legacy Content-Encoding tokens) mapped to the canonical name below.
_ENCODING_ALIASES = {"brotli": "br", "x-gzip": "gzip"}

# Encodings decompress_body() understands (after alias normalisation).
_KNOWN_ENCODINGS = frozenset({"gzip", "deflate", "permessage-deflate", "br", "zstd"})

# gzip member magic: ID1 ID2 + CM=8 (deflate), RFC 1952 section 2.3.1.
_GZIP_MAGIC = b"\x1f\x8b\x08"

# Default cap on the inflated size of an embedded gzip member (zip-bomb guard).
_EMBEDDED_GZIP_MAX_OUT = 16 * 1024 * 1024

# Default cap on how many magic candidates find_embedded_gzip() tries.
_EMBEDDED_GZIP_MAX_CANDIDATES = 64


def _normalize_encoding(encoding: str) -> str:
    """Lower-cased, stripped encoding name with aliases resolved."""
    enc = encoding.lower().strip()
    return _ENCODING_ALIASES.get(enc, enc)


def decompress_body(body: bytes, encoding: str) -> tuple[bytes, str]:
    """Decompress HTTP body based on Content-Encoding.

    Returns (decompressed_body, error_message). Error is empty on success.
    """
    if not body or not encoding:
        return body, ""
    enc = _normalize_encoding(encoding)
    try:
        if enc == "gzip":
            return zlib.decompress(body, zlib.MAX_WBITS | 16), ""
        elif enc in ("deflate", "permessage-deflate"):
            try:
                return zlib.decompress(body, -zlib.MAX_WBITS), ""
            except zlib.error:
                pass
            # Try with RFC 7692 permessage-deflate sync flush trailer.
            # Must use streaming decompressobj — the trailer is a flush
            # point, not a stream end, so one-shot decompress() rejects it.
            try:
                dec = zlib.decompressobj(-zlib.MAX_WBITS)
                return dec.decompress(body + b"\x00\x00\xff\xff"), ""
            except zlib.error:
                pass
            # Try with zlib wrapper (some servers send wrapped deflate)
            return zlib.decompress(body), ""
        elif enc == "br":
            if _brotli:
                return brotli.decompress(body), ""
            return body, "brotli not installed"
        elif enc == "zstd":
            if _zstd:
                return zstandard.ZstdDecompressor().decompress(body), ""
            return body, "zstandard not installed"
    except Exception as e:
        return body, f"decompress failed: {e}"
    return body, ""


def _inflate_gzip_member(data: bytes, max_out: int) -> tuple[bytes, int] | None:
    """Inflate the gzip member at the start of *data*: ``(output, member_len)``.

    Trailing bytes after the member are ignored. Returns None when the data
    is not one finished member or the output exceeds *max_out* (rejected
    rather than truncated).
    """
    dec = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        out = dec.decompress(data, max_out + 1)
    except zlib.error:
        return None
    if not dec.eof or len(out) > max_out:
        return None
    return out, len(data) - len(dec.unused_data)


def _find_gzip_member(
    data: bytes, max_out: int, max_candidates: int,
) -> tuple[int, bytes, int] | None:
    """``(offset, inflated, member_len)`` of the first inflatable gzip member."""
    offset = data.find(_GZIP_MAGIC)
    tried = 0
    while offset != -1 and tried < max_candidates:
        member = _inflate_gzip_member(data[offset:], max_out)
        if member is not None:
            return offset, member[0], member[1]
        tried += 1
        offset = data.find(_GZIP_MAGIC, offset + 1)
    return None


def find_embedded_gzip(
    body: bytes,
    max_out: int = _EMBEDDED_GZIP_MAX_OUT,
    max_candidates: int = _EMBEDDED_GZIP_MAX_CANDIDATES,
) -> tuple[int, bytes] | None:
    """Locate the first complete gzip member inside *body*.

    Scans for the ``1f 8b 08`` magic and returns ``(offset, inflated)`` for
    the first candidate that inflates to a finished member of at most
    *max_out* bytes. At most *max_candidates* magic hits are tried. Returns
    None when no member is found. Useful for payloads that wrap a gzip
    member in a framing header (e.g. MTProto ``rpc_result`` → ``gzip_packed``).
    """
    if not body:
        return None
    found = _find_gzip_member(bytes(body), max_out, max_candidates)
    return None if found is None else (found[0], found[1])


def _embedded_gzip_fallback(body: bytes) -> tuple[bytes, list[str], str | None]:
    """Lenient gzip: search for an embedded member when offset 0 fails."""
    found = _find_gzip_member(bytes(body), _EMBEDDED_GZIP_MAX_OUT,
                              _EMBEDDED_GZIP_MAX_CANDIDATES)
    if found is None:
        return body, [], "gzip: no gzip member found in body"
    offset, inflated, member_len = found
    note = f"gzip member at offset 0x{offset:X} ({member_len}→{len(inflated)} bytes)"
    return inflated, [note], None


def decompress_lenient(
    body: bytes, encoding: str,
) -> tuple[bytes, list[str], str | None]:
    """User-requested decompression that tolerates a framing prefix.

    Returns ``(data, notes, error)``. Strict :func:`decompress_body` runs
    first; for gzip a failure falls back to :func:`find_embedded_gzip` and
    adds a note such as ``"gzip member at offset 0x1C (N→M bytes)"``. An
    unknown encoding yields an explicit error instead of a silent no-op.
    On error *data* is the unchanged *body*. HTTP ``Content-Encoding``
    handling should keep using the strict :func:`decompress_body`.
    """
    if not body or not encoding:
        return body, [], None
    enc = _normalize_encoding(encoding)
    if enc not in _KNOWN_ENCODINGS:
        return body, [], f"unknown encoding: {encoding!r}"
    data, err = decompress_body(body, enc)
    if not err:
        return data, [], None
    if enc == "gzip":
        return _embedded_gzip_fallback(body)
    return body, [], err
