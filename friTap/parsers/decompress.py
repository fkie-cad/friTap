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

# Default cap on decompress_body() output (decompression-bomb guard). Generous
# so that real HTTP bodies are never cut, but finite: a captured body is
# attacker-controlled and a 16 KiB zstd frame can otherwise expand to 512 MiB.
MAX_DECOMPRESSED_BODY = 256 * 1024 * 1024

# Error text decompress_body() reports when *max_out* would be exceeded.
DECOMPRESS_LIMIT_ERROR = "decompressed size exceeds limit"

# Input slice fed per call by the chunked (output-unbounded API) decoders. A
# zstd block yields at most 128 KiB from ~4 input bytes, so one slice can
# overshoot the cap by a few MiB at worst before the check runs.
_STREAM_INPUT_CHUNK = 256


def _brotli_supports_output_limit() -> bool:
    """True when ``brotli.Decompressor.process`` takes ``output_buffer_limit``."""
    if not _brotli:
        return False
    try:
        brotli.Decompressor().process(b"", output_buffer_limit=1)
    except TypeError:
        return False
    return True


_BROTLI_OUTPUT_LIMIT = _brotli_supports_output_limit()


def _normalize_encoding(encoding: str) -> str:
    """Lower-cased, stripped encoding name with aliases resolved."""
    enc = encoding.lower().strip()
    return _ENCODING_ALIASES.get(enc, enc)


def decompress_body(
    body: bytes, encoding: str, max_out: int = MAX_DECOMPRESSED_BODY,
) -> tuple[bytes, str]:
    """Decompress HTTP body based on Content-Encoding.

    Output is bounded by *max_out* bytes for every encoding (streaming
    decoders, never a one-shot inflate of an untrusted body); a larger result
    is rejected, not truncated, with an error starting with
    :data:`DECOMPRESS_LIMIT_ERROR`.

    Returns (decompressed_body, error_message). Error is empty on success;
    on error the unchanged *body* is returned.
    """
    if not body or not encoding:
        return body, ""
    enc = _normalize_encoding(encoding)
    try:
        if enc == "gzip":
            return _inflate_to_end(body, zlib.MAX_WBITS | 16, max_out), ""
        elif enc in ("deflate", "permessage-deflate"):
            return _inflate_deflate(body, max_out), ""
        elif enc == "br":
            if _brotli:
                return _brotli_bounded(body, max_out), ""
            return body, "brotli not installed"
        elif enc == "zstd":
            if _zstd:
                return _zstd_bounded(body, max_out), ""
            return body, "zstandard not installed"
    except InflateLimitError:
        return body, f"{DECOMPRESS_LIMIT_ERROR} ({max_out} bytes)"
    except Exception as e:
        return body, f"decompress failed: {e}"
    return body, ""


class InflateLimitError(ValueError):
    """A compressed body would inflate beyond the allowed size."""


def _check_output_limit(produced: int, max_out: int) -> None:
    """Raise :class:`InflateLimitError` once *produced* exceeds *max_out*."""
    if produced > max_out:
        raise InflateLimitError(f"inflate exceeds {max_out} B limit")


def _inflate_to_end(body: bytes, wbits: int, max_out: int) -> bytes:
    """Bounded one-stream zlib inflate; like ``zlib.decompress`` it rejects a
    stream that does not finish (trailing bytes after the end are ignored).
    """
    inflater = zlib.decompressobj(wbits)
    out = inflater.decompress(body, max_out + 1)
    _check_output_limit(len(out), max_out)
    if not inflater.eof:
        raise zlib.error("Error -5 while decompressing data: incomplete or truncated stream")
    return out


def _inflate_deflate(body: bytes, max_out: int) -> bytes:
    """Bounded ``deflate``: raw, then sync-flushed raw, then zlib-wrapped."""
    try:
        return _inflate_to_end(body, -zlib.MAX_WBITS, max_out)
    except zlib.error:
        pass
    # Try with RFC 7692 permessage-deflate sync flush trailer.
    # The trailer is a flush point, not a stream end, so the stream is not
    # required to finish here.
    try:
        dec = zlib.decompressobj(-zlib.MAX_WBITS)
        out = dec.decompress(body + b"\x00\x00\xff\xff", max_out + 1)
        _check_output_limit(len(out), max_out)
        return out
    except zlib.error:
        pass
    # Try with zlib wrapper (some servers send wrapped deflate)
    return _inflate_to_end(body, zlib.MAX_WBITS, max_out)


def _feed_in_chunks(process, body: bytes, max_out: int, finished) -> bytes:
    """Feed *body* to ``process(chunk) -> bytes`` slice by slice, bounded.

    For decoders whose API cannot cap output per call: the cap is checked
    after every :data:`_STREAM_INPUT_CHUNK`-byte slice. Stops early once
    ``finished()`` reports the stream end.
    """
    parts: list[bytes] = []
    produced = 0
    for start in range(0, len(body), _STREAM_INPUT_CHUNK):
        part = process(body[start:start + _STREAM_INPUT_CHUNK])
        produced += len(part)
        _check_output_limit(produced, max_out)
        parts.append(part)
        if finished():
            break
    return b"".join(parts)


def _brotli_bounded(body: bytes, max_out: int) -> bytes:
    """Bounded brotli decode; a stream that does not finish is an error."""
    decoder = brotli.Decompressor()
    if _BROTLI_OUTPUT_LIMIT:
        out = decoder.process(body, output_buffer_limit=max_out + 1)
        _check_output_limit(len(out), max_out)
    else:
        out = _feed_in_chunks(decoder.process, body, max_out, decoder.is_finished)
    if not decoder.is_finished():
        raise brotli.error("brotli: decoder failed (truncated stream)")
    return out


def _zstd_bounded(body: bytes, max_out: int) -> bytes:
    """Bounded decode of the first zstd frame (trailing bytes ignored).

    Unlike ``ZstdDecompressor().decompress`` this also accepts frames that
    do not declare their content size; an unfinished frame is an error.
    """
    decoder = zstandard.ZstdDecompressor().decompressobj()
    out = _feed_in_chunks(decoder.decompress, body, max_out, lambda: decoder.eof)
    if not decoder.eof:
        raise zstandard.ZstdError("decompression error: did not decompress full frame")
    return out


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
    body: bytes, encoding: str, max_out: int = MAX_DECOMPRESSED_BODY,
) -> tuple[bytes, list[str], str | None]:
    """User-requested decompression that tolerates a framing prefix.

    Returns ``(data, notes, error)``. Strict :func:`decompress_body` runs
    first; for gzip a failure falls back to :func:`find_embedded_gzip` and
    adds a note such as ``"gzip member at offset 0x1C (N→M bytes)"``. An
    unknown encoding yields an explicit error instead of a silent no-op, and
    output over *max_out* is rejected like in :func:`decompress_body`.
    On error *data* is the unchanged *body*. HTTP ``Content-Encoding``
    handling should keep using the strict :func:`decompress_body`.
    """
    if not body or not encoding:
        return body, [], None
    enc = _normalize_encoding(encoding)
    if enc not in _KNOWN_ENCODINGS:
        return body, [], f"unknown encoding: {encoding!r}"
    data, err = decompress_body(body, enc, max_out)
    if not err:
        return data, [], None
    if enc == "gzip" and not err.startswith(DECOMPRESS_LIMIT_ERROR):
        return _embedded_gzip_fallback(body)
    return body, [], err


# Default cap on the inflated size for inflate_bounded() (decompression-bomb guard).
MAX_INFLATE = 16 * 1024 * 1024


def inflate_bounded(packed: bytes, limit: int = MAX_INFLATE) -> bytes:
    """Inflate a gzip- or zlib-framed body to at most *limit* bytes.

    ``MAX_WBITS | 32`` auto-detects the header (e.g. Telegram's ``gzip_packed``
    carries real gzip members, which a plain zlib ``decompressobj()`` rejects).
    Raises ``zlib.error`` on a corrupt stream and :class:`InflateLimitError`
    when the output would exceed *limit* (input left unconsumed) instead of
    inflating it unbounded.
    """
    inflater = zlib.decompressobj(zlib.MAX_WBITS | 32)
    inflated = inflater.decompress(packed, limit)
    if inflater.unconsumed_tail:
        raise InflateLimitError(f"inflate exceeds {limit} B limit")
    return inflated
