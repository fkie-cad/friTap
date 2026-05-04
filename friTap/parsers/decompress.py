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


def decompress_body(body: bytes, encoding: str) -> tuple[bytes, str]:
    """Decompress HTTP body based on Content-Encoding.

    Returns (decompressed_body, error_message). Error is empty on success.
    """
    if not body or not encoding:
        return body, ""
    enc = encoding.lower().strip()
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
