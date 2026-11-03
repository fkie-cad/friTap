"""Shared HTTP content decompression."""

import os
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

# Cap for decompression that runs automatically, without the user asking for
# it (TUI rendering, analyzers, WebSocket permessage-deflate). Explicit saves
# keep using :data:`MAX_DECOMPRESSED_BODY`.
MAX_AUTO_DECOMPRESS = 16 * 1024 * 1024

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


# --- Brotli CVE-2026-111497 guard ------------------------------------------
# A heap out-of-bounds write in Google's Brotli C decoder (1.0.3 - 1.2.0,
# fixed in 1.2.1 on PyPI). The PyPI wheel bundles its own decoder, so only the
# Python package version matters here. Captured bodies are attacker-controlled,
# so br bodies are not decoded on a vulnerable build.
_BROTLI_FIRST_VULNERABLE = (1, 0, 3)
_BROTLI_MIN_SAFE = (1, 2, 1)

# Set to a truthy value to decode br bodies with an unpatched-looking brotli
# (only for distro builds that backported the fix without a version bump).
ALLOW_UNPATCHED_BROTLI_ENV = "FRITAP_ALLOW_UNPATCHED_BROTLI"
_TRUTHY = frozenset({"1", "true", "yes"})

# Error decompress_body() reports when it skips a br body on a vulnerable brotli.
BROTLI_VULNERABLE_ERROR_FMT = (
    "brotli {version} is vulnerable to CVE-2026-111497; "
    "upgrade to brotli>=1.2.1 (decoding skipped)"
)

_BROTLI_SECURITY_WARNING_FMT = (
    "brotli {version} is vulnerable to CVE-2026-111497 \u2014 br bodies will "
    "not be decoded; run: pip install -U 'brotli>=1.2.1' (or set "
    "FRITAP_ALLOW_UNPATCHED_BROTLI=1 if your distro backported the fix)"
)


def _installed_brotli_version() -> str | None:
    """Version string of the imported brotli module, or None when absent."""
    if not _brotli:
        return None
    version = getattr(brotli, "__version__", None) or getattr(brotli, "version", None)
    return str(version) if version else "unknown"


_BROTLI_VERSION = _installed_brotli_version()


def _parse_version(s: str) -> tuple[int, ...]:
    """Leading numeric dotted components of *s* (``"1.2.0.post1"`` -> (1, 2, 0)).

    Parsing stops at the first component that is not purely numeric; a
    component such as ``"0-2"`` contributes its leading digits and then stops.
    Returns ``()`` when *s* does not start with a number.
    """
    parts: list[int] = []
    for component in str(s or "").strip().split("."):
        digits = _leading_digits(component)
        if not digits:
            break
        parts.append(int(digits))
        if len(digits) != len(component):
            break
    return tuple(parts)


def _leading_digits(text: str) -> str:
    """The run of ASCII digits at the start of *text*."""
    end = 0
    while end < len(text) and text[end] in "0123456789":
        end += 1
    return text[:end]


def _is_vulnerable_brotli(version_str: str | None) -> bool:
    """True when *version_str* lies in the CVE-2026-111497 range.

    Conservative: a version that cannot be parsed is not known to be safe and
    is therefore treated as vulnerable.
    """
    version = _parse_version(version_str or "")
    if not version:
        return True
    return _BROTLI_FIRST_VULNERABLE <= version < _BROTLI_MIN_SAFE


def _unpatched_brotli_allowed() -> bool:
    """True when the env override is set (read at call time, not import)."""
    value = os.environ.get(ALLOW_UNPATCHED_BROTLI_ENV, "")
    return value.strip().lower() in _TRUTHY


def brotli_status() -> tuple[str | None, bool, bool]:
    """``(version, vulnerable, overridden)`` for the installed brotli.

    *version* is None when brotli is not installed (then neither flag is set).
    """
    if _BROTLI_VERSION is None:
        return None, False, False
    return (_BROTLI_VERSION, _is_vulnerable_brotli(_BROTLI_VERSION),
            _unpatched_brotli_allowed())


def _brotli_blocked_error() -> str:
    """The CVE error when br decoding must be skipped, else ``""``."""
    version, vulnerable, overridden = brotli_status()
    if vulnerable and not overridden:
        return BROTLI_VULNERABLE_ERROR_FMT.format(version=version)
    return ""


def brotli_security_warning() -> str | None:
    """Startup warning text for a vulnerable, non-overridden brotli, else None."""
    version, vulnerable, overridden = brotli_status()
    if vulnerable and not overridden:
        return _BROTLI_SECURITY_WARNING_FMT.format(version=version)
    return None


def _normalize_encoding(encoding: str) -> str:
    """Lower-cased, stripped encoding name with aliases resolved."""
    enc = encoding.lower().strip()
    return _ENCODING_ALIASES.get(enc, enc)


# --- Optional process isolation (friTap.decoder_isolation) -----------------
# With --isolate-decoders / FRITAP_ISOLATE_DECODERS=1 the native decoders run
# in a restricted worker process. The worker loads this very file as its
# engine and sets _IN_DECODER_WORKER, so inside it every call runs in-process.
_IN_DECODER_WORKER = False


def _isolated_decoders():
    """The decoder-isolation client when isolation is on, else None."""
    if _IN_DECODER_WORKER:
        return None
    from friTap.decoder_isolation import isolated_decoders
    return isolated_decoders()


def _decoder_unavailable_error(enc: str) -> str:
    """Why *enc* cannot be decoded here (missing module, brotli CVE), else ``""``.

    Same texts and order as :func:`decompress_body`; checked in the parent
    before anything is sent to the worker (which repeats the checks).
    """
    if enc == "br":
        return "brotli not installed" if not _brotli else _brotli_blocked_error()
    if enc == "zstd" and not _zstd:
        return "zstandard not installed"
    return ""


def _decompress_body_isolated(isolated, body: bytes, encoding: str,
                              max_out: int) -> tuple[bytes, str]:
    """:func:`decompress_body` via the decoder worker (same contract)."""
    enc = _normalize_encoding(encoding)
    if enc not in _KNOWN_ENCODINGS:
        return body, ""
    unavailable = _decoder_unavailable_error(enc)
    if unavailable:
        return body, unavailable
    return isolated.isolated_decompress_body(
        body, enc, max_out, allow_unpatched_brotli=_unpatched_brotli_allowed())


def _inflate_checked_isolated(isolated, packed: bytes, limit: int) -> tuple[bytes, bool]:
    """:func:`inflate_bounded_checked` via the decoder worker (same exceptions).

    A worker crash, timeout or invalid reply surfaces as ``zlib.error``.
    """
    if limit < 0:
        raise ValueError("max_length must be non-negative")
    outcome = isolated.isolated_inflate_checked(packed, limit)
    if outcome.error == "limit":
        raise InflateLimitError(outcome.message)
    if outcome.error:
        raise zlib.error(outcome.message)
    return outcome.data, outcome.complete


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
    isolated = _isolated_decoders()
    if isolated is not None:
        return _decompress_body_isolated(isolated, body, encoding, max_out)
    enc = _normalize_encoding(encoding)
    try:
        if enc == "gzip":
            return _inflate_to_end(body, zlib.MAX_WBITS | 16, max_out), ""
        elif enc in ("deflate", "permessage-deflate"):
            return _inflate_deflate(body, max_out), ""
        elif enc == "br":
            if not _brotli:
                return body, "brotli not installed"
            blocked = _brotli_blocked_error()
            if blocked:
                return body, blocked
            return _brotli_bounded(body, max_out), ""
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
    return _inflate_gzip_candidate(data, max_out)[0]


# Total inflate work _find_gzip_member() may spend across all candidates, as
# a multiple of *max_out* (each failed candidate can otherwise cost max_out).
_EMBEDDED_GZIP_WORK_FACTOR = 4


def _find_gzip_member(
    data: bytes, max_out: int, max_candidates: int,
) -> tuple[int, bytes, int] | None:
    """``(offset, inflated, member_len)`` of the first inflatable gzip member.

    All candidates share one output budget of
    ``_EMBEDDED_GZIP_WORK_FACTOR * max_out`` bytes, and candidates are sliced
    through a memoryview (no per-candidate copy of the tail of *data*).
    Runs in the decoder worker when isolation is on.
    """
    isolated = _isolated_decoders()
    if isolated is not None:
        return isolated.isolated_find_gzip_member(data, max_out, max_candidates)
    view = memoryview(data)
    budget = _EMBEDDED_GZIP_WORK_FACTOR * max_out
    offset = data.find(_GZIP_MAGIC)
    tried = 0
    while offset != -1 and tried < max_candidates and budget > 0:
        member, spent = _inflate_gzip_candidate(view[offset:], min(max_out, budget))
        if member is not None:
            return offset, member[0], member[1]
        budget -= spent
        tried += 1
        offset = data.find(_GZIP_MAGIC, offset + 1)
    return None


def _inflate_gzip_candidate(
    data, max_out: int,
) -> tuple[tuple[bytes, int] | None, int]:
    """``(_inflate_gzip_member(...), output_bytes_spent)`` for one candidate."""
    dec = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        out = dec.decompress(data, max_out + 1)
    except zlib.error:
        return None, 0
    if not dec.eof or len(out) > max_out:
        return None, len(out)
    return (out, len(data) - len(dec.unused_data)), len(out)


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


def inflate_bounded(
    packed: bytes, limit: int = MAX_INFLATE, require_eof: bool = False,
) -> bytes:
    """Inflate a gzip- or zlib-framed body to at most *limit* bytes.

    ``MAX_WBITS | 32`` auto-detects the header (e.g. Telegram's ``gzip_packed``
    carries real gzip members, which a plain zlib ``decompressobj()`` rejects).
    Raises ``zlib.error`` on a corrupt stream and :class:`InflateLimitError`
    when the output would exceed *limit* (input left unconsumed) instead of
    inflating it unbounded.

    By default a truncated stream yields the output inflated so far; with
    *require_eof* it raises ``zlib.error`` instead. Use
    :func:`inflate_bounded_checked` to keep the partial output AND learn that
    it is incomplete.
    """
    inflated, complete = inflate_bounded_checked(packed, limit)
    if require_eof and not complete:
        raise zlib.error("Error -5 while decompressing data: incomplete or truncated stream")
    return inflated


def inflate_bounded_checked(
    packed: bytes, limit: int = MAX_INFLATE,
) -> tuple[bytes, bool]:
    """:func:`inflate_bounded` that also reports completeness: ``(data, complete)``.

    *complete* is False when the gzip/zlib stream ended before its end marker
    (a truncated capture); *data* is then the output inflated so far, which is
    still worth showing as long as it is flagged as partial. Raises exactly
    like :func:`inflate_bounded`: ``zlib.error`` on a corrupt stream and
    :class:`InflateLimitError` when the output would exceed *limit*.
    """
    isolated = _isolated_decoders()
    if isolated is not None:
        return _inflate_checked_isolated(isolated, packed, limit)
    inflater = zlib.decompressobj(zlib.MAX_WBITS | 32)
    inflated = inflater.decompress(packed, limit)
    if inflater.unconsumed_tail:
        raise InflateLimitError(f"inflate exceeds {limit} B limit")
    return inflated, inflater.eof


def inflate_stream_bounded(dec, data: bytes, max_out: int) -> bytes:
    """Feed *data* to a stateful zlib ``decompressobj`` *dec*, bounded.

    For streams whose inflater persists across messages (e.g. WebSocket
    permessage-deflate context takeover). Raises :class:`InflateLimitError`
    when *data* would inflate beyond *max_out* bytes; *dec* is then mid-stream
    and must be discarded by the caller. ``zlib.error`` propagates.
    """
    out = dec.decompress(data, max_out + 1)
    if len(out) > max_out or dec.unconsumed_tail:
        raise InflateLimitError(f"inflate exceeds {max_out} B limit")
    return out
