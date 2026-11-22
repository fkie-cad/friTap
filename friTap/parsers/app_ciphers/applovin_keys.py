"""Static key-material extraction for the AppLovin MAX "mediate" cipher.

The cipher key is ``SHA-256(salt32 || sdk_key[:32])``.  Both inputs ship
inside the app bundle:

* the **SDK key** is an 86-character per-publisher token, normally in the
  Android manifest (``<meta-data android:name="applovin.sdk.key">``) or the
  iOS ``Info.plist`` (``AppLovinSdkKey``), sometimes in resources or code;
* the **salt** is a 32-byte constant embedded in the AppLovin SDK
  (21 meaningful bytes + 11 zero bytes).  We do not know it, but the wire
  envelope carries ``protocol_id = SHA-1(salt32).hex()``, which is an exact
  oracle: we hash every candidate window of the SDK binaries until one
  matches.

Stdlib only (zipfile, plistlib, hashlib, re, struct) so it stays a parsers leaf.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import logging
import os
import plistlib
import re
import struct
import zipfile
from concurrent.futures import FIRST_COMPLETED, Executor, wait
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Union

from friTap.parsers.app_ciphers.salt_scan_pool import SubprocessWindowScan

logger = logging.getLogger("friTap.parsers.app_ciphers.applovin_keys")

SDK_KEY_LENGTH = 86
SALT_LENGTH = 32
SALT_MEANINGFUL_LENGTH = 21
SALT_ZERO_TAIL = bytes(SALT_LENGTH - SALT_MEANINGFUL_LENGTH)

ANDROID_META_DATA_NAME = "applovin.sdk.key"
IOS_PLIST_KEY = "AppLovinSdkKey"

# Per-file read cap: a bigger member is scanned over its first MAX bytes only.
MAX_BLOB_BYTES = 128 * 1024 * 1024
# Nested APKs (inside .apks / .xapk) are loaded into memory up to this size.
MAX_NESTED_APK_BYTES = 512 * 1024 * 1024

# Byte markers of the AppLovin SDK: blobs containing one are scanned first.
APPLOVIN_BLOB_MARKERS = (b"Lcom/applovin/", b"AppLovinSDK", b"ALSdk")

# Sliding-window scan: blobs at least this big are split over worker processes
# (``python -m`` subprocesses, see salt_scan_pool -- never multiprocessing, which
# re-runs an unguarded caller script in every spawned worker).
PARALLEL_MIN_BLOB_BYTES = 2 * 1024 * 1024
# Offsets per worker task (several tasks per worker: load balance + early exit).
PARALLEL_CHUNK_OFFSETS = 256 * 1024
# ``FRITAP_APPLOVIN_SCAN_WORKERS``: worker count; 0 or 1 forces the serial scan.
ENV_SCAN_WORKERS = "FRITAP_APPLOVIN_SCAN_WORKERS"

# Extra salt-candidate generator: ``(blob_label, blob) -> candidate byte strings``.
CandidateGenerator = Callable[[str, bytes], Iterable[bytes]]

# Candidate sources, best (most specific) first.
SOURCE_RANK = {
    "manifest": 0,
    "info.plist": 0,
    "manifest-token": 1,
    "plist-token": 1,
    "resources": 2,
    "dex-string": 3,
    "binary-string": 4,
}

_ASCII_KEY_RE = re.compile(rb"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{86}(?![A-Za-z0-9_\-])")
_UTF16_KEY_RE = re.compile(
    rb"(?<![A-Za-z0-9_\-]\x00)(?:[A-Za-z0-9_\-]\x00){86}(?![A-Za-z0-9_\-]\x00)"
)
_SDK_KEY_TEXT_RE = re.compile(r"^[A-Za-z0-9_\-]{86}$")
_HEX_SALT_RE = re.compile(rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{42})(?![0-9A-Fa-f])")
_BASE64_SALT_RE = re.compile(
    rb"(?<![A-Za-z0-9+/_\-])(?:[A-Za-z0-9+/_\-]{43}=?|[A-Za-z0-9+/_\-]{28})(?![A-Za-z0-9+/=_\-])"
)
# Fast equivalents of the two salt regexes above: match maximal character runs
# (no per-offset lookbehind) and check the run length in Python -- ~3x faster
# on large binaries.  See _iter_hex_salt_tokens / _iter_base64_salt_tokens.
_HEX_RUN_RE = re.compile(rb"[0-9A-Fa-f]{42,}")
_BASE64_RUN_RE = re.compile(rb"([A-Za-z0-9+/_\-]{28,})(=*)")
_BASE64_CHARS_AS_BYTES = frozenset(bytes([c]) for c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-")
_PROTOCOL_ID_RE = re.compile(r"^[0-9a-fA-F]{40}$")

_IPA_APP_PREFIX_RE = re.compile(r"^Payload/[^/]+\.app/")
_IPA_INFO_PLIST_RE = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")
_DEX_RE = re.compile(r"(^|/)classes\d*\.dex$")
_NATIVE_LIB_RE = re.compile(r"(^|/)lib/[^/]+/[^/]+\.so$")
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",  # 32-bit
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",  # 64-bit
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",  # fat
}

# Binary AXML (Android compiled XML) chunk types.
_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_START_ELEMENT_TYPE = 0x0102
_STRING_POOL_UTF8_FLAG = 0x100
_TYPE_STRING = 0x03
_NO_INDEX = 0xFFFFFFFF


@dataclass(frozen=True)
class SdkKeyCandidate:
    """One SDK-key candidate and where it was found (see ``SOURCE_RANK``)."""

    key: str
    source: str


# --------------------------------------------------------------------------
# Small shared helpers
# --------------------------------------------------------------------------

def is_sdk_key(value: str) -> bool:
    """True when *value* has the shape of an AppLovin SDK key."""
    return bool(_SDK_KEY_TEXT_RE.match(value))


def protocol_id_for_salt(salt: bytes) -> str:
    """The wire ``protocol_id`` for a 32-byte salt: ``SHA-1(salt).hex()``."""
    return hashlib.sha1(salt).hexdigest()


def _read_member(zf: zipfile.ZipFile, name: str, limit: int = MAX_BLOB_BYTES) -> bytes:
    """Read up to *limit* bytes of a zip member (b'' when it is absent)."""
    try:
        with zf.open(name) as handle:
            return handle.read(limit)
    except KeyError:
        return b""


def _is_ipa(zf: zipfile.ZipFile) -> bool:
    return any(_IPA_APP_PREFIX_RE.match(name) for name in zf.namelist())


def _iter_android_zips(outer: zipfile.ZipFile) -> Iterator[zipfile.ZipFile]:
    """The APK itself, then every nested APK (split .apks / .xapk bundles)."""
    yield outer
    for info in outer.infolist():
        if info.filename.endswith(".apk") and info.file_size <= MAX_NESTED_APK_BYTES:
            try:
                yield zipfile.ZipFile(io.BytesIO(outer.read(info.filename)))
            except zipfile.BadZipFile:
                continue


# --------------------------------------------------------------------------
# Binary AXML: just enough to read <meta-data name=... value=...>
# --------------------------------------------------------------------------

def _read_pool_length(data: bytes, pos: int, unit: int) -> tuple[int, int]:
    """Decode a string-pool length (1 or 2 units, high bit = long form)."""
    fmt, high_bit = ("<B", 0x80) if unit == 1 else ("<H", 0x8000)
    (first,) = struct.unpack_from(fmt, data, pos)
    if not first & high_bit:
        return first, pos + unit
    (second,) = struct.unpack_from(fmt, data, pos + unit)
    return ((first & ~high_bit) << (8 * unit)) | second, pos + 2 * unit


def _decode_utf8_pool_entry(chunk: bytes, pos: int) -> str:
    _, pos = _read_pool_length(chunk, pos, 1)  # UTF-16 length, unused
    byte_count, pos = _read_pool_length(chunk, pos, 1)
    return chunk[pos:pos + byte_count].decode("utf-8", "replace")


def _decode_utf16_pool_entry(chunk: bytes, pos: int) -> str:
    char_count, pos = _read_pool_length(chunk, pos, 2)
    return chunk[pos:pos + 2 * char_count].decode("utf-16-le", "replace")


def parse_string_pool(chunk: bytes) -> list[str]:
    """Decode a ResStringPool chunk (UTF-8 or UTF-16) into its strings."""
    header_size, = struct.unpack_from("<H", chunk, 2)
    count, _styles, flags, strings_start = struct.unpack_from("<IIII", chunk, 8)
    offsets = struct.unpack_from(f"<{count}I", chunk, header_size)
    decode = _decode_utf8_pool_entry if flags & _STRING_POOL_UTF8_FLAG else _decode_utf16_pool_entry
    return [decode(chunk, strings_start + offset) for offset in offsets]


def _iter_axml_chunks(axml: bytes) -> Iterator[tuple[int, int, bytes]]:
    """Yield ``(chunk_type, header_size, chunk_bytes)`` for top-level chunks."""
    _, outer_header_size, _ = struct.unpack_from("<HHI", axml, 0)
    pos = outer_header_size
    while pos + 8 <= len(axml):
        chunk_type, header_size, size = struct.unpack_from("<HHI", axml, pos)
        if size < 8:
            return
        yield chunk_type, header_size, axml[pos:pos + size]
        pos += size


def _pool_string(strings: list[str], index: int) -> str | None:
    return strings[index] if index != _NO_INDEX and index < len(strings) else None


def _element_attributes(chunk: bytes, header_size: int, strings: list[str]) -> dict[str, str | None]:
    """Map attribute name -> string value for one XML start-element chunk."""
    attr_start, attr_size, attr_count = struct.unpack_from("<HHH", chunk, header_size + 8)
    base = header_size + attr_start
    attributes: dict[str, str | None] = {}
    for i in range(attr_count):
        _, name, raw, _, _, data_type, data = struct.unpack_from("<IIIHBBI", chunk, base + i * attr_size)
        value = _pool_string(strings, raw)
        if value is None and data_type == _TYPE_STRING:
            value = _pool_string(strings, data)
        attributes[_pool_string(strings, name) or f"#{i}"] = value
    return attributes


def _sdk_key_from_meta_data(attributes: dict[str, str | None]) -> str | None:
    """The ``value`` of a ``<meta-data name="applovin.sdk.key">`` element."""
    if ANDROID_META_DATA_NAME not in attributes.values():
        return None
    value = attributes.get("value")
    return value.strip() if value else None


def find_manifest_sdk_key(axml: bytes) -> str | None:
    """The literal SDK key from a binary AndroidManifest.xml, if present.

    Returns None when the meta-data is absent or its value is a resource
    reference (``@string/...``) -- the resources token scan covers that case.
    """
    strings: list[str] | None = None
    try:
        for chunk_type, header_size, chunk in _iter_axml_chunks(axml):
            if chunk_type == _RES_STRING_POOL_TYPE and strings is None:
                strings = parse_string_pool(chunk)
            elif chunk_type == _RES_XML_START_ELEMENT_TYPE and strings is not None:
                key = _sdk_key_from_meta_data(_element_attributes(chunk, header_size, strings))
                if key:
                    return key
    except (struct.error, IndexError):
        return None
    return None


# --------------------------------------------------------------------------
# SDK key candidates
# --------------------------------------------------------------------------

def scan_sdk_key_tokens(data: bytes) -> list[str]:
    """All 86-char key-shaped tokens in *data* (ASCII/UTF-8 and UTF-16LE)."""
    tokens = [m.group().decode("ascii") for m in _ASCII_KEY_RE.finditer(data)]
    tokens += [m.group().decode("utf-16-le") for m in _UTF16_KEY_RE.finditer(data)]
    return tokens


def _token_candidates(data: bytes, source: str) -> Iterator[SdkKeyCandidate]:
    for token in scan_sdk_key_tokens(data):
        yield SdkKeyCandidate(token, source)


def _apk_candidates(zf: zipfile.ZipFile) -> Iterator[SdkKeyCandidate]:
    manifest = _read_member(zf, "AndroidManifest.xml")
    key = find_manifest_sdk_key(manifest) if manifest else None
    if key:
        yield SdkKeyCandidate(key, "manifest")
    yield from _token_candidates(manifest, "manifest-token")
    yield from _token_candidates(_read_member(zf, "resources.arsc"), "resources")
    for name in zf.namelist():
        if _DEX_RE.search(name):
            yield from _token_candidates(_read_member(zf, name), "dex-string")


def _plist_sdk_key(raw: bytes) -> str | None:
    """``AppLovinSdkKey`` from an XML or binary plist."""
    try:
        value = plistlib.loads(raw).get(IOS_PLIST_KEY)
    except (plistlib.InvalidFileException, ValueError, AttributeError, TypeError):
        return None
    return value.strip() if isinstance(value, str) and value.strip() else None


def _ipa_candidates(zf: zipfile.ZipFile) -> Iterator[SdkKeyCandidate]:
    for name in zf.namelist():
        if _IPA_INFO_PLIST_RE.match(name):
            raw = _read_member(zf, name)
            key = _plist_sdk_key(raw)
            if key:
                yield SdkKeyCandidate(key, "info.plist")
            yield from _token_candidates(raw, "plist-token")
    for name in zf.namelist():
        if _IPA_APP_PREFIX_RE.match(name) and name.endswith((".plist", ".json", ".strings")):
            yield from _token_candidates(_read_member(zf, name), "resources")
    for _label, blob in _iter_ipa_macho_blobs(zf):
        yield from _token_candidates(blob, "binary-string")


def _rank_and_dedupe(candidates: Iterable[SdkKeyCandidate]) -> list[SdkKeyCandidate]:
    """Keep each key once (its best source), ordered best-first, stable."""
    best: dict[str, SdkKeyCandidate] = {}
    for candidate in candidates:
        current = best.get(candidate.key)
        if current is None or SOURCE_RANK[candidate.source] < SOURCE_RANK[current.source]:
            best[candidate.key] = candidate
    return sorted(best.values(), key=lambda c: SOURCE_RANK[c.source])


def find_sdk_key_candidates(bundle_path: str) -> list[SdkKeyCandidate]:
    """SDK-key candidates from an APK / .apks / .xapk / IPA, best first."""
    with zipfile.ZipFile(bundle_path) as zf:
        if _is_ipa(zf):
            return _rank_and_dedupe(_ipa_candidates(zf))
        found = (c for inner in _iter_android_zips(zf) for c in _apk_candidates(inner))
        return _rank_and_dedupe(found)


# --------------------------------------------------------------------------
# SDK binaries (where the salt lives)
# --------------------------------------------------------------------------

def _applovin_first(names: list[str]) -> list[str]:
    """AppLovin-named members first: they are the likeliest salt carriers."""
    return sorted(names, key=lambda name: "applovin" not in name.lower())


def _iter_android_binary_blobs(zf: zipfile.ZipFile, prefix: str) -> Iterator[tuple[str, bytes]]:
    names = [n for n in zf.namelist() if _DEX_RE.search(n) or _NATIVE_LIB_RE.search(n)]
    for name in _applovin_first(names):
        yield f"{prefix}{name}", _read_member(zf, name)


def _is_macho_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bool:
    if info.is_dir() or info.file_size < 4096 or not _IPA_APP_PREFIX_RE.match(info.filename):
        return False
    with zf.open(info) as handle:
        return handle.read(4) in _MACHO_MAGICS


def _iter_ipa_macho_blobs(zf: zipfile.ZipFile) -> Iterator[tuple[str, bytes]]:
    """Mach-O files under ``Payload/*.app/`` (incl. ``Frameworks/*``)."""
    names = [info.filename for info in zf.infolist() if _is_macho_member(zf, info)]
    for name in _applovin_first(names):
        yield name, _read_member(zf, name)


def has_applovin_marker(blob: bytes) -> bool:
    """True when *blob* contains an AppLovin SDK marker (``APPLOVIN_BLOB_MARKERS``)."""
    return any(marker in blob for marker in APPLOVIN_BLOB_MARKERS)


# A binary-blob member: (zip it lives in, member name, label to report).
_BlobMember = tuple[zipfile.ZipFile, str, str]


def _android_blob_members(zf: zipfile.ZipFile) -> Iterator[_BlobMember]:
    for index, inner in enumerate(_iter_android_zips(zf)):
        prefix = "" if index == 0 else f"nested[{index}]!"
        names = [n for n in inner.namelist() if _DEX_RE.search(n) or _NATIVE_LIB_RE.search(n)]
        for name in _applovin_first(names):
            yield inner, name, f"{prefix}{name}"


def _ipa_blob_members(zf: zipfile.ZipFile) -> Iterator[_BlobMember]:
    names = [info.filename for info in zf.infolist() if _is_macho_member(zf, info)]
    for name in _applovin_first(names):
        yield zf, name, name


def _markers_first(members: Iterable[_BlobMember]) -> Iterator[tuple[str, bytes]]:
    """Yield marker-carrying blobs at once; re-read the rest afterwards.

    Deferred members are re-read instead of held, so memory stays at one blob.
    """
    deferred: list[_BlobMember] = []
    for member in members:
        zf, name, label = member
        blob = _read_member(zf, name)
        if has_applovin_marker(blob):
            yield label, blob
        else:
            deferred.append(member)
    for zf, name, label in deferred:
        yield label, _read_member(zf, name)


def iter_sdk_binary_blobs(bundle_path: str) -> Iterator[tuple[str, bytes]]:
    """Yield ``(label, bytes)`` for every binary that may embed the salt.

    APK: ``classes*.dex`` and ``lib/*/*.so`` (nested split APKs too);
    IPA: Mach-O files under ``Payload/*.app/``.  Each read is capped at
    ``MAX_BLOB_BYTES``.  Blobs carrying an AppLovin marker
    (``APPLOVIN_BLOB_MARKERS``) come first, then AppLovin-named members.
    """
    with zipfile.ZipFile(bundle_path) as zf:
        members = _ipa_blob_members(zf) if _is_ipa(zf) else _android_blob_members(zf)
        yield from _markers_first(members)


# --------------------------------------------------------------------------
# Salt recovery (SHA-1 oracle)
# --------------------------------------------------------------------------

def _parse_protocol_id(protocol_id_hex: str) -> bytes:
    text = protocol_id_hex.strip()
    if not _PROTOCOL_ID_RE.match(text):
        raise ValueError(f"protocol_id must be 40 hex chars, got {protocol_id_hex!r}")
    return bytes.fromhex(text)


def _as_salt(decoded: bytes) -> bytes | None:
    """A decoded token as a 32-byte salt (21-byte tokens get the zero tail)."""
    if len(decoded) == SALT_LENGTH:
        return decoded
    if len(decoded) == SALT_MEANINGFUL_LENGTH:
        return decoded + SALT_ZERO_TAIL
    return None


def _decode_base64_token(token: bytes) -> bytes | None:
    standard = token.translate(bytes.maketrans(b"-_", b"+/")).rstrip(b"=")
    try:
        return base64.b64decode(standard + b"=" * (-len(standard) % 4), validate=True)
    except binascii.Error:
        return None


def _iter_hex_salt_tokens(blob: bytes) -> Iterator[bytes]:
    """Same tokens as ``_HEX_SALT_RE``: isolated hex runs of exactly 42 or 64 chars."""
    for match in _HEX_RUN_RE.finditer(blob):
        if len(match.group()) in (42, 64):
            yield match.group()


def _base64_run_is_token(blob: bytes, match: "re.Match[bytes]") -> bool:
    """Same acceptance as ``_BASE64_SALT_RE`` for one maximal base64 run."""
    run_length, padding = len(match.group(1)), match.group(2)
    if run_length == 28:
        return not padding
    if run_length != 43 or len(padding) > 1:
        return False
    return not padding or blob[match.end():match.end() + 1] not in _BASE64_CHARS_AS_BYTES


def _iter_base64_salt_tokens(blob: bytes) -> Iterator[bytes]:
    """Same tokens as ``_BASE64_SALT_RE``: isolated 28 / 43(+'=') char runs."""
    for match in _BASE64_RUN_RE.finditer(blob):
        if _base64_run_is_token(blob, match):
            yield match.group()


def _iter_encoded_salt_candidates(blob: bytes) -> Iterator[bytes]:
    """Salts spelled as hex (42/64 chars) or base64 (28/43-44 chars) text."""
    for token in _iter_hex_salt_tokens(blob):
        salt = _as_salt(bytes.fromhex(token.decode("ascii")))
        if salt:
            yield salt
    for token in _iter_base64_salt_tokens(blob):
        salt = _as_salt(_decode_base64_token(token) or b"")
        if salt:
            yield salt


def _scan_encoded_tokens(blob: bytes, target: bytes) -> bytes | None:
    for salt in _iter_encoded_salt_candidates(blob):
        if hashlib.sha1(salt).digest() == target:
            return salt
    return None


def _padded_for_windows(blob: bytes) -> bytes:
    """*blob* plus 20 zero bytes, so windows running off the end are zero-filled."""
    return bytes(blob) + bytes(SALT_MEANINGFUL_LENGTH - 1)


def _scan_window_range(data: bytes, base_offset: int, count: int, target: bytes) -> int | None:
    """Absolute offset of the first window in ``data[0:count]`` hashing to *target*.

    Shared with the subprocess workers (salt_scan_worker).  *data* must
    extend ``SALT_MEANINGFUL_LENGTH - 1`` bytes past the last window start.
    """
    sha1, tail, width = hashlib.sha1, SALT_ZERO_TAIL, SALT_MEANINGFUL_LENGTH
    for offset in range(count):
        if sha1(data[offset:offset + width] + tail).digest() == target:
            return base_offset + offset
    return None


def _salt_at(padded: bytes, offset: int) -> bytes:
    return padded[offset:offset + SALT_MEANINGFUL_LENGTH] + SALT_ZERO_TAIL


def _scan_raw_windows(blob: bytes, target: bytes) -> bytes | None:
    """Hash ``blob[i:i+21] + 11 zero bytes`` for every offset *i* (serial).

    This one pass covers both storage forms: a full 32-byte salt at *i*
    has zeros at ``[i+21, i+32)`` so it hashes identically, and a salt
    stored without its zero tail (dex fill-array-data, Mach-O __const)
    is matched directly.  Windows running off the end are zero-filled.
    """
    padded = _padded_for_windows(blob)
    offset = _scan_window_range(padded, 0, len(blob), target)
    return None if offset is None else _salt_at(padded, offset)


def _window_chunks(total: int, chunk: int) -> Iterator[tuple[int, int]]:
    """``(start, count)`` ranges of window offsets covering ``[0, total)``."""
    for start in range(0, total, chunk):
        yield start, min(chunk, total - start)


def _scan_raw_windows_parallel(blob: bytes, target: bytes, executor: Executor,
                               chunk: int = PARALLEL_CHUNK_OFFSETS) -> bytes | None:
    """:func:`_scan_raw_windows` split over *executor* (same result: lowest offset).

    Each task gets its offsets plus a 20-byte overlap (``SALT_MEANINGFUL_LENGTH
    - 1``), so a salt straddling a chunk boundary is still seen whole.  Once a
    hit is known, higher chunks are cancelled and only lower ones awaited.
    """
    padded = _padded_for_windows(blob)
    overlap = SALT_MEANINGFUL_LENGTH - 1
    pending = {executor.submit(_scan_window_range, padded[start:start + count + overlap], start, count, target): start
               for start, count in _window_chunks(len(blob), chunk)}
    best: int | None = None
    try:
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                pending.pop(future)
                hit = future.result()
                if hit is not None and (best is None or hit < best):
                    best = hit
            if best is not None:
                for future in [f for f, start in pending.items() if start > best]:
                    future.cancel()
                    pending.pop(future)
        return None if best is None else _salt_at(padded, best)
    finally:
        for future in pending:
            future.cancel()


def _scan_worker_count() -> int:
    """Workers for the parallel scan: ``FRITAP_APPLOVIN_SCAN_WORKERS`` or the CPU count."""
    configured = os.environ.get(ENV_SCAN_WORKERS, "").strip()
    if configured.isdigit():
        return int(configured)
    return os.cpu_count() or 1


def _scan_raw_windows_subprocesses(blob: bytes, target: bytes, workers: int,
                                   chunk: int = PARALLEL_CHUNK_OFFSETS) -> tuple[bytes | None, bool]:
    """:func:`_scan_raw_windows` over ``python -m`` worker subprocesses.

    Returns ``(salt | None, healthy)``; *healthy* is False when no worker
    produced a single valid report (every range was then scanned serially).
    """
    padded = _padded_for_windows(blob)
    scan = SubprocessWindowScan(padded, len(blob), target, workers, chunk,
                                serial_scan=_scan_window_range, overlap=SALT_MEANINGFUL_LENGTH - 1)
    offset = scan.run()
    return (None if offset is None else _salt_at(padded, offset)), scan.healthy


class _WindowScanner:
    """Sliding-window scan that uses worker subprocesses for big blobs.

    Workers are fresh ``python -m`` interpreters (see :mod:`salt_scan_pool`),
    so the caller's ``__main__`` is never re-executed.  Ranges a worker fails
    to report are scanned serially; if no worker works at all (no
    subprocesses in a sandbox, broken interpreter) the parallel path is
    disabled for the rest of this scanner's life.
    """

    def __init__(self, workers: int | None = None,
                 min_parallel_bytes: int = PARALLEL_MIN_BLOB_BYTES,
                 chunk: int = PARALLEL_CHUNK_OFFSETS) -> None:
        self.workers = _scan_worker_count() if workers is None else workers
        self.min_parallel_bytes = min_parallel_bytes
        self.chunk = chunk
        self._parallel_ok = self.workers > 1
        self.parallel_scans = 0  # blobs scanned (at least partly) by worker subprocesses

    def scan(self, blob: bytes, target: bytes) -> bytes | None:
        if self._parallel_ok and len(blob) >= self.min_parallel_bytes:
            try:
                salt, healthy = _scan_raw_windows_subprocesses(blob, target, self.workers, self.chunk)
            except Exception as exc:  # noqa: BLE001 - any worker-setup failure -> serial
                logger.debug("Parallel salt scan unavailable, scanning serially: %s", exc)
                self._parallel_ok = False
            else:
                self.parallel_scans += healthy
                if not healthy:
                    logger.debug("Salt-scan workers produced no results; using the serial scan from now on")
                    self._parallel_ok = False
                return salt
        return _scan_raw_windows(blob, target)

    def close(self) -> None:
        """Kept for the context-manager API; workers never outlive a :meth:`scan`."""

    def __enter__(self) -> "_WindowScanner":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def _candidate_salts(candidate: bytes) -> Iterator[bytes]:
    """A structured candidate as-is, plus its zero-padded form when 21 bytes long."""
    candidate = bytes(candidate)
    yield candidate
    if len(candidate) == SALT_MEANINGFUL_LENGTH:
        yield candidate + SALT_ZERO_TAIL


def _match_candidates(candidates: Iterable[bytes], target: bytes) -> bytes | None:
    sha1 = hashlib.sha1
    for candidate in candidates:
        for salt in _candidate_salts(candidate):
            if sha1(salt).digest() == target:
                return salt
    return None


def _extra_candidate_salt(label: str, blob: bytes, target: bytes,
                          generators: Iterable[CandidateGenerator]) -> bytes | None:
    """Check every extra generator's candidates; a failing generator is skipped."""
    for generate in generators:
        try:
            salt = _match_candidates(generate(label, blob), target)
        except Exception as exc:  # noqa: BLE001 - a candidate hook must not abort recovery
            logger.debug("AppLovin salt-candidate generator %r failed on %s: %s", generate, label, exc)
            continue
        if salt:
            return salt
    return None


def _structured_salt(label: str, blob: bytes, target: bytes,
                     generators: Iterable[CandidateGenerator]) -> bytes | None:
    """The cheap checks: encoded hex/base64 tokens, then extra candidate generators."""
    return _scan_encoded_tokens(blob, target) or _extra_candidate_salt(label, blob, target, generators)


# A data source: raw bytes, or ``(label, bytes)`` as yielded by iter_sdk_binary_blobs.
DataSource = Union[bytes, bytearray, memoryview, "tuple[str, bytes]"]


def _labelled(source: DataSource) -> tuple[str, bytes]:
    if isinstance(source, tuple):
        label, blob = source
        return label, bytes(blob)
    return "", bytes(source)


def recover_salt(data_sources: Iterable[DataSource], protocol_id_hex: str,
                 extra_candidates: CandidateGenerator | None = None) -> bytes | None:
    """Find the 32-byte salt whose SHA-1 equals *protocol_id_hex*.

    Each blob (raw bytes or ``(label, bytes)``) is searched first for
    hex/base64-encoded salts and *extra_candidates* (cheap), then
    exhaustively over raw byte windows (parallel for big blobs).
    Returns None if nothing matches.
    """
    target = _parse_protocol_id(protocol_id_hex)
    generators = [extra_candidates] if extra_candidates else []
    with _WindowScanner() as scanner:
        for source in data_sources:
            label, blob = _labelled(source)
            salt = _structured_salt(label, blob, target, generators) or scanner.scan(blob, target)
            if salt:
                return salt
    return None


def _salt_candidates_hook() -> CandidateGenerator | None:
    """``salt_candidates.iter_salt_candidates`` when that module is available."""
    try:
        from friTap.parsers.app_ciphers.salt_candidates import iter_salt_candidates
    except ImportError:
        return None
    return iter_salt_candidates


def recover_salt_from_bundle(bundle_path: str, protocol_id_hex: str,
                             extra_candidates: CandidateGenerator | None = None) -> bytes | None:
    """Recover the salt by searching every SDK binary in the bundle.

    Two passes: the cheap structured candidates (encoded tokens,
    ``salt_candidates.iter_salt_candidates``, *extra_candidates*) over all
    blobs first, then the exhaustive sliding window, marker blobs first.
    """
    target = _parse_protocol_id(protocol_id_hex)
    generators = [g for g in (_salt_candidates_hook(), extra_candidates) if g]
    for label, blob in iter_sdk_binary_blobs(bundle_path):
        salt = _structured_salt(label, blob, target, generators)
        if salt:
            return salt
    with _WindowScanner() as scanner:
        for _label, blob in iter_sdk_binary_blobs(bundle_path):
            salt = scanner.scan(blob, target)
            if salt:
                return salt
    return None
