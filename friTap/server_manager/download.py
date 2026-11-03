#!/usr/bin/env python3

"""Verified, bounded frida-server downloads (stdlib only).

The expected SHA-256 is the ``digest`` field (``"sha256:<hex>"``) that GitHub
computes for every release asset when it is uploaded. GitHub records it for
releases published from June 2025 on (frida >= 17.1.0); frida publishes no
checksum files of its own.

Downloads are streamed into a temp file next to the destination, hashed
while streaming, size-capped, and only renamed into place once the digest
matches. A missing digest fails closed unless ``FRITAP_ALLOW_UNVERIFIED_SERVER=1``
is set; a mismatching digest always fails.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import lzma
import os
import re
import tempfile
import urllib.request
from pathlib import Path
from typing import BinaryIO, Iterable, Optional

RELEASE_API_URL = "https://api.github.com/repos/frida/frida/releases/tags/{version}"
ASSET_DOWNLOAD_URL = "https://github.com/frida/frida/releases/download/{version}/{filename}"

# urllib applies a single timeout to the connect and to every socket read, so
# this bounds both a stalled connect and a stalled transfer.
HTTP_TIMEOUT = 30.0
CHUNK_SIZE = 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024

ALLOW_UNVERIFIED_ENV = "FRITAP_ALLOW_UNVERIFIED_SERVER"
_TRUTHY = ("1", "true", "yes", "on")
_SHA256_DIGEST_RE = re.compile(r"^sha256:([0-9a-fA-F]{64})$")
_USER_AGENT = "friTap"

logger = logging.getLogger("friTap.server_manager.download")


class ServerDownloadError(RuntimeError):
    """A frida-server download failed (missing asset, size cap exceeded, ...)."""


class ServerVerificationError(ServerDownloadError):
    """A frida-server download has no usable digest or its digest does not match."""


def allow_unverified_from_env() -> bool:
    """True if ``FRITAP_ALLOW_UNVERIFIED_SERVER`` is set to a truthy value."""
    return os.environ.get(ALLOW_UNVERIFIED_ENV, "").strip().lower() in _TRUTHY


def asset_download_url(version: str, filename: str) -> str:
    return ASSET_DOWNLOAD_URL.format(version=version, filename=filename)


def open_url(url: str, accept: str = "*/*"):
    """``urlopen`` with a timeout and no content encoding requested."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", _USER_AGENT)
    req.add_header("Accept", accept)
    req.add_header("Accept-Encoding", "identity")
    return urllib.request.urlopen(req, timeout=HTTP_TIMEOUT)


def read_capped(resp: BinaryIO, max_bytes: int, what: str) -> bytes:
    """Read a whole (small) response body, refusing anything above *max_bytes*."""
    data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ServerDownloadError(f"{what} exceeds the size cap of {max_bytes} bytes; aborted")
    return data


def parse_sha256_digest(digest: Optional[str]) -> Optional[str]:
    """``"sha256:<hex>"`` -> lowercase hex; anything else -> None."""
    match = _SHA256_DIGEST_RE.match(digest or "")
    return match.group(1).lower() if match else None


def fetch_asset_sha256(version: str, filename: str) -> Optional[str]:
    """Expected SHA-256 of *filename* from GitHub's release metadata, or None.

    Network and JSON errors propagate (``OSError`` / ``ValueError``).

    :raises ServerDownloadError: if the release does not contain the asset.
    """
    url = RELEASE_API_URL.format(version=version)
    with open_url(url, accept="application/vnd.github+json") as resp:
        release = json.loads(read_capped(resp, MAX_METADATA_BYTES, "release metadata"))
    for asset in release.get("assets") or []:
        if asset.get("name") == filename:
            return parse_sha256_digest(asset.get("digest"))
    raise ServerDownloadError(f"frida release {version} has no asset named {filename}")


def enforce_digest(
    asset_name: str,
    expected: Optional[str],
    actual: str,
    allow_unverified: bool,
    unavailable_reason: str = "no digest available",
) -> bool:
    """Fail unless *actual* matches *expected*.

    :return: True if verified, False if accepted unverified (override set).
    :raises ServerVerificationError: on a mismatch, or a missing digest
        without the override.
    """
    if expected is None:
        return _accept_unverified(asset_name, actual, allow_unverified, unavailable_reason)
    if expected.lower() != actual.lower():
        raise ServerVerificationError(
            f"SHA-256 mismatch for {asset_name}: expected {expected}, got {actual}. "
            "The download was deleted; it may be corrupted or tampered with."
        )
    logger.info("SHA-256 verified for %s: %s", asset_name, actual)
    return True


def _accept_unverified(asset_name: str, actual: str, allow_unverified: bool, reason: str) -> bool:
    if not allow_unverified:
        raise ServerVerificationError(
            f"Refusing to install {asset_name}: no expected SHA-256 ({reason}); "
            f"downloaded file had sha256 {actual} and was deleted. GitHub only records "
            "asset digests for releases published from June 2025 on (frida >= 17.1.0). "
            f"To install an older frida-server anyway, set {ALLOW_UNVERIFIED_ENV}=1."
        )
    logger.warning(
        "!!! INSTALLING UNVERIFIED frida-server %s (%s; %s=1 is set). sha256 of the "
        "download: %s -- check it manually. Expected for frida releases older than "
        "June 2025. !!!",
        asset_name, reason, ALLOW_UNVERIFIED_ENV, actual,
    )
    return False


def download_verified(
    url: str,
    dest_path: Path,
    expected: Optional[str],
    allow_unverified: bool,
    unavailable_reason: str = "no digest available",
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> str:
    """Stream *url* to *dest_path*, verifying the digest before the final rename.

    On any failure the partial/unverified file is deleted.

    :return: The hex SHA-256 of the downloaded file.
    """
    dest_path = Path(dest_path)
    digest = hashlib.sha256()
    with _temp_sibling(dest_path) as (out, part_path):
        with open_url(url) as resp:
            _write_capped(_iter_chunks(resp), out, max_bytes, f"download of {dest_path.name}", digest)
        out.close()
        actual = digest.hexdigest()
        enforce_digest(dest_path.name, expected, actual, allow_unverified, unavailable_reason)
        os.replace(part_path, dest_path)
    return actual


def decompress_xz_bounded(
    src_path: Path,
    dst_path: Path,
    max_bytes: int = MAX_DECOMPRESSED_BYTES,
) -> None:
    """Decompress the .xz at *src_path* to *dst_path*, aborting above *max_bytes*."""
    dst_path = Path(dst_path)
    with _temp_sibling(dst_path) as (out, part_path):
        with lzma.open(src_path, "rb") as src:
            _write_capped(_iter_chunks(src), out, max_bytes, f"decompressed {Path(src_path).name}")
        out.close()
        os.replace(part_path, dst_path)


@contextlib.contextmanager
def _temp_sibling(dest: Path):
    """Yield ``(file, path)`` of a temp file next to *dest*; removed unless renamed away."""
    fd, part = tempfile.mkstemp(prefix=".frida-server-", suffix=".part", dir=dest.parent)
    part_path = Path(part)
    out = os.fdopen(fd, "wb")
    try:
        yield out, part_path
    finally:
        out.close()
        part_path.unlink(missing_ok=True)  # no-op after a successful os.replace


def _iter_chunks(stream: BinaryIO) -> Iterable[bytes]:
    return iter(lambda: stream.read(CHUNK_SIZE), b"")


def _write_capped(chunks: Iterable[bytes], out: BinaryIO, max_bytes: int, what: str, digest=None) -> int:
    """Copy *chunks* to *out* (updating *digest*); raise once *max_bytes* is exceeded.

    :return: The number of bytes written.
    """
    total = 0
    for chunk in chunks:
        total += len(chunk)
        if total > max_bytes:
            raise ServerDownloadError(f"{what} exceeds the size cap of {max_bytes} bytes; aborted")
        if digest is not None:
            digest.update(chunk)
        out.write(chunk)
    return total
