"""HTTP content utilities for flow analysis.

Helpers for Content-Disposition parsing, image detection, and filename extraction.
"""

import re
from pathlib import PurePosixPath
from typing import Optional
from urllib.parse import urlparse, unquote


IMAGE_MIME_TYPES = frozenset({
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/svg+xml",
    "image/bmp",
    "image/tiff",
    "image/avif",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "image/heic",
    "image/heif",
    "image/apng",
})

_MIME_TO_EXT = {
    "png": ".png",
    "jpeg": ".jpg",
    "gif": ".gif",
    "webp": ".webp",
    "svg+xml": ".svg",
    "bmp": ".bmp",
    "tiff": ".tiff",
    "avif": ".avif",
    "x-icon": ".ico",
    "vnd.microsoft.icon": ".ico",
    "heic": ".heic",
    "heif": ".heif",
    "apng": ".apng",
}

# RFC 6266 Content-Disposition filename extraction patterns
_CD_FILENAME_STAR = re.compile(
    r"""filename\*\s*=\s*(?:UTF-8|utf-8)''(.+?)(?:;|$)""", re.IGNORECASE
)
_CD_FILENAME_QUOTED = re.compile(
    r'''filename\s*=\s*"([^"]+)"''', re.IGNORECASE
)
_CD_FILENAME_TOKEN = re.compile(
    r"""filename\s*=\s*([^\s;]+)""", re.IGNORECASE
)


def is_image_content_type(content_type: str) -> bool:
    """Check whether a Content-Type value indicates an image."""
    if not content_type:
        return False
    mime = content_type.split(";", 1)[0].strip().lower()
    return mime in IMAGE_MIME_TYPES


def parse_content_disposition_filename(header_value: str) -> Optional[str]:
    """Extract filename from a Content-Disposition header value.

    Supports:
      - ``filename*=UTF-8''encoded%20name.jpg`` (RFC 5987)
      - ``filename="name.jpg"`` (quoted)
      - ``filename=name.jpg`` (token)

    Returns ``None`` if no filename is found.
    """
    if not header_value:
        return None

    m = _CD_FILENAME_STAR.search(header_value)
    if m:
        return unquote(m.group(1))

    m = _CD_FILENAME_QUOTED.search(header_value)
    if m:
        return m.group(1)

    m = _CD_FILENAME_TOKEN.search(header_value)
    if m:
        return m.group(1)

    return None


def filename_from_url(url: str) -> Optional[str]:
    """Extract a plausible filename from the path component of a URL.

    Returns ``None`` if no meaningful filename can be extracted
    (e.g., ``/`` or empty path).
    """
    if not url:
        return None
    try:
        path = urlparse(url).path if "://" in url else url
        name = PurePosixPath(unquote(path)).name
        if name and "." in name:
            return name
    except Exception:
        pass
    return None


# Magic byte signatures for common image formats (offset 0)
_IMAGE_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "image/webp"),  # RIFF....WEBP — checked further below
    (b"BM", "image/bmp"),
    (b"II\x2a\x00", "image/tiff"),  # little-endian TIFF
    (b"MM\x00\x2a", "image/tiff"),  # big-endian TIFF
)


def detect_image_mime_from_bytes(data: bytes) -> Optional[str]:
    """Detect image MIME type from the first bytes of ``data``.

    Returns ``None`` if no known image signature matches.
    """
    if len(data) < 4:
        return None
    for magic, mime in _IMAGE_MAGIC:
        if data.startswith(magic):
            # RIFF container needs an extra check for the WEBP marker at offset 8
            if magic == b"RIFF" and data[8:12] != b"WEBP":
                continue
            return mime
    return None


def sanitize_filename(name: str) -> str:
    """Replace characters unsafe in filenames, collapse runs, strip edges.

    Keeps alphanumerics, hyphens, underscores, and dots.
    """
    sanitized = re.sub(r"[^\w.\-]", "_", name)
    sanitized = re.sub(r"_+", "_", sanitized)
    sanitized = sanitized.strip("._")
    return sanitized or "unnamed"


def extension_for_image_mime(content_type: str) -> str:
    """Return an appropriate file extension for an image MIME type.

    Returns ``.bin`` if the type is not recognized.
    """
    mime = content_type.split(";", 1)[0].strip().lower()
    if "/" in mime:
        subtype = mime.split("/", 1)[1]
        return _MIME_TO_EXT.get(subtype, ".bin")
    return ".bin"
