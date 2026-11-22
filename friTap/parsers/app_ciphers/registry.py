"""Registry of app-layer cipher decoders shown alongside an HTTP request.

A decoder recognises one application's encrypted request (by host/path
first, so non-matching flows cost a string compare) and turns it into a
:class:`DecodedView`: a titled block of plain text, or the reason it could
not be decoded. Presentation layers (the TUI flow detail) render the views;
this module stays free of rich/textual.

Usage::

    from friTap.parsers.app_ciphers.registry import default_registry
    views = default_registry().decode_request(host, url, body, content_encoding)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

logger = logging.getLogger("friTap.parsers.app_ciphers.registry")


@dataclass(frozen=True)
class DecodedView:
    """The outcome of one decoder for one request.

    title:  section heading, e.g. ``"AppLovin (decrypted)"``
    text:   decoded plaintext (pretty JSON when possible); empty when not ok
    ok:     True when *text* holds the decrypted payload
    reason: why decoding failed (empty when ok)
    notes:  short ``"label: value"`` facts about the decode (variant, timestamp)
    """

    title: str
    text: str = ""
    ok: bool = False
    reason: str = ""
    notes: tuple[str, ...] = ()


@runtime_checkable
class AppCipherDecoder(Protocol):
    """One application-layer cipher decoder."""

    def matches(self, host: str, path: str, query: str, body: bytes) -> bool:
        """Cheap check (host/path first) whether this request is ours."""
        ...

    def decode(self, host: str, path: str, query: str, body: bytes) -> DecodedView | None:
        """Decode a matched request; None when it carries nothing to decode."""
        ...


def split_request_target(host: str, url: str) -> tuple[str, str, str]:
    """``(host, path, query)`` with a lower-cased, port-less host.

    *url* may be origin-form (``/a?b``) or absolute (``https://h/a?b``);
    the host falls back to the URL's host when *host* is empty.
    """
    parts = urlsplit(url or "")
    resolved = (host or parts.hostname or "").split(":")[0].lower()
    return resolved, parts.path, parts.query


def _decompressed(body: bytes, content_encoding: str) -> bytes:
    """*body* after Content-Encoding decompression (unchanged on error)."""
    if not content_encoding:
        return body
    from friTap.parsers.decompress import MAX_AUTO_DECOMPRESS, decompress_body
    out, error = decompress_body(body, content_encoding, max_out=MAX_AUTO_DECOMPRESS)
    return body if error else out


def decoder_identity(decoder: object) -> str:
    """Stable identity of *decoder*: its ``name``/``id`` attribute, else its class."""
    for attr in ("name", "id"):
        value = getattr(decoder, attr, None)
        if isinstance(value, str) and value:
            return value
    cls = type(decoder)
    return f"{cls.__module__}.{cls.__qualname__}"


class AppCipherRegistry:
    """Ordered collection of :class:`AppCipherDecoder` instances."""

    def __init__(self) -> None:
        self._decoders: list[AppCipherDecoder] = []
        self._warned: set[tuple[str, str]] = set()

    def _warn_once(self, kind: str, identity: str, msg: str, *args, **log_kwargs) -> None:
        """Log *msg* once per (*kind*, decoder *identity*)."""
        if (kind, identity) in self._warned:
            return
        self._warned.add((kind, identity))
        logger.warning(msg, *args, **log_kwargs)

    def register(self, decoder: AppCipherDecoder) -> None:
        """Add *decoder*; one with the same identity is replaced in place."""
        identity = decoder_identity(decoder)
        for index, existing in enumerate(self._decoders):
            if decoder_identity(existing) == identity:
                self._decoders[index] = decoder
                return
        self._decoders.append(decoder)

    def _safe_matches(self, decoder, host, path, query, body) -> bool:
        """``decoder.matches`` where a raising third-party decoder means no match."""
        try:
            return bool(decoder.matches(host, path, query, body))
        except Exception:  # noqa: BLE001 - third-party code must not break parsing
            identity = decoder_identity(decoder)
            self._warn_once("matches", identity,
                            "app-cipher decoder %s raised in matches(); skipping it",
                            identity, exc_info=True)
            return False

    @property
    def decoders(self) -> tuple[AppCipherDecoder, ...]:
        return tuple(self._decoders)

    def decode_request(
        self, host: str, url: str, body: bytes, content_encoding: str = "",
    ) -> list[DecodedView]:
        """Views from every decoder that matches this request (usually none)."""
        host, path, query = split_request_target(host, url)
        views: list[DecodedView] = []
        plain_body: bytes | None = None
        for decoder in self._decoders:
            if not self._safe_matches(decoder, host, path, query, body or b""):
                continue
            if plain_body is None:
                plain_body = _decompressed(body or b"", content_encoding)
            view = self._safe_decode(decoder, host, path, query, plain_body)
            if view is None:
                continue
            if not isinstance(view, DecodedView):
                self._warn_bad_view(decoder, view)
                continue
            views.append(view)
        return views

    def _warn_bad_view(self, decoder, view) -> None:
        """Log once per decoder identity that decode() returned a non-DecodedView."""
        identity = decoder_identity(decoder)
        self._warn_once(
            "bad_view", identity,
            "app-cipher decoder %s returned %s from decode(), expected "
            "DecodedView or None; skipping it", identity, type(view).__name__)

    @staticmethod
    def _safe_decode(decoder, host, path, query, body) -> DecodedView | None:
        """Run one decoder; a crash on captured (hostile) data becomes a reason."""
        try:
            return decoder.decode(host, path, query, body)
        except Exception as exc:  # noqa: BLE001 - wire data must not break rendering
            logger.debug("app-cipher decoder %r failed", decoder, exc_info=True)
            title = getattr(decoder, "title", type(decoder).__name__)
            return DecodedView(title=title, reason=f"decoder error: {type(exc).__name__}: {exc}")


_DEFAULT_REGISTRY: AppCipherRegistry | None = None


def default_registry() -> AppCipherRegistry:
    """The process-wide registry with the built-in decoders (built lazily, once)."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        from friTap.parsers.app_ciphers.applovin_decoder import AppLovinMediateDecoder
        registry = AppCipherRegistry()
        registry.register(AppLovinMediateDecoder())
        _DEFAULT_REGISTRY = registry
    return _DEFAULT_REGISTRY


def register_app_cipher_decoder(decoder: AppCipherDecoder) -> None:
    """Add *decoder* to the process-wide app-cipher registry used by the viewer.

    A decoder's identity is its ``name`` (or ``id``) attribute, else its class
    qualname; registering a decoder with an existing identity replaces the old
    one. Two differently-configured instances of one class therefore replace
    each other unless each is given its own ``name`` attribute.
    """
    default_registry().register(decoder)


__all__ = [
    "AppCipherDecoder",
    "AppCipherRegistry",
    "DecodedView",
    "default_registry",
    "register_app_cipher_decoder",
    "split_request_target",
]
