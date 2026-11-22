"""Opt-in process isolation for friTap's native decompressors.

brotli, zstd and zlib are C decoders fed attacker-controlled bytes (e.g. a
captured malware C2 response). With isolation on, decoding runs in a separate
restricted worker, so a decoder exploit compromises only that disposable process,
not the one holding the Frida session and keys.

Enable with ``--isolate-decoders``, ``FRITAP_ISOLATE_DECODERS=1`` (also TUI and
offline paths) or :func:`enable_decoder_isolation`. Default off.

Stateful decoders (WebSocket permessage-deflate via :func:`isolated_inflater`,
QPACK via :func:`isolated_qpack_decoder`) become worker-side contexts; when a
worker dies their state is lost and parsers disable/poison them
(:class:`DecoderContextLost`). The module stays import-light: ``multiprocessing``
is imported only once isolation is used.
"""

from __future__ import annotations

import os

from .errors import DecoderContextError, DecoderContextLost, HeaderListTooLarge

ISOLATE_DECODERS_ENV = "FRITAP_ISOLATE_DECODERS"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

# None: follow the environment variable; True/False: explicit override.
_override: bool | None = None


def enable_decoder_isolation(enabled: bool | None = True) -> None:
    """Turn decoder isolation on (default) or off; ``None`` defers to the env var."""
    global _override
    _override = enabled


def decoder_isolation_enabled() -> bool:
    """True when decoding must run in the worker process."""
    if _override is not None:
        return _override
    return os.environ.get(ISOLATE_DECODERS_ENV, "").strip().lower() in _TRUTHY


def isolated_decoders():
    """The worker client module when isolation is on, else None (called on every decode; off costs one flag/env lookup)."""
    if not decoder_isolation_enabled():
        return None
    from . import client
    return client


def isolated_inflater(wbits: int):
    """A worker-side persistent inflater (``inflate_bounded(data, max_out)``, like
    :func:`friTap.parsers.decompress.inflate_stream_bounded`) when isolation is on, else None."""
    if not decoder_isolation_enabled():
        return None
    from .inflate_proxy import IsolatedInflater
    return IsolatedInflater(wbits)


def isolated_qpack_decoder(capacity: int, blocked_streams: int, *, max_count: int,
                           max_bytes: int):
    """A worker-side ``pylsqpack.Decoder`` stand-in when isolation is on, else None.

    The worker withholds header lists above *max_count*/*max_bytes* and the parent rejects larger replies.
    """
    if not decoder_isolation_enabled():
        return None
    from .qpack_proxy import IsolatedQpackDecoder
    return IsolatedQpackDecoder(capacity, blocked_streams, max_count=max_count,
                                max_bytes=max_bytes)


def close_isolated_decoder(decoder) -> bool:
    """Free *decoder*'s worker context if it is an isolated stand-in; True when released."""
    if not getattr(decoder, "isolated", False):
        return False
    decoder.close()
    return True


def shutdown_decoder_worker() -> None:
    """Stop the shared decoder worker if one is running (also runs at exit)."""
    from .supervisor import shutdown_supervisor
    shutdown_supervisor()


__all__ = [
    "DecoderContextError",
    "DecoderContextLost",
    "HeaderListTooLarge",
    "ISOLATE_DECODERS_ENV",
    "close_isolated_decoder",
    "decoder_isolation_enabled",
    "enable_decoder_isolation",
    "isolated_decoders",
    "isolated_inflater",
    "isolated_qpack_decoder",
    "shutdown_decoder_worker",
]
