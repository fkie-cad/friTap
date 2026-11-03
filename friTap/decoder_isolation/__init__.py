"""Opt-in process isolation for friTap's native decompressors.

brotli, zstd and zlib are C decoders fed attacker-controlled bytes (e.g. a
malware C2 response captured by friTap). With isolation on, decoding runs in
a separate, restricted worker process, so a decoder exploit compromises only
that disposable worker -- not the friTap process holding the Frida session
and the keys.

Switch it on with ``--isolate-decoders``, ``FRITAP_ISOLATE_DECODERS=1`` (also
covers the TUI and offline paths) or :func:`enable_decoder_isolation`.
Default off: decoding stays in-process exactly as before.

Stateful decoders run there too: WebSocket permessage-deflate inflaters
(:func:`isolated_inflater`) and QPACK dynamic-table decoders
(:func:`isolated_qpack_decoder`) become worker-side contexts; when a worker
dies their state is lost and the parsers disable / poison them
(:class:`DecoderContextLost`).

This module stays import-light; the worker machinery (``multiprocessing``)
is imported only once isolation is actually used.
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
    """The worker client module when isolation is on, else None.

    :mod:`friTap.parsers.decompress` calls this on every decode to decide
    where to run; when isolation is off it costs one flag/env lookup.
    """
    if not decoder_isolation_enabled():
        return None
    from . import client
    return client


def isolated_inflater(wbits: int):
    """A worker-side persistent inflater when isolation is on, else None.

    The object offers ``inflate_bounded(data, max_out)`` with the semantics
    of :func:`friTap.parsers.decompress.inflate_stream_bounded`.
    """
    if not decoder_isolation_enabled():
        return None
    from .inflate_proxy import IsolatedInflater
    return IsolatedInflater(wbits)


def isolated_qpack_decoder(capacity: int, blocked_streams: int, *, max_count: int,
                           max_bytes: int):
    """A worker-side ``pylsqpack.Decoder`` stand-in when isolation is on, else None.

    *max_count* / *max_bytes* are the caller's header-list caps: the worker
    withholds larger lists and the parent rejects any reply above them.
    """
    if not decoder_isolation_enabled():
        return None
    from .qpack_proxy import IsolatedQpackDecoder
    return IsolatedQpackDecoder(capacity, blocked_streams, max_count=max_count,
                                max_bytes=max_bytes)


def close_isolated_decoder(decoder) -> bool:
    """Free *decoder*'s worker context if it is an isolated stand-in.

    Returns True when something was released; in-process decoder objects are
    left untouched (False).
    """
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
