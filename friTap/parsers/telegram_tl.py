"""Back-compat shim: the Telegram TL parsers moved to :mod:`friTap.offline.mtproto.tl_parser`.

Every name (public and private) resolves lazily on first access, so importing
this module never pulls in the offline MTProto package by itself.
"""

from __future__ import annotations


def _impl():
    """The relocated implementation module (imported on first use)."""
    import friTap.offline.mtproto.tl_parser as tl_parser

    return tl_parser


def __getattr__(name: str):
    try:
        return getattr(_impl(), name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(_impl())))
