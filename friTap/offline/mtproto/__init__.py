"""Offline MTProto (Telegram) decryption support.

This package implements friTap's own MTProto 2.0 decryptor. Unlike TLS/QUIC —
where friTap shells out to tshark — tshark cannot decrypt MTProto, so the whole
pipeline (TCP reassembly, transport de-obfuscation, AES-IGE record decryption)
lives here in pure Python and feeds the existing FlowCollector -> TapWriter path.

The crypto backend (the ``cryptography`` package, optionally ``tgcrypto``) is an
**optional** dependency: importing this package never requires it. Functions that
need it raise :class:`MtprotoDependencyError` with an actionable hint, and the
offline driver catches that to skip MTProto gracefully.
"""

from __future__ import annotations


class MtprotoError(Exception):
    """Base class for MTProto decryption errors."""


class MtprotoDependencyError(MtprotoError):
    """Raised when the crypto backend is unavailable.

    The backend ships in friTap's base install; you only hit this on a
    ``--no-deps`` / minimal install. Restore it with ``pip install cryptography``
    (the optional ``TgCrypto-pyrofork`` AES-IGE accelerator installs automatically
    with the base wherever a wheel exists).
    """


class MtprotoCryptoError(MtprotoError):
    """Raised when a record fails to decrypt or its msg_key does not verify."""


# Single canonical, user-facing hint shown wherever MTProto is requested but the
# optional crypto backend is absent (live CLI, offline CLI, and the TUI).
MTPROTO_DEPENDENCY_HINT = (
    "Telegram/MTProto decryption needs the 'cryptography' backend, which is not "
    "installed. Install it with:  pip install cryptography  "
    "(it ships with friTap's default install; you only see this on a --no-deps / "
    "minimal install). Note: the optional 'tgcrypto' accelerator alone is NOT "
    "enough — cryptography is required for the transport AES-CTR de-obfuscation."
)


def mtproto_backend_available() -> bool:
    """Return True if the optional AES backend for MTProto decryption is importable.

    Never raises: used by CLI/TUI entry points to decide whether to show
    :data:`MTPROTO_DEPENDENCY_HINT`. Lazy so importing this package costs nothing.
    """
    try:
        from .crypto import backend_available

        return backend_available()
    except Exception:  # noqa: BLE001 - any import/probe failure means "unavailable"
        return False


__all__ = [
    "MtprotoError",
    "MtprotoDependencyError",
    "MtprotoCryptoError",
    "MTPROTO_DEPENDENCY_HINT",
    "mtproto_backend_available",
]
