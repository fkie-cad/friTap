"""MTProto (Telegram) offline-decrypt backend probe — a side-effect-free leaf.

Holds the user-facing dependency hint and the availability probe for the
optional ``cryptography`` backend, so the live protocol handlers can warn early
WITHOUT importing :mod:`friTap.offline.mtproto` (whose import self-registers the
offline decryptors). :mod:`friTap.offline.mtproto` re-exports both names.
"""

from __future__ import annotations

from .crypto_backend import cryptography_ciphers_available

# Single canonical, user-facing hint shown wherever MTProto is requested but the
# optional crypto backend is absent (live CLI, offline CLI, and the TUI).
MTPROTO_DEPENDENCY_HINT = (
    "Telegram/MTProto decryption needs the 'cryptography' backend, which is not "
    "installed. Install it with:  pip install cryptography  "
    "(it ships with friTap's default install; you only see this on a --no-deps / "
    "minimal install). Note: the optional 'tgcrypto' accelerator alone is NOT "
    "enough — cryptography is required for the transport AES-CTR de-obfuscation."
)


# Gates on the ``cryptography`` floor, exactly like
# :func:`friTap.offline.mtproto.crypto.backend_available` (``tgcrypto`` alone
# cannot do the transport AES-CTR). Never raises; used by CLI/TUI entry points to
# decide whether to show :data:`MTPROTO_DEPENDENCY_HINT`.
mtproto_backend_available = cryptography_ciphers_available


__all__ = ["MTPROTO_DEPENDENCY_HINT", "mtproto_backend_available"]
