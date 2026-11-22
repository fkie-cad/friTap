"""MTProto offline-decrypt backend probe (side-effect-free leaf).

Lets live handlers warn early without importing :mod:`friTap.offline.mtproto`,
whose import self-registers the offline decryptors. That package re-exports both names.
"""

from __future__ import annotations

from .crypto_backend import cryptography_ciphers_available

MTPROTO_DEPENDENCY_HINT = (
    "Telegram/MTProto decryption needs the 'cryptography' backend, which is not "
    "installed. Install it with:  pip install cryptography  "
    "(it ships with friTap's default install; you only see this on a --no-deps / "
    "minimal install). Note: the optional 'tgcrypto' accelerator alone is NOT "
    "enough — cryptography is required for the transport AES-CTR de-obfuscation."
)


# Same gate as :func:`friTap.offline.mtproto.crypto.backend_available`
# (``tgcrypto`` alone cannot do the transport AES-CTR). Never raises.
mtproto_backend_available = cryptography_ciphers_available


__all__ = ["MTPROTO_DEPENDENCY_HINT", "mtproto_backend_available"]
