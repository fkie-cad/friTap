"""The single ``cryptography`` availability probe (side-effect-free leaf).

MTProto, Signal and the TLS 1.3 peel share it; each exposes its own public name
(e.g. :func:`friTap.protocols.mtproto_backend.mtproto_backend_available`) as an alias.
"""

from __future__ import annotations


def cryptography_ciphers_available() -> bool:
    """True if ``cryptography`` ciphers, AEAD and HKDF are importable. Never raises."""
    try:
        import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
        import cryptography.hazmat.primitives.kdf.hkdf  # noqa: F401
        from cryptography.hazmat.primitives.ciphers import (  # type: ignore  # noqa: F401
            Cipher,
            algorithms,
            modes,
        )

        return True
    except Exception:  # noqa: BLE001 - any import/probe failure means "unavailable"
        return False


__all__ = ["cryptography_ciphers_available"]
