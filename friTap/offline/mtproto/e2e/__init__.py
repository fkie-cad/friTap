"""Offline Telegram secret-chat (end-to-end) decryption support.

Secret chats ride ON TOP of the cloud-chat transport decryptor: each E2E message
is a TL-serialized blob embedded inside an already-decrypted transport message
(:class:`friTap.offline.mtproto.records.DecryptedMessage`). This subpackage adds
the second AES-IGE layer — keyed by the per-chat 256-byte shared key rather than
the transport auth_key — reusing the MTProto 2.0 KDF/IGE primitives in the parent
:mod:`friTap.offline.mtproto.crypto`.

The crypto backend (``cryptography``, optionally ``tgcrypto``) is the same
**optional** dependency as the parent package: importing this subpackage never
requires it, and the error classes are re-exported from the parent so callers
catch one consistent hierarchy.
"""

from __future__ import annotations

from .. import (  # noqa: F401  (re-exported for callers of this subpackage)
    MTPROTO_DEPENDENCY_HINT,
    MtprotoCryptoError,
    MtprotoDependencyError,
    MtprotoError,
)

__all__ = [
    "MtprotoError",
    "MtprotoDependencyError",
    "MtprotoCryptoError",
    "MTPROTO_DEPENDENCY_HINT",
]
