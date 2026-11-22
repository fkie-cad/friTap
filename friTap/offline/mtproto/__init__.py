"""Offline MTProto (Telegram) decryption support.

tshark cannot decrypt MTProto, so TCP reassembly, transport de-obfuscation and
AES-IGE decryption live here in pure Python.

The crypto backend (``cryptography``, optionally ``tgcrypto``) is optional;
functions needing it raise :class:`MtprotoDependencyError`, which the driver
catches to skip MTProto.
"""

from __future__ import annotations


class MtprotoError(Exception):
    """Base class for MTProto decryption errors."""


class MtprotoDependencyError(MtprotoError):
    """Raised when the crypto backend is unavailable (e.g. a ``--no-deps`` install).

    Restore it with ``pip install cryptography``.
    """


class MtprotoCryptoError(MtprotoError):
    """Raised when a record fails to decrypt or its msg_key does not verify."""


# Leaf module so live handlers avoid importing this self-registering package.
from friTap.protocols.mtproto_backend import (  # noqa: E402
    MTPROTO_DEPENDENCY_HINT,
    mtproto_backend_available,
)


def offline_cli_dependency_warnings(keylog_value, tls_keylog_path) -> list:
    """Offline-CLI hook (discovered by name): warnings when the backend is missing.

    *keylog_value* is the ``mtproto`` keylog (truthy when MTProto was requested);
    *tls_keylog_path* is unused. Never raises.
    """
    if not keylog_value or mtproto_backend_available():
        return []
    return [
        f"Warning: {MTPROTO_DEPENDENCY_HINT}",
        "         MTProto streams in this capture will be skipped.",
    ]


# Discovery marker for pcap_to_tap._discover_offline_decryptor_extensions:
# importing this package self-registers offline decryptors. pcap_to_tap imports
# it before the scan, so ``mtproto`` and ``telegram`` stay first in order.
is_fritap_offline_decryptor = True


def _register_mtproto_offline_decryptors() -> None:
    """Register the MTProto and Telegram offline decryptors (in that order).

    Never raises; failures are logged at debug. Re-registration is idempotent.
    """
    from friTap.offline.registry import register_offline_decryptors_safely

    register_offline_decryptors_safely(
        __name__,
        ("build_mtproto_offline_decryptor_entry",
         "build_telegram_offline_decryptor_entry"),
        "MTProto offline decryptor self-registration skipped",
    )


def _register_telegram_pipeline_state() -> None:
    """Register the Telegram per-conversion state namespace. Never raises."""
    try:
        from .state import register_telegram_pipeline_state

        register_telegram_pipeline_state()
    except Exception:  # noqa: BLE001 - registration must never break the import
        import logging

        logging.getLogger(__name__).debug(
            "Telegram pipeline-state registration skipped", exc_info=True)


_register_telegram_pipeline_state()

_register_mtproto_offline_decryptors()


__all__ = [
    "MtprotoError",
    "MtprotoDependencyError",
    "MtprotoCryptoError",
    "MTPROTO_DEPENDENCY_HINT",
    "mtproto_backend_available",
    "offline_cli_dependency_warnings",
]
