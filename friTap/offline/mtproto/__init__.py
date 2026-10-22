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


# The dependency hint and backend probe live in the side-effect-free leaf
# :mod:`friTap.protocols.mtproto_backend` (so the live protocol handlers can
# use them without importing this self-registering package); re-exported here
# as the same objects so every existing import path keeps working.
from friTap.protocols.mtproto_backend import (  # noqa: E402
    MTPROTO_DEPENDENCY_HINT,
    mtproto_backend_available,
)


def offline_cli_dependency_warnings(keylog_value, tls_keylog_path) -> list:
    """Offline-CLI hook: warning lines for a requested MTProto decryption run.

    Discovered by convention by :mod:`friTap.offline.cli` (like Signal's hook).
    *keylog_value* is the ``mtproto`` keylog (truthy when MTProto was requested);
    *tls_keylog_path* is unused (MTProto rides raw TCP). Loud and up front when
    the optional backend is missing, rather than silently producing a .tap
    without the Telegram flows; non-fatal. Never raises.
    """
    if not keylog_value or mtproto_backend_available():
        return []
    return [
        f"Warning: {MTPROTO_DEPENDENCY_HINT}",
        "         MTProto streams in this capture will be skipped.",
    ]


# Module-level discovery marker: tells the offline-decryptor discovery scan
# (:func:`friTap.offline.pcap_to_tap._discover_offline_decryptor_extensions`,
# mirroring ``is_fritap_parser``/``is_fritap_analyzer``) that importing this
# package self-registers offline decryptors, exactly like the Signal package.
# ``pcap_to_tap`` imports this package before its discovery scan runs, so the
# ``mtproto`` and ``telegram`` entries stay first in registration order.
is_fritap_offline_decryptor = True


def _register_mtproto_offline_decryptors() -> None:
    """Register the MTProto and Telegram offline decryptors (in that order).

    Lazy + fully guarded so importing this package can never raise: a missing
    dependency or an import cycle during registration is logged at debug and
    skipped. Re-registration of an identical entry is idempotent.
    """
    from friTap.offline.registry import register_offline_decryptors_safely

    register_offline_decryptors_safely(
        __name__,
        ("build_mtproto_offline_decryptor_entry",
         "build_telegram_offline_decryptor_entry"),
        "MTProto offline decryptor self-registration skipped",
    )



def _register_telegram_pipeline_state() -> None:
    """Register the Telegram per-conversion state namespace on the writer state.

    Guarded like the decryptor self-registration below: importing this package
    can never raise; a failure is logged at debug and skipped.
    """
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
