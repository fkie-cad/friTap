"""Offline RC4 decryption (PUBLIC).

Handles two shapes: standalone RC4 over raw TCP, and nested RC4-in-TLS
(plaintext -> RC4 -> TLS 1.3 -> socket; tshark strips TLS with ``--keylog``,
then RC4 is stripped from the TLS plaintext).

Keys come from an RC4 keylog (``RC4_KEY`` lines, parsed by
:mod:`friTap.protocols.rc4_keylog_spec`); without one, trial-decrypt keeps the
candidate whose output looks like plaintext.

The RC4 core is pure Python. ``cryptography`` is needed only for the pure-Python
TLS 1.3 AEAD peeler. Importing this package requires neither; the entry
self-registers and the emitter log-and-skips on a missing dependency.
"""

from __future__ import annotations

# True if the optional AEAD backend (pure-Python TLS peel) is importable.
from ..tls.backend import backend_available as rc4_backend_available  # noqa: F401


class Rc4Error(Exception):
    """Base class for offline RC4 decryption errors."""


class Rc4DependencyError(Rc4Error):
    """Raised when an optional backend needed for a nested-TLS peel is absent."""


# User-facing hint for a pure-Python TLS peel requested without the crypto backend.
RC4_DEPENDENCY_HINT = (
    "The pure-Python TLS 1.3 peel for nested RC4-in-TLS needs the 'cryptography' "
    "backend, which is not installed. Install it with:  pip install cryptography  "
    "(it ships with friTap's default install). Standalone RC4 and the "
    "tshark-driven nested path do not require it."
)


# Discovery marker for
# :func:`friTap.offline.pcap_to_tap._discover_offline_decryptor_extensions`:
# importing this package self-registers an offline decryptor.
is_fritap_offline_decryptor = True


def _register_rc4_offline_decryptor() -> None:
    """Register the RC4 offline decryptor into the process-global registry.

    Guarded so importing this package never raises; failures are logged at
    debug and skipped. Re-registration is idempotent.
    """
    from friTap.offline.registry import register_offline_decryptors_safely

    register_offline_decryptors_safely(
        __name__, ("build_rc4_offline_decryptor_entry",),
        "RC4 offline decryptor self-registration skipped",
    )


def _register_rc4_pipeline_state() -> None:
    """Register the RC4 per-conversion state namespace on the writer state.

    Guarded like the decryptor self-registration: never raises on import.
    """
    try:
        from .state import register_rc4_pipeline_state

        register_rc4_pipeline_state()
    except Exception:  # noqa: BLE001 - registration must never break the import
        import logging

        logging.getLogger(__name__).debug(
            "RC4 pipeline-state registration skipped", exc_info=True)


_register_rc4_pipeline_state()

_register_rc4_offline_decryptor()


# Offline-CLI extension hooks (discovered by convention, like friTap.offline.signal).
# A managed-RC4 key is neither on the wire nor in a keylog unless the live agent
# recovered it, so these flags mine candidate keys from the client's memory
# (.dmp/.bin dump, or a live read-only read by pid/name) at replay time.

# Stashed by handle_offline_cli_extras, read by _emit_rc4_streams. None = no source.
_SCAN_SOURCE: dict | None = None


def set_rc4_scan_source(dump=None, pid=None, name=None, all_pages=False) -> None:
    """Record a memory source for the offline emitter to mine RC4 candidate keys from."""
    global _SCAN_SOURCE
    if dump or pid is not None or name:
        _SCAN_SOURCE = {"dump": dump, "pid": pid, "name": name, "all_pages": all_pages}
    else:
        _SCAN_SOURCE = None


def get_rc4_scan_source() -> dict | None:
    """Return the recorded memory scan source (or None)."""
    return _SCAN_SOURCE


def register_offline_cli_extras(parser) -> None:
    """Register RC4 memory-scan flags on the offline argparse *parser*."""
    parser.add_argument(
        "--rc4-scan-dump", dest="rc4_scan_dump", default=None,
        help="Recover the RC4 key offline by mining candidate keys from a process "
             "memory dump (.dmp minidump or flat .bin) of the RC4 client and "
             "trial-decrypting them; use with --keylog for nested RC4-in-TLS.",
    )
    parser.add_argument(
        "--rc4-scan-pid", dest="rc4_scan_pid", type=int, default=None,
        help="Like --rc4-scan-dump, but read a LIVE process (read-only, Windows) "
             "by pid. Never point this at lsass; the RC4 client's own key is the "
             "target.",
    )
    parser.add_argument(
        "--rc4-scan-name", dest="rc4_scan_name", default=None,
        help="Like --rc4-scan-pid, but resolve the live process by image name.",
    )
    parser.add_argument(
        "--rc4-scan-all-pages", dest="rc4_scan_all_pages", action="store_true",
        help="Mine read-only pages too, not just writable ones (live/dump scan).",
    )


def _unlink_quietly(path: str) -> None:
    """Remove ``path``; a file that is already gone (or locked) is not an error."""
    import os

    try:
        os.unlink(path)
    except OSError:
        pass


def _write_placeholder_keylog() -> str:
    """Write a keyless RC4 keylog (header only) and return its path.

    The file is removed at interpreter exit, so repeated runs do not litter the
    temp directory with ``fritap_rc4_scan_*.rc4.log`` placeholders.
    """
    import atexit
    import tempfile

    from friTap.protocols.rc4_keylog_spec import HEADER_COMMENT

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".rc4.log", prefix="fritap_rc4_scan_",
        delete=False, encoding="utf-8",
    )
    try:
        tmp.write(HEADER_COMMENT + "\n")
    finally:
        tmp.close()
        atexit.register(_unlink_quietly, tmp.name)
    return tmp.name


def handle_offline_cli_extras(args):
    """Stash the RC4 memory-scan source for the emitter; never short-circuits.

    Returns ``None`` so the normal conversion continues (unlike an action hook
    that would return an exit code). Never raises for a user-input problem.
    """
    try:
        set_rc4_scan_source(
            dump=getattr(args, "rc4_scan_dump", None),
            pid=getattr(args, "rc4_scan_pid", None),
            name=getattr(args, "rc4_scan_name", None),
            all_pages=bool(getattr(args, "rc4_scan_all_pages", False)),
        )
        # The driver treats a decryptor as present only with a keylog path, so a
        # scan source without --rc4-keylog gets a keyless placeholder keylog.
        if get_rc4_scan_source() is not None and not getattr(args, "rc4_keylog", None):
            args.rc4_keylog = _write_placeholder_keylog()
    except Exception:  # noqa: BLE001 - a bad value must not crash the CLI
        import logging

        logging.getLogger(__name__).debug("RC4 scan-source stash failed", exc_info=True)
    return None


__all__ = [
    "Rc4Error",
    "Rc4DependencyError",
    "RC4_DEPENDENCY_HINT",
    "rc4_backend_available",
    "is_fritap_offline_decryptor",
    "set_rc4_scan_source",
    "get_rc4_scan_source",
    "register_offline_cli_extras",
    "handle_offline_cli_extras",
]
