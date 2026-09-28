"""Offline RC4 decryption support (PUBLIC).

This package implements friTap's own offline RC4 decryptor. RC4 shows up in two
shapes and this one package handles both:

  * **standalone** — RC4 is the outer cipher directly over raw TCP; and
  * **nested RC4-in-TLS** — plaintext -> RC4 -> TLS 1.3 -> socket, where tshark
    (driven with the TLS ``--keylog``) strips the outer TLS layer first and RC4
    is then stripped from the decrypted TLS plaintext.

RC4 keys are read from a friTap RC4 keylog (``RC4_KEY`` lines, parsed by the
shared :mod:`friTap.protocols.rc4_keylog_spec`); when no key is supplied the
trial-decrypt path recovers one from candidate bytes by keeping the key whose
output looks like plaintext.

The RC4 core is pure Python (standalone RC4 works with no third-party backend).
The optional ``cryptography`` package is needed only for the pure-Python TLS 1.3
AEAD peeler (the tshark-driven nested path needs tshark, not ``cryptography``).
Importing this package never requires either — like the Signal/MTProto packages,
the entry self-registers and the emitter log-and-skips on a missing dependency.
"""

from __future__ import annotations


class Rc4Error(Exception):
    """Base class for offline RC4 decryption errors."""


class Rc4DependencyError(Rc4Error):
    """Raised when an optional backend needed for a nested-TLS peel is absent."""


# Single canonical, user-facing hint shown wherever the pure-Python TLS peel is
# requested but the optional crypto backend is absent. The tshark-driven nested
# path and standalone RC4 do NOT need it.
RC4_DEPENDENCY_HINT = (
    "The pure-Python TLS 1.3 peel for nested RC4-in-TLS needs the 'cryptography' "
    "backend, which is not installed. Install it with:  pip install cryptography  "
    "(it ships with friTap's default install). Standalone RC4 and the "
    "tshark-driven nested path do not require it."
)


# Module-level discovery marker: tells the offline-decryptor discovery scan
# (:func:`friTap.offline.pcap_to_tap._discover_offline_decryptor_extensions`,
# mirroring ``is_fritap_parser``/``is_fritap_analyzer``) that importing this
# package self-registers an offline decryptor. RC4 is PUBLIC — this in-tree
# subpackage of ``friTap.offline`` is discovered generically, exactly like the
# Signal package, and the import below registers the entry.
is_fritap_offline_decryptor = True


def _register_rc4_offline_decryptor() -> None:
    """Register the RC4 offline decryptor into the process-global registry.

    Lazy + fully guarded so importing this package can never raise: a missing
    dependency or an import cycle during registration is logged at debug and
    skipped. Re-registration of an identical entry is idempotent.
    """
    try:
        from friTap.offline.registry import register_offline_decryptor

        from .offline_decryptor import build_rc4_offline_decryptor_entry

        register_offline_decryptor(build_rc4_offline_decryptor_entry())
    except Exception:  # noqa: BLE001 - registration must never break import
        import logging

        logging.getLogger(__name__).debug(
            "RC4 offline decryptor self-registration skipped", exc_info=True
        )


_register_rc4_offline_decryptor()


def rc4_backend_available() -> bool:
    """Return True if the optional AEAD backend (for the pure-Python TLS peel) is
    importable. Never raises; standalone RC4 does not depend on it."""
    try:
        from .crypto import backend_available

        return backend_available()
    except Exception:  # noqa: BLE001 - any import/probe failure means "unavailable"
        return False


# --------------------------------------------------------------------------- #
# Offline-CLI extension hooks (generic convention; mirrors friTap.offline.signal).
#
# A managed-RC4 key (a passphrase in the client's own byte arrays) is not on the
# wire and not in an RC4 keylog unless the live agent recovered it. These extras
# let the OFFLINE decryptor recover it too, at replay time, by mining candidate
# keys from the client process's memory (a .dmp/.bin dump, or a live read-only
# ReadProcessMemory by pid/name) and trial-decrypting them against the ciphertext.
# The public CLI discovers these by convention and never names RC4.
# --------------------------------------------------------------------------- #

# Scan source stashed by handle_offline_cli_extras (parsed pre-conversion) and read
# by the emitter (_emit_rc4_streams) in the same process. None = no memory source.
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
        # The RC4 offline entry only runs when it has a keylog path (that is how the
        # generic driver decides a decryptor is "present"). When the user supplies a
        # memory scan source but NO --rc4-keylog, synthesize a keyless placeholder
        # keylog so the entry activates; the emitter then recovers the key from the
        # scan source. Harmless: a keyless RC4 keylog contributes zero keylog keys.
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
