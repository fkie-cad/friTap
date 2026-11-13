"""Build the ``--tap`` file from a finished full capture (``-f --tap X.tap``).

Full-capture mode disables the agent's plaintext hooks, so the live
:class:`~friTap.output.tap_handler.TapOutputHandler` would never see a single
event and the ``.tap`` would stay empty. Instead, once the full-capture pcap
(and its ``<pcap>.fritap.json`` manifest) is finalized, the session hands it to
the same in-process offline pipeline ``fritap --from-pcap`` uses.

Everything here is best-effort teardown work: :func:`auto_build_tap` never
raises, never modifies the pcap or keylog, and writes the ``.tap`` atomically so
a failed conversion never leaves a truncated or half-written file behind.
All messages go to the given logger (stderr) -- never to stdout.
"""

from __future__ import annotations

import logging
import os
import shlex
import time
from typing import Callable

from .._fs_util import is_non_empty_file, remove_quietly

_DEFAULT_LOGGER = logging.getLogger("friTap.offline.auto_tap")


def should_auto_build_tap(*, full_capture: bool, tap_path: str | None,
                          pcap_path: str | None, auxiliary_session: bool = False) -> bool:
    """Whether the end-of-capture ``.tap`` build applies to this session.

    True only for a main (non-LSASS-helper) full capture with ``--tap`` whose
    final pcap exists and holds data.
    """
    if not full_capture or not tap_path or auxiliary_session:
        return False
    return is_non_empty_file(pcap_path)


def manual_from_pcap_command(pcap_path: str, keylog_path: str | None, tap_path: str) -> str:
    """The shell command that redoes this conversion by hand (shell-quoted)."""
    parts = ["fritap", "--from-pcap", pcap_path]
    if keylog_path:
        parts += ["--keylog", keylog_path]
    parts += ["--tap", tap_path]
    return " ".join(shlex.quote(part) for part in parts)


def _partial_tap_path(tap_path: str) -> str:
    """A hidden per-process temp path next to *tap_path* (same filesystem for os.replace).

    Not pre-created (unlike ``mkstemp``), so the converter's own ``open("wb")``
    gives the final file the usual umask permissions instead of 0600.
    """
    directory = os.path.dirname(os.path.abspath(tap_path))
    name = f".{os.path.basename(tap_path)}.{os.getpid()}.partial"
    return os.path.join(directory, name)


def build_tap_atomically(pcap_path: str, tap_path: str, *,
                         convert: Callable | None = None, **convert_kwargs):
    """Convert *pcap_path* into *tap_path* via a temp file + ``os.replace``.

    *convert* defaults to :func:`friTap.offline.pcap_to_tap.pcap_to_tap`. On any
    exception the temp file is removed and the error re-raised; an existing
    *tap_path* is left untouched. Returns the converter's result.
    """
    if convert is None:
        from .pcap_to_tap import pcap_to_tap as convert
    partial = _partial_tap_path(tap_path)
    try:
        result = convert(pcap_path, tap_path=partial, **convert_kwargs)
        os.replace(partial, tap_path)
    except BaseException:
        remove_quietly(partial)
        raise
    return result


def _summary_line(result, tap_path: str, seconds: float) -> str:
    """One human line describing a finished conversion."""
    flows = getattr(result, "flow_count", 0)
    decrypted = getattr(result, "decrypted_packet_count", 0)
    return (f"Wrote {tap_path} from the full capture: {flows} flow(s), "
            f"{decrypted} decrypted packet(s) in {seconds:.1f}s")


def _failure_reason(error: BaseException) -> str:
    """A short, user-facing reason for a failed conversion."""
    from .pcap_to_tap import NoDecryptionKeysError
    from .tshark import TsharkLimitError, TsharkNotFoundError
    if isinstance(error, NoDecryptionKeysError):
        return f"no decryption keys available ({error})"
    if isinstance(error, TsharkNotFoundError):
        return f"tshark not found ({error})"
    if isinstance(error, TsharkLimitError):
        return f"tshark hit a resource limit ({error})"
    return f"{type(error).__name__}: {error}"


def auto_build_tap(pcap_path: str, tap_path: str, *, keylog_path: str | None = None,
                   capture_target: str = "", logger: logging.Logger | None = None,
                   convert: Callable | None = None) -> bool:
    """Build *tap_path* from a finished full capture; never raises.

    Uses the pcap's manifest for ports and extra keylogs (``use_manifest=True``);
    *keylog_path* is optional (plaintext / DSB captures convert without one).
    Returns True on success. On failure logs the reason and the manual
    ``fritap --from-pcap`` command; the pcap and keylog are never modified.
    """
    log = logger or _DEFAULT_LOGGER
    log.info("Building %s from full capture %s ...", tap_path, pcap_path)
    started = time.monotonic()
    try:
        result = build_tap_atomically(
            pcap_path, tap_path, convert=convert, keylog_path=keylog_path,
            capture_target=capture_target or "", use_manifest=True)
    except Exception as error:  # noqa: BLE001 - teardown must never break
        log.warning("Could not build %s from the full capture: %s. To retry manually, run:  %s",
                    tap_path, _failure_reason(error),
                    manual_from_pcap_command(pcap_path, keylog_path, tap_path))
        log.debug("auto .tap build failure details", exc_info=True)
        return False
    log.info(_summary_line(result, tap_path, time.monotonic() - started))
    return True
