#!/usr/bin/env python3

"""Capture-container helpers: the one rule that decides pcap vs pcapng.

The container of the ``-p`` file is resolved once, when the config is built
(:meth:`friTap.config.OutputConfig.resolve_pcap_container`); every writer (the
plaintext PCAP object, the -p output handler, the full-capture finalizer with
its DSB injection and the LSASS helper session sharing the file) reads that
resolved value, so they can never disagree about the container of one file.

Rule: an explicit format (``--pcap-format`` / ``FriTap.pcapng()``) wins;
otherwise the extension decides (``.pcapng`` -> pcapng, anything else -> pcap).
"""

import logging

PCAP_FORMAT_AUTO = "auto"
PCAP_FORMAT_PCAP = "pcap"
PCAP_FORMAT_PCAPNG = "pcapng"
#: Values accepted for the requested format (``auto`` = decide by extension).
PCAP_FORMAT_CHOICES = (PCAP_FORMAT_AUTO, PCAP_FORMAT_PCAP, PCAP_FORMAT_PCAPNG)

_EXTENSION_FORMATS = {".pcap": PCAP_FORMAT_PCAP, ".pcapng": PCAP_FORMAT_PCAPNG}


def is_pcapng_filename(name):
    """Return True iff `name` has a .pcapng extension (case-insensitive)."""
    return bool(name) and name.lower().endswith(".pcapng")


def _extension_format(path):
    """The container a recognised extension implies, else None."""
    lowered = (path or "").lower()
    for extension, fmt in _EXTENSION_FORMATS.items():
        if lowered.endswith(extension):
            return fmt
    return None


def normalize_pcap_format(requested):
    """``None``/empty -> ``auto``; otherwise one of :data:`PCAP_FORMAT_CHOICES`.

    Raises ValueError for anything else so a typo never silently falls back.
    """
    value = (requested or PCAP_FORMAT_AUTO).strip().lower()
    if value not in PCAP_FORMAT_CHOICES:
        raise ValueError(
            f"unknown pcap format {requested!r}; expected one of: "
            f"{', '.join(PCAP_FORMAT_CHOICES)}")
    return value


def resolve_pcap_format(path, requested=PCAP_FORMAT_AUTO):
    """Return ``"pcap"`` or ``"pcapng"`` for the capture file ``path``.

    An explicit ``requested`` format wins; with ``auto`` a ``.pcapng``
    extension selects pcapng and anything else classic pcap. Pure: the
    contradicting-extension warning is :func:`warn_pcap_format_conflict`.
    """
    explicit = normalize_pcap_format(requested)
    if explicit == PCAP_FORMAT_AUTO:
        return _extension_format(path) or PCAP_FORMAT_PCAP
    return explicit


def warn_pcap_format_conflict(path, requested=PCAP_FORMAT_AUTO):
    """Warn when an explicit format contradicts a recognised extension.

    ``-p out.pcap --pcap-format pcapng`` writes pcapng; the user is told so.
    Called once per built config (see :class:`friTap.config.FriTapConfig`).
    """
    explicit = normalize_pcap_format(requested)
    by_extension = _extension_format(path)
    if explicit == PCAP_FORMAT_AUTO or by_extension in (None, explicit):
        return
    logging.getLogger("friTap").warning(
        "%s has a .%s extension but the %s format was requested; writing %s "
        "(the explicit format wins).", path, by_extension, explicit, explicit)
