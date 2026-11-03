#!/usr/bin/env python3

"""Per-protocol keylog line formatter abstraction.

Each :class:`~friTap.protocols.base.ProtocolHandler` may expose a
``keylog_formatter()`` that returns one of these. The generic
:class:`~friTap.output.keylog_handler.KeylogOutputHandler` then uses the
formatter to turn :class:`~friTap.events.KeylogEvent` instances into the
Wireshark-loadable lines for that specific protocol, without the output
layer needing protocol-specific branching.
"""

from __future__ import annotations

import logging
import re
import threading
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from ..events import KeylogEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Keylog line validation
#
# Key material arrives from an agent running inside a possibly hostile process,
# so every string that ends up in a keylog file is attacker-controlled. A CR/LF
# (or other control character) inside a label or secret would inject extra,
# forged lines into a keylog the user later feeds to Wireshark/tshark. These
# validators are total: non-``str`` input is rejected, never raised on.
# ---------------------------------------------------------------------------

# Longest single keylog line accepted (an MTProto OBF/E2E line is ~600 chars).
MAX_KEYLOG_LINE_LENGTH = 16 * 1024
# Longest hex field accepted (4096 hex chars = 2 KiB of key material).
MAX_HEX_FIELD_LENGTH = 4096

# Labels in use: NSS TLS (CLIENT_RANDOM, *_TRAFFIC_SECRET_0, EXPORTER_SECRET...),
# SSH (SSH_ENC_KEY_C2S, SSH_IV_S2C...), MTProto/RC4 (MTPROTO_AUTH_KEY, RC4_KEY)
# and user-chosen custom-plugin labels (AES_KEY, WG_SENDING_KEY...). Custom
# labels may be lower case or hyphenated, so both are allowed.
_KEYLOG_LABEL_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_\-]{0,63}")
_HEX_FIELD_RE = re.compile(r"[0-9a-fA-F]+")
# Custom plugins may emit base64 secrets (``encoding="base64"``).
_SECRET_FIELD_RE = re.compile(r"[A-Za-z0-9+/=_\-]+")
# A Schannel/LSASS keylog may carry an unknown client_random as ``???``.
UNKNOWN_CLIENT_RANDOM = "???"

_dropped_lock = threading.Lock()
_dropped_reasons: set = set()
_MAX_TRACKED_DROP_REASONS = 256


def _has_control_chars(text: str) -> bool:
    """True when *text* holds a C0 control character (CR, LF, NUL, TAB...) or DEL."""
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text)


def is_safe_keylog_line(line) -> bool:
    """True when *line* can be written as exactly ONE keylog line.

    Rejects non-strings, empty lines, over-long lines and any control character
    (CR/LF/NUL included), so one agent string can never become several lines.
    """
    if not isinstance(line, str) or not line:
        return False
    if len(line) > MAX_KEYLOG_LINE_LENGTH:
        return False
    return not _has_control_chars(line)


def is_safe_keylog_label(label) -> bool:
    """True for a keylog label: ``[A-Za-z0-9_-]{1,64}`` not starting with ``-``."""
    return isinstance(label, str) and bool(_KEYLOG_LABEL_RE.fullmatch(label))


def is_hex_field(value, max_length: int = MAX_HEX_FIELD_LENGTH) -> bool:
    """True for an even-length hex string of 2..*max_length* characters."""
    if not isinstance(value, str) or not 2 <= len(value) <= max_length:
        return False
    return len(value) % 2 == 0 and bool(_HEX_FIELD_RE.fullmatch(value))


def is_secret_field(value, allow_base64: bool = False) -> bool:
    """True for a hex secret, or (with *allow_base64*) a base64/base64url one."""
    if is_hex_field(value):
        return True
    if not allow_base64 or not isinstance(value, str):
        return False
    return 2 <= len(value) <= MAX_HEX_FIELD_LENGTH and bool(
        _SECRET_FIELD_RE.fullmatch(value))


def sanitize_keylog_fields(label, *hex_fields) -> Optional[str]:
    """``"<label> <hex> ..."`` when *label* and every hex field are valid, else ``None``."""
    if not is_safe_keylog_label(label) or not hex_fields:
        return None
    if not all(is_hex_field(field) for field in hex_fields):
        return None
    return " ".join((label, *hex_fields))


def is_nss_keylog_line(line) -> bool:
    """True for an NSS-style ``LABEL <hex|???> <hex> ...`` keylog line.

    The label must match ``^[A-Z0-9_]{1,64}$``; every following field must be
    an even-length hex string, or ``???`` (an unknown Schannel client_random).
    """
    if not is_safe_keylog_line(line):
        return False
    label, *fields = line.split(" ")
    if not fields or not re.fullmatch(r"[A-Z0-9_]{1,64}", label):
        return False
    return all(f == UNKNOWN_CLIENT_RANDOM or is_hex_field(f) for f in fields)


# A data field of a generic keylog line: hex, (signed) decimal, base64 or
# base64url (``-``/``_``), the ``???`` unknown-client_random placeholder, or a
# numeric ``<ipv4|[ipv6]>:<port>`` endpoint (MTProto OBF lines record one).
_KEYLOG_FIELD_RE = re.compile(
    r"\?\?\?|-?[0-9]+|[A-Za-z0-9+/]+={0,2}|[A-Za-z0-9_\-]+={0,2}"
    r"|(?:[0-9.]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}")


def is_keylog_shaped_line(line) -> bool:
    """True for a generic ``LABEL <field> [<field> ...]`` keylog line.

    A safe single line (:func:`is_safe_keylog_line`) whose first token is a
    keylog label (:func:`is_safe_keylog_label`) followed by at least one
    whitespace-separated hex / decimal / base64 field — no free text. Used to
    vet lines copied out of untrusted files (a PEM key or prose never matches).
    """
    if not is_safe_keylog_line(line):
        return False
    label, *fields = line.split()
    if not fields or not is_safe_keylog_label(label):
        return False
    return all(_KEYLOG_FIELD_RE.fullmatch(field) for field in fields)


def is_valid_keylog_line_for(protocol: str, line) -> bool:
    """True when *line* is a well-formed keylog line for *protocol*.

    TLS lines must be NSS lines (:func:`is_nss_keylog_line`); every other
    protocol uses the generic shape check (:func:`is_keylog_shaped_line`).
    """
    if protocol == "tls":
        return is_nss_keylog_line(line)
    return is_keylog_shaped_line(line)


def warn_dropped_keylog_line(reason: str, detail: str = "") -> None:
    """Log a dropped (unsafe) keylog line once per *reason* (rate limit)."""
    with _dropped_lock:
        if reason in _dropped_reasons:
            return
        if len(_dropped_reasons) < _MAX_TRACKED_DROP_REASONS:
            _dropped_reasons.add(reason)
    logger.warning(
        "Dropping malformed keylog line (%s)%s; further drops for this reason "
        "are not logged", reason, f": {detail}" if detail else "")


def _drop_reason_for(line) -> str:
    """A short, log-safe identity for a rejected *line* (its label, if any)."""
    if not isinstance(line, str):
        return f"non-str {type(line).__name__}"
    head = line.split(" ", 1)[0][:64]
    return head if is_safe_keylog_label(head) else "unsafe label"


def filter_safe_keylog_lines(lines) -> List[str]:
    """The :func:`is_safe_keylog_line` subset of *lines*; drops are logged once."""
    safe: List[str] = []
    for line in lines or ():
        if is_safe_keylog_line(line):
            safe.append(line)
        else:
            warn_dropped_keylog_line(_drop_reason_for(line))
    return safe


class KeylogFormatter(ABC):
    """Translates a :class:`KeylogEvent` into Wireshark-loadable keylog lines.

    Subclasses bind the formatter to exactly one protocol via the
    ``protocol`` property — the output handler uses that as an event-bus
    routing filter (``event.protocol == formatter.protocol``).
    """

    @property
    @abstractmethod
    def protocol(self) -> str:
        """Protocol identifier this formatter targets (e.g. ``"tls"``, ``"ssh"``)."""
        ...

    def header_comment(self) -> Optional[str]:
        """Optional comment written once when the keylog file is first opened.

        Wireshark dissectors ignore ``#``-prefixed lines, so this is a safe
        place to put human-readable provenance. Return ``None`` for no header.
        """
        return None

    def format(self, event: "KeylogEvent") -> List[str]:
        """Return zero or more keylog lines for *event* (no trailing newlines).

        The default returns ``event.key_data`` as a single line when present.
        This handles the common case where the agent already produced a
        protocol-correct line (NSS ``CLIENT_RANDOM …``, OpenSSH-style
        ``SSH_ENC_KEY_C2S …``, etc.); override for protocols that emit
        structured payloads (see :class:`SshKeylogFormatter`).

        ``key_data`` comes from the (untrusted) agent: a value that is not a
        single safe line (CR/LF/NUL/control characters, non-``str``) is dropped
        with a rate-limited warning instead of being written verbatim.
        """
        if not event.key_data:
            return []
        return filter_safe_keylog_lines([event.key_data])

    def dedup_key(self, event: "KeylogEvent") -> str:
        """Stable identity for the LRU deduplicator.

        The default joins the formatted lines — correct but calls
        :meth:`format` a second time. Subclasses on the keylog hot path
        should override with a cheaper identity (e.g. SSH
        ``cookie|shared_secret``) to avoid the double-format cost; the
        built-in TLS/SSH formatters do.
        """
        return "\n".join(self.format(event))
