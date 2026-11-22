#!/usr/bin/env python3

"""Hint for the frida-server 17.24.0-17.24.3 remote message-size bug.

These servers close the WebSocket of a remote (``-H``) session on any host
message above 128 KiB (libsoup ``max-incoming-payload-size``); fixed in 17.25.0
(frida-core 418f4727, frida/frida-core#1267). The agent is staged in pieces
(:mod:`friTap.backends.frida_chunked_loader`), but any other large message
still kills the connection, which looks like a crashed target:
``TransportError: the connection is closed`` or a ``connection-terminated`` detach.

The helpers are pure: callers pass the error text and the server version.
"""

from __future__ import annotations

import re
from typing import Any, Optional

AFFECTED_MIN = (17, 24, 0)
AFFECTED_MAX = (17, 24, 3)
FIXED_VERSION = "17.25.0"

_CONNECTION_CLOSED_MARKERS = (
    "connection is closed",
    "connection closed",
    "connection-terminated",
)

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(text: Any) -> Optional[tuple[int, int, int]]:
    """``(major, minor, patch)`` of the first ``X.Y.Z`` in *text*, else None."""
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.search(text)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def server_version_from_params(params: Any) -> Optional[str]:
    """The frida-server version in ``query_system_parameters()``, if any.

    frida 17.24 reports none; both ``{"frida": {"version": ...}}`` and
    ``"frida_version"`` are accepted in case a server starts to.
    """
    if not isinstance(params, dict):
        return None
    frida_info = params.get("frida")
    if isinstance(frida_info, dict) and isinstance(frida_info.get("version"), str):
        return frida_info["version"]
    if isinstance(params.get("frida_version"), str):
        return params["frida_version"]
    return None


def is_connection_closed(error: Any) -> bool:
    """True when *error* (exception or text) says the frida connection closed."""
    text = str(error).lower()
    return any(marker in text for marker in _CONNECTION_CLOSED_MARKERS)


def is_affected_server_version(version: Any) -> Optional[bool]:
    """True/False for a parseable version, None when the version is unknown."""
    parsed = parse_version(version)
    if parsed is None:
        return None
    return AFFECTED_MIN <= parsed <= AFFECTED_MAX


def remote_message_limit_hint(server_version: Optional[str],
                              host_frida_version: Optional[str] = None) -> Optional[str]:
    """The hint for a closed remote connection, or None if the server is not affected."""
    affected = is_affected_server_version(server_version)
    if affected is False:
        return None
    if affected:
        return (f"The remote frida-server is {server_version}: frida-server "
                f"17.24.0–17.24.3 drops the connection on any host→server message "
                f"> 128 KiB, so this may not be a crash of the target. Upgrade "
                f"frida-server to ≥ {FIXED_VERSION}.")
    host = f"; host frida {host_frida_version}" if host_frida_version else ""
    return (f"The connection to the remote frida-server closed. If it runs "
            f"frida-server 17.24.0–17.24.3, that version drops the connection on any "
            f"host→server message > 128 KiB, so this may not be a crash of the target; "
            f"upgrade frida-server to ≥ {FIXED_VERSION}. (Server version not "
            f"reported{host}.)")
