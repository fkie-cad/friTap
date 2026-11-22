"""Validation and rendering of the socket fields the agent reports (untrusted)."""

import ipaddress
import logging
import socket
import struct
from typing import Optional

# The agent runs inside the target process, so its fields are untrusted.
# Addresses reach BPF / display filters; anything not a well-formed IPv4/IPv6
# address of a whitelisted family becomes the empty value downstream skips.
DEFAULT_SS_FAMILY = "AF_INET"
FILTERABLE_SS_FAMILIES = frozenset({"AF_INET", "AF_INET6"})
KNOWN_SS_FAMILIES = FILTERABLE_SS_FAMILIES | {"AF_UNIX"}
MISSING_ADDRESS = ""
_IPV6_HEX_LEN = 32
_MAX_PORT = 0xFFFF
_invalid_socket_field_warned = False


def _warn_invalid_socket_field_once(field: str) -> None:
    global _invalid_socket_field_warned
    if _invalid_socket_field_warned:
        return
    _invalid_socket_field_warned = True
    logging.getLogger("friTap").warning(
        "Ignoring malformed %s reported by the agent (further occurrences are "
        "silently replaced by an empty address / port 0).", field)


def _is_missing(value) -> bool:
    return value is None or value == ""


def _ipv4_packed(socket_addr) -> Optional[bytes]:
    """Agent IPv4 (host-order int or dotted string) as 4 bytes, else None."""
    if isinstance(socket_addr, bool):
        return None
    if isinstance(socket_addr, int):
        if 0 <= socket_addr <= 0xFFFFFFFF:
            return struct.pack(">I", socket_addr)
        return None
    if isinstance(socket_addr, str):
        try:
            return ipaddress.IPv4Address(socket_addr).packed
        except ValueError:
            return None
    return None


def _ipv6_packed(socket_addr) -> Optional[bytes]:
    """Agent IPv6 (32-char hex or textual form) as 16 bytes, else None."""
    if not isinstance(socket_addr, str):
        return None
    if len(socket_addr) == _IPV6_HEX_LEN:
        try:
            return bytes.fromhex(socket_addr)
        except ValueError:
            pass
    try:
        return ipaddress.IPv6Address(socket_addr).packed
    except ValueError:
        return None


def normalize_ss_family(ss_family) -> str:
    """Whitelist the agent's ``ss_family``; anything else is the default."""
    if isinstance(ss_family, str) and ss_family in KNOWN_SS_FAMILIES:
        return ss_family
    if not _is_missing(ss_family):
        _warn_invalid_socket_field_once("ss_family")
    return DEFAULT_SS_FAMILY


def resolve_ss_family(raw_family):
    """``(family, address_family)``: the whitelisted family, and the family to parse addresses with.

    ``address_family`` is ``None`` for an unknown family, so its addresses are
    discarded rather than reinterpreted as IPv4.
    """
    family = normalize_ss_family(raw_family)
    if _is_missing(raw_family) or raw_family == family:
        return family, family
    return family, None


def coerce_port(port) -> int:
    """Agent port as an int in 0..65535; anything else becomes 0."""
    if isinstance(port, int) and not isinstance(port, bool) and 0 <= port <= _MAX_PORT:
        return port
    if not _is_missing(port):
        _warn_invalid_socket_field_once("port")
    return 0


def sanitize_raw_addr(socket_addr, ss_family):
    """The raw agent address if it is valid for ``ss_family``, else ``""``."""
    if ss_family == "AF_INET" and _ipv4_packed(socket_addr) is not None:
        return socket_addr
    if ss_family == "AF_INET6" and _ipv6_packed(socket_addr) is not None:
        return socket_addr
    return MISSING_ADDRESS


def get_addr_string(socket_addr, ss_family):
    """Render a valid AF_INET / AF_INET6 agent address as an IP string.

    Anything else yields ``""``, never the raw agent value, so it cannot be
    interpolated into a BPF or display filter.
    """
    if _is_missing(socket_addr):
        return MISSING_ADDRESS
    if ss_family == "AF_INET":
        packed = _ipv4_packed(socket_addr)
        if packed is not None:
            return socket.inet_ntop(socket.AF_INET, packed)
    elif ss_family == "AF_INET6":
        packed = _ipv6_packed(socket_addr)
        if packed is not None:
            return socket.inet_ntop(socket.AF_INET6, packed)
    if ss_family != "AF_UNIX":
        _warn_invalid_socket_field_once("socket address")
    return MISSING_ADDRESS
