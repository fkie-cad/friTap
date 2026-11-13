"""Synthetic TCP endpoints for TLS records that carry no socket tuple.

An fd-less record (Chromium/Cronet memory BIOs, ...) still carries its TLS
``client_random``. :func:`synthetic_tuple` derives a stable, per-connection
IPv4 tuple from it inside the RFC 2544 benchmarking range ``198.18.0.0/15``
(client in ``198.18/16``, server in ``198.19/16``), so each connection lands in
its own TCP stream instead of being dropped or merged onto the ``-ed``
placeholder. A synthetic endpoint is never a real address: consumers use
:func:`is_synthetic_ip` to flag or skip it.

Pure functions only; no state.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from typing import Optional

from .sinks.tcp_state import InvalidEndpointError, ipv4_address_int

#: The RFC 2544 range every synthetic address is drawn from.
SYNTHETIC_NETWORK = ipaddress.IPv4Network("198.18.0.0/15")
_SYNTHETIC_FIRST = int(SYNTHETIC_NETWORK.network_address)    # 0xC6120000
_SYNTHETIC_LAST = int(SYNTHETIC_NETWORK.broadcast_address)   # 0xC613FFFF
#: Every dotted address in 198.18.0.0/15 starts with this; a cheap prefilter.
_SYNTHETIC_TEXT_PREFIX = "198.1"
_CLIENT_PREFIX = (198 << 24) | (18 << 16)
_SERVER_PREFIX = (198 << 24) | (19 << 16)
SYNTHETIC_SERVER_PORT = 443
_EPHEMERAL_PORT_BASE = 49152
_EPHEMERAL_PORT_SPAN = 16384

#: The agent's ``--enable_default_fd`` placeholder: 127.0.0.1:1234 <-> 127.0.0.1:2345.
DEFAULT_FD_LOOPBACK_ADDR = 0x7F000001
DEFAULT_FD_PORTS = frozenset({1234, 2345})


@dataclass(frozen=True)
class SyntheticTuple:
    """A synthetic connection in (client, server) orientation; IPv4 addresses as ints."""
    client_ip: int
    client_port: int
    server_ip: int
    server_port: int


def synthetic_tuple(client_random: str) -> SyntheticTuple:
    """The deterministic synthetic tuple for a normalized *client_random*.

    Built from ``blake2s(client_random)`` rather than the raw bytes, whose first
    four can be a TLS 1.2 ``gmt_unix_time`` shared by many connections.
    Raises ``ValueError`` when *client_random* is not hex.
    """
    digest = hashlib.blake2s(bytes.fromhex(client_random)).digest()
    port_seed = (digest[4] << 8) | digest[5]
    return SyntheticTuple(
        client_ip=_CLIENT_PREFIX | (digest[0] << 8) | digest[1],
        client_port=_EPHEMERAL_PORT_BASE + port_seed % _EPHEMERAL_PORT_SPAN,
        server_ip=_SERVER_PREFIX | (digest[2] << 8) | digest[3],
        server_port=SYNTHETIC_SERVER_PORT,
    )


def _ipv4_int(addr) -> Optional[int]:
    """*addr* (host-order int or dotted string) as an IPv4 int, else ``None``.

    Thin wrapper over :func:`friTap.sinks.tcp_state.ipv4_address_int`: an
    out-of-range int or another type is ``None`` instead of raising; a
    malformed string keeps that helper's ``0`` (0.0.0.0) fallback, which is
    neither synthetic nor the loopback placeholder.
    """
    if isinstance(addr, bool) or not isinstance(addr, (int, str)):
        return None
    try:
        return ipv4_address_int(addr.strip() if isinstance(addr, str) else addr)
    except InvalidEndpointError:
        return None


def is_synthetic_ip(addr) -> bool:
    """True when *addr* (int or dotted string) lies in ``198.18.0.0/15``."""
    if isinstance(addr, str) and not addr.lstrip().startswith(_SYNTHETIC_TEXT_PREFIX):
        return False  # fast path: most real addresses never get parsed
    value = _ipv4_int(addr)
    return value is not None and _SYNTHETIC_FIRST <= value <= _SYNTHETIC_LAST


def flow_endpoints_synthetic(flow) -> bool:
    """True when *flow*'s tuple is a synthetic ``198.18.0.0/15`` one (fd-less record).

    The single synthetic-flow predicate: trusts the flow's
    ``endpoints_synthetic`` flag and, for flows that predate it, recognises a
    synthetic address on either end.
    """
    if getattr(flow, "endpoints_synthetic", False):
        return True
    return (is_synthetic_ip(getattr(flow, "src_addr", None))
            or is_synthetic_ip(getattr(flow, "dst_addr", None)))


def is_default_fd_placeholder(src_addr, src_port, dst_addr, dst_port) -> bool:
    """True for the agent's ``-ed`` placeholder tuple, in either orientation."""
    return (_ipv4_int(src_addr) == DEFAULT_FD_LOOPBACK_ADDR
            and _ipv4_int(dst_addr) == DEFAULT_FD_LOOPBACK_ADDR
            and {src_port, dst_port} == DEFAULT_FD_PORTS)
