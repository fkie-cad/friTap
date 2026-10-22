"""Endpoint and per-direction helpers shared by the offline decryptors."""

from __future__ import annotations

import ipaddress
from typing import Dict, Iterable, Optional, Tuple


def ss_family(addr: str) -> str:
    """Address family of *addr* ("AF_INET6" when it is an IPv6 literal)."""
    return "AF_INET6" if ":" in addr else "AF_INET"


def join_by_direction(segments: Iterable[Tuple[str, bytes]]) -> Dict[str, bytearray]:
    """Concatenate ``(direction, bytes)`` segments per direction, in order.

    ``"write"`` (client->server) and ``"read"`` (server->client) are always
    present, in that order (possibly empty); any other direction is appended.
    """
    by_direction: Dict[str, bytearray] = {"write": bytearray(), "read": bytearray()}
    for direction, data in segments:
        by_direction.setdefault(direction, bytearray()).extend(data)
    return by_direction


def normalize_endpoint(text: Optional[str]) -> Optional[str]:
    """Canonical ``ip:port`` form of a keylog endpoint hint, or ``None`` if unknown.

    The agent writes IPv6 peers bracketed with all eight groups uncompressed
    (``[2001:67c:4e8:f004:0:0:0:a]:443``) while scapy reports stream addresses
    compressed and unbracketed, so both sides go through this one helper before
    being compared. IPv4 stays ``a.b.c.d:port``; IPv6 becomes ``[compressed]:port``;
    a v4-mapped IPv6 address (``::ffff:a.b.c.d``) collapses to its IPv4 form. The
    unknown marker ``-``, blanks, and text without a numeric port yield ``None``
    (never matched). A host that is not an IP literal is kept verbatim.
    """
    host, sep, port = (text or "").strip().rpartition(":")
    if not sep or not host or not port.isdigit():
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return f"{host}:{int(port)}"
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 6:
        return f"[{ip.compressed}]:{int(port)}"
    return f"{ip}:{int(port)}"


def stream_endpoint(addr: Tuple[str, int]) -> Optional[str]:
    """Canonical ``ip:port`` (see :func:`normalize_endpoint`) of a stream address."""
    host, port = addr
    return normalize_endpoint(f"[{host}]:{port}" if ":" in str(host) else f"{host}:{port}")
