"""Read a friTap MTProto keylog into an auth_key_id -> key lookup.

Thin wrapper over :mod:`friTap.protocols.mtproto_keylog_spec` (the single source
of truth for the line format) so the offline reader never drifts from the live
writer. Tolerant by design: comments, blanks, and malformed lines are skipped.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

from ...protocols.mtproto_keylog_spec import (
    MtprotoAuthKey,
    MtprotoObfKey,
    parse_line,
    parse_obf_line,
)


def load_mtproto_keylog(path: str) -> Dict[bytes, MtprotoAuthKey]:
    """Parse an MTProto keylog file into ``{auth_key_id(8 bytes): MtprotoAuthKey}``.

    Each line is parsed via :func:`mtproto_keylog_spec.parse_line`, which returns
    ``None`` for comments/blank/malformed lines (those are simply ignored). When
    duplicate auth_key_ids appear, the last entry wins.
    """
    keymap: Dict[bytes, MtprotoAuthKey] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = parse_line(line)
            if entry is not None:
                keymap[entry.auth_key_id] = entry
    return keymap


def load_mtproto_obf_keylog(path: str) -> List[MtprotoObfKey]:
    """Parse an MTProto keylog file into a LIST of :class:`MtprotoObfKey` entries.

    A LIST, not a dict: obfuscation-transport keys carry no natural join key (the
    endpoint hint is only advisory and may be ``-``), so the offline path joins
    them to captured streams by trial de-obfuscation. Comments/blank/foreign lines
    are skipped via :func:`mtproto_keylog_spec.parse_obf_line`; order is preserved.
    """
    keys: List[MtprotoObfKey] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = parse_obf_line(line)
            if entry is not None:
                keys.append(entry)
    return keys


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
