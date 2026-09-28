"""Attribute each TLS session (and its secrets) to the owning process (PUBLIC).

Port of ``research/memory_scan_lsass/tools/schannel_pidmap.py``. lsass serves every
process, so a secret recovered from lsass memory carries no PID. Nothing in lsass
reliably stores the owning PID next to the key material, so we do NOT read a PID out
of lsass — we correlate on the one artifact the owning process provably controls:
its TCP 4-tuple::

    netstat  : PID           -> (local ip:port, remote ip:port)   [ESTABLISHED snapshot]
    pcap     : 4-tuple       -> tcp.stream -> ClientHello client_random
    keylog   : client_random -> {LABEL: secret}
    =>  PID -> client_random -> secrets

This distinguishes concurrent processes that all use lsass, because each owns a
distinct 4-tuple. This module ports the PURE join helpers; the pcap read itself
(scapy/tshark) is environment-dependent and lives in the dev/live tooling.
"""

from __future__ import annotations

import json
import re
from typing import Dict, Iterable, List, Tuple

_HEX = re.compile(r"^[0-9a-fA-F]+$")


def canon_ip(ip: str) -> str:
    """Canonicalize an address for comparison (fold IPv6 loopback to v4)."""
    ip = (ip or "").strip().strip("[]").lower()
    if ip in ("::1", "0:0:0:0:0:0:0:1"):
        return "127.0.0.1"
    return ip


def tuple_key(src_ip: str, src_port, dst_ip: str, dst_port) -> tuple:
    """Build the canonical (src_ip, src_port, dst_ip, dst_port) comparison key."""
    return (canon_ip(src_ip), str(src_port).strip(), canon_ip(dst_ip), str(dst_port).strip())


def parse_netstat(text: str) -> List[dict]:
    """Parse the harness netstat.json into connection records.

    Accepts either a bare list or ``{"connections": [...]}``. Each record needs a
    pid and local_port; the rest default to empty. Records lacking a pid are dropped.
    """
    data = json.loads(text.lstrip("﻿"))  # PowerShell UTF8 Set-Content adds a BOM
    conns = data.get("connections", data) if isinstance(data, dict) else data
    out: List[dict] = []
    for c in conns:
        if c.get("pid") is None or c.get("local_port") is None:
            continue
        out.append({
            "pid": int(c["pid"]),
            "local_addr": c.get("local_addr", ""),
            "local_port": str(c.get("local_port", "")).strip(),
            "remote_addr": c.get("remote_addr", ""),
            "remote_port": str(c.get("remote_port", "")).strip(),
            "process": c.get("process", ""),
        })
    return out


def parse_stream_rows(rows: Iterable[List[str]]) -> Dict[tuple, str]:
    """(stream 6-col rows) -> {4-tuple(client->server): client_random}.

    Columns: tcp.stream, ip.src, tcp.srcport, ip.dst, tcp.dstport, tls.handshake.random.
    The ClientHello's ip.src/srcport is the client's LOCAL endpoint, which is what a
    per-PID netstat snapshot reports as local_addr/local_port.
    """
    out: Dict[tuple, str] = {}
    for row in rows:
        stream, src, sport, dst, dport, rnd = (list(row) + [""] * 6)[:6]
        rnd = rnd.replace(":", "").strip().lower()
        if not (len(rnd) == 64 and _HEX.match(rnd)):
            continue
        out[tuple_key(src, sport, dst, dport)] = rnd
    return out


def parse_keylog_by_cr(text: str) -> Dict[str, Dict[str, str]]:
    """client_random -> {LABEL: secret} from an NSS keylog."""
    out: Dict[str, Dict[str, str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        label, cr, secret = parts[0], parts[1].lower(), parts[2].lower()
        if len(cr) == 64 and _HEX.match(cr) and _HEX.match(secret):
            out.setdefault(cr, {})[label] = secret
    return out


def match_pid_to_cr(conns: Iterable[dict],
                    stream_tuples: Dict[tuple, str]) -> Dict[int, dict]:
    """PID -> {client_random, matched_by, tuple}. Tiered match, most specific first.

    1. full 4-tuple (local ip:port + remote ip:port)
    2. (local_port, remote_ip, remote_port) — local ip differs (e.g. 0.0.0.0 bind)
    3. (local_port, remote_port) — last resort within one capture

    A looser tier only matches when it is UNAMBIGUOUS (one distinct client_random).
    """
    by_full = stream_tuples
    by_lport_remote: Dict[tuple, List[str]] = {}
    by_ports: Dict[tuple, List[str]] = {}
    for (sip, sport, dip, dport), cr in stream_tuples.items():
        by_lport_remote.setdefault((sport, dip, dport), []).append(cr)
        by_ports.setdefault((sport, dport), []).append(cr)

    result: Dict[int, dict] = {}
    for c in conns:
        lip, lport = canon_ip(c["local_addr"]), c["local_port"]
        rip, rport = canon_ip(c["remote_addr"]), c["remote_port"]
        full = (lip, lport, rip, rport)
        cr = by_full.get(full)
        matched_by = "4-tuple"
        if cr is None:
            cand = by_lport_remote.get((lport, rip, rport))
            if cand and len(set(cand)) == 1:
                cr, matched_by = cand[0], "lport+remote"
        if cr is None:
            cand = by_ports.get((lport, rport))
            if cand and len(set(cand)) == 1:
                cr, matched_by = cand[0], "ports-only"
        if cr is not None:
            result[c["pid"]] = {"client_random": cr, "matched_by": matched_by,
                                "tuple": full, "process": c.get("process", "")}
    return result


def build_pid_keylog(pid_cr: Dict[int, dict],
                     keys_by_cr: Dict[str, Dict[str, str]]) -> str:
    """NSS keylog lines for exactly the client_randoms owned by a known PID."""
    lines: List[str] = []
    seen: set[Tuple[str, str]] = set()
    for info in pid_cr.values():
        cr = info["client_random"]
        for label, secret in sorted(keys_by_cr.get(cr, {}).items()):
            if (label, cr) in seen:
                continue
            seen.add((label, cr))
            lines.append(f"{label} {cr} {secret}")
    return "\n".join(lines) + ("\n" if lines else "")


def secrets_from_any(text: str) -> List[str]:
    """Pull candidate secrets (32/48-byte hex) from a keylog OR a ``secret=`` dump."""
    out: List[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        for tok in line.replace("secret=", " ").split():
            tok = tok.strip().lower()
            if len(tok) in (64, 96) and _HEX.match(tok):
                out.append(tok)
    return list(dict.fromkeys(out))


__all__ = [
    "canon_ip",
    "tuple_key",
    "parse_netstat",
    "parse_stream_rows",
    "parse_keylog_by_cr",
    "match_pid_to_cr",
    "build_pid_keylog",
    "secrets_from_any",
]
