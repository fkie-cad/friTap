"""In-process (per-PID) Schannel secret correlation by byte-equality (PUBLIC).

Port of ``research/memory_scan_lsass/tools/sspi_correlate.py``. Schannel delegates
the handshake to lsass but runs the RECORD layer (Encrypt/DecryptMessage) inside
the calling process via an in-process ncryptsslp.dll, so the negotiated secrets
exist in BOTH places with the SAME bytes. That byte-equality is a direct per-PID
join to lsass with no pcap needed::

    target PID's in-process secret  ==  lsass secret  =>  this lsass secret is PID P's

Everything is read-only. The pure helpers (entropy gates, set intersection, keylog
assembly) and the two in-memory scanners (TLS 1.3 at ``3lss+0x6a``; TLS 1.2 via the
ncryptsslp needle) run against any source exposing ``search`` / ``read_va`` (a live
process or a minidump). Live process access is Windows-only and lives in the dev
tools, so nothing here is platform-specific.
"""

from __future__ import annotations

import json
import math
import struct
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ..tls.keylog import parse_strict_nss_line

_PATTERNS = Path(__file__).resolve().parents[2] / "memory_scanning" / "patterns.json"


def shannon(b: bytes) -> float:
    """Shannon entropy (bits/byte) of *b*; 0.0 for empty input."""
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    e = 0.0
    for n in counts:
        if n:
            p = n / len(b)
            e -= p * math.log2(p)
    return e


def zero_fraction(b: bytes) -> float:
    """Fraction of zero bytes in *b* (1.0 for empty input)."""
    return b.count(0) / len(b) if b else 1.0


def looks_secret(b: Optional[bytes]) -> bool:
    """CSPRNG gate: non-empty, <=50% zeros, and >= 4 bits/byte of entropy."""
    return bool(b) and zero_fraction(b) <= 0.5 and shannon(b) >= 4.0


def intersect(target: Set[str], lsass: Set[str]) -> Set[str]:
    """Secrets present in BOTH the target process and lsass (byte-identical)."""
    return target & lsass


def keylog_secret_map(text: str) -> Dict[str, Tuple[str, str]]:
    """secret(hex) -> (label, client_random) from an NSS keylog."""
    out: Dict[str, Tuple[str, str]] = {}
    for line in text.splitlines():
        entry = parse_strict_nss_line(line, allow_unknown_client_random=True)
        if entry is not None:
            out[entry.secret] = (entry.label, entry.client_random)
    return out


def build_keylog_lines(mapping: Dict[str, Tuple[str, str]], secrets: Set[str]) -> str:
    """NSS keylog lines for `secrets` that have a (label, cr) in `mapping`."""
    seen: Set[Tuple[str, str, str]] = set()
    lines: List[str] = []
    for sec in sorted(secrets):
        if sec in mapping:
            label, cr = mapping[sec]
            key = (label, cr, sec)
            if key not in seen:
                seen.add(key)
                lines.append(f"{label} {cr} {sec}")
    return "\n".join(lines) + ("\n" if lines else "")


def _tag_positions(src, tag: bytes) -> List[int]:
    """Sorted VAs of a magic tag, both byte orders folded together."""
    hits = set(src.search(tag))
    rev = tag[::-1]
    if rev != tag:
        hits |= set(src.search(rev))
    return sorted(hits)


def scan_tls13(src, profile: Optional[dict] = None) -> Set[str]:
    """Recover TLS 1.3 secrets anchored on the tag-relative secret slot.

    Anchor tag, secret offset and candidate lengths come from the profile's
    ``tls13_secret`` tier (default: shipped arm64 offsets via :func:`load_profile`).
    """
    tier = (profile or load_profile())["tiers"]["tls13_secret"]
    anchor_tag = tier["anchor_tag"].encode() if isinstance(tier["anchor_tag"], str) \
        else tier["anchor_tag"]
    secret_at = tier["secret_at"]
    out: Set[str] = set()
    for pos in _tag_positions(src, anchor_tag):
        for length in tier["secret_lens"]:
            s = src.read_va(pos + secret_at, length)
            if looks_secret(s):
                out.add(s.hex())
                break
    return out


def scan_tls12(src, ncryptsslp_base: int, profile: dict) -> Set[str]:
    """Recover TLS 1.2 masters via the ncryptsslp needle, using THIS module base."""
    tier = profile["tiers"]["tls12_master"]
    needle_at, master_at, mlen = tier["needle_at"], tier["master_at"], tier["master_len"]
    out: Set[str] = set()
    for cand in profile["needles"]["candidates"]:
        value = ncryptsslp_base + int(cand["rva"], 16)
        for site in src.search(struct.pack("<Q", value)):
            ssl5 = site - needle_at
            m = src.read_va(ssl5 + master_at, mlen)
            if looks_secret(m):
                out.add(m.hex())
    return out


def load_profile(arch: str = "arm64") -> dict:
    """Flatten ``arch.<arch>.needle``/``tiers`` into ``{"needles": ..., "tiers": ...}``.

    Defaults to ``arm64``, the calibrated arch; x64 needle candidates are empty
    until :mod:`dev.schannel_calibrate` measures them.
    """
    db = json.loads(_PATTERNS.read_text(encoding="utf-8"))
    schannel = next(p for p in db["profiles"] if p.get("engine") == "schannel")
    block = schannel["arch"][arch]
    return {
        "needles": {"candidates": list(block["needle"].get("candidates", []))},
        "tiers": block["tiers"],
    }


__all__ = [
    "shannon",
    "zero_fraction",
    "looks_secret",
    "intersect",
    "keylog_secret_map",
    "build_keylog_lines",
    "scan_tls13",
    "scan_tls12",
    "load_profile",
]
