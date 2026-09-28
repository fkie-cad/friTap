#!/usr/bin/env python3
"""Turn a calibrate.js report (calib.json) into a paste-ready x64 offset block.

The read-only Schannel scanner ships with ``arch.x64.calibrated:false`` and an
EMPTY needle-candidate list, so on x64 the tls12/session-cache tiers resolve no
needle and no-op safely rather than emit garbage (the arm64 arch is the calibrated
one). This tool reads the JSON that ``schannel_calibrate.py --out calib.json``
wrote — which is pure MEASUREMENT from the ncrypt hooks — and renders the
``arch.x64`` block for ``friTap/memory_scanning/patterns.json``.

It INVENTS NOTHING: every needle RVA comes from a pointer the agent actually saw
land inside ncryptsslp.dll, and every struct offset comes from a layout the agent
CONFIRMED by byte-comparing the hooked ground-truth secret. Where the run measured
nothing, the field keeps its seeded value and ``calibrated`` stays ``false`` with a
printed warning — a partial run is not a calibration.

    python3 emit_x64_offsets.py --report calib.json
    python3 emit_x64_offsets.py --report calib.json --min-count 3
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

_OFF_RE = re.compile(r"0x[0-9a-fA-F]+")


def _parse_rel_offset(expr: Any) -> int | None:
    """Extract the trailing ``+0xNN`` from a layout string like ``ssl5+0x1c``."""
    if not isinstance(expr, str):
        return None
    hits = _OFF_RE.findall(expr)
    if not hits:
        return None
    return int(hits[-1], 16)


def ncryptsslp_needle_candidates(derived: dict, min_count: int) -> list[dict]:
    """Ranked ``{rva, note}`` for pointers seen landing inside ncryptsslp.dll.

    Only candidates the agent observed at least *min_count* times are kept, most-
    seen first, so a one-off stray pointer never becomes a shipped needle.
    """
    cands = derived.get("needle_candidates")
    if not isinstance(cands, dict):
        return []
    rows = [c for c in cands.values()
            if isinstance(c, dict)
            and str(c.get("module")) == "ncryptsslp.dll"
            and int(c.get("count", 0)) >= min_count]
    rows.sort(key=lambda c: int(c.get("count", 0)), reverse=True)
    out: list[dict] = []
    seen: set[str] = set()
    for c in rows:
        rva = str(c.get("rva", "")).lower()
        if not rva or rva in seen:
            continue
        seen.add(rva)
        out.append({
            "rva": rva,
            "note": f"measured x{c.get('count', 0)} at {c.get('struct', '?')}"
                    f"@{c.get('offset', '?')} (value {c.get('value', '?')})",
        })
    return out


def tls12_tier_from_offsets(derived: dict) -> tuple[dict, bool]:
    """Build the tls12_master tier from a CONFIRMED layout; (tier, confirmed?).

    ``confirmed.ssl5_at`` (keyObj+0x10 -> needle_at 16), ``confirmed.master_at``
    (ssl5+0x1c -> master_at 28) and ``confirmed.len`` are read straight off the
    agent's byte-compare result. When the run did not confirm, the seeded arm64
    values are returned and the second element is False.
    """
    seeded = {"enabled": True, "needle_at": 16, "master_at": 28,
              "master_len": 48, "label": "CLIENT_RANDOM"}
    offsets = derived.get("offsets")
    conf = None
    if isinstance(offsets, dict):
        sect = offsets.get("tls12_master")
        if isinstance(sect, dict):
            conf = sect.get("confirmed")
    if not isinstance(conf, dict):
        return seeded, False
    needle_at = _parse_rel_offset(conf.get("ssl5_at")) or 16
    master_at = _parse_rel_offset(conf.get("master_at"))
    master_len = int(conf.get("len") or 48)
    if master_at is None:
        return seeded, False
    return ({"enabled": True, "needle_at": needle_at, "master_at": master_at,
             "master_len": master_len, "label": "CLIENT_RANDOM"}, True)


def build_x64_block(derived: dict, min_count: int) -> tuple[dict, bool, list[str]]:
    """Assemble the ``arch.x64`` block. Returns (block, calibrated, warnings)."""
    warnings: list[str] = []
    candidates = ncryptsslp_needle_candidates(derived, min_count)
    if not candidates:
        warnings.append(
            "no ncryptsslp.dll needle candidate met --min-count: the tls12/"
            "session-cache tiers cannot resolve a needle, so x64 stays uncalibrated.")
    tls12_tier, tls12_confirmed = tls12_tier_from_offsets(derived)
    if not tls12_confirmed:
        warnings.append(
            "tls12_master layout was NOT confirmed by the agent's byte-compare; "
            "the seeded arm64 offsets are shown but not trusted.")

    calibrated = bool(candidates) and tls12_confirmed
    block = {
        "_calibrated_from": "schannel_calibrate.py + emit_x64_offsets.py (MEASURED, not invented)",
        "calibrated": calibrated,
        "needle": {
            "module": "ncryptsslp.dll",
            "at_offset_in_struct": tls12_tier["needle_at"],
            "candidates": candidates,
        },
        "tiers": {
            "tls12_master": tls12_tier,
            "tls13_secret": {
                "enabled": False,
                "anchor_tag": "3lss",
                "secret_at": 106,
                "size_at": -1,
                "secret_lens": [48, 32],
            },
            "session_cache": {
                "enabled": False,
                "vftable_at": 0,
                "bddd_ptr_at": 16,
                "ssl5_ptr_at": 16,
                "ssl5_needle_at": 16,
                "master_at": tls12_tier["master_at"],
                "master_len": tls12_tier["master_len"],
                "bddd_magic": "BDDD",
                "bddd_magic_at": 4,
                "session_id_at": 216,
                "session_id_maxlen": 32,
                "session_id_calibrated": False,
                "bootstrap_max_ssl5": 6,
                "reverse_scan_cap": 128,
                "dump_bytes": 288,
                "dump": False,
            },
        },
    }
    return block, calibrated, warnings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", required=True, type=Path,
                    help="calib.json written by schannel_calibrate.py --out")
    ap.add_argument("--min-count", type=int, default=2,
                    help="minimum times a needle pointer must recur to be trusted "
                         "(default: %(default)s)")
    args = ap.parse_args(argv)

    if not args.report.exists():
        print(f"[!] report not found: {args.report}", file=sys.stderr)
        return 2
    data = json.loads(args.report.read_text(encoding="utf-8"))
    derived = data.get("derived") if isinstance(data, dict) else None
    if not isinstance(derived, dict):
        print("[!] report has no 'derived' object (was calibrate.js's export read?)",
              file=sys.stderr)
        return 2

    block, calibrated, warnings = build_x64_block(derived, args.min_count)
    for w in warnings:
        print(f"[!] {w}", file=sys.stderr)

    print("// paste this as the schannel profile's arch.x64 block in "
          "friTap/memory_scanning/patterns.json:", file=sys.stderr)
    print(json.dumps({"x64": block}, indent=2))

    if calibrated:
        print("\n[*] x64 CALIBRATED: needle candidates found and tls12 layout "
              "confirmed. Set arch.x64.calibrated:true (done in the block above).",
              file=sys.stderr)
    else:
        print("\n[!] x64 NOT fully calibrated — leave arch.x64.calibrated:false. "
              "Re-run schannel_calibrate.py while driving more TLS 1.2 traffic "
              "through lsass to gather needle recurrences and a confirmed layout.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
