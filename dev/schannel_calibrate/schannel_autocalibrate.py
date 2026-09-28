#!/usr/bin/env python3
"""Automatic, offline calibration of the SChannel session_cache offsets.

WHY THIS EXISTS
  The read-only session_cache scanner (agent/schannel_scanner.js) can emit
  Wireshark-ready 'RSA Session-ID:<sid> Master-Key:<master>' lines for TLS 1.2 —
  which is how you AVOID the trial-decryption overhead entirely: the session id is
  a memory-resident correlator, so once we know where it sits we pair
  session_id -> master straight from the structure, no probing. The catch is the
  ONE build-specific number: the session id's offset inside CSslCacheClientItem
  (`session_id_at`, ~0xd8 on Win10 x64, unknown elsewhere).

  This tool finds that number automatically so anyone can reproduce the setup on
  their own machine, and it does the finding OFFLINE:

    1. `schannel_mem_scan.py --dump-cache` writes each cache item's bytes window
       to schannel.cachedump.txt (read-only; no hooking).
    2. this tool reads that dump, gets the real session ids from the pcap (their
       ServerHello), locates each id inside its cache-item window, and the offset
       they agree on IS session_id_at. With --write it patches the profile and
       flips session_id_calibrated to true.

  It also has an --analyze mode: given a flat memory dump plus ground-truth
  client randoms (e.g. from a calibrate.js oracle keylog), it searches the WHOLE
  dump for each client random and reports where it lives relative to the key
  structs. That is the reverse-engineering answer to "can we avoid trial
  decryption for TLS 1.3 too" — it measures, on your build, whether the client
  random is persisted anywhere reachable, rather than assuming.

    # calibrate session_id_at from a dump-cache run + the matching pcap
    python tools/schannel_autocalibrate.py session-id \
        --cachedump schannel.cachedump.txt --pcap capture.pcap --write

    # RE: where does each known client random live in a flat lsass dump?
    python tools/schannel_autocalibrate.py analyze \
        --dump lsass.bin --oracle oracle.keylog

Nothing here touches lsass; it is pure offline post-processing.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import decrypt_pcap  # noqa: E402  (reuse its hermetic tshark resolver)
import minidump_reader  # noqa: E402  (VA-space dump reader)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NO_TSHARK = 3
EXIT_NOTHING = 4

_HEX = re.compile(r"^[0-9a-fA-F]+$")
MAGIC_TAGS = ("BDDD", "ssl5", "5lss", "3lss", "YKSM", "UUUR")
# The TLS 1.3 hypothesis chain anchors (patterns/schannel_secrets.json tls13_secret):
# BDDD -> 3lss -> UUUR -> YKSM -> secret. tag_positions folds each tag's reverse.
TLS13_TAGS = ("BDDD", "3lss", "UUUR", "YKSM")


def _fail(message: str, code: int = EXIT_USAGE) -> "NoReturn":  # noqa: F821
    print(f"[!] {message}", file=sys.stderr)
    raise SystemExit(code)


# --------------------------------------------------------------------------- #
# Pure helpers (unit-testable without tshark or a dump)
# --------------------------------------------------------------------------- #

def parse_cachedump(text: str) -> list[dict[str, str]]:
    """Parse schannel.cachedump.txt lines into records.

    Each line is space-joined key=value; `bytes` is last and space-free, so a
    plain split is safe. Only lines carrying a non-empty `bytes` window matter.
    """
    records: list[dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rec: dict[str, str] = {}
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                rec[k] = v
        if rec.get("bytes"):
            records.append(rec)
    return records


def find_needle_offsets(window_hex: str, needle_hex: str) -> list[int]:
    """Byte offsets at which needle_hex occurs inside window_hex (both hex)."""
    if not window_hex or not needle_hex:
        return []
    try:
        window = bytes.fromhex(window_hex)
        needle = bytes.fromhex(needle_hex)
    except ValueError:
        return []
    if not needle:
        return []
    offsets, start = [], 0
    while True:
        idx = window.find(needle, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def calibrate_session_id_at(records: Iterable[dict[str, str]],
                            known_sids: Iterable[str]) -> dict[str, object]:
    """Find the offset at which cache items store their session id.

    For every cache-item window we look for every known session id. A window
    contains ITS OWN id at the true offset; other ids will almost never appear.
    So the offset that recurs across the most DISTINCT cache items is the answer,
    and agreement across >=2 items is what turns a guess into a calibration.
    """
    sids = [s.lower() for s in known_sids if s and _HEX.match(s)]
    votes: Counter[int] = Counter()
    items_supporting: dict[int, set[str]] = {}
    hits: list[tuple[str, str, int]] = []  # (cache_item, sid, offset)
    for rec in records:
        window = rec.get("bytes", "")
        item = rec.get("cache_item", "?")
        seen_offsets_this_item: set[int] = set()
        for sid in sids:
            for off in find_needle_offsets(window, sid):
                hits.append((item, sid, off))
                if off not in seen_offsets_this_item:
                    seen_offsets_this_item.add(off)
                    votes[off] += 1
                    items_supporting.setdefault(off, set()).add(item)
    if not votes:
        return {"chosen": None, "agreement": 0, "votes": {}, "hits": hits}
    chosen, agreement = votes.most_common(1)[0]
    return {
        "chosen": chosen,
        "agreement": agreement,
        "distinct_items": len(items_supporting.get(chosen, set())),
        "votes": dict(votes),
        "hits": hits,
    }


def parse_tshark_session_ids(output: str) -> set[str]:
    """Session ids (hex, colons stripped, non-empty) from a -T fields column."""
    out: set[str] = set()
    for line in output.splitlines():
        sid = line.strip().replace(":", "").lower()
        if sid and _HEX.match(sid):
            out.add(sid)
    return out


def client_randoms_from_keylog(text: str) -> set[str]:
    """CLIENT_RANDOM / *_TRAFFIC_SECRET client-random fields from a keylog."""
    out: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 3 and _HEX.match(parts[1]) and len(parts[1]) == 64:
            out.add(parts[1].lower())
    return out


def find_all_in_dump(dump: bytes, needle_hex: str) -> list[int]:
    """Every byte offset of needle_hex within a flat dump."""
    try:
        needle = bytes.fromhex(needle_hex)
    except ValueError:
        return []
    if not needle:
        return []
    offsets, start = [], 0
    while True:
        idx = dump.find(needle, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def magic_inventory(dump: bytes, tags: Iterable[str] = MAGIC_TAGS) -> dict[str, int]:
    """Count occurrences of each ASCII magic tag (both byte orders) in a dump."""
    counts: dict[str, int] = {}
    for tag in tags:
        forward = tag.encode("ascii")
        reverse = forward[::-1]
        n = len(find_all_in_dump(dump, forward.hex()))
        if reverse != forward:
            n += len(find_all_in_dump(dump, reverse.hex()))
        counts[tag] = n
    return counts


def secrets_from_keylog(text: str) -> list[tuple[str, str, str]]:
    """(label, client_random, secret) triples from an NSS keylog.

    Unlike client_randoms_from_keylog this keeps the SECRET too, so tls13-locate can
    search the dump for the actual secret bytes (32B for SHA256 suites, 48B for
    SHA384) and report where each labeled secret lives relative to the SChannel tags.
    """
    out: list[tuple[str, str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        label, cr, secret = parts[0], parts[1].lower(), parts[2].lower()
        if len(cr) == 64 and _HEX.match(cr) and _HEX.match(secret) and len(secret) in (64, 96):
            out.append((label, cr, secret))
    return out


class _FlatDump:
    """Flat raw dump wearing the MiniDump search interface (va == file offset)."""

    def __init__(self, data: bytes):
        self.data = data

    def search(self, needle: bytes) -> list[int]:
        out, start = [], 0
        while True:
            idx = self.data.find(needle, start)
            if idx == -1:
                break
            out.append(idx)
            start = idx + 1
        return out

    def total_bytes(self) -> int:
        return len(self.data)


def load_dump(path: Path):
    """A MiniDump for a real .dmp, else a _FlatDump. Both expose .search(bytes)."""
    data = path.read_bytes()
    if len(data) >= 4 and data[:4] == b"MDMP":
        return minidump_reader.MiniDump(data)
    return _FlatDump(data)


def build_tag_index(dump, tags: Iterable[str] = TLS13_TAGS) -> dict[str, list[int]]:
    """tag name -> sorted VAs (both byte orders folded), for nearest-tag deltas."""
    index: dict[str, list[int]] = {}
    for tag in tags:
        index[tag] = minidump_reader.tag_positions(dump, tag.encode("ascii"))
    return index


# --------------------------------------------------------------------------- #
# Profile patching (targeted, formatting-preserving)
# --------------------------------------------------------------------------- #

def patch_session_id_at(profile_text: str, offset: int) -> str:
    """Set session_id_at and session_id_calibrated inside the session_cache block.

    A targeted string edit, not a json round-trip: the profile is hand-formatted
    with aligned entries and `_doc` keys, and re-dumping would churn all of it.
    """
    start = profile_text.find('"session_cache"')
    if start == -1:
        raise ValueError("no session_cache tier found in the profile")
    # Bound the edit to the session_cache object so a same-named key elsewhere is
    # never touched; the tier is the last one, so end-of-string is a safe bound.
    head, block = profile_text[:start], profile_text[start:]
    block, n1 = re.subn(r'("session_id_at"\s*:\s*)\d+', rf'\g<1>{offset}', block, count=1)
    block, n2 = re.subn(r'("session_id_calibrated"\s*:\s*)(?:true|false)',
                        r'\g<1>true', block, count=1)
    if n1 == 0:
        raise ValueError("session_id_at not found in the session_cache block")
    if n2 == 0:
        raise ValueError("session_id_calibrated not found in the session_cache block")
    return head + block


# --------------------------------------------------------------------------- #
# tshark
# --------------------------------------------------------------------------- #

def session_ids_from_pcap(tshark: str, pcap: Path) -> set[str]:
    """Server- and client-offered session ids from every handshake in the pcap."""
    ids: set[str] = set()
    for htype in ("2", "1"):  # ServerHello, then ClientHello (resumption offers)
        proc = subprocess.run(
            [tshark, "-r", str(pcap.resolve()), "-Y", f"tls.handshake.type=={htype}",
             "-T", "fields", "-e", "tls.handshake.session_id"],
            capture_output=True, text=True)
        ids |= parse_tshark_session_ids(proc.stdout)
    return ids


# --------------------------------------------------------------------------- #
# Sub-commands
# --------------------------------------------------------------------------- #

def cmd_session_id(args: argparse.Namespace) -> int:
    if not args.cachedump.exists():
        _fail(f"cachedump not found: {args.cachedump} "
              f"(run: python schannel_mem_scan.py --dump-cache --once)")
    records = parse_cachedump(args.cachedump.read_text(encoding="utf-8", errors="replace"))
    if not records:
        _fail(f"no cache-item windows in {args.cachedump}; did --dump-cache find any items?",
              EXIT_NOTHING)
    print(f"[*] {len(records)} cache-item window(s) in {args.cachedump}", file=sys.stderr)

    sids: set[str] = {s.lower() for s in (args.session_id or []) if _HEX.match(s)}
    if args.pcap:
        if not args.pcap.exists():
            _fail(f"pcap not found: {args.pcap}")
        tshark = decrypt_pcap.find_tshark(args.tshark_path)
        sids |= session_ids_from_pcap(tshark, args.pcap)
    if not sids:
        _fail("no known session ids to search for; pass --pcap and/or --session-id", EXIT_NOTHING)
    print(f"[*] searching for {len(sids)} known session id(s)", file=sys.stderr)

    result = calibrate_session_id_at(records, sids)
    chosen = result["chosen"]
    if chosen is None:
        print("[!] no known session id was found in any cache-item window.", file=sys.stderr)
        print("    Either the pcap does not match this dump, or the reverse-scan chain "
              "(bddd_ptr_at/ssl5_ptr_at) is wrong for this build, so the 'cache items' are "
              "not really cache items. Re-dump and check the bytes windows by hand.", file=sys.stderr)
        return EXIT_NOTHING
    print(f"[+] session_id_at = {chosen} (0x{chosen:x}), agreed by "
          f"{result['distinct_items']} distinct cache item(s)", file=sys.stderr)
    if result["distinct_items"] < 2:
        print("    WARNING: only one item agreed; treat as tentative until a second confirms.",
              file=sys.stderr)
    other = {o: v for o, v in result["votes"].items() if o != chosen}
    if other:
        print(f"    (other offsets seen: {other})", file=sys.stderr)

    if args.write:
        prof = args.profile
        if not prof.exists():
            _fail(f"profile not found: {prof}")
        try:
            patched = patch_session_id_at(prof.read_text(encoding="utf-8"), int(chosen))
        except ValueError as exc:
            _fail(str(exc))
        prof.write_text(patched, encoding="utf-8")
        print(f"[*] wrote session_id_at=0x{chosen:x} and session_id_calibrated=true -> {prof}",
              file=sys.stderr)
        print("    now: python schannel_mem_scan.py --name lsass --emit-session-id --duration 120",
              file=sys.stderr)
    else:
        print(f"[*] re-run with --write to set it in {args.profile}, or set by hand:", file=sys.stderr)
        print(f'      "session_id_at": {chosen}, "session_id_calibrated": true', file=sys.stderr)
    return EXIT_OK


def cmd_analyze(args: argparse.Namespace) -> int:
    if not args.dump.exists():
        _fail(f"dump not found: {args.dump}")
    raw = args.dump.read_bytes()
    if len(raw) >= 4 and raw[:4] == b"MDMP":
        # Concatenate committed ranges so the flat search still works on a real .dmp.
        # (For VA-anchored, struct-relative offsets use the `tls13-locate` command.)
        md = minidump_reader.MiniDump(raw)
        dump = b"".join(buf for _, buf in md.iter_ranges())
        print(f"[*] loaded minidump {args.dump}: {len(dump):,} bytes across "
              f"{len(md.ranges)} ranges", file=sys.stderr)
    else:
        dump = raw
        print(f"[*] loaded {len(dump):,} bytes from {args.dump}", file=sys.stderr)

    inv = magic_inventory(dump)
    print("[*] SChannel magic-tag inventory (both byte orders):", file=sys.stderr)
    for tag, n in inv.items():
        print(f"      {tag}: {n}", file=sys.stderr)

    randoms: set[str] = {r.lower() for r in (args.client_random or []) if _HEX.match(r)}
    if args.oracle:
        if not args.oracle.exists():
            _fail(f"oracle keylog not found: {args.oracle}")
        randoms |= client_randoms_from_keylog(args.oracle.read_text(encoding="utf-8", errors="replace"))
    if not randoms:
        print("[*] no client randoms given (--oracle / --client-random); "
              "reported tag inventory only.", file=sys.stderr)
        return EXIT_OK

    print(f"[*] locating {len(randoms)} known client random(s) in the dump:", file=sys.stderr)
    found_any = False
    for cr in sorted(randoms):
        offsets = find_all_in_dump(dump, cr)
        if offsets:
            found_any = True
            shown = ", ".join(f"0x{o:x}" for o in offsets[:8])
            print(f"      {cr[:16]}… -> {len(offsets)} location(s): {shown}"
                  + (" …" if len(offsets) > 8 else ""), file=sys.stderr)
        else:
            print(f"      {cr[:16]}… -> NOT present anywhere in this dump", file=sys.stderr)
    print("", file=sys.stderr)
    if found_any:
        print("[=] client randoms ARE resident in this dump. If they sit at a stable offset "
              "relative to an 'ssl5'/'3lss' struct (compare these addresses to the tag "
              "locations), a scanner tier could read them directly and skip trial decryption. "
              "If their locations are scattered (transcript buffers, freed heap), trial "
              "correlation stays the robust route.", file=sys.stderr)
    else:
        print("[=] client randoms are NOT in this dump — consistent with SChannel keeping them "
              "only as transient call parameters. Trial correlation (schannel_correlate.py) or "
              "the session-id path is the way; there is nothing to read directly.", file=sys.stderr)
    return EXIT_OK


def locate_report(dump, tag_index: dict[str, list[int]],
                  triples: list[tuple[str, str, str]]) -> dict:
    """Locate each secret + client_random in the dump relative to the tag chain.

    Returns a structured result (also drives the printed report and the tests):
      per_label:   label -> list of {va, nearest_tag, delta} for each hit
      client_random: cr(16) -> list of {va, nearest_tag, delta}
      consensus:   label -> (tag, delta, count) most common (tag,delta) across hits
    """
    secrets: dict[str, str] = {}
    crs: set[str] = set()
    for label, cr, secret in triples:
        secrets.setdefault(label, secret)
        crs.add(cr)

    per_label: dict[str, list[dict]] = {}
    consensus: dict[str, tuple] = {}
    for label, secret in secrets.items():
        hits = dump.search(bytes.fromhex(secret))
        recs, votes = [], Counter()
        for va in hits:
            nt = minidump_reader.nearest_tag(tag_index, va)
            rec = {"va": va,
                   "nearest_tag": (nt[0] if nt else None),
                   "delta": (nt[1] if nt else None)}
            recs.append(rec)
            if nt is not None:
                votes[(nt[0], nt[1])] += 1
        per_label[label] = recs
        if votes:
            (tag, delta), n = votes.most_common(1)[0]
            consensus[label] = (tag, delta, n)

    cr_hits: dict[str, list[dict]] = {}
    for cr in sorted(crs):
        recs = []
        for va in dump.search(bytes.fromhex(cr)):
            nt = minidump_reader.nearest_tag(tag_index, va)
            recs.append({"va": va,
                         "nearest_tag": (nt[0] if nt else None),
                         "delta": (nt[1] if nt else None)})
        cr_hits[cr] = recs

    return {"per_label": per_label, "consensus": consensus, "client_random": cr_hits}


def cmd_tls13_locate(args: argparse.Namespace) -> int:
    if not args.keylog or not args.keylog.exists():
        _fail("a ground-truth --keylog is required (e.g. captures/.../server.keylog)")

    if args.live_name or args.live_pid is not None:
        # Read the target live (no dump file) — avoids Defender quarantining an
        # lsass .dmp. Same read-only primitive, nothing persists to disk.
        import proc_mem  # ctypes/Windows; imported only on the live path
        dump = proc_mem.open_live(pid=args.live_pid, name=args.live_name)
        who = args.live_name or f"pid {args.live_pid}"
        print(f"[*] read live {who} ({dump.total_bytes():,} bytes of committed rw memory)",
              file=sys.stderr)
    else:
        if not args.dump or not args.dump.exists():
            _fail(f"dump not found: {args.dump} (or pass --live-name/--live-pid)")
        dump = load_dump(args.dump)
        print(f"[*] loaded dump {args.dump} ({dump.total_bytes():,} bytes of memory)",
              file=sys.stderr)

    triples = secrets_from_keylog(args.keylog.read_text(encoding="utf-8", errors="replace"))
    tls13 = [t for t in triples if t[0] != "CLIENT_RANDOM"]  # keep the TLS 1.3 labels
    if not tls13:
        _fail("no TLS 1.3 secret lines in the keylog (need *_TRAFFIC_SECRET / EXPORTER_SECRET)",
              EXIT_NOTHING)

    tag_index = build_tag_index(dump, TLS13_TAGS)
    print("[*] TLS 1.3 struct-tag inventory (both byte orders):", file=sys.stderr)
    for tag, positions in tag_index.items():
        print(f"      {tag}: {len(positions)}", file=sys.stderr)

    result = locate_report(dump, tag_index, tls13)

    print("[*] locating each ground-truth TLS 1.3 secret in the dump:", file=sys.stderr)
    any_secret = False
    for label in sorted(result["per_label"]):
        recs = result["per_label"][label]
        if not recs:
            print(f"      {label}: NOT present", file=sys.stderr)
            continue
        any_secret = True
        cons = result["consensus"].get(label)
        where = (f"{cons[0]}+0x{cons[1]:x} (x{cons[2]})" if cons else "no tag nearby")
        vas = ", ".join(f"0x{r['va']:x}" for r in recs[:4])
        print(f"      {label}: {len(recs)} hit(s) @ {vas} -> nearest {where}", file=sys.stderr)

    print("[*] locating the client_random(s):", file=sys.stderr)
    cr_resident = False
    for cr, recs in result["client_random"].items():
        if recs:
            cr_resident = True
            cons = Counter((r["nearest_tag"], r["delta"]) for r in recs if r["nearest_tag"])
            near = (f"{cons.most_common(1)[0][0][0]}+0x{cons.most_common(1)[0][0][1]:x}"
                    if cons else "no tag nearby")
            vas = ", ".join(f"0x{r['va']:x}" for r in recs[:4])
            print(f"      {cr[:16]}…: {len(recs)} hit(s) @ {vas} -> nearest {near}",
                  file=sys.stderr)
        else:
            print(f"      {cr[:16]}…: NOT present anywhere in this dump", file=sys.stderr)

    if any_secret:
        print("[=] TLS 1.3 secrets ARE resident. Where a label's hits agree on one "
              "(tag, delta), that is the confirmed offset for the profile's tls13_secret "
              "chain (on this build: secret_at = 3lss+0x6a). Fill patterns/schannel_secrets.json.",
              file=sys.stderr)
    else:
        print("[=] no ground-truth TLS 1.3 secret was found in this dump. If this is the "
              "CLIENT dump that is expected (secrets stay in lsass); if it is the lsass "
              "dump, re-check the capture overlapped the live session.", file=sys.stderr)
    if cr_resident:
        print("[=] client_random IS resident in this dump. If it sits at a stable delta "
              "from a struct tag it is a memory-resident correlator (zero trial cost); if "
              "scattered/only in the CLIENT dump it rides the socket buffers, not the key "
              "struct.", file=sys.stderr)
    else:
        print("[=] client_random is NOT in this dump — for lsass this matches the TLS 1.2 "
              "finding (no resident correlator); pair via the pcap/pidmap instead.",
              file=sys.stderr)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("session-id", help="derive session_id_at from a dump-cache run + pcap")
    s.add_argument("--cachedump", type=Path, default=Path("schannel.cachedump.txt"),
                   help="output of `schannel_mem_scan.py --dump-cache` (default: %(default)s)")
    s.add_argument("--pcap", type=Path, default=None, help="pcap to read known session ids from")
    s.add_argument("--session-id", action="append", default=None,
                   help="a known session id in hex (repeatable); use instead of/with --pcap")
    s.add_argument("--profile", type=Path, default=Path("patterns/schannel_secrets.json"),
                   help="profile to patch with --write (default: %(default)s)")
    s.add_argument("--write", action="store_true", help="write the derived offset into the profile")
    s.add_argument("--tshark-path", default=None, help="explicit tshark binary")
    s.set_defaults(func=cmd_session_id)

    a = sub.add_parser("analyze", help="RE a flat memory dump: tag inventory + where client randoms live")
    a.add_argument("--dump", type=Path, required=True, help="flat binary memory dump of lsass")
    a.add_argument("--oracle", type=Path, default=None,
                   help="a keylog of ground-truth client randoms (e.g. oracle.keylog)")
    a.add_argument("--client-random", action="append", default=None,
                   help="a known client random in hex (repeatable)")
    a.set_defaults(func=cmd_analyze)

    t = sub.add_parser("tls13-locate",
                       help="locate ground-truth TLS 1.3 secrets + client_random in a dump "
                            "(.dmp or flat) relative to the BDDD/3lss/UUUR/YKSM chain")
    t.add_argument("--dump", type=Path, default=None,
                   help="minidump (.dmp) or flat memory dump (lsass or client)")
    t.add_argument("--live-name", default=None,
                   help="read a live process by name instead of a dump (e.g. lsass) — "
                        "read-only, no file on disk (avoids Defender quarantining an lsass dump)")
    t.add_argument("--live-pid", type=int, default=None,
                   help="read a live process by PID instead of a dump")
    t.add_argument("--keylog", type=Path, required=True,
                   help="ground-truth NSS keylog from tools/tls13_server.py (server.keylog)")
    t.set_defaults(func=cmd_tls13_locate)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
