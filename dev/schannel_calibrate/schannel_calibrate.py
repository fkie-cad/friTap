#!/usr/bin/env python3
"""Phase 0/1 driver: run agent/calibrate.js against Windows lsass.exe and collect
the SChannel ground truth + layout measurements it derives.

The agent hooks the seven ncrypt Ssl* functions inside lsass, emits NSS keylog
lines (JOB 1, the oracle), and MEASURES the SChannel/NCrypt memory layout a pure
memory scan would depend on (JOB 2): the invariant "needle" pointer into
ncryptsslp.dll, whether the client_random is reachable near the key structs, and
whether the hypothesised ARM64 struct offsets actually hold. This driver writes
the oracle keylog and prints the derived layout for the researcher to read off.

Everything this needs beyond the agent itself - device selection, process-name
resolution, the deduplicating output file and the NSS line parser - already
exists in schannel_secret_scan.py, one import away in this directory. Sharing it
matters more here than anywhere else: this script writes the ORACLE that
tools/verify_keylog.py compares the scanner against, so any weakness in the
writer here is scored as a scanner defect there.

    python3 schannel_calibrate.py --pid 1012 --out calib.json --keylog truth.keylog
    python3 schannel_calibrate.py            # defaults: --name lsass --device local
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from frida_helpers import (
    DedupLineFile,
    ProfileError,
    attach_agent,
    parse_keylog_line,
    rpc_call,
)

EXIT_OK = 0
EXIT_BAD_SETUP = 2


class GroundTruthCollector:
    """Collects agent/calibrate.js payloads and writes the keylog oracle.

    A line is written only once ``parse_keylog_line`` has accepted it. The oracle
    is the yardstick every scanner measurement is taken against, so a malformed
    line in it does not look like a bad oracle - it looks like a permanent
    scanner miss, or worse, a precision failure that is not really there.
    """

    def __init__(self, keylog: DedupLineFile | None) -> None:
        self.keylog = keylog
        self.records: list[dict[str, Any]] = []
        self.rejected = 0

    def on_message(self, message: dict[str, Any], _data: Any = None) -> None:
        """Entry point for script.on("message", ...)."""
        if message.get("type") == "error":
            print("[agent error] " + message.get("stack", str(message)), file=sys.stderr)
            return
        payload = message.get("payload")
        if isinstance(payload, dict) and payload.get("type") == "ground_truth":
            self._on_ground_truth(payload)

    def _on_ground_truth(self, payload: dict[str, Any]) -> None:
        """Record one hooked secret and, when asked, write its NSS line."""
        self.records.append(payload)
        line = str(payload.get("line") or "").strip()
        if self.keylog is None or not line:
            return
        if parse_keylog_line(line) is None:
            self.rejected += 1
            print(f"[!] not an NSS keylog record, not written: {line!r}", file=sys.stderr)
            return
        self.keylog.add(line)


def _top_counter(counter: Any, limit: int = 6) -> list[tuple[str, int]]:
    """Sort a {label: count} object into the highest counts first.

    The agent returns its counters as plain objects, so a consistent winner - the
    invariant needle, the recurring client_random offset - is simply the key with
    the largest count. Non-dict input (a missing section) sorts to nothing.
    """
    if not isinstance(counter, dict):
        return []
    pairs = [(str(k), int(v)) for k, v in counter.items() if isinstance(v, int)]
    pairs.sort(key=lambda kv: kv[1], reverse=True)
    return pairs[:limit]


def _print_symbols(symbols: Any) -> None:
    """One line per hooked symbol: where it resolved, or that it did not."""
    print("  symbol resolution:", file=sys.stderr)
    if not isinstance(symbols, dict) or not symbols:
        print("    (none reported)", file=sys.stderr)
        return
    for name, info in symbols.items():
        if isinstance(info, dict) and info.get("found") is not False:
            print(f"    {name:<28} {info.get('module', '?')}+{info.get('rva', '?')}"
                  f"  ({info.get('address', '?')})", file=sys.stderr)
        else:
            tried = ", ".join(info.get("tried", [])) if isinstance(info, dict) else "?"
            print(f"    {name:<28} NOT FOUND (tried {tried})", file=sys.stderr)


def _print_needles(candidates: Any) -> None:
    """The needle candidates, most-seen first; the invariant into ncryptsslp.dll
    is the pure-scan anchor we are hunting for."""
    print("  needle candidates (invariant pointer INTO a module):", file=sys.stderr)
    if not isinstance(candidates, dict) or not candidates:
        print("    (none seen - no captured struct slot pointed into a module)", file=sys.stderr)
        return
    ranked = sorted(candidates.values(),
                    key=lambda c: c.get("count", 0) if isinstance(c, dict) else 0,
                    reverse=True)
    for c in ranked[:10]:
        if not isinstance(c, dict):
            continue
        star = "  <== ncryptsslp.dll" if str(c.get("module")) == "ncryptsslp.dll" else ""
        print(f"    x{c.get('count', 0):<4} {c.get('struct', '?')} @ {c.get('offset', '?')}"
              f"  -> {c.get('module', '?')}+{c.get('rva', '?')}"
              f"  (value {c.get('value', '?')}){star}", file=sys.stderr)


def _print_cr_verdict(name: str, section: Any) -> None:
    """Whether the client_random was reachable near the key structs, and where.

    A recurring relative offset is the pure-scan pairing path; a run where
    'found' stayed 0 means the cr is not reachable that way and pairing needs a
    different route. Stated as a verdict, not just numbers, because that verdict
    is the make-or-break result for pure-scan pairing.
    """
    if not isinstance(section, dict):
        return
    found, not_found = section.get("found", 0), section.get("not_found", 0)
    print(f"  client_random reachability [{name}]: "
          f"found in {found} capture(s), not found in {not_found}", file=sys.stderr)
    if not found:
        print("    verdict: NOT reachable near the key structs in this run", file=sys.stderr)
        return
    for label in ("rel_ssl5", "rel_keyObj", "range_rel_ssl5",
                  "rel_yksm", "rel_bddd", "range_rel_yksm"):
        top = _top_counter(section.get(label))
        if top:
            shown = ", ".join(f"{off} x{cnt}" for off, cnt in top)
            print(f"    {label}: {shown}", file=sys.stderr)


def _print_offset_confirmation(offsets: Any) -> None:
    """Whether the hypothesised ARM64 struct offsets yielded sane secrets, plus
    any neighbour offset a probe found when they did not."""
    print("  offset confirmation on ARM64:", file=sys.stderr)
    if not isinstance(offsets, dict):
        print("    (none reported)", file=sys.stderr)
        return
    for name, sect in offsets.items():
        if not isinstance(sect, dict):
            continue
        ok, bad = sect.get("ok", 0), sect.get("bad", 0)
        confirmed = sect.get("confirmed")
        verdict = "CONFIRMED" if confirmed else ("NOT confirmed" if bad else "no data")
        print(f"    {name}: {verdict}  (ok={ok} bad={bad})", file=sys.stderr)
        if confirmed:
            print(f"      layout: {json.dumps(confirmed)}", file=sys.stderr)
        else:
            print(f"      hypothesis: {json.dumps(sect.get('hypothesis'))}", file=sys.stderr)
        sizes = _top_counter(sect.get("sizes"))
        if sizes:
            print("      sizes seen: " + ", ".join(f"{s}B x{c}" for s, c in sizes), file=sys.stderr)
        probes = _top_counter(sect.get("probes"))
        if probes:
            print("      probe hits (candidate real offset): "
                  + ", ".join(f"{p} x{c}" for p, c in probes), file=sys.stderr)


def print_derived(derived: dict[str, Any]) -> None:
    """Render the SChannel findings in a readable, per-item layout."""
    print("\n=== derived SChannel layout ===", file=sys.stderr)
    print(f"  arch={derived.get('arch', '?')} pointer_size={derived.get('pointer_size', '?')} "
          f"ncrypt_buffer_stride={derived.get('ncrypt_buffer_stride', '?')}", file=sys.stderr)
    modules = derived.get("modules")
    if isinstance(modules, dict):
        for name, info in modules.items():
            if isinstance(info, dict):
                print(f"  module {name}: base={info.get('base', '?')} size={info.get('size', '?')}",
                      file=sys.stderr)
    _print_symbols(derived.get("symbols"))
    gt = _top_counter(derived.get("ground_truth_counts"), limit=20)
    if gt:
        print("  ground-truth lines by label: "
              + ", ".join(f"{lbl}={cnt}" for lbl, cnt in gt), file=sys.stderr)
    _print_needles(derived.get("needle_candidates"))
    cr = derived.get("cr_reachability")
    if isinstance(cr, dict):
        _print_cr_verdict("TLS1.2", cr.get("tls12"))
        _print_cr_verdict("TLS1.3", cr.get("tls13"))
    _print_offset_confirmation(derived.get("offsets"))
    errors = derived.get("errors")
    if isinstance(errors, list) and errors:
        print(f"  faulting reads sampled: {len(errors)} (first: {errors[0]})", file=sys.stderr)


def read_derived(script) -> dict[str, Any]:
    """Print and return the layout fields the agent derived.

    Diagnostic only: the ground truth is already collected by the time this runs,
    so a missing or broken export must not cost the caller the keylog. The full
    object still lands in --out via write_report; this prints the readable digest.
    """
    try:
        derived = rpc_call(script, "derived")
    except Exception as exc:  # noqa: BLE001 - diagnostic path, never fatal
        print(f"[!] could not read derived exports: {exc}", file=sys.stderr)
        return {}
    if isinstance(derived, dict):
        print_derived(derived)
    else:
        print(f"\n=== derived (unexpected shape) ===\n{derived!r}", file=sys.stderr)
    return derived if isinstance(derived, dict) else {}


def write_report(path: Path, collector: GroundTruthCollector, derived: dict[str, Any]) -> None:
    """Write the full JSON record of the session."""
    path.write_text(
        json.dumps({"ground_truth": collector.records, "derived": derived}, indent=2),
        encoding="utf-8")
    print(f"[*] wrote {path} ({len(collector.records)} secret(s))", file=sys.stderr)


def wait_for_secrets(seconds: float) -> bool:
    """Stay attached for the collection window; True when Ctrl-C cut it short.

    Ctrl-C ends the wait rather than the program, the same way run_scans() in
    schannel_secret_scan.py does. Interrupting once the layout check has scrolled
    past is the expected way to end a long calibration, and every record it is
    going to write has already been collected by the message callback - so
    treating the interrupt as an abort would throw away the oracle the run was
    started for.
    """
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        return True
    return False


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Build the CLI; the target options mirror schannel_secret_scan.py's."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pid", type=int, help="pid to attach to (e.g. the lsass pid)")
    parser.add_argument("--name", default="lsass",
                        help="process name to resolve on the device instead of --pid "
                             "(default: %(default)s)")
    parser.add_argument("--device", default="local",
                        help="local (default, for lsass on this Windows host), usb, remote, "
                             "or an explicit frida device id")
    parser.add_argument("--seconds", type=float, default=40.0,
                        help="how long to stay attached while TLS traffic is driven through "
                             "the target (default: %(default)s)")
    parser.add_argument("--agent", default="agent/calibrate.js",
                        help="calibration agent to load (default: %(default)s)")
    parser.add_argument("--out", default=None, help="write collected ground truth here as JSON")
    parser.add_argument("--keylog", default=None,
                        help="write the ground truth as an NSS SSLKEYLOGFILE (the oracle "
                             "tools/verify_keylog.py compares the scanner against); appended "
                             "and deduplicated")
    args = parser.parse_args(argv)
    if args.pid is None and not args.name:
        parser.error("give either --pid or --name")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    """Attach, listen for hooked secrets, then write the oracle and the report.

    An interrupted run still reads the derived fields and writes --out: the
    records are collected as they arrive, so by the time Ctrl-C lands the
    session's whole result already exists in memory and only has to be put on
    disk. Returns EXIT_OK either way - a short calibration is a complete one,
    and the printed summary says how many secrets it stands on.
    """
    args = parse_args(argv)
    keylog = DedupLineFile(Path(args.keylog)) if args.keylog else None
    collector = GroundTruthCollector(keylog)
    session, script = attach_agent(args, collector.on_message)
    try:
        if wait_for_secrets(args.seconds):
            print(f"[*] interrupted after {len(collector.records)} secret(s); the layout and "
                  "the files below are from the records collected so far", file=sys.stderr)
        derived = read_derived(script)
        if args.out:
            write_report(Path(args.out), collector, derived)
    finally:
        if keylog is not None:
            keylog.close()
            print(f"[*] wrote {keylog.path} ({len(keylog)} unique NSS line(s), "
                  f"{collector.rejected} rejected)", file=sys.stderr)
        session.detach()
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ProfileError as error:
        print(f"[!] {error}", file=sys.stderr)
        sys.exit(EXIT_BAD_SETUP)
